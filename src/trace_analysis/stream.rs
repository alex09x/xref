/*
 * XRef — Streaming bounded trace import
 * Copyright (c) 2026 Alexander Panasenko
 * Contact: alex@prod.codes
 * Author: https://prod.codes/about/
 * Project: https://github.com/alex09x/xref
 * SPDX-License-Identifier: MIT OR Apache-2.0
 */

use super::{
    index::{RuntimeMapping, SymbolIndex},
    mapping::MappingState,
    models::{FrameKind, ObservedStore, SymbolizedFrame, TraceStats},
    observed::{COUNT_UNIT, EDGE_SEMANTICS, EdgeAccumulator},
    parse::{InputFormat, MAX_LINE_BYTES, RawSample, TextParser, TraceEvent},
};
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeSet,
    io::BufRead,
    sync::atomic::{AtomicBool, Ordering},
    time::{Duration, Instant},
};

pub const MAX_INPUT_BYTES: u64 = 8 * 1024 * 1024 * 1024;
pub const MAX_SAMPLES: u64 = 1_000_000;

pub struct TraceConfig<'a> {
    pub format: InputFormat,
    pub frame_kind: FrameKind,
    pub target_path: Option<String>,
    pub pid: Option<u32>,
    pub mappings: Vec<RuntimeMapping>,
    pub trace_build_id: Option<String>,
    pub max_bytes: u64,
    pub max_samples: u64,
    pub timeout: Duration,
    pub cancel: Option<&'a AtomicBool>,
}

impl Default for TraceConfig<'_> {
    fn default() -> Self {
        Self {
            format: InputFormat::Addresses,
            frame_kind: FrameKind::Auto,
            target_path: None,
            pid: None,
            mappings: vec![],
            trace_build_id: None,
            max_bytes: 2 * 1024 * 1024 * 1024,
            max_samples: 100_000,
            timeout: Duration::from_secs(30),
            cancel: None,
        }
    }
}

struct ImportState<'a> {
    index: &'a SymbolIndex,
    mappings: MappingState,
    edges: EdgeAccumulator,
    stats: TraceStats,
    warnings: BTreeSet<String>,
    used_verified_mapping: bool,
    used_unverified_mapping: bool,
}

impl<'a> ImportState<'a> {
    fn new(index: &'a SymbolIndex, config: &TraceConfig<'_>) -> Self {
        let mut state = Self {
            index,
            mappings: MappingState::with_explicit(config.mappings.clone()),
            edges: EdgeAccumulator::default(),
            stats: TraceStats::default(),
            warnings: index.warnings.iter().cloned().collect(),
            used_verified_mapping: false,
            used_unverified_mapping: false,
        };
        state.warnings.insert("stack_adjacency_and_sample_counts_are_not_direct_calls_or_invocation_counts".to_owned());
        state.warnings.insert("fde_ranges_are_not_source_function_boundaries".to_owned());
        if config.format == InputFormat::Perf && config.frame_kind == FrameKind::Auto {
            state.warnings.insert("perf_callchain_ancestors_treated_as_return_addresses".to_owned());
        }
        state
    }

    fn event(
        &mut self,
        event: TraceEvent,
        config: &TraceConfig<'_>,
        emit: &mut impl FnMut(&[SymbolizedFrame], u64) -> Result<(), String>,
    ) -> Result<(), String> {
        match event {
            TraceEvent::Mmap(event) => {
                self.mappings.mmap(self.index, &event, config.target_path.as_deref())?;
                if event.build_id.is_none() {
                    self.warnings.insert("mmap_build_id_unavailable_path_only_identity".to_owned());
                }
            }
            TraceEvent::Fork { pid, tid, parent_pid, parent_tid } => {
                self.mappings.fork(pid, tid, parent_pid, parent_tid)?;
            }
            TraceEvent::Exec(pid) => self.mappings.exec(pid)?,
            TraceEvent::Lost(count) => {
                self.stats.lost_events =
                    self.stats.lost_events.checked_add(count).ok_or("lost-event count overflow")?;
                self.warnings.insert("perf_lost_records_observation_is_partial".to_owned());
            }
            TraceEvent::KernelMapping => {
                self.stats.kernel_mapping_records_ignored += 1;
                self.warnings.insert("kernel_mapping_records_ignored_selected_user_executable_scope".to_owned());
            }
            TraceEvent::Malformed => {
                self.stats.malformed_lines += 1;
                self.warnings.insert("unrecognized_trace_lines_skipped".to_owned());
            }
            TraceEvent::Sample(sample) => self.sample(sample, config, emit)?,
        }
        Ok(())
    }

    fn sample(
        &mut self,
        sample: RawSample,
        config: &TraceConfig<'_>,
        emit: &mut impl FnMut(&[SymbolizedFrame], u64) -> Result<(), String>,
    ) -> Result<(), String> {
        let pid = self
            .mappings
            .sample_pid(&sample)
            .or_else(|| if config.format == InputFormat::Perf { None } else { config.pid });
        if config.pid.is_some_and(|selected| pid != Some(selected)) {
            self.stats.samples_ignored += 1;
            if pid.is_none() {
                self.warnings.insert("sample_without_pid_cannot_apply_process_filter".to_owned());
            }
            return Ok(());
        }
        if sample.weight == 0 {
            return Err("sample weight must be positive".to_owned());
        }
        self.stats.samples += 1;
        self.stats.weight = self.stats.weight.checked_add(sample.weight).ok_or("sample weight overflow")?;
        if sample.truncated {
            self.stats.aggregation_truncated = true;
            self.warnings.insert("stack_depth_limit_frames_omitted".to_owned());
        }
        let mappings = self.mappings.for_sample(pid, config.pid)?;
        let mut frames = Vec::with_capacity(sample.frames.len());
        for input in sample.frames {
            if config.cancel.is_some_and(|flag| flag.load(Ordering::Relaxed)) {
                return Err("trace symbolization cancelled".to_owned());
            }
            let frame = self.index.frame(&input.token, input.kind, pid, mappings);
            match frame.mapping_evidence.as_deref() {
                Some("mmap_build_id_matches_selected_image" | "fork_inherited_build_id_matched_mapping") => {
                    self.used_verified_mapping = true;
                }
                Some(_) => self.used_unverified_mapping = true,
                None if frame.function.is_some() => self.used_unverified_mapping = true,
                None => {}
            }
            self.stats.frames += 1;
            if frame.function.is_some() {
                self.stats.resolved_frames += 1;
            } else {
                self.stats.unresolved_frames += 1;
            }
            frames.push(frame);
        }
        if frames.is_empty() {
            self.warnings.insert("sample_has_no_address_frames".to_owned());
        }
        self.edges.add(&frames, sample.weight)?;
        emit(&frames, sample.weight)
    }
}

fn hex_digest(bytes: impl IntoIterator<Item = u8>) -> String {
    use std::fmt::Write;
    let mut output = String::with_capacity(64);
    for byte in bytes {
        let _ = write!(output, "{byte:02x}");
    }
    output
}

pub fn import_trace<R: BufRead>(
    reader: &mut R,
    index: &SymbolIndex,
    config: &TraceConfig<'_>,
    mut emit: impl FnMut(&[SymbolizedFrame], u64) -> Result<(), String>,
) -> Result<ObservedStore, String> {
    if config.max_bytes == 0
        || config.max_bytes > MAX_INPUT_BYTES
        || config.max_samples == 0
        || config.max_samples > MAX_SAMPLES
        || config.timeout.is_zero()
        || config.timeout > Duration::from_secs(600)
        || config.mappings.len() > super::mapping::MAX_MAPPINGS
    {
        return Err("invalid trace input/time/sample budget".to_owned());
    }
    let declared_id = index.validate_identity(config.trace_build_id.as_deref())?;
    let mut state = ImportState::new(index, config);
    let mut parser = TextParser::new(config.format, config.frame_kind);
    let started = Instant::now();
    let mut digest = Sha256::new();
    let mut line = Vec::with_capacity(4096);
    loop {
        if config.cancel.is_some_and(|flag| flag.load(Ordering::Relaxed)) {
            return Err("trace symbolization cancelled".to_owned());
        }
        if state.stats.samples >= config.max_samples {
            if parser.has_pending() || !reader.fill_buf().map_err(|error| error.to_string())?.is_empty() {
                state.stats.input_truncated = true;
                state.warnings.insert("trace_sample_budget_exhausted".to_owned());
            }
            break;
        }
        if started.elapsed() >= config.timeout {
            state.stats.input_truncated = true;
            state.warnings.insert("trace_time_or_sample_budget_exhausted".to_owned());
            break;
        }
        line.clear();
        let complete =
            read_bounded_line(reader, &mut line, &mut state.stats.input_bytes, config.max_bytes, &mut digest)?;
        if !complete {
            if !line.is_empty() || !reader.fill_buf().map_err(|error| error.to_string())?.is_empty() {
                state.stats.input_truncated = true;
                state.warnings.insert("trace_byte_budget_exhausted".to_owned());
            }
            break;
        }
        if line.is_empty() {
            break;
        }
        let text = std::str::from_utf8(&line).map_err(|_| "trace text is not UTF-8")?;
        for event in parser.line(text)? {
            state.event(event, config, &mut emit)?;
        }
    }
    if !state.stats.input_truncated
        && let Some(event) = parser.finish()
    {
        state.event(event, config, &mut emit)?;
    }
    state.stats.aggregation_truncated |= state.edges.truncated;
    if state.edges.truncated {
        state.warnings.insert("observed_edge_budget_exhausted".to_owned());
    }
    if state.stats.unresolved_frames > 0 {
        state.warnings.insert("unknown_frames_preserved_edges_never_bridge_them".to_owned());
    }
    if state.stats.input_truncated {
        state.warnings.insert("input_sha256_is_consumed_prefix_only".to_owned());
    }
    let identity_evidence = if state.used_verified_mapping && !state.used_unverified_mapping {
        "mmap_build_id_matches_selected_image"
    } else if state.used_verified_mapping {
        "mixed_build_id_matched_and_caller_assumed_mappings"
    } else if declared_id {
        "caller_provided_build_id_matches_selected_image"
    } else {
        "caller_selected_image_mapping_not_trace_identity_proof"
    };
    state.warnings.insert("imported_trace_producer_not_authenticated".to_owned());
    if state.used_unverified_mapping {
        state.warnings.insert("some_target_mappings_not_independently_build_id_verified".to_owned());
    }
    Ok(ObservedStore {
        schema_version: 1,
        image: index.identity.clone(),
        input_sha256: hex_digest(digest.finalize()),
        count_unit: COUNT_UNIT.to_owned(),
        edge_semantics: EDGE_SEMANTICS.to_owned(),
        identity_evidence: identity_evidence.to_owned(),
        stats: state.stats,
        warnings: state.warnings.into_iter().collect(),
        edges: state.edges.into_edges(),
    })
}

fn read_bounded_line(
    reader: &mut impl BufRead,
    line: &mut Vec<u8>,
    total: &mut u64,
    limit: u64,
    digest: &mut Sha256,
) -> Result<bool, String> {
    loop {
        let buffer = reader.fill_buf().map_err(|error| error.to_string())?;
        if buffer.is_empty() {
            return Ok(true);
        }
        let available = buffer.iter().position(|byte| *byte == b'\n').map_or(buffer.len(), |position| position + 1);
        let remaining = usize::try_from(limit.saturating_sub(*total)).unwrap_or(usize::MAX);
        let count = available.min(remaining);
        if line.len().saturating_add(count) > MAX_LINE_BYTES {
            return Err("trace line exceeds 64 KiB".to_owned());
        }
        line.extend_from_slice(&buffer[..count]);
        digest.update(&buffer[..count]);
        *total += u64::try_from(count).map_err(|_| "trace byte count overflow")?;
        let newline = count > 0 && buffer[count - 1] == b'\n';
        reader.consume(count);
        if count < available {
            return Ok(false);
        }
        if newline {
            return Ok(true);
        }
    }
}
