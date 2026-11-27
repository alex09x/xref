/*
 * XRef — streaming profile analysis
 * Copyright (c) 2026 Alexander Panasenko
 * Contact: alex@prod.codes
 * Author: https://prod.codes/about/
 * Project: https://github.com/alex09x/xref
 * SPDX-License-Identifier: MIT OR Apache-2.0
 */
use super::{
    aggregate::{Aggregate, Frame, Limits},
    codec::ProfileReader,
    resolve::{MappingIndex, Module},
    types::{Footer, Header, Mapping, Record, Sample},
    unwind::Unwinder,
};
use crate::image::Image;
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeSet,
    io::{Read, Seek, SeekFrom},
};

const MAX_MAPPINGS: usize = 65_536;
const CONTEXT_MAX: u64 = u64::MAX - 4095;
pub(super) const CONTEXT_KERNEL: u64 = (-128_i64).cast_unsigned();
const CONTEXT_USER: u64 = (-512_i64).cast_unsigned();
const CONTEXT_GUEST_KERNEL: u64 = (-2176_i64).cast_unsigned();
const CONTEXT_GUEST_USER: u64 = (-2560_i64).cast_unsigned();

pub struct Analysis {
    pub header: Header,
    pub footer: Footer,
    pub aggregate: Aggregate,
    /// PT instruction counts are never added to hardware sample counts.
    pub pt_aggregate: Option<Aggregate>,
    pub pt_ignored: u64,
    pub pt_unresolved: u64,
    pub modules: Vec<Module>,
    pub ignored_samples: u64,
    pub unresolved_frames: u64,
    pub warnings: BTreeSet<String>,
    /// What a reader should know about the samples (a wrong base, library leaves under frame pointers).
    pub notes: Vec<String>,
    /// The span `--from/--to` kept, when given.
    pub time_window: Option<super::time_range::TimeWindow>,
}

/// Two passes preserve mapping timestamps even when rings are drained out of
/// order. A malformed/truncated file never yields a complete report.
#[allow(clippy::too_many_lines)] // Both event streams share one bounded analysis pass.
pub fn analyze<R: Read + Seek>(input: &mut R, image: &Image, within: &BTreeSet<u64>) -> Result<Analysis, String> {
    analyze_windows(input, image, within, None, false)
}

/// Analyze a selected trigger window or the union of all recorded windows.
pub fn analyze_windows<R: Read + Seek>(
    input: &mut R,
    image: &Image,
    within: &BTreeSet<u64>,
    selected: Option<usize>,
    require_windows: bool,
) -> Result<Analysis, String> {
    analyze_selected(input, image, within, selected, require_windows, None)
}

/// Analyze a trigger window, the union of windows, or the samples of a time range.
#[allow(clippy::too_many_lines)]
pub fn analyze_selected<R: Read + Seek>(
    input: &mut R,
    image: &Image,
    within: &BTreeSet<u64>,
    selected: Option<usize>,
    require_windows: bool,
    time: Option<super::time_range::TimeRange>,
) -> Result<Analysis, String> {
    input.seek(SeekFrom::Start(0)).map_err(|error| error.to_string())?;
    let (header, footer, mappings, maps_truncated, mut windows, sample_span) = read_metadata(input)?;
    if windows.is_empty()
        && let (Some(trigger), Some(width)) = (footer.trigger_timestamp_ns, header.trigger_window_ns)
    {
        let begin = trigger.saturating_sub(width / 2);
        let end = trigger
            .checked_add(width - width / 2)
            .and_then(|value| value.checked_add(1))
            .ok_or("trigger window timestamp overflow")?;
        windows.push(super::windowing::Window { trigger_ns: begin, end_ns: end });
    }
    if windows.is_empty() && (selected.is_some() || require_windows) {
        return Err("profile has no trigger windows".into());
    }
    // Checked after a window written before schema 3 is rebuilt from the header and footer.
    if time.is_some() && !windows.is_empty() {
        return Err("this recording keeps trigger windows: select one with --window instead of --from/--to".into());
    }
    let window_index = super::windowing::WindowIndex::new(&windows, selected)?;
    let mut bounds = time.map(|range| range.bounds(sample_span)).transpose()?;
    let hash = crate::trace_analysis::index::hex_bytes(&Sha256::digest(&image.data));
    if hash != header.image_sha256 {
        return Err(format!(
            "profile image SHA-256 does not match --bin: the profile was recorded against {}, -b is {}",
            header.image_sha256, hash
        ));
    }
    let index = MappingIndex::new(mappings, &header);
    let unwinders =
        if header.callchain == "dwarf" { index.unwinders(image, &header) } else { std::collections::BTreeMap::new() };
    input.seek(SeekFrom::Start(0)).map_err(|error| error.to_string())?;
    let mut reader = ProfileReader::new(input).map_err(|error| error.to_string())?;
    let mut aggregate = Aggregate::new(Limits::default());
    let mut warnings = BTreeSet::new();
    let mut ignored_samples = 0_u64;
    let mut unresolved_frames = 0_u64;
    let mut pt_aggregate = Aggregate::new(Limits::default());
    let mut pt_warnings = BTreeSet::new();
    let mut pt_ignored = 0_u64;
    let mut pt_unresolved = 0_u64;
    let mut pt_header = header.clone();
    "fp".clone_into(&mut pt_header.callchain);
    if header.event == super::types::SYNTHETIC_PT_EVENT {
        warnings.insert("intel_pt_instruction_events_are_not_cpu_samples".to_owned());
        warnings.insert("intel_pt_instruction_timing_unavailable".to_owned());
        aggregate.incomplete = true;
    }
    if maps_truncated {
        warnings.insert("mapping_budget_exhausted".to_owned());
        aggregate.incomplete = true;
    }
    if footer.partial_coverage || footer.dropped > 0 {
        warnings.insert("capture_coverage_is_incomplete".to_owned());
        aggregate.incomplete = true;
    }
    if footer.stop_reason.starts_with("import_aux_trace_not_decoded") {
        warnings.insert("aux_trace_not_decoded".to_owned());
    }
    if header.trigger_static_va.is_some() {
        // The system-wide trigger sees every thread, but CPU samplers attach per thread after it is
        // seen: a thread that exits within the attach latency contributes no samples to the window.
        warnings.insert("trigger_window_samples_miss_threads_that_exit_before_attach".to_owned());
        if header.schema_version < 4 {
            // Written before the system-wide trigger (schema 4): it may have used per-thread
            // triggers, which miss a thread that starts, hits and exits between /proc polls.
            warnings.insert("trigger_misses_threads_shorter_than_the_proc_poll_interval".to_owned());
        }
    }
    if header.binary_match == "perf_data_mmap_unverified" {
        warnings.insert("perf_mmap_target_identity_or_runtime_bytes_unverified".to_owned());
        aggregate.incomplete = true;
    }
    if footer.stop_reason == "intel_pt_instruction_budget_exhausted" {
        warnings.insert("intel_pt_instruction_budget_exhausted".to_owned());
    }
    if matches!(header.binary_match.as_str(), "caller_supplied_base_unverified" | "caller_supplied_maps_unverified") {
        warnings.insert("import_target_mapping_is_synthetic_and_base_is_unverified".to_owned());
        if header.event.starts_with("perf_script") {
            warnings.insert("perf_script_may_not_include_lost_events_or_mapping_changes".to_owned());
            warnings.insert("perf_script_periods_and_timestamps_may_be_missing".to_owned());
        } else if header.event.starts_with("perf_data:") {
            warnings.insert("perf_data_may_have_missing_identity_mapping_or_sample_metadata".to_owned());
        }
        aggregate.incomplete = true;
    }
    if header.trigger_static_va.is_some() {
        warnings.insert("loss_counts_cover_the_entire_capture_not_only_the_trigger_window".to_owned());
        if header.schema_version >= 3 {
            warnings.insert("trigger_sampling_starts_after_observer_receives_event".to_owned());
        }
        if footer.trigger_lost > 0 {
            warnings.insert("trigger_events_lost".to_owned());
            aggregate.incomplete = true;
        }
    }
    if header.callchain == "dwarf" && !unwinders.contains_key(&(1, header.pie_slide)) {
        warnings.insert("target_cfi_unavailable".to_owned());
    }
    if header.callchain == "lbr" {
        warnings.insert("lbr_is_a_bounded_branch_history_not_a_proven_complete_stack".to_owned());
    }
    if index.modules.iter().any(|module| module.kind == "shared_object" && module.symbols_loaded) {
        warnings.insert("module_file_snapshot_not_proof_of_live_memory_bytes".to_owned());
    }
    let mut batch = super::parallel::FrameBatch::new(
        &index,
        image,
        &header,
        &unwinders,
        within,
        &mut aggregate,
        &mut warnings,
        &mut ignored_samples,
        &mut unresolved_frames,
    );
    let mut pt_batch = super::parallel::FrameBatch::new(
        &index,
        image,
        &pt_header,
        &unwinders,
        within,
        &mut pt_aggregate,
        &mut pt_warnings,
        &mut pt_ignored,
        &mut pt_unresolved,
    );
    while let Some(record) = reader.read_record().map_err(|error| error.to_string())? {
        match record {
            Record::Sample(sample) => {
                let kept = bounds.as_mut().is_none_or(|bounds| bounds.keep(sample.timestamp_ns));
                if kept && (windows.is_empty() || window_index.contains(sample.timestamp_ns)) {
                    batch.push(sample);
                }
            }
            Record::PtInstruction(sample) => {
                if !windows.is_empty() {
                    return Err("untimed PT events cannot be attributed to trigger windows".into());
                }
                if bounds.is_some() {
                    return Err("untimed PT events cannot be selected by --from/--to".into());
                }
                pt_batch.push(sample);
            }
            // A loss outside the time range is not counted in it.
            Record::Lost { timestamp_ns, count, .. }
                if bounds.as_ref().is_none_or(|bounds| (bounds.begin..bounds.end).contains(&timestamp_ns)) =>
            {
                batch.lost(count);
            }
            _ => {}
        }
    }
    let sites = batch.finish();
    pt_batch.finish();
    let time_window = bounds.as_ref().map(|bounds| bounds.window(aggregate.lost));
    if let Some(window) = &time_window
        && aggregate.samples == 0
        && ignored_samples == 0
    {
        return Err(format!(
            "no samples between {:.3} s and {:.3} s; the recording spans {:.3} s from its first sample",
            window.from_seconds, window.to_seconds, window.recording_seconds
        ));
    }
    warnings.extend(pt_warnings);
    if pt_aggregate.samples > 0 || pt_ignored > 0 {
        pt_aggregate.incomplete = true;
        warnings.insert("intel_pt_instruction_events_are_not_cpu_samples".to_owned());
        warnings.insert("intel_pt_instruction_timing_unavailable".to_owned());
    }
    if !within.is_empty() {
        warnings.insert("within_filter_can_miss_incomplete_callchains".to_owned());
    }
    if unresolved_frames > 0 {
        warnings.insert("unresolved_frames_preserved_by_module".to_owned());
        aggregate.incomplete = true;
    }
    if warnings.iter().any(|warning| warning == "target_cfi_unavailable" || warning.starts_with("cfi_unwind_stopped_"))
    {
        aggregate.incomplete = true;
    }
    let pt_aggregate = (pt_aggregate.samples > 0 || pt_ignored > 0).then_some(pt_aggregate);
    let notes = super::hints::notes(&header, &mut aggregate, &index.modules, image, sites, &mut warnings);
    Ok(Analysis {
        header,
        footer,
        aggregate,
        pt_aggregate,
        pt_ignored,
        pt_unresolved,
        modules: index.modules,
        ignored_samples,
        unresolved_frames,
        warnings,
        notes,
        time_window,
    })
}

type Metadata = (Header, Footer, Vec<Mapping>, bool, Vec<super::windowing::Window>, Option<(u64, u64)>);

fn read_metadata<R: Read>(input: &mut R) -> Result<Metadata, String> {
    let mut reader = ProfileReader::new(input).map_err(|error| error.to_string())?;
    let header = reader.header.clone();
    let mut mappings = Vec::new();
    let mut truncated = false;
    let mut footer = None;
    let mut windows = Vec::new();
    while let Some(record) = reader.read_metadata_record().map_err(|error| error.to_string())? {
        match record {
            Record::Mapping(mapping) if mappings.len() < MAX_MAPPINGS => mappings.push(mapping),
            Record::Mapping(_) => truncated = true,
            Record::Window { trigger_ns, end_ns } => {
                if windows.len() >= 10_000
                    || windows
                        .last()
                        .is_some_and(|previous: &super::windowing::Window| previous.trigger_ns > trigger_ns)
                {
                    return Err("profile trigger windows exceed budget or are out of order".into());
                }
                windows.push(super::windowing::Window { trigger_ns, end_ns });
            }
            Record::End(value) => footer = Some(value),
            _ => {}
        }
    }
    Ok((header, footer.ok_or("profile footer missing")?, mappings, truncated, windows, reader.sample_span))
}

pub(super) fn sample_frames(
    index: &MappingIndex,
    image: &Image,
    header: &Header,
    sample: &Sample,
    unwinders: &std::collections::BTreeMap<(u32, i64), Unwinder<'_>>,
    warnings: &mut BTreeSet<String>,
) -> Vec<Frame> {
    let kernel = matches!(sample.cpu_mode, 1 | 3 | 4);
    let mut ips = vec![(sample.ip, kernel, false)];
    match header.callchain.as_str() {
        "dwarf" if !kernel => {
            if !sample.branches.is_empty() {
                warnings.insert("recorded_branch_history_not_used_with_dwarf_callchain".to_owned());
            }
            let result = super::unwind::unwind_with(sample, 512, |ip, return_address| {
                index
                    .unwinder_key(image, header, sample.pid, sample.timestamp_ns, ip, return_address)
                    .and_then(|key| unwinders.get(&key))
            });
            if result.stop_reason != "end_of_stack" {
                warnings.insert(format!("cfi_unwind_stopped_{}", result.stop_reason));
            }
            ips.extend(result.frames.into_iter().skip(1).map(|ip| (ip, false, true)));
        }
        "dwarf" => {
            // Sampled in the kernel: its frames are the kernel part of the recorded callchain, and
            // the user stack unwinds from where the thread entered the kernel (the saved user IP).
            for &ip in &sample.callchain {
                if ip == CONTEXT_USER || ip == CONTEXT_GUEST_USER {
                    break;
                }
                if ip < CONTEXT_MAX && (ips.len() != 1 || ip != sample.ip) {
                    ips.push((ip, true, true));
                }
            }
            if let Some(user) = super::unwind::user_ip(sample) {
                let result = super::unwind::unwind_from(sample, user, 512, |ip, return_address| {
                    index
                        .unwinder_key(image, header, sample.pid, sample.timestamp_ns, ip, return_address)
                        .and_then(|key| unwinders.get(&key))
                });
                if result.stop_reason != "end_of_stack" {
                    warnings.insert(format!("cfi_unwind_stopped_{}", result.stop_reason));
                }
                // The user IP is where the syscall returns to: an instruction, not a return address.
                ips.push((user, false, false));
                ips.extend(result.frames.into_iter().skip(1).map(|ip| (ip, false, true)));
            }
        }
        "fp" | "imported_perf_script" => {
            let mut in_kernel = kernel;
            for &ip in &sample.callchain {
                if ip >= CONTEXT_MAX {
                    if ip == CONTEXT_KERNEL || ip == CONTEXT_GUEST_KERNEL {
                        in_kernel = true;
                    }
                    if ip == CONTEXT_USER || ip == CONTEXT_GUEST_USER {
                        in_kernel = false;
                    }
                } else if ips.len() != 1 || ip != sample.ip {
                    ips.push((ip, in_kernel, true));
                }
            }
        }
        "lbr" => ips.extend(sample.branches.iter().map(|branch| (branch.from, false, false))),
        "none" => {}
        _ => {
            warnings.insert("unknown_or_unavailable_callchain_mode".to_owned());
        }
    }
    let mut frames: Vec<Frame> = ips
        .into_iter()
        .map(|(ip, kernel, return_address)| {
            index.frame(image, header, sample.pid, sample.timestamp_ns, ip, kernel, return_address)
        })
        .collect();
    // Kernel frames without names (no readable kallsyms) are all `[kernel]:unknown`: a run of
    // them is one frame of the path, not a recursion of one function.
    frames.dedup_by(|frame, previous| {
        frame.function == previous.function && frame.function.start.is_none() && frame.function.module == 2
    });
    frames
}
