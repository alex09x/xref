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
const CONTEXT_KERNEL: u64 = (-128_i64).cast_unsigned();
const CONTEXT_USER: u64 = (-512_i64).cast_unsigned();
const CONTEXT_GUEST_KERNEL: u64 = (-2176_i64).cast_unsigned();
const CONTEXT_GUEST_USER: u64 = (-2560_i64).cast_unsigned();

pub struct Analysis {
    pub header: Header,
    pub footer: Footer,
    pub aggregate: Aggregate,
    pub modules: Vec<Module>,
    pub ignored_samples: u64,
    pub unresolved_frames: u64,
    pub warnings: BTreeSet<String>,
}

/// Two passes preserve mapping timestamps even when rings are drained out of
/// order. A malformed/truncated file never yields a complete report.
pub fn analyze<R: Read + Seek>(input: &mut R, image: &Image, within: &BTreeSet<u64>) -> Result<Analysis, String> {
    input.seek(SeekFrom::Start(0)).map_err(|error| error.to_string())?;
    let (header, footer, mappings, maps_truncated) = read_metadata(input)?;
    let hash = crate::trace_analysis::index::hex_bytes(&Sha256::digest(&image.data));
    if hash != header.image_sha256 {
        return Err("profile image SHA-256 does not match --bin".to_owned());
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
    if maps_truncated {
        warnings.insert("mapping_budget_exhausted".to_owned());
        aggregate.incomplete = true;
    }
    if footer.partial_coverage || footer.dropped > 0 {
        warnings.insert("capture_coverage_is_incomplete".to_owned());
        aggregate.incomplete = true;
    }
    if footer.stop_reason == "import_aux_trace_not_decoded" {
        warnings.insert("aux_trace_not_decoded".to_owned());
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
    while let Some(record) = reader.read_record().map_err(|error| error.to_string())? {
        match record {
            Record::Sample(sample) => batch.push(sample),
            Record::Lost { count, .. } => batch.lost(count),
            _ => {}
        }
    }
    batch.finish();
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
    Ok(Analysis { header, footer, aggregate, modules: index.modules, ignored_samples, unresolved_frames, warnings })
}

fn read_metadata<R: Read>(input: &mut R) -> Result<(Header, Footer, Vec<Mapping>, bool), String> {
    let mut reader = ProfileReader::new(input).map_err(|error| error.to_string())?;
    let header = reader.header.clone();
    let mut mappings = Vec::new();
    let mut truncated = false;
    let mut footer = None;
    let mut samples = 0_u64;
    while let Some(record) = reader.read_metadata_record().map_err(|error| error.to_string())? {
        match record {
            Record::Sample(_) => {
                samples = samples.checked_add(1).ok_or("profile sample count overflow")?;
                if samples > super::config::MAX_SAMPLES {
                    return Err("profile sample budget exceeded".to_owned());
                }
            }
            Record::Mapping(mapping) if mappings.len() < MAX_MAPPINGS => mappings.push(mapping),
            Record::Mapping(_) => truncated = true,
            Record::End(value) => footer = Some(value),
            _ => {}
        }
    }
    Ok((header, footer.ok_or("profile footer missing")?, mappings, truncated))
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
                    .unwinder_key(header, sample.pid, sample.timestamp_ns, ip, return_address)
                    .and_then(|key| unwinders.get(&key))
            });
            if result.stop_reason != "end_of_stack" {
                warnings.insert(format!("cfi_unwind_stopped_{}", result.stop_reason));
            }
            ips.extend(result.frames.into_iter().skip(1).map(|ip| (ip, false, true)));
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
    ips.into_iter()
        .map(|(ip, kernel, return_address)| {
            index.frame(image, header, sample.pid, sample.timestamp_ns, ip, kernel, return_address)
        })
        .collect()
}
