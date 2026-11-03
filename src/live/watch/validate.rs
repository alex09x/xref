/*
 * XRef — Stage L3 hardware data watchpoint target resolution, alignment, and budget checks
 * Copyright (c) 2026 Alexander Panasenko
 * Contact: alex@prod.codes
 * Author: https://prod.codes/about/
 * Project: https://github.com/alex09x/xref
 * SPDX-License-Identifier: MIT OR Apache-2.0
 */

//! Validates `--addr` watchpoint targets (`<= 4` `DR0`–`DR3` slots, natural alignment `1|2|4|8`,
//! readable/writable mapping bounds, and initial `/proc/<pid>/mem` snapshot reads).

use std::collections::BTreeSet;

use crate::image::Image;
use crate::live::classify::{find_load_segment, find_region};
use crate::live::cli::{MAX_WATCHES_PER_SESSION, WatchAccessMode, WatchLen};
use crate::live::memscan::ReadAt;
use crate::live::procfs::LiveSession;
use crate::live::types::{BinaryMatch, HexAddr, RegionEntry, apply_slide, remove_slide};
use crate::live::watch::types::WatchTargetSpec;

pub fn validate_session_for_watch(session: &LiveSession) -> Result<(), String> {
    if session.process.process_changed {
        return Err(format!("process_changed: target pid {} identity changed before watch setup", session.process.pid));
    }
    if !session.process.pid_alive_after {
        return Err(format!("process_exited: target pid {} exited before watch setup", session.process.pid));
    }
    if session.process.binary_match == BinaryMatch::ForcedMismatch {
        return Err(
            "verified executable identity required for live watch: --force-bin mismatch cannot attribute instructions or prove store values"
                .to_owned(),
        );
    }
    for warn in &session.process.warnings {
        if warn == "target_identity_unverified"
            || warn == "pie_slide_unresolved_forced_zero"
            || warn.starts_with("forced_unverified_exe")
        {
            return Err(format!("verified executable identity and load bias required for live watch ({warn})"));
        }
    }
    #[cfg(target_os = "linux")]
    if session.exe_dev_ino.is_none_or(|(_, ino)| ino == 0) {
        return Err(
            "verified (dev, ino) for /proc/<pid>/exe required before installing hardware watchpoints".to_owned()
        );
    }
    Ok(())
}

pub fn validate_watch_targets(
    image: &Image,
    pie_slide: i64,
    regions: &[RegionEntry],
    addrs: &[u64],
    len_bytes: WatchLen,
    access: WatchAccessMode,
    mem_reader: Option<&dyn ReadAt>,
) -> Result<Vec<WatchTargetSpec>, String> {
    if addrs.is_empty() {
        return Ok(Vec::new());
    }
    if addrs.len() > MAX_WATCHES_PER_SESSION {
        return Err(format!(
            "watch requires 1..={MAX_WATCHES_PER_SESSION} <ADDR> targets (x86-64 provides DR0..DR3 = 4 hardware slots)"
        ));
    }

    let len_u64 = u64::from(len_bytes.as_u8());
    let mut seen_runtime = BTreeSet::new();
    let mut specs = Vec::with_capacity(addrs.len());

    for &input in addrs {
        let (runtime_va, static_va) = resolve_watch_input(image, pie_slide, regions, input)?;
        if !runtime_va.is_multiple_of(len_u64) {
            return Err(format!(
                "unaligned_watch_address: runtime address {runtime_va:#x} (from input {input:#x}) is not naturally aligned to {len_u64}-byte hardware watchpoint boundary"
            ));
        }
        let Some(end_va) = runtime_va.checked_add(len_u64) else {
            return Err(format!("invalid_watch_address: runtime address {runtime_va:#x}+{len_u64} overflows u64"));
        };
        let Some(region) = find_region(regions, runtime_va) else {
            return Err(format!(
                "unmapped_watch_address: runtime address {runtime_va:#x} (from input {input:#x}) is not inside any mapped region of target process"
            ));
        };
        if end_va > region.end.0 {
            return Err(format!(
                "watch_crosses_region_boundary: watch range {runtime_va:#x}..{end_va:#x} crosses region end {:#x}",
                region.end.0
            ));
        }
        if access == WatchAccessMode::Write && !region.perms.contains('w') {
            return Err(format!(
                "non_writable_watch_region: runtime address {runtime_va:#x} is in region {} with perms '{}' (write watchpoint requires writable mapping or --access rw)",
                region.format_location(runtime_va),
                region.perms
            ));
        }
        if !region.perms.contains('r') && !region.perms.contains('w') {
            return Err(format!(
                "inaccessible_watch_region: runtime address {runtime_va:#x} is in guard/inaccessible region {} with perms '{}'",
                region.format_location(runtime_va),
                region.perms
            ));
        }
        if !seen_runtime.insert(runtime_va) {
            return Err(format!(
                "duplicate_watch_target: input {input:#x} resolves to duplicate runtime address {runtime_va:#x}"
            ));
        }

        let initial_snapshot = mem_reader.and_then(|r| read_watch_scalar(r, runtime_va, len_bytes));
        specs.push(WatchTargetSpec {
            input,
            runtime_va,
            static_va,
            region: region.format_location(runtime_va),
            perms: region.perms.clone(),
            access,
            len_bytes,
            initial_snapshot,
        });
    }

    Ok(specs)
}

pub fn resolve_watch_input(
    image: &Image,
    pie_slide: i64,
    regions: &[RegionEntry],
    input: u64,
) -> Result<(u64, Option<u64>), String> {
    let segments = &image.metadata.load_segments;
    if find_region(regions, input).is_some() {
        let static_va = remove_slide(input, pie_slide).filter(|&s| find_load_segment(segments, s).is_some());
        return Ok((input, static_va));
    }
    if find_load_segment(segments, input).is_some()
        && let Some(rt) = apply_slide(input, pie_slide)
        && find_region(regions, rt).is_some()
    {
        return Ok((rt, Some(input)));
    }
    Err(format!(
        "unmapped_watch_address: address {input:#x} is neither a mapped live runtime VA nor a static ELF VA with a mapped runtime region"
    ))
}

#[must_use]
pub fn read_watch_scalar(reader: &dyn ReadAt, runtime_va: u64, len_bytes: WatchLen) -> Option<HexAddr> {
    let mut buf = [0_u8; 8];
    let n = usize::from(len_bytes.as_u8());
    let got = reader.read_at(&mut buf[..n], runtime_va).ok()?;
    if got != n {
        return None;
    }
    let val = match len_bytes {
        WatchLen::B1 => u64::from(buf[0]),
        WatchLen::B2 => u64::from(u16::from_le_bytes([buf[0], buf[1]])),
        WatchLen::B4 => u64::from(u32::from_le_bytes([buf[0], buf[1], buf[2], buf[3]])),
        WatchLen::B8 => u64::from_le_bytes(buf),
    };
    Some(HexAddr(val))
}

pub fn validate_slot_watch_target(
    image: &Image,
    pie_slide: i64,
    regions: &[RegionEntry],
    input: u64,
    mem_reader: Option<&dyn ReadAt>,
) -> Result<WatchTargetSpec, String> {
    let (runtime_va, static_va) = resolve_watch_input(image, pie_slide, regions, input)?;
    if !runtime_va.is_multiple_of(8) {
        return Err(format!("unaligned_watch_address: pointer slot {runtime_va:#x} must be 8-byte aligned"));
    }
    let Some(region) = find_region(regions, runtime_va) else {
        return Err(format!("unmapped_watch_address: pointer slot {runtime_va:#x} is unmapped"));
    };
    if runtime_va.saturating_add(8) > region.end.0 || !region.perms.contains('r') || !region.perms.contains('w') {
        return Err(format!("non_writable_watch_region: pointer slot {runtime_va:#x} requires rw-p region"));
    }
    let initial_snapshot = mem_reader.and_then(|r| read_watch_scalar(r, runtime_va, WatchLen::B8));
    Ok(WatchTargetSpec {
        input,
        runtime_va,
        static_va,
        region: region.format_location(runtime_va),
        perms: region.perms.clone(),
        access: WatchAccessMode::Write,
        len_bytes: WatchLen::B8,
        initial_snapshot,
    })
}

pub fn prepare_dependent_watches(
    target: (&Image, i64, &[RegionEntry]),
    defaults: (&[String], WatchLen, WatchAccessMode),
    base_watch_idx: usize,
    mem_reader: Option<&dyn ReadAt>,
) -> Result<Vec<crate::live::watch::rebind_runtime::RuntimeDependentWatch>, String> {
    use crate::live::watch::perf_stream::WatchAccumulator;
    use crate::live::watch::rebind::{
        DependentBindingState, RootLivenessStatus, evaluate_dependent_chain, parse_follow_spec,
    };
    use crate::live::watch::rebind_runtime::RuntimeDependentWatch;

    let (image, pie_slide, regions) = target;
    let (follow_raw, default_len, default_access) = defaults;
    let mut out = Vec::with_capacity(follow_raw.len());
    let mut next_idx = base_watch_idx;

    for raw in follow_raw {
        let spec = parse_follow_spec(raw, default_len, default_access)?;
        let ptr_slot_spec = validate_slot_watch_target(image, pie_slide, regions, spec.ptr_slot, mem_reader)?;
        let header_slot_spec = spec
            .header_ptr_slot
            .map(|h| validate_slot_watch_target(image, pie_slide, regions, h, mem_reader))
            .transpose()?;
        let resolved_len_slot_va =
            spec.len_slot.map(|l| resolve_watch_input(image, pie_slide, regions, l).map(|p| p.0)).transpose()?;
        let resolved_guard_slot_va =
            spec.guard_slot.map(|g| resolve_watch_input(image, pie_slide, regions, g).map(|p| p.0)).transpose()?;

        let ptr_slot_watch_index = next_idx;
        next_idx += 1;
        let header_slot_watch_index = header_slot_spec.as_ref().map(|_| {
            let idx = next_idx;
            next_idx += 1;
            idx
        });
        let leaf_watch_index = next_idx;
        next_idx += 1;

        let mut rt = RuntimeDependentWatch {
            spec,
            active_ptr_slot_spec: Some(ptr_slot_spec.clone()),
            ptr_slot_spec,
            header_slot_spec,
            resolved_len_slot_va,
            resolved_guard_slot_va,
            ptr_slot_watch_index,
            header_slot_watch_index,
            leaf_watch_index,
            state: DependentBindingState::DisarmedNullOrUnmapped,
            liveness: RootLivenessStatus::InvalidatedByNullOrBounds,
            generation: 0,
            active_leaf_spec: None,
            initial_leaf_snapshot: None,
            observed_len: None,
            rebind_events: Vec::new(),
            root_ptr_slot_hits: 0,
            leaf_acc: WatchAccumulator::default(),
        };
        let eval = evaluate_dependent_chain(
            &rt.spec,
            regions,
            mem_reader,
            rt.ptr_slot_spec.runtime_va,
            rt.header_slot_spec.as_ref().map(|s| s.runtime_va),
            rt.resolved_len_slot_va,
            rt.resolved_guard_slot_va,
        );
        let _ = rt.apply_evaluated(eval, true);
        out.push(rt);
    }
    Ok(out)
}

#[cfg(any(target_os = "linux", test))]
#[must_use]
pub fn build_dependent_watch_result(
    dep: crate::live::watch::rebind_runtime::RuntimeDependentWatch,
    mem_reader: Option<&dyn ReadAt>,
) -> crate::live::watch::rebind::DependentWatchResult {
    use crate::live::watch::rebind::{DEPENDENT_REBIND_CAVEAT, DependentWatchResult};
    use crate::live::watch::types::WriterSiteEntry;

    let latest_leaf_snapshot = dep
        .active_leaf_spec
        .as_ref()
        .and_then(|s| mem_reader.and_then(|r| read_watch_scalar(r, s.runtime_va, s.len_bytes)));
    let mut writer_sites: Vec<WriterSiteEntry> = dep.leaf_acc.writer_sites.into_values().collect();
    writer_sites.sort_by(|a, b| b.hits.cmp(&a.hits).then_with(|| a.trap_runtime_ip.cmp(&b.trap_runtime_ip)));

    DependentWatchResult {
        hardware_slots_reserved: dep.spec.hardware_slots_required(),
        spec: dep.spec.raw_spec,
        ptr_slot_runtime_va: HexAddr(dep.ptr_slot_spec.runtime_va),
        leaf_offset: dep.spec.offset,
        leaf_len_bytes: dep.spec.leaf_len.as_u8(),
        leaf_access: dep.spec.leaf_access.as_str(),
        binding_state: dep.state,
        root_liveness: dep.liveness,
        generation: dep.generation,
        active_leaf_runtime_va: dep.active_leaf_spec.as_ref().map(|s| HexAddr(s.runtime_va)),
        active_leaf_region: dep.active_leaf_spec.as_ref().map(|s| s.region.clone()),
        observed_len: dep.observed_len,
        initial_leaf_snapshot: dep.initial_leaf_snapshot,
        latest_leaf_snapshot,
        rebind_coverage_gap: true,
        caveat: DEPENDENT_REBIND_CAVEAT,
        root_ptr_slot_hits: dep.root_ptr_slot_hits,
        accepted_hits: dep.leaf_acc.accepted_hits,
        first_timestamp_ns: dep.leaf_acc.first_timestamp_ns,
        last_timestamp_ns: dep.leaf_acc.last_timestamp_ns,
        rebind_events: dep.rebind_events,
        writer_sites,
        samples_truncated: dep.leaf_acc.samples_truncated,
        samples: dep.leaf_acc.samples,
    }
}
