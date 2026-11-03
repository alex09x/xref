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
    if addrs.is_empty() || addrs.len() > MAX_WATCHES_PER_SESSION {
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

fn resolve_watch_input(
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
