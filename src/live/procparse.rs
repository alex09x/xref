/*
 * XRef — Live Linux procfs inspection and xref-aware memory scanning
 * Copyright (c) 2026 Alexander Panasenko
 * Contact: alex@prod.codes
 * Author: https://prod.codes/about/
 * Project: https://github.com/alex09x/xref
 * SPDX-License-Identifier: MIT OR Apache-2.0
 */

//! Pure, bounded parsers for Linux `/proc/<pid>/{stat,maps,smaps}`, target matching, and PIE slide.

use std::collections::BTreeMap;
use std::fmt::Write as _;

use object::Object;
use sha2::{Digest, Sha256};

use crate::image::Image;
use crate::image_format::LoadSegment;
use crate::live::types::{BinaryMatch, HexAddr, RegionEntry, ScanStatus};

pub const MAX_STAT_BYTES: usize = 64 * 1024;
pub const MAX_MAPS_BYTES: usize = 16 * 1024 * 1024;
pub const MAX_MAPS_REGIONS: usize = 65_536;

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct TargetIdentity {
    pub dev_major_minor: Option<(u64, u64)>,
    pub inode: Option<u64>,
    pub pathname: Option<String>,
}

impl TargetIdentity {
    #[must_use]
    pub fn matches_region(&self, dev: &str, inode: u64, pathname: Option<&str>) -> bool {
        if inode != 0
            && self.inode == Some(inode)
            && let Some(expected_dev) = self.dev_major_minor
            && parse_dev_pair(dev) == Some(expected_dev)
        {
            return true;
        }
        let Some(target_path) = self.pathname.as_deref().map(strip_deleted_suffix) else {
            return false;
        };
        pathname.map(strip_deleted_suffix).is_some_and(|p| p == target_path)
    }
}

fn strip_deleted_suffix(path: &str) -> &str {
    path.strip_suffix(" (deleted)").unwrap_or(path)
}

fn parse_dev_pair(dev: &str) -> Option<(u64, u64)> {
    let (maj, min) = dev.split_once(':')?;
    Some((u64::from_str_radix(maj, 16).ok()?, u64::from_str_radix(min, 16).ok()?))
}

/// Parse `starttime_ticks` (field 22) from `/proc/<pid>/stat` after the LAST `')'` of `comm`.
pub fn parse_stat_starttime(stat_bytes: &[u8], expected_pid: u32) -> Result<u64, String> {
    if expected_pid == 0 {
        return Err("expected PID must be non-zero".to_owned());
    }
    if stat_bytes.len() > MAX_STAT_BYTES {
        return Err(format!("procfs stat exceeds {MAX_STAT_BYTES}-byte limit"));
    }
    let open =
        stat_bytes.iter().position(|&b| b == b'(').ok_or_else(|| "malformed procfs stat: missing '('".to_owned())?;
    let close =
        stat_bytes.iter().rposition(|&b| b == b')').ok_or_else(|| "malformed procfs stat: missing ')'".to_owned())?;
    if close <= open {
        return Err("malformed procfs stat: ')' precedes '('".to_owned());
    }
    let pid_str = std::str::from_utf8(&stat_bytes[..open])
        .map_err(|_| "malformed procfs stat: non-ASCII pid header".to_owned())?
        .trim();
    let pid = pid_str.parse::<u32>().map_err(|e| format!("malformed procfs stat pid '{pid_str}': {e}"))?;
    if pid != expected_pid {
        return Err(format!("procfs stat PID {pid} does not match requested PID {expected_pid}"));
    }
    let tail_str = std::str::from_utf8(&stat_bytes[close + 1..])
        .map_err(|_| "malformed procfs stat: non-ASCII numeric fields".to_owned())?;
    let starttime_str = tail_str
        .split_ascii_whitespace()
        .nth(19)
        .ok_or_else(|| "malformed procfs stat: fewer than 22 fields".to_owned())?;
    starttime_str.parse::<u64>().map_err(|e| format!("malformed starttime '{starttime_str}': {e}"))
}

#[must_use]
pub const fn is_valid_perms(perms: &str) -> bool {
    let bytes = perms.as_bytes();
    bytes.len() == 4
        && matches!(bytes[0], b'r' | b'-')
        && matches!(bytes[1], b'w' | b'-')
        && matches!(bytes[2], b'x' | b'-')
        && matches!(bytes[3], b'p' | b's')
}

#[must_use]
pub fn classify_scan_status(
    perms: &str,
    pathname: Option<&str>,
    vm_flags: Option<&[String]>,
    is_target_image: bool,
) -> ScanStatus {
    if pathname.is_some_and(|p| matches!(p, "[vvar]" | "[vdso]" | "[vsyscall]") || p.starts_with("[vvar")) {
        return ScanStatus::SkippedDeviceOrSpecial;
    }
    if perms.as_bytes().get(3) == Some(&b's') {
        return ScanStatus::SkippedShared;
    }
    if perms != "rw-p" {
        return ScanStatus::SkippedNonWritable;
    }
    if pathname.is_some_and(|p| p.starts_with("/dev/")) {
        return ScanStatus::SkippedDeviceOrSpecial;
    }
    let Some(flags) = vm_flags else {
        return ScanStatus::SkippedMissingVmflags;
    };
    if flags.iter().any(|flag| matches!(flag.as_str(), "io" | "pf" | "dd" | "ht" | "um")) {
        return ScanStatus::SkippedVmflags;
    }
    let eligible_anon_or_stack =
        pathname.is_none_or(|p| p == "[heap]" || p == "[stack]" || p.starts_with("[stack:") || p.starts_with("[anon"));
    if !eligible_anon_or_stack && !is_target_image {
        return ScanStatus::SkippedUnclassifiedFile;
    }
    ScanStatus::ScannableRwp
}

pub fn parse_smaps_vmflags(smaps_bytes: &[u8]) -> Result<BTreeMap<(u64, u64), Vec<String>>, String> {
    if smaps_bytes.len() > MAX_MAPS_BYTES {
        return Err(format!("procfs smaps exceeds {MAX_MAPS_BYTES}-byte limit"));
    }
    let text = String::from_utf8_lossy(smaps_bytes);
    let mut out = BTreeMap::new();
    let mut current_range: Option<(u64, u64)> = None;
    let mut seen_flags_for_current = false;
    for (idx, raw_line) in text.lines().enumerate() {
        let line = raw_line.trim_end_matches('\r');
        if let Some(flags_str) = line.strip_prefix("VmFlags:") {
            let Some(range) = current_range else {
                return Err(format!("smaps line {}: VmFlags without mapping header", idx + 1));
            };
            if seen_flags_for_current {
                return Err(format!("smaps line {}: duplicate VmFlags for {:#x}..{:#x}", idx + 1, range.0, range.1));
            }
            seen_flags_for_current = true;
            out.insert(range, flags_str.split_ascii_whitespace().map(str::to_owned).collect());
        } else if let Some(first_token) = line.split_ascii_whitespace().next()
            && !first_token.ends_with(':')
            && let Some((start_s, end_s)) = first_token.split_once('-')
            && let (Ok(start), Ok(end)) = (u64::from_str_radix(start_s, 16), u64::from_str_radix(end_s, 16))
        {
            current_range = Some((start, end));
            seen_flags_for_current = false;
        }
    }
    Ok(out)
}

pub fn parse_maps(
    maps_bytes: &[u8],
    smaps_bytes: Option<&[u8]>,
    target: &TargetIdentity,
) -> Result<Vec<RegionEntry>, String> {
    if maps_bytes.len() > MAX_MAPS_BYTES {
        return Err(format!("procfs maps exceeds {MAX_MAPS_BYTES}-byte limit"));
    }
    let smaps_flags = match smaps_bytes {
        Some(raw) => Some(parse_smaps_vmflags(raw)?),
        None => None,
    };
    let text = String::from_utf8_lossy(maps_bytes);
    let mut regions = Vec::new();
    let mut prev_end = 0_u64;
    for (idx, raw_line) in text.lines().enumerate() {
        let line = raw_line.trim_end_matches('\r');
        if line.trim().is_empty() {
            continue;
        }
        if regions.len() >= MAX_MAPS_REGIONS {
            return Err(format!("procfs maps exceeds {MAX_MAPS_REGIONS}-region limit"));
        }
        let line_no = idx + 1;
        let (range_tok, rest) = split_ws_once(line).ok_or_else(|| format!("maps line {line_no}: missing range"))?;
        let (start_s, end_s) = range_tok.split_once('-').ok_or_else(|| format!("maps line {line_no}: bad range"))?;
        let start = u64::from_str_radix(start_s, 16).map_err(|e| format!("maps line {line_no}: start: {e}"))?;
        let end = u64::from_str_radix(end_s, 16).map_err(|e| format!("maps line {line_no}: end: {e}"))?;
        if end <= start || start < prev_end {
            return Err(format!("maps line {line_no}: invalid or unsorted range {start:#x}..{end:#x}"));
        }
        prev_end = end;
        let (perms, rest) = split_ws_once(rest).ok_or_else(|| format!("maps line {line_no}: missing perms"))?;
        if !is_valid_perms(perms) {
            return Err(format!("maps line {line_no}: invalid permissions '{perms}'"));
        }
        let (offset_s, rest) = split_ws_once(rest).ok_or_else(|| format!("maps line {line_no}: missing offset"))?;
        let offset = u64::from_str_radix(offset_s, 16).map_err(|e| format!("maps line {line_no}: offset: {e}"))?;
        let (dev, rest) = split_ws_once(rest).ok_or_else(|| format!("maps line {line_no}: missing dev"))?;
        if parse_dev_pair(dev).is_none() {
            return Err(format!("maps line {line_no}: invalid device '{dev}'"));
        }
        let (inode_s, tail) = split_ws_tail(rest);
        let inode = inode_s.parse::<u64>().map_err(|e| format!("maps line {line_no}: inode: {e}"))?;
        let path_trimmed = tail.trim_start_matches([' ', '\t']);
        let pathname = (!path_trimmed.is_empty()).then(|| path_trimmed.to_owned());
        let vm_flags = smaps_flags.as_ref().and_then(|map| lookup_vmflags(map, start, end));
        let is_target_image = target.matches_region(dev, inode, pathname.as_deref());
        let scan_status = classify_scan_status(perms, pathname.as_deref(), vm_flags.as_deref(), is_target_image);
        regions.push(RegionEntry {
            start: HexAddr(start),
            end: HexAddr(end),
            perms: perms.to_owned(),
            offset: HexAddr(offset),
            dev: dev.to_owned(),
            inode,
            pathname,
            vm_flags,
            is_target_image,
            scan_status,
        });
    }
    if regions.is_empty() {
        return Err("procfs maps is empty".to_owned());
    }
    Ok(regions)
}

fn lookup_vmflags(map: &BTreeMap<(u64, u64), Vec<String>>, start: u64, end: u64) -> Option<Vec<String>> {
    map.get(&(start, end))
        .cloned()
        .or_else(|| map.iter().find(|&(&(s, e), _)| s <= start && end <= e).map(|(_, f)| f.clone()))
}

fn split_ws_once(input: &str) -> Option<(&str, &str)> {
    let trimmed = input.trim_start_matches([' ', '\t']);
    trimmed.find([' ', '\t']).map(|at| (&trimmed[..at], &trimmed[at..]))
}

fn split_ws_tail(input: &str) -> (&str, &str) {
    let trimmed = input.trim_start_matches([' ', '\t']);
    trimmed.find([' ', '\t']).map_or((trimmed, ""), |idx| (&trimmed[..idx], &trimmed[idx..]))
}

const PAGE_MASK: u64 = !0xfff;

fn candidate_slides_for_region(segments: &[LoadSegment], region: &RegionEntry) -> Result<Vec<i64>, String> {
    let r_len = region.end.0.saturating_sub(region.start.0);
    let r_off_page = region.offset.0 & PAGE_MASK;
    let is_exec = region.perms.contains('x');
    let is_write = region.perms.contains('w');
    let mut slides = Vec::new();
    for seg in segments {
        if seg.mem_size == 0 || is_exec != seg.executable || (is_write && !seg.writable) {
            continue;
        }
        let seg_file_page_start = seg.file_offset & PAGE_MASK;
        let seg_file_page_end = seg.file_offset.saturating_add(seg.file_size).saturating_add(0xfff) & PAGE_MASK;
        if r_off_page < seg_file_page_start || (seg.file_size > 0 && r_off_page >= seg_file_page_end) {
            continue;
        }
        let page_delta = r_off_page - seg_file_page_start;
        let Some(static_start) = (seg.va & PAGE_MASK).checked_add(page_delta) else {
            continue;
        };
        let seg_mem_page_end = seg.va.saturating_add(seg.mem_size).saturating_add(0xfff) & PAGE_MASK;
        if static_start.saturating_add(r_len) > seg_mem_page_end {
            continue;
        }
        let delta = i128::from(region.start.0) - i128::from(static_start);
        let slide = i64::try_from(delta).map_err(|_| format!("PIE slide overflow: {delta}"))?;
        if !slides.contains(&slide) {
            slides.push(slide);
        }
    }
    Ok(slides)
}

pub fn compute_pie_slide(segments: &[LoadSegment], regions: &mut [RegionEntry]) -> Result<i64, String> {
    if !regions.iter().any(|r| r.is_target_image) {
        return Err("target ELF binary has no matching mapping in procfs maps".to_owned());
    }
    let has_exec_target = regions.iter().any(|r| r.is_target_image && r.perms.contains('x'));
    let mut common: Option<Vec<i64>> = None;
    let mut first_seen: Option<i64> = None;
    for region in regions.iter().filter(|r| r.is_target_image && (!has_exec_target || r.perms.contains('x'))) {
        let region_slides = candidate_slides_for_region(segments, region)?;
        if region_slides.is_empty() {
            return Err(format!(
                "procfs target mapping {:#x}..{:#x} (off {:#x}, {}) does not match any ELF PT_LOAD segment",
                region.start.0, region.end.0, region.offset.0, region.perms
            ));
        }
        if first_seen.is_none() {
            first_seen = region_slides.first().copied();
        }
        if let Some(existing) = &mut common {
            existing.retain(|slide| region_slides.contains(slide));
            if existing.is_empty() {
                let lhs = first_seen.unwrap_or(0);
                let rhs = region_slides[0];
                return Err(format!("inconsistent load bias across target mappings: {lhs:#x} vs {rhs:#x}"));
            }
        } else {
            common = Some(region_slides);
        }
    }
    let slide = common
        .and_then(|slides| slides.into_iter().next())
        .ok_or_else(|| "could not match any procfs target mapping offset against ELF PT_LOAD segments".to_owned())?;

    for region in regions.iter_mut().filter(|r| r.is_target_image) {
        let region_slides = candidate_slides_for_region(segments, region)?;
        if !region_slides.contains(&slide) {
            if region.perms == "r--p" {
                // Demote secondary read-only raw file mmaps (e.g., std::backtrace mapping /proc/self/exe).
                region.is_target_image = false;
            } else {
                let other = region_slides.first().copied().unwrap_or(0);
                return Err(format!("inconsistent load bias across target mappings: {slide:#x} vs {other:#x}"));
            }
        }
    }
    Ok(slide)
}

#[must_use]
pub fn sha256_hex(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    let mut out = String::with_capacity(64);
    for byte in digest {
        let _ = write!(out, "{byte:02x}");
    }
    out
}

pub fn verify_binary_bytes(
    image: &Image,
    exe_bytes: &[u8],
    force_bin: bool,
) -> Result<(BinaryMatch, String, Vec<String>), String> {
    let exe_sha = sha256_hex(exe_bytes);
    let exe_build_id =
        object::File::parse(exe_bytes).ok().and_then(|f| f.build_id().ok().flatten().map(<[u8]>::to_vec));
    if let (Some(bin_id), Some(live_id)) = (&image.metadata.build_id, &exe_build_id)
        && !bin_id.is_empty()
        && !live_id.is_empty()
    {
        if bin_id == live_id {
            return Ok((BinaryMatch::VerifiedBuildId, exe_sha, Vec::new()));
        }
        return if force_bin {
            Ok((BinaryMatch::ForcedMismatch, exe_sha, vec!["forced_binary_mismatch".to_owned()]))
        } else {
            Err("binary_mismatch: --bin GNU build-id differs from procfs exe (pass --force-bin)".into())
        };
    }
    if sha256_hex(&image.data) == exe_sha {
        return Ok((BinaryMatch::VerifiedSha256, exe_sha, Vec::new()));
    }
    if force_bin {
        Ok((BinaryMatch::ForcedMismatch, exe_sha, vec!["forced_binary_mismatch".to_owned()]))
    } else {
        Err("binary_mismatch: --bin SHA-256 differs from procfs exe (pass --force-bin)".into())
    }
}
