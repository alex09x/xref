/*
 * XRef — Live Linux procfs inspection and xref-aware memory scanning
 * Copyright (c) 2026 Alexander Panasenko
 * Contact: alex@prod.codes
 * Author: https://prod.codes/about/
 * Project: https://github.com/alex09x/xref
 * SPDX-License-Identifier: MIT OR Apache-2.0
 */

//! Bidirectional `PT_LOAD` address translation and candidate 8-byte context word classification.

use crate::api::clipped;
use crate::image::Image;
use crate::image_format::LoadSegment;
use crate::live::types::{
    ContextWord, ContextWordKind, HexAddr, RegionEntry, ResolveDirection, ResolvedAddress, apply_slide, remove_slide,
};

const MAX_ASCII_PREVIEW: usize = 48;
const MAX_CANDIDATE_TARGETS: usize = 4;

#[must_use]
pub fn find_load_segment(segments: &[LoadSegment], static_va: u64) -> Option<&LoadSegment> {
    segments.iter().find(|seg| static_va >= seg.va && static_va - seg.va < seg.mem_size)
}

/// Translate `static_va` within `PT_LOAD` segments to `(file_offset, in_bss, executable)`.
#[must_use]
pub fn static_va_to_file_offset(segments: &[LoadSegment], static_va: u64) -> Option<(Option<u64>, bool, bool)> {
    let seg = find_load_segment(segments, static_va)?;
    let seg_offset = static_va - seg.va;
    if seg_offset < seg.file_size {
        Some((seg.file_offset.checked_add(seg_offset), false, seg.executable))
    } else {
        Some((None, true, seg.executable))
    }
}

/// Translate an ELF file offset back to `static_va` using file-backed `PT_LOAD` bounds.
#[cfg(test)]
#[must_use]
pub fn file_offset_to_static_va(segments: &[LoadSegment], file_offset: u64) -> Option<u64> {
    let seg = segments
        .iter()
        .find(|s| s.file_size > 0 && file_offset >= s.file_offset && file_offset - s.file_offset < s.file_size)?;
    seg.va.checked_add(file_offset - seg.file_offset)
}

#[must_use]
pub fn find_region(regions: &[RegionEntry], runtime_va: u64) -> Option<&RegionEntry> {
    regions.iter().find(|region| region.contains(runtime_va))
}

#[must_use]
pub fn lookup_symbol(image: &Image, static_va: u64) -> Option<String> {
    let idx = image.symbols.partition_point(|(addr, _)| *addr < static_va);
    image.symbols.get(idx).filter(|(addr, _)| *addr == static_va).map(|(_, name)| name.clone())
}

#[must_use]
pub fn resolve_address(image: &Image, pie_slide: i64, regions: &[RegionEntry], input: u64) -> ResolvedAddress {
    let segments = &image.metadata.load_segments;
    let as_static = find_load_segment(segments, input);
    let unslid = remove_slide(input, pie_slide).and_then(|s| find_load_segment(segments, s).map(|seg| (s, seg)));

    if pie_slide != 0
        && let Some((static_va, _)) = unslid
        && (as_static.is_none() || find_region(regions, input).is_some())
    {
        return build_image_resolution(
            image,
            regions,
            input,
            ResolveDirection::RuntimeToStatic,
            static_va,
            Some(input),
        );
    }
    if as_static.is_some() {
        return build_image_resolution(
            image,
            regions,
            input,
            ResolveDirection::StaticToRuntime,
            input,
            apply_slide(input, pie_slide),
        );
    }
    if let Some(region) = find_region(regions, input) {
        return ResolvedAddress {
            input: HexAddr(input),
            direction: ResolveDirection::RuntimeToStatic,
            static_va: None,
            file_offset: None,
            in_bss: false,
            executable: region.perms.contains('x'),
            runtime_va: Some(HexAddr(input)),
            region: Some(region.format_location(input)),
            function_start: None,
            function_end: None,
            function_offset: None,
            symbol: None,
        };
    }
    ResolvedAddress {
        input: HexAddr(input),
        direction: ResolveDirection::Unmapped,
        static_va: None,
        file_offset: None,
        in_bss: false,
        executable: false,
        runtime_va: None,
        region: None,
        function_start: None,
        function_end: None,
        function_offset: None,
        symbol: None,
    }
}

fn build_image_resolution(
    image: &Image,
    regions: &[RegionEntry],
    input: u64,
    direction: ResolveDirection,
    static_va: u64,
    runtime_va: Option<u64>,
) -> ResolvedAddress {
    let (file_offset, in_bss, executable) =
        static_va_to_file_offset(&image.metadata.load_segments, static_va).unwrap_or((None, false, false));
    let func = image.function_at(static_va);
    let function_start = func.as_ref().map(|r| HexAddr(r.start));
    let function_end = func.as_ref().map(|r| HexAddr(r.end));
    let function_offset = func.as_ref().map(|r| static_va - r.start);
    let symbol = lookup_symbol(image, static_va).or_else(|| func.as_ref().and_then(|r| lookup_symbol(image, r.start)));
    let region = runtime_va.and_then(|rva| find_region(regions, rva).map(|reg| reg.format_location(rva)));
    ResolvedAddress {
        input: HexAddr(input),
        direction,
        static_va: Some(HexAddr(static_va)),
        file_offset: file_offset.map(HexAddr),
        in_bss,
        executable,
        runtime_va: runtime_va.map(HexAddr),
        region,
        function_start,
        function_end,
        function_offset,
        symbol,
    }
}

pub struct WordMeta {
    pub runtime_va: u64,
    pub relative_offset: i64,
    pub is_match: bool,
    pub value: u64,
}

#[must_use]
pub fn classify_word(image: &Image, pie_slide: i64, regions: &[RegionEntry], meta: &WordMeta) -> ContextWord {
    if meta.value == 0 {
        return ContextWord::scalar(meta.runtime_va, meta.relative_offset, meta.is_match, 0);
    }
    if let Some(static_va) = remove_slide(meta.value, pie_slide)
        && let Some(seg) = find_load_segment(&image.metadata.load_segments, static_va)
        && find_region(regions, meta.value).is_none_or(|r| r.is_target_image)
    {
        return classify_image_pointer(image, seg, static_va, meta);
    }
    if let Some(region) = find_region(regions, meta.value) {
        return ContextWord {
            relative_offset: meta.relative_offset,
            runtime_va: HexAddr(meta.runtime_va),
            value: Some(HexAddr(meta.value)),
            is_match: meta.is_match,
            kind: classify_region_kind(region),
            static_va: None,
            target_function: None,
            function_offset: None,
            symbol: None,
            candidate_targets: Vec::new(),
            static_ascii_preview: None,
            target_region: Some(region.format_location(meta.value)),
        };
    }
    ContextWord::scalar(meta.runtime_va, meta.relative_offset, meta.is_match, meta.value)
}

fn classify_image_pointer(image: &Image, seg: &LoadSegment, static_va: u64, meta: &WordMeta) -> ContextWord {
    if is_code_va(image, seg, static_va) {
        let func = image.function_at(static_va);
        let target_function = func.as_ref().map(|r| HexAddr(r.start));
        let function_offset = func.as_ref().map(|r| static_va - r.start);
        let symbol =
            lookup_symbol(image, static_va).or_else(|| func.as_ref().and_then(|r| lookup_symbol(image, r.start)));
        return ContextWord {
            relative_offset: meta.relative_offset,
            runtime_va: HexAddr(meta.runtime_va),
            value: Some(HexAddr(meta.value)),
            is_match: meta.is_match,
            kind: ContextWordKind::CodePtr,
            static_va: Some(HexAddr(static_va)),
            target_function,
            function_offset,
            symbol,
            candidate_targets: Vec::new(),
            static_ascii_preview: None,
            target_region: None,
        };
    }
    let candidate_targets = collect_relro_targets(image, static_va);
    if !candidate_targets.is_empty() {
        return ContextWord {
            relative_offset: meta.relative_offset,
            runtime_va: HexAddr(meta.runtime_va),
            value: Some(HexAddr(meta.value)),
            is_match: meta.is_match,
            kind: ContextWordKind::RelroPtrCandidate,
            static_va: Some(HexAddr(static_va)),
            target_function: None,
            function_offset: None,
            symbol: lookup_symbol(image, static_va),
            candidate_targets,
            static_ascii_preview: None,
            target_region: None,
        };
    }
    ContextWord {
        relative_offset: meta.relative_offset,
        runtime_va: HexAddr(meta.runtime_va),
        value: Some(HexAddr(meta.value)),
        is_match: meta.is_match,
        kind: ContextWordKind::StaticDataPtr,
        static_va: Some(HexAddr(static_va)),
        target_function: None,
        function_offset: None,
        symbol: lookup_symbol(image, static_va),
        candidate_targets: Vec::new(),
        static_ascii_preview: static_ascii_preview(image, static_va),
        target_region: None,
    }
}

fn is_code_va(image: &Image, seg: &LoadSegment, static_va: u64) -> bool {
    seg.executable
        || image.metadata.code_ranges.iter().any(|r| r.contains(&static_va))
        || image.function_at(static_va).is_some()
}

fn is_any_code_va(image: &Image, static_va: u64) -> bool {
    find_load_segment(&image.metadata.load_segments, static_va).is_some_and(|s| s.executable)
        || image.metadata.code_ranges.iter().any(|r| r.contains(&static_va))
        || image.function_at(static_va).is_some()
}

fn collect_relro_targets(image: &Image, static_va: u64) -> Vec<HexAddr> {
    let start_idx = image.pointers.partition_point(|(place, _)| *place < static_va);
    let direct_hit = image.pointers.get(start_idx).is_some_and(|&(p, t)| p == static_va && is_any_code_va(image, t));
    let header_hit = !direct_hit
        && image.read_u64(static_va) == Some(0)
        && static_va.checked_add(0x10).is_some_and(|vfn0| {
            let idx = image.pointers.partition_point(|(place, _)| *place < vfn0);
            image.pointers.get(idx).is_some_and(|&(p, t)| p == vfn0 && is_any_code_va(image, t))
        });
    if !direct_hit && !header_hit {
        return Vec::new();
    }
    let window_end = static_va.saturating_add(64);
    let mut targets = Vec::new();
    for &(place, target) in &image.pointers[start_idx..] {
        if place >= window_end || targets.len() >= MAX_CANDIDATE_TARGETS {
            break;
        }
        if (place - static_va).is_multiple_of(8) && is_any_code_va(image, target) {
            targets.push(HexAddr(target));
        }
    }
    targets
}

/// Read bounded printable ASCII preview (`<= 48` bytes, UTF-8 boundary safe) ONLY from static `Image` bytes.
fn static_ascii_preview(image: &Image, static_va: u64) -> Option<String> {
    let seg = image
        .segments
        .iter()
        .find(|s| static_va >= s.va && u64::try_from(s.size).is_ok_and(|sz| static_va - s.va < sz))?;
    let offset = usize::try_from(static_va - seg.va).ok()?;
    let avail = (seg.size - offset).min(MAX_ASCII_PREVIEW + 1);
    let bytes = image.data.get(seg.offset + offset..seg.offset + offset + avail)?;
    if let Some((preview, _)) = image.rodata_preview(static_va) {
        let (short, _) = clipped(&preview, MAX_ASCII_PREVIEW);
        if !short.is_empty() {
            return Some(short);
        }
    }
    let run = bytes.iter().take_while(|b| (0x20..0x7f).contains(*b)).count();
    (run >= 4 || (run >= 2 && bytes.get(run) == Some(&0)))
        .then(|| String::from_utf8_lossy(&bytes[..run.min(MAX_ASCII_PREVIEW)]).into_owned())
}

fn classify_region_kind(region: &RegionEntry) -> ContextWordKind {
    if region.perms.contains('x') {
        return ContextWordKind::ExecMappingPtr;
    }
    match region.pathname.as_deref() {
        Some("[heap]") => ContextWordKind::HeapPtr,
        Some(path) if path == "[stack]" || path.starts_with("[stack:") => ContextWordKind::StackPtr,
        None => ContextWordKind::AnonPtr,
        Some(path) if path.starts_with("[anon") => ContextWordKind::AnonPtr,
        Some(_) => ContextWordKind::MappedPtr,
    }
}
