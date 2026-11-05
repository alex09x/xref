/*
 * XRef — x86-64 binary analysis and cross-reference tooling
 * Copyright (c) 2026 Alexander Panasenko
 *
 * Contact: alex@prod.codes
 * Author: https://prod.codes/about/
 * Project: https://github.com/alex09x/xref
 * SPDX-License-Identifier: MIT OR Apache-2.0
 */

//! Typed data reading at virtual addresses mapped through load segments.

mod helpers;
#[cfg(test)]
mod tests;

use std::error::Error;
use std::io::Write;

use crate::image::Image;
use crate::image_format::LoadSegment;
use helpers::{format_str_debug, format_typed_value, read_bytes, segment_distance, segment_permissions};

#[derive(Clone, Copy, Debug, PartialEq, Eq, clap::ValueEnum)]
#[value(rename_all = "lowercase")]
pub enum DataType {
    F64,
    F32,
    U64,
    U32,
    U16,
    U8,
    I64,
    I32,
    I16,
    I8,
    Bytes,
    Str,
}

impl DataType {
    pub const fn name(self) -> &'static str {
        match self {
            Self::F64 => "f64",
            Self::F32 => "f32",
            Self::U64 => "u64",
            Self::U32 => "u32",
            Self::U16 => "u16",
            Self::U8 => "u8",
            Self::I64 => "i64",
            Self::I32 => "i32",
            Self::I16 => "i16",
            Self::I8 => "i8",
            Self::Bytes => "bytes",
            Self::Str => "str",
        }
    }

    pub const fn element_size(self) -> Option<usize> {
        match self {
            Self::F64 | Self::U64 | Self::I64 => Some(8),
            Self::F32 | Self::U32 | Self::I32 => Some(4),
            Self::U16 | Self::I16 => Some(2),
            Self::U8 | Self::I8 => Some(1),
            Self::Bytes | Self::Str => None,
        }
    }
}

fn validate_bounds(as_type: DataType, count: Option<usize>, max_len: usize) -> Result<usize, Box<dyn Error>> {
    let count = match count {
        Some(c) => c,
        None if as_type == DataType::Bytes => 64,
        None => 1,
    };
    if count == 0 {
        return Err("--count must be at least 1".into());
    }
    if as_type == DataType::Bytes {
        if count > 1_048_576 {
            return Err("--count cannot exceed 1 MiB (1048576 bytes)".into());
        }
    } else if count > 65536 {
        return Err("--count cannot exceed 65536".into());
    }
    if max_len == 0 {
        return Err("--max-len must be at least 1".into());
    }
    if max_len > 1_048_576 {
        return Err("--max-len cannot exceed 1 MiB (1048576 bytes)".into());
    }
    Ok(count)
}

fn run_bytes(
    image: &Image,
    seg: &LoadSegment,
    va: u64,
    count: usize,
    out: &mut dyn Write,
) -> Result<(), Box<dyn Error>> {
    let seg_end = seg.va.saturating_add(seg.mem_size);
    let avail = usize::try_from(seg_end.saturating_sub(va)).unwrap_or(usize::MAX);
    let to_read = count.min(avail);
    let cut = count > avail;
    let (bytes, _) = read_bytes(image, seg, va, to_read);
    for (i, chunk) in bytes.chunks(16).enumerate() {
        let line_addr = va.saturating_add((i as u64).saturating_mul(16));
        let hex_strs: Vec<String> = chunk.iter().map(|b| format!("{b:02x}")).collect();
        let hex_line = hex_strs.join(" ");
        let line_is_bss = line_addr.saturating_add(chunk.len() as u64) > seg.va.saturating_add(seg.file_size);
        if line_is_bss {
            writeln!(out, "{line_addr:#x}  {hex_line}  (bss)")?;
        } else {
            writeln!(out, "{line_addr:#x}  {hex_line}")?;
        }
    }
    if cut {
        writeln!(out, "range cut at segment end")?;
    }
    Ok(())
}

fn run_str(
    image: &Image,
    seg: &LoadSegment,
    va: u64,
    count: usize,
    max_len: usize,
    out: &mut dyn Write,
) -> Result<(), Box<dyn Error>> {
    let seg_end = seg.va.saturating_add(seg.mem_size);
    let mut cur_va = va;
    for _ in 0..count {
        if cur_va >= seg_end {
            writeln!(out, "range cut at segment end")?;
            break;
        }
        let avail = usize::try_from(seg_end.saturating_sub(cur_va)).unwrap_or(usize::MAX);
        let to_check = max_len.min(avail);
        let (bytes, _) = read_bytes(image, seg, cur_va, to_check);
        if let Some(nul_pos) = bytes.iter().position(|&b| b == 0) {
            let str_bytes = &bytes[..nul_pos];
            let escaped = format_str_debug(str_bytes);
            let is_bss = cur_va.saturating_add(nul_pos as u64) >= seg.va.saturating_add(seg.file_size);
            let bss_tag = if is_bss { "  (bss)" } else { "" };
            writeln!(out, "{cur_va:#x}  str  {escaped}{bss_tag}")?;
            cur_va = cur_va.saturating_add((nul_pos as u64).saturating_add(1));
        } else if to_check == max_len {
            let escaped = format_str_debug(&bytes);
            let is_bss = cur_va.saturating_add(max_len as u64) > seg.va.saturating_add(seg.file_size);
            let bss_tag = if is_bss { "  (bss)" } else { "" };
            writeln!(out, "{cur_va:#x}  str  {escaped}{bss_tag}  (capped at max-len)")?;
            cur_va = cur_va.saturating_add(max_len as u64);
            if avail == max_len {
                writeln!(out, "range cut at segment end")?;
                break;
            }
        } else {
            let escaped = format_str_debug(&bytes);
            let is_bss = cur_va.saturating_add(bytes.len() as u64) > seg.va.saturating_add(seg.file_size);
            let bss_tag = if is_bss { "  (bss)" } else { "" };
            writeln!(out, "{cur_va:#x}  str  {escaped}{bss_tag}")?;
            writeln!(out, "range cut at segment end")?;
            break;
        }
    }
    Ok(())
}

fn run_typed(
    image: &Image,
    seg: &LoadSegment,
    va: u64,
    typed: DataType,
    count: usize,
    out: &mut dyn Write,
) -> Result<(), Box<dyn Error>> {
    let seg_end = seg.va.saturating_add(seg.mem_size);
    let elem_size = typed.element_size().unwrap_or(1);
    let mut cut = false;
    for i in 0..count {
        let offset = (i as u64).saturating_mul(elem_size as u64);
        let Some(elem_addr) = va.checked_add(offset) else {
            cut = true;
            break;
        };
        if elem_addr.saturating_add(elem_size as u64) > seg_end {
            cut = true;
            break;
        }
        let (bytes, is_bss) = read_bytes(image, seg, elem_addr, elem_size);
        let val = format_typed_value(typed, &bytes);
        if is_bss {
            writeln!(out, "{elem_addr:#x}  {}  {val}  (bss)", typed.name())?;
        } else {
            writeln!(out, "{elem_addr:#x}  {}  {val}", typed.name())?;
        }
    }
    if cut {
        writeln!(out, "range cut at segment end")?;
    }
    Ok(())
}

pub fn run(
    image: &Image,
    va: u64,
    as_type: DataType,
    count: Option<usize>,
    max_len: usize,
    out: &mut dyn Write,
) -> Result<(), Box<dyn Error>> {
    let count = validate_bounds(as_type, count, max_len)?;

    let Some(seg) = image.metadata.load_segments.iter().find(|s| va >= s.va && va < s.va.saturating_add(s.mem_size))
    else {
        let nearest = image
            .metadata
            .load_segments
            .iter()
            .min_by_key(|s| segment_distance(va, s))
            .ok_or_else(|| "no load segments in binary".to_string())?;
        let start = nearest.va;
        let end = nearest.va.saturating_add(nearest.mem_size);
        let perms = segment_permissions(nearest);
        return Err(format!(
            "VA {va:#x} is outside all segments; nearest segment is {start:#x}..{end:#x} (permissions: {perms})"
        )
        .into());
    };

    match as_type {
        DataType::Bytes => run_bytes(image, seg, va, count, out),
        DataType::Str => run_str(image, seg, va, count, max_len, out),
        typed => run_typed(image, seg, va, typed, count, out),
    }
}
