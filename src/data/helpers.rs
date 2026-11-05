/*
 * XRef — x86-64 binary analysis and cross-reference tooling
 * Copyright (c) 2026 Alexander Panasenko
 *
 * Contact: alex@prod.codes
 * Author: https://prod.codes/about/
 * Project: https://github.com/alex09x/xref
 * SPDX-License-Identifier: MIT OR Apache-2.0
 */

//! Decoding, segment distance, and formatting helpers for typed data reading.

use crate::image::Image;
use crate::image_format::LoadSegment;

use super::DataType;

pub(super) fn read_bytes(image: &Image, seg: &LoadSegment, addr: u64, len: usize) -> (Vec<u8>, bool) {
    let seg_end = seg.va.saturating_add(seg.mem_size);
    if addr < seg.va || addr >= seg_end {
        return (Vec::new(), false);
    }
    let avail = usize::try_from(seg_end.saturating_sub(addr)).unwrap_or(usize::MAX);
    let to_read = len.min(avail);
    let mut bytes = Vec::with_capacity(to_read);
    let mut is_bss = false;
    for i in 0..to_read {
        let cur = addr + i as u64;
        let offset = cur - seg.va;
        if offset < seg.file_size {
            let file_idx = usize::try_from(seg.file_offset + offset).ok();
            bytes.push(file_idx.and_then(|idx| image.data.get(idx)).copied().unwrap_or(0));
        } else {
            bytes.push(0);
            is_bss = true;
        }
    }
    (bytes, is_bss)
}

pub(super) fn format_typed_value(as_type: DataType, bytes: &[u8]) -> String {
    match as_type {
        DataType::F64 => format!("{:?}", f64::from_le_bytes(bytes.try_into().unwrap_or([0; 8]))),
        DataType::F32 => format!("{:?}", f32::from_le_bytes(bytes.try_into().unwrap_or([0; 4]))),
        DataType::U64 => format!("{}", u64::from_le_bytes(bytes.try_into().unwrap_or([0; 8]))),
        DataType::U32 => format!("{}", u32::from_le_bytes(bytes.try_into().unwrap_or([0; 4]))),
        DataType::U16 => format!("{}", u16::from_le_bytes(bytes.try_into().unwrap_or([0; 2]))),
        DataType::U8 => format!("{}", bytes.first().copied().unwrap_or(0)),
        DataType::I64 => format!("{}", i64::from_le_bytes(bytes.try_into().unwrap_or([0; 8]))),
        DataType::I32 => format!("{}", i32::from_le_bytes(bytes.try_into().unwrap_or([0; 4]))),
        DataType::I16 => format!("{}", i16::from_le_bytes(bytes.try_into().unwrap_or([0; 2]))),
        DataType::I8 => format!("{}", i8::from_le_bytes([bytes.first().copied().unwrap_or(0)])),
        DataType::Bytes | DataType::Str => String::new(),
    }
}

pub(super) fn format_str_debug(bytes: &[u8]) -> String {
    std::str::from_utf8(bytes).map_or_else(
        |_| {
            let mut out = String::from("\"");
            for &b in bytes {
                for c in std::ascii::escape_default(b) {
                    out.push(c as char);
                }
            }
            out.push('"');
            out
        },
        |s| format!("{s:?}"),
    )
}

pub(super) const fn segment_distance(va: u64, seg: &LoadSegment) -> u64 {
    let start = seg.va;
    let end = seg.va.saturating_add(seg.mem_size);
    let under = start.saturating_sub(va);
    let over = va.saturating_sub(end);
    if under > over { under } else { over }
}

pub(super) fn segment_permissions(seg: &LoadSegment) -> String {
    let w = if seg.writable { 'w' } else { '-' };
    let x = if seg.executable { 'x' } else { '-' };
    format!("r{w}{x}")
}
