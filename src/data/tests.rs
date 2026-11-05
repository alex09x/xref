/*
 * xref — Ultra blazing fast cross-references of an x86-64 ELF binary
 * Copyright (c) 2026 Alexander Panasenko
 *
 * Contact: alex@prod.codes
 * Author: https://prod.codes/about/
 * SPDX-License-Identifier: MIT OR Apache-2.0
 */

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::cast_possible_truncation)]

use super::*;
use crate::image::Segment;
use crate::image_format::{LoadSegment, Metadata};

fn synthetic_image(
    data: Vec<u8>,
    va: u64,
    file_size: u64,
    mem_size: u64,
    writable: bool,
    executable: bool,
) -> Image {
    Image {
        data,
        segments: vec![Segment { va, offset: 0, size: file_size as usize }],
        functions: Vec::new(),
        pointers: Vec::new(),
        imports: Vec::new(),
        symbols: Vec::new(),
        metadata: Metadata {
            load_segments: vec![LoadSegment {
                va,
                file_offset: 0,
                file_size,
                mem_size,
                executable,
                writable,
            }],
            ..Metadata::default()
        },
    }
}

#[test]
fn data_read_synthetic_decodes_f64_u64_bytes_str() {
    let mut data = Vec::new();
    data.extend_from_slice(&1000.0f64.to_le_bytes());
    data.extend_from_slice(&42u64.to_le_bytes());
    data.extend_from_slice(b"hello\0");
    let image = synthetic_image(data, 0x4000, 22, 32, false, false);

    let mut out = Vec::new();
    run(&image, 0x4000, DataType::F64, Some(1), 256, &mut out).unwrap();
    assert_eq!(String::from_utf8(out).unwrap(), "0x4000  f64  1000.0\n");

    let mut out = Vec::new();
    run(&image, 0x4008, DataType::U64, Some(1), 256, &mut out).unwrap();
    assert_eq!(String::from_utf8(out).unwrap(), "0x4008  u64  42\n");

    let mut out = Vec::new();
    run(&image, 0x4010, DataType::Str, Some(1), 256, &mut out).unwrap();
    assert_eq!(String::from_utf8(out).unwrap(), "0x4010  str  \"hello\"\n");

    let mut out = Vec::new();
    run(&image, 0x4010, DataType::Bytes, Some(5), 256, &mut out).unwrap();
    assert_eq!(String::from_utf8(out).unwrap(), "0x4010  68 65 6c 6c 6f\n");
}

#[test]
fn data_read_synthetic_marks_bss() {
    let data = 99u64.to_le_bytes().to_vec();
    let image = synthetic_image(data, 0x4000, 8, 24, true, false);

    let mut out = Vec::new();
    run(&image, 0x4008, DataType::U64, Some(2), 256, &mut out).unwrap();
    assert_eq!(String::from_utf8(out).unwrap(), "0x4008  u64  0  (bss)\n0x4010  u64  0  (bss)\n");

    let mut out = Vec::new();
    run(&image, 0x4008, DataType::Bytes, Some(16), 256, &mut out).unwrap();
    assert_eq!(String::from_utf8(out).unwrap(), "0x4008  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  (bss)\n");
}

#[test]
fn data_read_synthetic_cuts_at_segment_end() {
    let data = vec![0u8; 16];
    let image = synthetic_image(data, 0x4000, 16, 16, false, false);

    let mut out = Vec::new();
    run(&image, 0x4008, DataType::U64, Some(2), 256, &mut out).unwrap();
    assert_eq!(String::from_utf8(out).unwrap(), "0x4008  u64  0\nrange cut at segment end\n");

    let mut out = Vec::new();
    run(&image, 0x400a, DataType::Bytes, Some(10), 256, &mut out).unwrap();
    assert_eq!(String::from_utf8(out).unwrap(), "0x400a  00 00 00 00 00 00\nrange cut at segment end\n");
}

#[test]
fn data_read_synthetic_unmapped_va_names_nearest_segment() {
    let data = vec![0u8; 16];
    let image = synthetic_image(data, 0x4000, 16, 16, false, true);

    let mut out = Vec::new();
    let err = run(&image, 0x10, DataType::F64, Some(1), 256, &mut out).unwrap_err();
    let msg = err.to_string();
    assert!(msg.contains("0x4000..0x4010"), "{msg}");
    assert!(msg.contains("permissions: r-x"), "{msg}");
}

#[test]
fn data_read_synthetic_rejects_invalid_count_and_max_len() {
    let data = vec![0u8; 16];
    let image = synthetic_image(data, 0x4000, 16, 16, false, false);
    let mut out = Vec::new();
    assert!(run(&image, 0x4000, DataType::F64, Some(0), 256, &mut out).is_err());
    assert!(run(&image, 0x4000, DataType::F64, Some(70000), 256, &mut out).is_err());
    assert!(run(&image, 0x4000, DataType::Bytes, Some(2_000_000), 256, &mut out).is_err());
    assert!(run(&image, 0x4000, DataType::Str, Some(1), 0, &mut out).is_err());
}
