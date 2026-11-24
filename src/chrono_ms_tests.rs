/*
 * xref — Ultra blazing fast cross-references of an x86-64 ELF binary
 * Copyright (c) 2026 Alexander Panasenko
 *
 * Contact: alex@prod.codes
 * Author: https://prod.codes/about/
 * Project: https://github.com/alex09x/xref
 * SPDX-License-Identifier: MIT OR Apache-2.0
 */

use super::{ChronoMs, find};
use crate::c::c_one;
use crate::image::{Image, Segment};
use crate::runtime::RuntimeMap;

/// The shape of chrono's inlined `timestamp_millis` with the date, seconds and nanoseconds read
/// from the struct at `rdi`.
const MILLIS: &[u8] = &[
    0x8b, 0x07, // 0x1000: mov eax, [rdi] (packed date)
    0x8b, 0x57, 0x04, // 0x1002: mov edx, [rdi+4] (secs)
    0x8b, 0x7f, 0x08, // 0x1005: mov edi, [rdi+8] (nanos)
    0xc1, 0xf8, 0x0d, // 0x1008: sar eax, 13 (year)
    0x69, 0xc8, 0x1f, 0x85, 0xeb, 0x51, // 0x100b: imul ecx, eax, 0x51eb851f (/ 100)
    0x48, 0x69, 0xc0, 0x80, 0x51, 0x01, 0x00, // 0x1011: imul rax, rax, 0x15180 (days * 86400)
    0x48, 0x01, 0xd0, // 0x1018: add rax, rdx (+ secs)
    0x48, 0x69, 0xf7, 0x83, 0xde, 0x1b, 0x43, // 0x101b: imul rsi, rdi, 0x431bde83
    0x48, 0xc1, 0xee, 0x32, // 0x1022: shr rsi, 50 (nanos / 1000000)
    0x48, 0x69, 0xc0, 0xe8, 0x03, 0x00, 0x00, // 0x1026: imul rax, rax, 1000
    0x48, 0x01, 0xf0, // 0x102d: add rax, rsi
    0xc3, // 0x1030: ret
];

fn image() -> Image {
    let mut data = vec![0xccu8; 0x100];
    data[..MILLIS.len()].copy_from_slice(MILLIS);
    Image {
        data,
        segments: vec![Segment { va: 0x1000, offset: 0, size: 0x100 }],
        functions: std::iter::once(0x1000..0x1031).collect(),
        ..Image::default()
    }
}

#[test]
fn an_inlined_timestamp_millis_is_found_by_its_constants() {
    let mut insns = Vec::new();
    crate::scan::decode(MILLIS, 0x1000, |instruction| insns.push(*instruction));
    let expected = ChronoMs { date_ip: 0x1008, secs_ip: 0x1018, nanos_ip: 0x101b, result_ip: 0x102d };
    assert_eq!(find(&insns), [expected]);
    // Without the `/ 100` of the leap-year rule it is just arithmetic.
    let plain: Vec<_> = insns.iter().copied().filter(|i| i.ip() != 0x100b).collect();
    assert_eq!(find(&plain), []);
}

#[test]
fn the_pseudo_c_names_the_result_with_its_three_inputs() {
    let image = image();
    let runtime = RuntimeMap::detect(&image);
    let (_, text) = c_one(&image, &[], &runtime, 0x1000, None, None).unwrap_or_default();
    assert!(text.contains("/* ms = timestamp_millis(date "), "{text}");
    assert!(text.contains("(arg_0)"), "{text}");
    assert!(text.contains("(arg_0 + 4)"), "{text}");
    assert!(text.contains("(arg_0 + 8)"), "{text}");
}
