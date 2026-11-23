/*
 * xref — Ultra blazing fast cross-references of an x86-64 ELF binary
 * Copyright (c) 2026 Alexander Panasenko
 *
 * Contact: alex@prod.codes
 * Author: https://prod.codes/about/
 * Project: https://github.com/alex09x/xref
 * SPDX-License-Identifier: MIT OR Apache-2.0
 */

use super::{parse_hex, pieces, run};
use crate::image::{Image, Segment};

#[test]
fn hex_takes_separators_and_rejects_odd_or_bad_digits() {
    assert_eq!(parse_hex("0x0011aaBB"), Ok(vec![0x00, 0x11, 0xaa, 0xbb]));
    assert_eq!(parse_hex("00 11:aa_bb"), Ok(vec![0x00, 0x11, 0xaa, 0xbb]));
    assert!(parse_hex("0x123").is_err());
    assert!(parse_hex("zz").is_err());
    assert!(parse_hex("").is_err());
}

#[test]
fn a_value_splits_into_16_byte_chunks_power_of_two_rest_and_an_overlapping_tail() {
    assert_eq!(pieces(20), vec![0..16, 16..20, 4..20]);
    assert_eq!(pieces(32), vec![0..16, 16..32]);
    assert_eq!(pieces(28), vec![0..16, 16..24, 24..28, 12..28]);
    assert_eq!(pieces(12), vec![0..8, 8..12, 4..12]);
    assert_eq!(pieces(16), Vec::<std::ops::Range<usize>>::new());
    assert_eq!(pieces(8), Vec::<std::ops::Range<usize>>::new());
}

/// One function compares a 20-byte value as a 16-byte constant plus a 4-byte immediate; another
/// loads one 20-byte copy at +0 and +0x10.
#[test]
fn a_20_byte_value_is_found_whole_and_as_its_16_plus_4_pieces() {
    let value: Vec<u8> = (1..=20).collect();
    let mut data = vec![0xc3u8; 0x200];
    let code: &[u8] = &[
        0x66, 0x0f, 0x74, 0x05, 0xf8, 0x00, 0x00, 0x00, // 0x1000: pcmpeqb xmm0, [rip+0xf8] (0x1100)
        0x81, 0x7f, 0x10, 0x11, 0x12, 0x13, 0x14, // 0x1008: cmp dword ptr [rdi+0x10], 0x14131211
        0xc3, // 0x100f
    ];
    data[..code.len()].copy_from_slice(code);
    let whole: &[u8] = &[
        0xf3, 0x0f, 0x6f, 0x0d, 0x58, 0x01, 0x00, 0x00, // 0x1020: movdqu xmm1, [rip+0x158] (0x1180)
        0x8b, 0x05, 0x62, 0x01, 0x00, 0x00, // 0x1028: mov eax, [rip+0x162] (0x1190)
        0xc3, // 0x102e
    ];
    data[0x20..0x20 + whole.len()].copy_from_slice(whole);
    data[0x100..0x110].copy_from_slice(&value[..16]);
    data[0x180..0x194].copy_from_slice(&value);
    let image = Image {
        data,
        segments: vec![Segment { va: 0x1000, offset: 0, size: 0x200 }],
        functions: vec![0x1000..0x1010, 0x1020..0x102f],
        ..Image::default()
    };
    let mut out = Vec::new();
    assert!(run(&image, &value, 10, &mut out).is_ok());
    let text = String::from_utf8_lossy(&out);
    assert!(text.starts_with("bytes 20 = 0102030405060708090a0b0c0d0e0f1011121314\n"), "{text}");
    assert!(text.contains("full  data 0x1180  2 users"), "{text}");
    assert!(text.contains("0x1028  in 0x1020  mov eax, [0x1190]  (+0x10)"), "{text}");
    assert!(text.contains("piece 0..16  data 0x1100  1 users\n  0x1000  in 0x1000  pcmpeqb"), "{text}");
    assert!(text.contains("piece 16..20  imm 0x14131211  1 users\n  0x1008  in 0x1000  cmp"), "{text}");
    assert!(text.contains("by function:\n  0x1000  piece 0..16, piece 16..20\n  0x1020  full\n"), "{text}");
    assert!(text.ends_with("4 hits\n"), "{text}");
}
