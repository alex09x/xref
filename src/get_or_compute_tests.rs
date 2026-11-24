/*
 * xref — Ultra blazing fast cross-references of an x86-64 ELF binary
 * Copyright (c) 2026 Alexander Panasenko
 *
 * Contact: alex@prod.codes
 * Author: https://prod.codes/about/
 * Project: https://github.com/alex09x/xref
 * SPDX-License-Identifier: MIT OR Apache-2.0
 */

use super::{GetOrCompute, detect};
use crate::image::{Image, Segment};

/// `entry.or_insert_with(compute)`: occupied returns the stored value, vacant computes and inserts.
const ENTRY: &[u8] = &[
    0x83, 0x3f, 0x01, // 0x1000: cmp dword ptr [rdi], 1
    0x75, 0x06, // 0x1003: jne 0x100b (vacant)
    0x48, 0x8b, 0x47, 0x08, // 0x1005: mov rax, [rdi+8]
    0xeb, 0x13, // 0x1009: jmp 0x101e
    0xe8, 0x30, 0x00, 0x00, 0x00, // 0x100b: call 0x1040 (compute)
    0x48, 0x85, 0xc0, // 0x1010: test rax, rax
    0x74, 0x09, // 0x1013: je 0x101e
    0x48, 0x89, 0xc2, // 0x1015: mov rdx, rax
    0xe8, 0x33, 0x00, 0x00, 0x00, // 0x1018: call 0x1050 (insert)
    0x90, // 0x101d
    0xc3, // 0x101e: ret
];

fn image(code: &[u8]) -> Image {
    let mut data = vec![0xc3u8; 0x100];
    data[..code.len()].copy_from_slice(code);
    Image {
        data,
        segments: vec![Segment { va: 0x1000, offset: 0, size: 0x100 }],
        functions: vec![0x1000..0x101f, 0x1040..0x1041, 0x1050..0x1051],
        ..Image::default()
    }
}

#[test]
fn an_entry_that_computes_only_when_vacant_names_the_compute_and_insert_calls() {
    let found = detect(&image(ENTRY), &(0x1000..0x101f));
    let expected = GetOrCompute { compute: Some(0x1040), compute_at: 0x100b, insert: 0x1050, insert_at: 0x1018 };
    assert_eq!(found, Some(expected));
}

#[test]
fn no_get_or_compute_when_the_result_is_not_inserted_or_the_fast_side_calls() {
    // The insert takes something else than the computed value: `xor edx, edx` for `mov rdx, rax`.
    let mut not_inserted = ENTRY.to_vec();
    not_inserted[0x15..0x18].copy_from_slice(&[0x31, 0xd2, 0x90]);
    assert_eq!(detect(&image(&not_inserted), &(0x1000..0x101f)), None);
    // Both sides call: `call 0x1040` (padded) for `mov rax, [rdi+8]; jmp`.
    let mut both_call = ENTRY.to_vec();
    both_call[0x05..0x0b].copy_from_slice(&[0xe8, 0x36, 0x00, 0x00, 0x00, 0x90]);
    assert_eq!(detect(&image(&both_call), &(0x1000..0x101f)), None);
    // The fast side builds a value (`mov qword ptr [rdi+8], 0`), like an empty Vec in a clone.
    let mut builds = ENTRY.to_vec();
    builds[0x05..0x0b].copy_from_slice(&[0x48, 0x89, 0x47, 0x08, 0xeb, 0x13]); // mov [rdi+8], rax; jmp 0x101e
    assert_eq!(detect(&image(&builds), &(0x1000..0x101f)), None);
}
