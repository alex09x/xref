/*
 * xref — Ultra blazing fast cross-references of an x86-64 ELF binary
 * Copyright (c) 2026 Alexander Panasenko
 *
 * Contact: alex@prod.codes
 * Author: https://prod.codes/about/
 * Project: https://github.com/alex09x/xref
 * SPDX-License-Identifier: MIT OR Apache-2.0
 */

use crate::graph::path_with;
use crate::image::{Image, Segment};

/// A `dyn` call `call [rax+0x18]` in 0x1000, and a vtable `[drop 0x1020, 16, 8, 0x1030]` at
/// 0x1100: 0x1030 is the first method, so the call may reach it.
fn image() -> Image {
    let mut data = vec![0xc3u8; 0x200];
    data[..7].copy_from_slice(&[
        0x48, 0x8b, 0x07, // 0x1000: mov rax, [rdi]
        0xff, 0x50, 0x18, // 0x1003: call qword ptr [rax+0x18]
        0xc3, // 0x1006
    ]);
    data[0x100..0x108].copy_from_slice(&0x1020u64.to_le_bytes());
    data[0x108..0x110].copy_from_slice(&16u64.to_le_bytes());
    data[0x110..0x118].copy_from_slice(&8u64.to_le_bytes());
    data[0x118..0x120].copy_from_slice(&0x1030u64.to_le_bytes());
    Image {
        data,
        segments: vec![Segment { va: 0x1000, offset: 0, size: 0x200 }],
        functions: vec![0x1000..0x1007, 0x1020..0x1021, 0x1030..0x1031],
        pointers: vec![(0x1100, 0x1020), (0x1118, 0x1030)],
        ..Image::default()
    }
}

#[test]
fn a_dyn_call_reaches_a_vtable_method_only_with_via_vtables_and_is_marked() {
    let image = image();
    let mut out = Vec::new();
    assert!(path_with(&image, "0x1000", "0x1030", 3, false, &mut out).is_ok());
    let text = String::from_utf8_lossy(&out);
    assert!(text.contains("0 paths"), "{text}");
    let mut out = Vec::new();
    assert!(path_with(&image, "0x1000", "0x1030", 3, true, &mut out).is_ok());
    let text = String::from_utf8_lossy(&out);
    assert!(text.starts_with("0x1000 -> 0x1030  (via 0x1003?)\n1 paths\nvia vtables: 1 vtable methods at 1 slot offsets, 1 dyn call sites"), "{text}");
    assert!(text.contains("\n? = a call through a vtable slot"), "{text}");
    // The drop slot (offset 0) is no method: the call does not reach it.
    let mut out = Vec::new();
    assert!(path_with(&image, "0x1000", "0x1020", 3, true, &mut out).is_ok());
    assert!(String::from_utf8_lossy(&out).contains("0 paths"));
}
