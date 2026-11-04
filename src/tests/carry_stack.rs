/*
 * XRef — carry/borrow flags of SUB/SBB whose destination is a stack slot (#117)
 * Copyright (c) 2026 Alexander Panasenko
 * Contact: alex@prod.codes
 * Author: https://prod.codes/about/
 * Project: https://github.com/alex09x/xref
 * SPDX-License-Identifier: MIT OR Apache-2.0
 */

//! The flags of `sub`/`sbb` with a memory destination must be computed from the operand value before
//! the write. A named stack slot carries no `*` in its expression, so it used to be treated as clean.

use crate::c::c_one;
use crate::image::{Image, Segment};
use crate::runtime::RuntimeMap;

fn decompile(code: &[u8]) -> String {
    let mut data = vec![0xcc_u8; 0x100];
    data[..code.len()].copy_from_slice(code);
    let img = Image {
        data,
        segments: vec![Segment { va: 0x1000, offset: 0, size: 0x100 }],
        functions: std::iter::once(0x1000..0x1000 + code.len() as u64).collect(),
        pointers: Vec::new(),
        imports: Vec::new(),
        symbols: Vec::new(),
        metadata: crate::image_format::Metadata::default(),
    };
    let rt = RuntimeMap::detect(&img);
    c_one(&img, &[], &rt, 0x1000, None, None).unwrap_or_default().1
}

/// The condition line of the single `if`, and the name of the `lhs_` snapshot taken before the write.
fn condition_and_snapshot(c: &str) -> (String, String) {
    let cond = c.lines().find(|line| line.trim_start().starts_with("if (")).unwrap_or_default().to_owned();
    let snapshot = c
        .lines()
        .find_map(|line| line.trim_start().strip_prefix("u64 ").and_then(|rest| rest.split(' ').next()))
        .unwrap_or_default()
        .to_owned();
    (cond, snapshot)
}

#[test]
fn sbb_into_stack_slot_branches_on_the_old_slot_value() {
    // mov [rsp-8], rdi; cmp rdx, 1; sbb [rsp-8], rsi; jb L; mov rax, [rsp-8]; ret; L: mov rax, 99; ret
    let c = decompile(&[
        0x48, 0x89, 0x7c, 0x24, 0xf8, 0x48, 0x83, 0xfa, 0x01, 0x48, 0x19, 0x74, 0x24, 0xf8, 0x72, 0x06, 0x48, 0x8b,
        0x44, 0x24, 0xf8, 0xc3, 0x48, 0xc7, 0xc0, 0x63, 0x00, 0x00, 0x00, 0xc3,
    ]);
    let (cond, snapshot) = condition_and_snapshot(&c);
    assert!(snapshot.starts_with("lhs_"), "expected a pre-write snapshot:\n{c}");
    assert!(cond.contains(&snapshot) && !cond.contains("slot_m8"), "branch must use the old value:\n{c}");
    let write = c.lines().find(|line| line.trim_start().starts_with("slot_m8 = (")).unwrap_or_default();
    assert!(write.contains(&snapshot), "the write itself reads the snapshot:\n{c}");
}

#[test]
fn sub_into_stack_slot_branches_on_the_old_slot_value() {
    // mov [rsp-8], rdi; sub [rsp-8], rsi; jb L; mov rax, [rsp-8]; ret; L: mov rax, 99; ret
    let c = decompile(&[
        0x48, 0x89, 0x7c, 0x24, 0xf8, 0x48, 0x29, 0x74, 0x24, 0xf8, 0x72, 0x06, 0x48, 0x8b, 0x44, 0x24, 0xf8, 0xc3,
        0x48, 0xc7, 0xc0, 0x63, 0x00, 0x00, 0x00, 0xc3,
    ]);
    let (cond, snapshot) = condition_and_snapshot(&c);
    assert!(snapshot.starts_with("lhs_"), "expected a pre-write snapshot:\n{c}");
    assert!(cond.contains(&snapshot) && !cond.contains("slot_m8"), "branch must use the old value:\n{c}");
}

#[test]
fn sbb_into_stack_slot_feeds_setb_from_the_old_slot_value() {
    // mov [rsp-8], rdi; cmp rdx, 1; sbb [rsp-8], rsi; setb al; movzx eax, al; ret
    let c = decompile(&[
        0x48, 0x89, 0x7c, 0x24, 0xf8, 0x48, 0x83, 0xfa, 0x01, 0x48, 0x19, 0x74, 0x24, 0xf8, 0x0f, 0x92, 0xc0, 0x0f,
        0xb6, 0xc0, 0xc3,
    ]);
    // Either the slot is folded away (the borrow is computed from arg_0 directly) or a snapshot is used;
    // the borrow must never compare the already-decremented slot.
    let borrow = c.lines().find(|line| line.contains("(u128)")).unwrap_or_default();
    assert!(!borrow.contains("slot_m8"), "setb must use the old value:\n{c}");
    assert!(borrow.contains("arg_0") || borrow.contains("lhs_"), "unexpected borrow source:\n{c}");
}

#[test]
fn sbb_into_register_still_uses_the_old_register_value() {
    // mov rax, rdi; cmp rdx, 1; sbb rax, rsi; setb cl; movzx ecx, cl; imul rcx, rcx, 1000; add rax, rcx; ret
    let c = decompile(&[
        0x48, 0x89, 0xf8, 0x48, 0x83, 0xfa, 0x01, 0x48, 0x19, 0xf0, 0x0f, 0x92, 0xc1, 0x0f, 0xb6, 0xc9, 0x48, 0x69,
        0xc9, 0xe8, 0x03, 0x00, 0x00, 0x48, 0x01, 0xc8, 0xc3,
    ]);
    let borrow = c.lines().find(|line| line.contains("(u128)")).unwrap_or_default();
    assert!(borrow.contains("(u128)(u64)arg_0 <"), "register borrow must use the old value:\n{c}");
}
