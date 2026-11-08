/*
 * XRef — Tests for expression rendering
 * Copyright (c) 2026 Alexander Panasenko
 * Contact: alex@prod.codes
 * Author: https://prod.codes/about/
 * Project: https://github.com/alex09x/xref
 * SPDX-License-Identifier: MIT OR Apache-2.0
 */

use super::{Flags, State, cond_expr, describe_rip, mem_type, neg_cond_expr, num, op_expr, reg_name, stack_name};
use crate::image::{Image, Segment};
use crate::locations::Location;
use crate::scan::decode;
use iced_x86::{ConditionCode, MemorySize, Register};

fn one(bytes: &[u8]) -> iced_x86::Instruction {
    let mut ins = iced_x86::Instruction::default();
    decode(bytes, 0x1000, |decoded| ins = *decoded);
    ins
}

#[test]
fn registers_memory_operands_tls_caller_args_and_conditions() {
    let mut data = vec![0u8; 0x300];
    data[0x100..0x109].copy_from_slice(b"hello txt");
    data[0x200..0x207].copy_from_slice(&[0x31, 0xff, 0x48, 0x01, 0xf0, 0xc3, 0x90]);
    let image = Image {
        data,
        segments: vec![Segment { va: 0x1000, offset: 0, size: 0x300 }],
        functions: std::iter::once(0x1200..0x1207).collect(),
        pointers: vec![(0x1050, 0x1100), (0x1060, 0x1200), (0x1070, 0x1010)],
        imports: vec![(0x1040, "puts".to_owned())],
        symbols: Vec::new(),
        metadata: crate::image_format::Metadata::default(),
    };
    let locs = [Location { place: 0x1080, file: "src/lib.rs".to_owned(), line: 10, col: 2 }];
    assert_eq!(reg_name(Register::EAX), "rax");
    assert_eq!((stack_name(0x18), stack_name(-8)), ("slot_18".to_owned(), "slot_m8".to_owned()));
    assert_eq!(super::wrap_unary("(-", "rsi == 43", ")"), "(-(rsi == 43))");
    assert_eq!((num(9), num(0x4000)), ("9".to_owned(), "0x4000".to_owned()));
    assert_eq!((mem_type(MemorySize::UInt8), mem_type(MemorySize::UInt64)), ("u8", "u64"));
    assert_eq!(mem_type(MemorySize::UInt128), "u128");
    for (place, lea, sz, exp) in [
        (0x1080, true, MemorySize::UInt64, "\"src/lib.rs:10:2\""),
        (0x1200, true, MemorySize::UInt64, "fn_1200"),
        (0x1040, false, MemorySize::UInt64, "puts"),
        (0x1050, false, MemorySize::UInt64, "\"hello txt\""),
        (0x1060, false, MemorySize::UInt64, "fn_1200"),
        (0x1070, false, MemorySize::UInt64, "0x1010"),
        (0x1070, false, MemorySize::UInt8, "*(u8 *)0x1070"),
        (0x1100, true, MemorySize::UInt64, "\"hello txt\""),
        (0x1010, true, MemorySize::UInt64, "0x1010"),
        (0x1010, false, MemorySize::UInt32, "*(u32 *)0x1010"),
    ] {
        assert_eq!(describe_rip(&image, &locs, place, lea, sz), exp);
    }
    let mut state = State { arg_base_rsp: Some(0x20), ..State::default() };
    state.set_reg(Register::RDI, "arg0".to_owned());
    state.set_reg(Register::RCX, "r9 * 3".to_owned());
    state.rodata_ptrs.insert(Register::RAX, 0x1100);
    state.stack.insert(8, "saved".to_owned());
    for (bytes, exp) in [
        (&[0x48, 0x8b, 0x44, 0x24, 0x08][..], "saved"),
        (&[0x48, 0x8b, 0x44, 0x24, 0x20], "arg_6"),
        (&[0x48, 0x8d, 0x44, 0x24, 0x08], "&slot_8"),
        (&[0x48, 0x8b, 0x04, 0xf7], "((u64 *)arg0)[rsi]"),
        (&[0x48, 0x8d, 0x04, 0xc8], "rax + r9 * 24"),
        (&[0x8b, 0x44, 0xb7, 0x10], "*(u32 *)(arg0 + rsi * 4 + 16)"),
        (&[0x48, 0x8d, 0x44, 0x37, 0x10], "arg0 + rsi + 16"),
        (&[0x8b, 0x47, 0xf8], "*(u32 *)(arg0 - 8)"),
        (&[0x64, 0x48, 0x8b, 0x04, 0x25, 0x00, 0x00, 0x00, 0x00], "*(u64 *)(fs:0)"),
        (&[0x65, 0x48, 0x8b, 0x04, 0x25, 0x08, 0x00, 0x00, 0x00], "*(u64 *)(gs:8)"),
        (&[0x8b, 0x04, 0x25, 0x00, 0x20, 0x00, 0x00], "*(u32 *)(0x2000)"),
        (&[0x48, 0x8d, 0x05, 0xf9, 0x00, 0x00, 0x00], "\"hello txt\""),
        (&[0xb8, 0x05, 0x00, 0x00, 0x00], "5"),
    ] {
        assert_eq!(op_expr(&image, &[], &mut state, &one(bytes), 1), exp);
    }
    state.uses_fp = true;
    assert_eq!(op_expr(&image, &[], &mut state, &one(&[0x48, 0x8b, 0x45, 0x10]), 1), "arg_6");
    state.clear_scratch();
    assert!(state.rodata_ptrs.is_empty());
    let (flags, two, cmp3) = (
        Flags::test("a".to_owned()),
        Flags::cmp("a".to_owned(), "b".to_owned()),
        Flags::cmp("((i64)rax > 0 - rcx)".to_owned(), "1".to_owned()),
    );
    for (got, exp) in [
        (cond_expr(ConditionCode::e, Some(&flags)), "a == 0"),
        (cond_expr(ConditionCode::e, Some(&cmp3)), "(i64)rax > 0"),
        (cond_expr(ConditionCode::ne, Some(&cmp3)), "!((i64)rax > 0)"),
        (neg_cond_expr(ConditionCode::e, Some(&flags)), "a != 0"),
        (cond_expr(ConditionCode::l, Some(&flags)), "(i64)a < 0"),
        (cond_expr(ConditionCode::g, Some(&two)), "(i64)a > (i64)b"),
        (cond_expr(ConditionCode::p, Some(&flags)), "isnan(a)"),
        (neg_cond_expr(ConditionCode::o, Some(&two)), "!sub_overflow((i64)a, (i64)b)"),
        (cond_expr(ConditionCode::e, None), "cc_e"),
    ] {
        assert_eq!(got, exp);
    }
}
