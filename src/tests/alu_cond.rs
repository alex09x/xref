/*
 * xref — Ultra blazing fast cross-references of an x86-64 ELF binary
 * Copyright (c) 2026 Alexander Panasenko
 *
 * Contact: alex@prod.codes
 * Author: https://prod.codes/about/
 * Project: https://github.com/alex09x/xref
 * SPDX-License-Identifier: MIT OR Apache-2.0
 */

//! Unit tests for `cond`, `carry_cond`, `carry_alu`, `c_step`, and `expr` (including issue #31).

use iced_x86::{ConditionCode, Instruction, MemorySize, Mnemonic, Register};

use crate::c::c_one;
use crate::c_step::flush_non_gpr_dirty;
use crate::carry_cond::{i_term, u_term};
use crate::cond::{
    FlagOp, Flags, cond_expr, has_call, invert_cond, neg_cond_expr, split_top_stmts, strip_trailing_continue_label,
    trim_parens,
};
use crate::expr::{State, mem_expr};
use crate::image::{Image, Segment};
use crate::runtime::RuntimeMap;
use crate::scan::decode;

fn build_img(fns: &[&[u8]]) -> (Image, Vec<u64>) {
    let (mut data, mut functions, mut starts, mut off) = (vec![0xccu8; 0x800], Vec::new(), Vec::new(), 0usize);
    for b in fns {
        data[off..off + b.len()].copy_from_slice(b);
        let va = 0x1000 + off as u64;
        functions.push(va..va + b.len() as u64);
        starts.push(va);
        off = (off + b.len() + 0x1f) & !0x1f;
    }
    (
        Image {
            data,
            segments: vec![Segment { va: 0x1000, offset: 0, size: 0x800 }],
            functions,
            pointers: Vec::new(),
            imports: Vec::new(),
            symbols: Vec::new(),
        },
        starts,
    )
}

#[test]
fn add_sub_unsigned_carry_and_borrow_conditions_cover_all_widths_and_cc() {
    let add64 =
        Flags::arith(FlagOp::from_bin_width(Mnemonic::Add, 64), "v_5".to_owned(), "v_4".to_owned(), "v_24".to_owned());
    assert_eq!(cond_expr(ConditionCode::b, Some(&add64)), "v_5 < v_4");
    assert_eq!(cond_expr(ConditionCode::ae, Some(&add64)), "v_5 >= v_4");
    assert_eq!(cond_expr(ConditionCode::be, Some(&add64)), "(v_5 < v_4 || v_5 == 0)");
    assert_eq!(cond_expr(ConditionCode::a, Some(&add64)), "(v_5 >= v_4 && v_5 != 0)");
    assert_eq!(cond_expr(ConditionCode::e, Some(&add64)), "v_5 == 0");

    let add_const = Flags::arith(FlagOp::Add(32), "v_5".to_owned(), "v_4".to_owned(), "1".to_owned());
    assert_eq!(cond_expr(ConditionCode::b, Some(&add_const)), "(u32)v_5 < (u32)v_4");
    assert_eq!(cond_expr(ConditionCode::be, Some(&add_const)), "(u32)v_5 < (u32)v_4");
    assert_eq!(cond_expr(ConditionCode::a, Some(&add_const)), "(u32)v_5 >= (u32)v_4");

    let add_zero = Flags::arith(FlagOp::Add(8), "(u8)v_5".to_owned(), "v_4".to_owned(), "0".to_owned());
    assert_eq!(cond_expr(ConditionCode::b, Some(&add_zero)), "0");
    assert_eq!(cond_expr(ConditionCode::ae, Some(&add_zero)), "1");
    assert_eq!(cond_expr(ConditionCode::be, Some(&add_zero)), "(u8)v_5 == 0");
    assert_eq!(cond_expr(ConditionCode::a, Some(&add_zero)), "(u8)v_5 != 0");

    let sub64 =
        Flags::arith(FlagOp::from_bin_width(Mnemonic::Sub, 64), "v_5".to_owned(), "v_4".to_owned(), "v_24".to_owned());
    assert_eq!(cond_expr(ConditionCode::b, Some(&sub64)), "v_4 < v_24");
    assert_eq!(cond_expr(ConditionCode::ae, Some(&sub64)), "v_4 >= v_24");
    assert_eq!(cond_expr(ConditionCode::be, Some(&sub64)), "v_4 <= v_24");
    assert_eq!(cond_expr(ConditionCode::a, Some(&sub64)), "v_4 > v_24");
    assert_eq!(cond_expr(ConditionCode::l, Some(&sub64)), "(i64)v_4 < (i64)v_24");
    assert_eq!(cond_expr(ConditionCode::ge, Some(&sub64)), "(i64)v_4 >= (i64)v_24");
    assert_eq!(cond_expr(ConditionCode::le, Some(&sub64)), "(i64)v_4 <= (i64)v_24");
    assert_eq!(cond_expr(ConditionCode::g, Some(&sub64)), "(i64)v_4 > (i64)v_24");
    assert_eq!(cond_expr(ConditionCode::s, Some(&sub64)), "(i64)v_5 < 0");

    let sub16 = Flags::arith(FlagOp::Sub(16), "v_2".to_owned(), "(i16)a".to_owned(), "0xfffe".to_owned());
    assert_eq!(cond_expr(ConditionCode::b, Some(&sub16)), "(u16)(i16)a < 0xfffe");
    assert_eq!(cond_expr(ConditionCode::l, Some(&sub16)), "(i16)a < -2");
    let sub8 = Flags::arith(FlagOp::Sub(8), "v_2".to_owned(), "a".to_owned(), "-1".to_owned());
    assert_eq!(cond_expr(ConditionCode::b, Some(&sub8)), "(u8)a < 255");
    assert_eq!(cond_expr(ConditionCode::l, Some(&sub8)), "(i8)(u8)a < -1");
    let sub32 = Flags::arith(FlagOp::Sub(32), "v_2".to_owned(), "a".to_owned(), "-2".to_owned());
    assert_eq!(cond_expr(ConditionCode::l, Some(&sub32)), "(i32)(u32)a < -2");
    assert_eq!(u_term("-16", 64), "0xfffffffffffffff0");
    assert_eq!(u_term("0x10", 64), "16");
}

#[test]
fn carry_cond_and_cond_helpers_cover_all_widths_and_edge_branches() {
    for (bits, is_adc) in [(8u8, true), (16, false), (32, true), (64, false)] {
        let op = if is_adc { FlagOp::Adc(bits) } else { FlagOp::Sbb(bits) };
        let f = Flags::carry_op(op, "r".to_owned(), "a + 1".to_owned(), "b".to_owned(), "c".to_owned());
        for cc in [
            ConditionCode::b,
            ConditionCode::ae,
            ConditionCode::e,
            ConditionCode::ne,
            ConditionCode::s,
            ConditionCode::ns,
            ConditionCode::be,
            ConditionCode::a,
            ConditionCode::o,
            ConditionCode::no,
            ConditionCode::l,
            ConditionCode::ge,
            ConditionCode::le,
            ConditionCode::g,
            ConditionCode::p,
        ] {
            let s = cond_expr(cc, Some(&f));
            assert!(!s.is_empty());
        }
    }
    let adc_z = Flags::carry_op(FlagOp::Adc(64), "r".to_owned(), "0".to_owned(), "0".to_owned(), "cf".to_owned());
    assert_eq!(cond_expr(ConditionCode::b, Some(&adc_z)), "0");
    let adc_all1 = Flags::carry_op(FlagOp::Adc(8), "r".to_owned(), "0xff".to_owned(), "0".to_owned(), "cf".to_owned());
    assert_eq!(cond_expr(ConditionCode::b, Some(&adc_all1)), "cf");
    let sbb_eq = Flags::carry_op(FlagOp::Sbb(64), "r".to_owned(), "x".to_owned(), "x".to_owned(), "cf".to_owned());
    assert_eq!(cond_expr(ConditionCode::b, Some(&sbb_eq)), "cf");

    let inc_cf = Flags::inc_dec_width(Mnemonic::Inc, 64, "x".to_owned(), "x0".to_owned(), "a < b".to_owned());
    assert_eq!(cond_expr(ConditionCode::ae, Some(&inc_cf)), "!((a < b))");
    assert_eq!(cond_expr(ConditionCode::be, Some(&inc_cf)), "((a < b) || x == 0)");
    assert_eq!(cond_expr(ConditionCode::a, Some(&inc_cf)), "(!(a < b) && x != 0)");

    let umul = Flags::arith(FlagOp::UMul, "rax".to_owned(), "rdi".to_owned(), "rsi".to_owned());
    assert_eq!(cond_expr(ConditionCode::b, Some(&umul)), "umul_overflow(rdi, rsi)");
    assert_eq!(cond_expr(ConditionCode::ae, Some(&umul)), "!umul_overflow(rdi, rsi)");

    let neg = Flags::unary_width(Mnemonic::Neg, 64, "(-x)".to_owned(), "x + 1".to_owned());
    assert_eq!(cond_expr(ConditionCode::b, Some(&neg)), "(x + 1) != 0");
    assert_eq!(cond_expr(ConditionCode::ae, Some(&neg)), "(x + 1) == 0");
    let other_unary = Flags::unary_width(Mnemonic::Not, 64, "(~x)".to_owned(), "x".to_owned());
    assert_eq!(cond_expr(ConditionCode::o, Some(&other_unary)), "overflow((~x))");
    assert_eq!(cond_expr(ConditionCode::np, Some(&other_unary)), "!isnan((~x))");
    assert_eq!(cond_expr(ConditionCode::p, Some(&Flags::other("x".to_owned(), "y".to_owned()))), "isnan(x, y)");
    assert_eq!(neg_cond_expr(ConditionCode::no, Some(&other_unary)), "overflow((~x))");
    assert_eq!(neg_cond_expr(ConditionCode::p, Some(&other_unary)), "!isnan((~x))");
    assert_eq!(neg_cond_expr(ConditionCode::np, Some(&other_unary)), "isnan((~x))");

    assert_eq!(trim_parens("(a) + (b)"), "(a) + (b)");
    assert!(has_call(r#"foo("escaped \" quote")"#));
    assert!(!has_call("/* comment (not a call) */"));
    assert_eq!(invert_cond("!(a && b)"), "a && b");
    assert_eq!(invert_cond("!(a) && !(b)"), "!(!(a) && !(b))");
    assert_eq!(invert_cond("a == b == c"), "!(a == b == c)");
    assert_eq!(invert_cond("a < b"), "a >= b");

    let mut body = vec![
        "while (y) {".to_owned(),
        "  goto L_1000;".to_owned(),
        "}".to_owned(),
        "L_2000:".to_owned(),
        "L_1000:".to_owned(),
    ];
    strip_trailing_continue_label(&mut body);
    assert_eq!(body.last().map(String::as_str), Some("L_1000:"));
    let mut clean_body = vec!["goto L_3000;".to_owned(), "L_3000:".to_owned()];
    strip_trailing_continue_label(&mut clean_body);
    assert_eq!(clean_body, vec!["continue;"]);
    assert!(split_top_stmts(&["}".to_owned()]).is_none());
}

#[test]
fn decompiles_issue_31_hex_loop_and_carry_alu_variants() {
    // f0: mov rax, rdi; add rax, rsi; setb al; movzx eax, al; ret (dead-sum add + setb)
    let f0: &[u8] = &[0x48, 0x89, 0xf8, 0x48, 0x01, 0xf0, 0x0f, 0x92, 0xc0, 0x0f, 0xb6, 0xc0, 0xc3];
    // f1: loop accumulator: xor eax, eax; L: shl rax, 4; add rax, rdi; setb cl; cmp rdi, 16; setae dl; or cl, dl; jz L; ret
    let f1: &[u8] = &[
        0x31, 0xc0, 0x48, 0xc1, 0xe0, 0x04, 0x48, 0x01, 0xf8, 0x0f, 0x92, 0xc1, 0x48, 0x83, 0xff, 0x10, 0x0f, 0x93,
        0xc2, 0x08, 0xd1, 0x74, 0xeb, 0xc3,
    ];
    // f2: mov rax, rdi; L: add rax, rax; jb exit; dec rsi; jnz L; exit: ret (in-place loop web add rax, rax + jb -> snapshots lhs)
    let f2: &[u8] = &[0x48, 0x89, 0xf8, 0x48, 0x01, 0xc0, 0x72, 0x05, 0x48, 0xff, 0xce, 0x75, 0xf6, 0xc3];
    // f3: L: sub rdi, rdi? No: mov rax, rdi; L: sub rax, rax? No, sub same-reg is zeroed! Use: mov rax, rdi; mov rcx, rsi; L: sub rax, rcx; jb exit; add rcx, 1; jmp L; exit: ret (in-place loop web sub -> snapshots lhs & rhs!)
    let f3: &[u8] =
        &[0x48, 0x89, 0xf8, 0x48, 0x89, 0xf1, 0x48, 0x29, 0xc8, 0x72, 0x06, 0x48, 0x83, 0xc1, 0x01, 0xeb, 0xf4, 0xc3];
    // f4: mov rax, rdi; mov rcx, rsi; L: cmp rax, rcx; adc rax, 0; cmp rax, rcx; not rax; bswap rcx; jb exit; jmp L; exit: ret
    let f4: &[u8] = &[
        0x48, 0x89, 0xf8, 0x48, 0x89, 0xf1, 0x48, 0x39, 0xc8, 0x48, 0xf7, 0xd0, 0x48, 0x0f, 0xc9, 0x72, 0x02, 0xeb,
        0xf1, 0xc3,
    ];
    // f5: cmp rdi, rsi; sbb al, al; movzx eax, al; ret + sbb ax, ax + sbb eax, eax + sbb rcx, rdx with dirty rhs
    let f5: &[u8] = &[0x48, 0x39, 0xf7, 0x18, 0xc0, 0x0f, 0xb6, 0xc0, 0xc3];
    let f6: &[u8] = &[0x48, 0x39, 0xf7, 0x66, 0x19, 0xc0, 0x0f, 0xb7, 0xc0, 0xc3];
    let f7: &[u8] = &[0x48, 0x39, 0xf7, 0x19, 0xc0, 0xc3];
    // f8: mov rax, rdi; L: cmp rdx, rsi; adc rax, rax; jb exit; dec rcx; jnz L; exit: ret (in-place loop adc -> lhs_ & rhs_)
    let f8: &[u8] =
        &[0x48, 0x89, 0xf8, 0x48, 0x39, 0xf2, 0x48, 0x11, 0xc0, 0x72, 0x05, 0x48, 0xff, 0xc9, 0x75, 0xf3, 0xc3];
    // f9..f15: carry_alu original 7 functions (sbb/adc/inc/dec/idiv/div8)
    let f9: &[u8] = &[
        0xb8, 0x00, 0x01, 0x00, 0x00, 0x48, 0x39, 0xf8, 0x1c, 0x00, 0x48, 0x89, 0x06, 0x0f, 0x92, 0xc0, 0x0f, 0xb6,
        0xc0, 0xc3,
    ];
    let f10: &[u8] = &[
        0xb8, 0x01, 0x01, 0x00, 0x00, 0x48, 0x39, 0xf8, 0x1c, 0x00, 0xb0, 0x05, 0x48, 0x89, 0x06, 0x0f, 0x94, 0xc0,
        0x0f, 0xb6, 0xc0, 0xc3,
    ];
    let f11: &[u8] = &[
        0x48, 0x39, 0xf7, 0x48, 0xc7, 0xc0, 0xff, 0xff, 0xff, 0xff, 0x48, 0x83, 0xd0, 0x00, 0x48, 0xff, 0xc1, 0x0f,
        0x92, 0xc2, 0x0f, 0xb6, 0xc2, 0xc3,
    ];
    let f12: &[u8] = &[
        0x48, 0x39, 0xf7, 0x48, 0xc7, 0xc0, 0xff, 0xff, 0xff, 0xff, 0x48, 0x83, 0xd0, 0x00, 0x48, 0xff, 0xc9, 0xb8,
        0x0a, 0x00, 0x00, 0x00, 0x48, 0x83, 0xd0, 0x00, 0xc3,
    ];
    let f13: &[u8] = &[
        0xb8, 0x00, 0x01, 0x00, 0x00, 0x48, 0x39, 0xf8, 0x1c, 0x00, 0xfe, 0xc0, 0x48, 0x89, 0x06, 0x0f, 0x92, 0xc0,
        0x0f, 0xb6, 0xc0, 0xc3,
    ];
    // f14: xorps xmm0, xmm1 (dirty non-GPR flushed at ret!) -> 0f 57 c1 c3
    let f14: &[u8] = &[0x0f, 0x57, 0xc1, 0xc3];
    // f15: mov rax, rdi; L: add rax, rax; jo exit; dec rsi; jnz L; exit: ret (in-place loop Add with reads_ovf -> snapshots lhs & rhs!)
    let f15: &[u8] = &[0x48, 0x89, 0xf8, 0x48, 0x01, 0xc0, 0x70, 0x05, 0x48, 0xff, 0xce, 0x75, 0xf6, 0xc3];
    // f16 (issue #32): cmp byte ptr [rdi + rsi], 0xc0; jge +6; mov eax, 1; ret; xor eax, eax; ret
    let f16: &[u8] = &[0x80, 0x3c, 0x37, 0xc0, 0x7d, 0x06, 0xb8, 0x01, 0x00, 0x00, 0x00, 0xc3, 0x31, 0xc0, 0xc3];
    // f17 (issue #32): test byte ptr [rdi], 0xff; sets al; movzx eax, al; ret
    let f17: &[u8] = &[0xf6, 0x07, 0xff, 0x0f, 0x98, 0xc0, 0x0f, 0xb6, 0xc0, 0xc3];
    // f18: not rdi (with None flags); cmp rdi, rsi; sbb rax, rax; ret
    let f18: &[u8] = &[0x48, 0xf7, 0xd7, 0x48, 0x39, 0xf7, 0x48, 0x19, 0xc0, 0xc3];
    // f19: loop `mov rax, rdi; L: not rax; cmp rdi, 10; inc rsi; not rdi; sub rdx, 1; jnz L; add rax, rsi; add rax, rdi; ret`
    let f19: &[u8] = &[
        0x48, 0x89, 0xf8, 0x48, 0xf7, 0xd0, 0x48, 0x83, 0xff, 0x0a, 0x48, 0xff, 0xc6, 0x48, 0xf7, 0xd7, 0x48, 0x83,
        0xea, 0x01, 0x75, 0xed, 0x48, 0x01, 0xf0, 0x48, 0x01, 0xf8, 0xc3,
    ];
    // f20: loop `L: add rsi, rdi; not rdi; sub rdx, 1; jnz L; lea rax, [rsi + rdi]; ret`
    let f20: &[u8] =
        &[0x48, 0x01, 0xfe, 0x48, 0xf7, 0xd7, 0x48, 0x83, 0xea, 0x01, 0x75, 0xf4, 0x48, 0x8d, 0x04, 0x3e, 0xc3];
    // f21: cmp byte ptr [rdi], 1; inc byte ptr [rdi]; jbe +6; mov eax, 1; ret; xor eax, eax; ret
    let f21: &[u8] = &[0x80, 0x3f, 0x01, 0xfe, 0x07, 0x76, 0x06, 0xb8, 0x01, 0x00, 0x00, 0x00, 0xc3, 0x31, 0xc0, 0xc3];
    // f22: stack spill_to_arg + 128-bit split_zero_128 store
    let f22: &[u8] = &[
        0x48, 0x83, 0xec, 0x28, 0x48, 0x89, 0x7c, 0x24, 0x08, 0x0f, 0x57, 0xc0, 0x0f, 0x11, 0x44, 0x24, 0x10, 0x48,
        0x8b, 0x44, 0x24, 0x08, 0x48, 0x03, 0x44, 0x24, 0x10, 0x48, 0x03, 0x44, 0x24, 0x18, 0x48, 0x83, 0xc4, 0x28,
        0xc3,
    ];

    let (img, starts) = build_img(&[
        f0, f1, f2, f3, f4, f5, f6, f7, f8, f9, f10, f11, f12, f13, f14, f15, f16, f17, f18, f19, f20, f21, f22,
    ]);
    let rt = RuntimeMap::detect(&img);

    let (_, c0) = c_one(&img, &[], &rt, starts[0], None, None).unwrap_or_default();
    assert!(c0.contains("< arg_0") && !c0.contains("< 0"));

    let (_, c1) = c_one(&img, &[], &rt, starts[1], None, None).unwrap_or_default();
    assert!(!c1.contains("< 0") && c1.contains(">= 16"));

    let (_, c2) = c_one(&img, &[], &rt, starts[2], None, None).unwrap_or_default();
    assert!(c2.contains("lhs_") && !c2.contains("< 0"));

    let (_, c3) = c_one(&img, &[], &rt, starts[3], None, None).unwrap_or_default();
    assert!(c3.contains("lhs_") && !c3.contains("< 0"));

    let (_, c4) = c_one(&img, &[], &rt, starts[4], None, None).unwrap_or_default();
    assert!(c4.contains("pre_") && c4.contains("__builtin_bswap64"));

    let (_, c5) = c_one(&img, &[], &rt, starts[5], None, None).unwrap_or_default();
    assert!(c5.contains("0xff : 0"));
    let (_, c6) = c_one(&img, &[], &rt, starts[6], None, None).unwrap_or_default();
    assert!(c6.contains("0xffff : 0"));
    let (_, c7) = c_one(&img, &[], &rt, starts[7], None, None).unwrap_or_default();
    assert!(c7.contains("0xffffffff : 0"));
    let (_, c8) = c_one(&img, &[], &rt, starts[8], None, None).unwrap_or_default();
    assert!(c8.contains("lhs_") && c8.contains("rhs_"));
    let (_, c9) = c_one(&img, &[], &rt, starts[9], None, None).unwrap_or_default();
    assert!(c9.contains("cf_") && c9.contains("lhs_"));
    let (_, c10) = c_one(&img, &[], &rt, starts[10], None, None).unwrap_or_default();
    assert!(c10.contains("== 0"));
    let (_, c11) = c_one(&img, &[], &rt, starts[11], None, None).unwrap_or_default();
    assert!(c11.contains("arg_0 < arg_1"));
    let (_, c12) = c_one(&img, &[], &rt, starts[12], None, None).unwrap_or_default();
    assert!(c12.contains("(10 + (arg_0 < arg_1))"));
    let (_, c13) = c_one(&img, &[], &rt, starts[13], None, None).unwrap_or_default();
    assert!(c13.contains("cf_") && c13.contains("lhs_"));
    let (_, c14) = c_one(&img, &[], &rt, starts[14], None, None).unwrap_or_default();
    assert!(c14.contains("/* xorps"));
    let (_, c15) = c_one(&img, &[], &rt, starts[15], None, None).unwrap_or_default();
    assert!(c15.contains("add_overflow") && c15.contains("rhs_"));
    let (_, c16) = c_one(&img, &[], &rt, starts[16], None, None).unwrap_or_default();
    assert!(c16.contains("(i8)((u8 *)arg_0)[arg_1] < -64") && !c16.contains("192"), "{c16}");
    let (_, c17) = c_one(&img, &[], &rt, starts[17], None, None).unwrap_or_default();
    assert!(c17.contains("(i8)") && c17.contains("< 0"), "{c17}");
    let (_, c18) = c_one(&img, &[], &rt, starts[18], None, None).unwrap_or_default();
    assert!(c18.contains("(-("), "{c18}");
    let (_, c19) = c_one(&img, &[], &rt, starts[19], None, None).unwrap_or_default();
    assert!(c19.contains("pre_"), "{c19}");
    let (_, c20) = c_one(&img, &[], &rt, starts[20], None, None).unwrap_or_default();
    assert!(c20.contains("pre_"), "{c20}");
    let (_, c21) = c_one(&img, &[], &rt, starts[21], None, None).unwrap_or_default();
    assert!(c21.contains("cf_") && c21.contains("(u8)("), "{c21}");
    let (_, c22) = c_one(&img, &[], &rt, starts[22], None, None).unwrap_or_default();
    assert!(c22.contains("arg_0") && c22.contains("= 0;"), "{c22}");

    assert_eq!(i_term("0x1000", 64), "(i64)0x1000");
    let other_ovf = Flags {
        lhs: "a".to_owned(),
        rhs: "b".to_owned(),
        op: FlagOp::Other,
        bits: 64,
        ovf: Some(("a".to_owned(), "b".to_owned())),
        carry: None,
    };
    assert_eq!(cond_expr(ConditionCode::o, Some(&other_ovf)), "overflow(a, b)");
    let neg_no_ovf =
        Flags { lhs: "x".to_owned(), rhs: "0".to_owned(), op: FlagOp::Neg, bits: 64, ovf: None, carry: None };
    assert_eq!(cond_expr(ConditionCode::b, Some(&neg_no_ovf)), "x < 0");
    assert_eq!(cond_expr(ConditionCode::ae, Some(&neg_no_ovf)), "x >= 0");
    assert!(!has_call(r#"x = "\"foo()\"";"#));

    let mut st = State::default();
    st.set_reg(Register::XMM0, "xmm1".to_owned());
    st.dirty.push(Register::RAX);
    let mut lines = Vec::new();
    flush_non_gpr_dirty(&mut st, &mut lines);
    assert_eq!(lines, vec!["zmm0 = xmm1;"]);

    // expr.rs line 241: negative scaled array offset `mov rax, [rdi + rsi*8 - 16]` -> 48 8b 44 f7 f0
    let mut neg_idx_ins = Instruction::default();
    decode(&[0x48, 0x8b, 0x44, 0xf7, 0xf0], 0x1000, |d| neg_idx_ins = *d);
    assert_eq!(neg_idx_ins.memory_size(), MemorySize::UInt64);
    assert_eq!(mem_expr(&img, &[], &mut st, &neg_idx_ins), "((u64 *)rdi)[rsi - 2]");
}
