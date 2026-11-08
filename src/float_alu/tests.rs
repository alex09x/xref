/*
 * XRef — x86-64 binary analysis and cross-reference tooling
 * Copyright (c) 2026 Alexander Panasenko
 *
 * Contact: alex@prod.codes
 * Author: https://prod.codes/about/
 * Project: https://github.com/alex09x/xref
 * SPDX-License-Identifier: MIT OR Apache-2.0
 */

use super::*;
use crate::{
    image::Segment,
    image_format::{LoadSegment, Metadata},
};

#[test]
fn formats_double_constants_without_losing_special_values_or_signed_zero() {
    assert_eq!(double_literal(1000.0f64.to_bits()), "1000.0");
    assert_eq!(double_literal(0.0f64.to_bits()), "0.0");
    assert_eq!(double_literal((-0.0f64).to_bits()), "-0.0");
    assert_eq!(double_literal(f64::INFINITY.to_bits()), "INFINITY");
    assert_eq!(double_literal(f64::NEG_INFINITY.to_bits()), "-INFINITY");
    assert_eq!(double_literal(f64::NAN.to_bits()), "NAN");
}

#[test]
fn lowers_scalar_sse2_arithmetic_and_integer_conversions() {
    for (mnemonic, expected) in [
        (Mnemonic::Addsd, "(xmm0 + 2.0)"),
        (Mnemonic::Subsd, "(xmm0 - 2.0)"),
        (Mnemonic::Mulsd, "(xmm0 * 2.0)"),
        (Mnemonic::Divsd, "(xmm0 / 2.0)"),
        (Mnemonic::Sqrtsd, "sqrt(2.0)"),
        (Mnemonic::Maxsd, "(xmm0 > 2.0 ? xmm0 : 2.0)"),
        (Mnemonic::Minsd, "(xmm0 < 2.0 ? xmm0 : 2.0)"),
        (Mnemonic::Cvtsi2sd, "(f64)(i64)(rdi)"),
        (Mnemonic::Cvttsd2si, "(i64)(xmm0) /* truncates toward zero; NaN/out-of-range yields i64_min */"),
    ] {
        let right = match mnemonic {
            Mnemonic::Cvttsd2si => "xmm0",
            Mnemonic::Cvtsi2sd => "rdi",
            _ => "2.0",
        };
        assert_eq!(expression(mnemonic, "xmm0", right, 64, 64).as_deref(), Some(expected));
    }
    assert_eq!(expression(Mnemonic::Ucomisd, "xmm0", "xmm1", 64, 64), None);
}

#[test]
fn f64_abi_lowers_scalar_single_arithmetic_and_width_conversions() {
    for (mnemonic, right, expected) in [
        (Mnemonic::Mulss, "0.5f", "(xmm0 * 0.5f)"),
        (Mnemonic::Sqrtss, "xmm1", "sqrtf(xmm1)"),
        (Mnemonic::Cvtss2sd, "xmm1", "(f64)(xmm1)"),
        (Mnemonic::Cvtsd2ss, "xmm1", "(f32)(xmm1)"),
        (Mnemonic::Cvtsi2ss, "rdi", "(f32)(i64)(rdi)"),
    ] {
        assert_eq!(expression(mnemonic, "xmm0", right, 64, 64).as_deref(), Some(expected));
    }
    assert_eq!(scalar_float(Mnemonic::Mulss), Some("f32"));
    assert_eq!(scalar_float(Mnemonic::Cvtss2sd), Some("f64"));
    assert_eq!(float_literal(0.5f32.to_bits()), "0.5f");
    assert_eq!(float_literal(f32::INFINITY.to_bits()), "INFINITY");
}

#[test]
fn unordered_scalar_double_comparisons_follow_ucomisd_flags() {
    let flags = Flags::float_cmp("xmm0".to_owned(), "xmm1".to_owned());
    assert_eq!(condition(ConditionCode::e, &flags), "(xmm0 == xmm1 || (isnan(xmm0) || isnan(xmm1)))");
    assert_eq!(condition(ConditionCode::ne, &flags), "(xmm0 != xmm1 && !(isnan(xmm0) || isnan(xmm1)))");
    assert_eq!(condition(ConditionCode::b, &flags), "(xmm0 < xmm1 || (isnan(xmm0) || isnan(xmm1)))");
    assert_eq!(condition(ConditionCode::a, &flags), "(xmm0 > xmm1 && !(isnan(xmm0) || isnan(xmm1)))");
    assert_eq!(condition(ConditionCode::p, &flags), "(isnan(xmm0) || isnan(xmm1))");
    assert_eq!(condition(ConditionCode::no, &flags), "1");
}

fn image_with_load_segment(value: f64, writable: bool, executable: bool) -> Image {
    let data = value.to_bits().to_le_bytes().to_vec();
    Image {
        data,
        segments: vec![Segment { va: 0x4000, offset: 0, size: 8 }],
        metadata: Metadata {
            load_segments: vec![LoadSegment {
                va: 0x4000,
                file_offset: 0,
                file_size: 8,
                mem_size: 8,
                executable,
                writable,
            }],
            ..Metadata::default()
        },
        ..Image::default()
    }
}

#[test]
fn reads_only_file_backed_nonwritable_nonexecutable_double_constants() {
    assert_eq!(read_only_data(&image_with_load_segment(1000.0, false, false), 0x4000), Some(1000.0f64.to_bits()));
    assert_eq!(read_only_data(&image_with_load_segment(1000.0, true, false), 0x4000), None);
    assert_eq!(read_only_data(&image_with_load_segment(1000.0, false, true), 0x4000), None);
    assert_eq!(read_only_data(&image_with_load_segment(1000.0, false, false), 0x4001), None);
}

#[test]
fn integer_conversion_memory_operands_are_not_reinterpreted_as_double_literals() {
    let instruction = iced_x86::Decoder::with_ip(
        64,
        &[0xf2, 0x48, 0x0f, 0x2a, 0x05, 0xf7, 0x2f, 0, 0],
        0x1000,
        iced_x86::DecoderOptions::NONE,
    )
    .decode();
    let image = image_with_load_segment(1000.0, false, false);
    let integer_operand = "*(u64 *)0x4000".to_owned();
    assert_eq!(operand(&image, &instruction, 1, integer_operand.clone()), integer_operand);
}

#[test]
fn u64_to_f64_idiom_matches_when_not_in_first_six_instructions() {
    let magic = 0x4530_0000_4330_0000u64.to_le_bytes();
    let bias = [0x4330_0000_0000_0000u64.to_le_bytes(), 0x4530_0000_0000_0000u64.to_le_bytes()].concat();
    let mut rodata = [0u8; 0x20];
    rodata[..8].copy_from_slice(&magic);
    rodata[0x10..].copy_from_slice(&bias);

    let image = Image {
        data: rodata.to_vec(),
        segments: vec![Segment { va: 0x3000, offset: 0, size: 0x20 }],
        metadata: Metadata {
            load_segments: vec![LoadSegment {
                va: 0x3000,
                file_offset: 0,
                file_size: 0x20,
                mem_size: 0x20,
                executable: false,
                writable: false,
            }],
            ..Metadata::default()
        },
        ..Image::default()
    };

    // 7 NOPs (0x1000..0x1007), then movq, punpckldq, subpd, movapd, unpckhpd, addsd, ret.
    #[rustfmt::skip]
    let code = [
        0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90,
        0x66, 0x48, 0x0f, 0x6e, 0xd7,
        0x66, 0x0f, 0x62, 0x15, 0xec, 0x1f, 0x00, 0x00,
        0x66, 0x0f, 0x5c, 0x15, 0xf4, 0x1f, 0x00, 0x00,
        0x66, 0x0f, 0x28, 0xca,
        0x66, 0x0f, 0x15, 0xca,
        0xf2, 0x0f, 0x58, 0xca,
        0xc3,
    ];

    let mut decoder = iced_x86::Decoder::new(64, &code, iced_x86::DecoderOptions::NONE);
    decoder.set_ip(0x1000);
    let mut insns = Vec::new();
    while decoder.can_decode() {
        insns.push(decoder.decode());
    }

    let ssa = SsaCfg { insns, ..Default::default() };
    let rt = crate::runtime::RuntimeMap::default();
    let ctx = FnCtx {
        image: &image,
        locations: &[],
        runtime: &rt,
        tables: &[],
        function: &(0x1000..0x1029),
        ssa: &ssa,
        ret_kind: crate::type_facts::ReturnKind::VoidUnused,
        partial_slice: false,
        mark_ip: None,
        mark_targets: None,
        xmm0_note: None,
        xmm_live: None,
    };

    let mut state = State::default();
    let mut block = crate::cfg::Block { start: 0x1000, stmts: Vec::new(), term: crate::cfg::Term::Fall };

    for idx in 0..7 {
        assert!(!step_u64_conversion_idiom(&ctx, &mut state, &ssa.insns[idx], idx, &mut block));
    }
    assert!(step_u64_conversion_idiom(&ctx, &mut state, &ssa.insns[7], 7, &mut block));
    assert!(block.stmts.iter().any(|s| s.contains("(f64)(u64)")));
    assert_eq!(state.reg(Register::XMM1), format!("fp_{:x}", ssa.insns[7].ip()));

    for idx in 8..=12 {
        assert!(step_u64_conversion_idiom(&ctx, &mut state, &ssa.insns[idx], idx, &mut block));
    }
    assert!(!step_u64_conversion_idiom(&ctx, &mut state, &ssa.insns[13], 13, &mut block));
}

#[test]
fn vex_scalar_forms_read_their_last_two_operands() {
    let decode = |bytes: &[u8]| {
        let mut decoder = iced_x86::Decoder::with_ip(64, bytes, 0x1000, iced_x86::DecoderOptions::NONE);
        decoder.decode()
    };
    // vmulsd xmm0, xmm1, xmm2: xmm0 = xmm1 * xmm2.
    let vex = decode(&[0xc5, 0xf3, 0x59, 0xc2]);
    assert_eq!((legacy(vex.mnemonic()), sources(&vex)), (Mnemonic::Mulsd, (1, 2)));
    assert_eq!(scalar_float(vex.mnemonic()), Some(F64));
    // vcvtss2sd xmm0, xmm0, xmm1: the scalar comes from xmm1.
    let convert = decode(&[0xc5, 0xfa, 0x5a, 0xc1]);
    assert_eq!((legacy(convert.mnemonic()), sources(&convert)), (Mnemonic::Cvtss2sd, (1, 2)));
    // vmovsd xmm0, [rdi]: a two-operand load reads its second operand, like movsd.
    let load = decode(&[0xc5, 0xfb, 0x10, 0x07]);
    assert_eq!((legacy(load.mnemonic()), sources(&load)), (Mnemonic::Movsd, (0, 1)));
    // mulsd xmm0, xmm1 keeps the legacy two-operand reading.
    let sse = decode(&[0xf2, 0x0f, 0x59, 0xc1]);
    assert_eq!((legacy(sse.mnemonic()), sources(&sse)), (Mnemonic::Mulsd, (0, 1)));
}
