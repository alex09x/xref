/*
 * XRef — x86-64 binary analysis and cross-reference tooling
 * Copyright (c) 2026 Alexander Panasenko
 *
 * Contact: alex@prod.codes
 * Author: https://prod.codes/about/
 * Project: https://github.com/alex09x/xref
 * SPDX-License-Identifier: MIT OR Apache-2.0
 */

use crate::{
    c_step::{FnCtx, assign},
    cond::Flags,
    expr::{State, reg_name},
    image::Image,
    ssa_webs::SsaCfg,
};
use iced_x86::{ConditionCode, Instruction, Mnemonic, OpKind, Register};

pub fn condition(cc: ConditionCode, flags: &Flags) -> String {
    let unordered = format!("(isnan({}) || isnan({}))", flags.lhs, flags.rhs);
    match cc {
        ConditionCode::e | ConditionCode::le => format!("({} == {} || {})", flags.lhs, flags.rhs, unordered),
        ConditionCode::ne | ConditionCode::g => format!("({} != {} && !{})", flags.lhs, flags.rhs, unordered),
        ConditionCode::b => format!("({} < {} || {})", flags.lhs, flags.rhs, unordered),
        ConditionCode::ae => format!("({} >= {} && !{})", flags.lhs, flags.rhs, unordered),
        ConditionCode::be => format!("({} <= {} || {})", flags.lhs, flags.rhs, unordered),
        ConditionCode::a => format!("({} > {} && !{})", flags.lhs, flags.rhs, unordered),
        ConditionCode::p => unordered,
        ConditionCode::np => format!("!{unordered}"),
        ConditionCode::o | ConditionCode::s | ConditionCode::l => "0".to_owned(),
        ConditionCode::no | ConditionCode::ns | ConditionCode::ge => "1".to_owned(),
        ConditionCode::None => format!("cc_float_{cc:?}({}, {})", flags.lhs, flags.rhs),
    }
}

const fn scalar_double(mnemonic: Mnemonic) -> bool {
    matches!(
        mnemonic,
        Mnemonic::Addsd
            | Mnemonic::Subsd
            | Mnemonic::Mulsd
            | Mnemonic::Divsd
            | Mnemonic::Sqrtsd
            | Mnemonic::Maxsd
            | Mnemonic::Minsd
            | Mnemonic::Movapd
            | Mnemonic::Ucomisd
            | Mnemonic::Comisd
            | Mnemonic::Movsd
            | Mnemonic::Cvtsi2sd
            | Mnemonic::Cvttsd2si
    )
}

pub fn is_xmm_register(register: Register) -> bool {
    let name = reg_name(register);
    name.starts_with("xmm") || name.starts_with("zmm")
}

pub fn read_only_bytes(image: &Image, address: u64, len: usize) -> Option<&[u8]> {
    let end = address.checked_add(u64::try_from(len).ok()?)?;
    let in_readonly = image.metadata.load_segments.iter().any(|segment| {
        !segment.writable
            && !segment.executable
            && address >= segment.va
            && segment.va.checked_add(segment.file_size).is_some_and(|file_end| end <= file_end)
    });
    in_readonly.then(|| image.read(address, len)).flatten()
}

fn read_only_data(image: &Image, address: u64) -> Option<u64> {
    let bytes = read_only_bytes(image, address, 8)?;
    Some(u64::from_le_bytes(bytes.try_into().ok()?))
}

fn double_literal(bits: u64) -> String {
    let value = f64::from_bits(bits);
    if value.is_nan() {
        "NAN".to_owned()
    } else if value == f64::INFINITY {
        "INFINITY".to_owned()
    } else if value == f64::NEG_INFINITY {
        "-INFINITY".to_owned()
    } else {
        format!("{value:?}")
    }
}

fn expression(mnemonic: Mnemonic, left: &str, right: &str, source_bits: u32, dest_bits: u32) -> Option<String> {
    Some(match mnemonic {
        Mnemonic::Movsd | Mnemonic::Movapd => right.to_owned(),
        Mnemonic::Addsd => format!("({left} + {right})"),
        Mnemonic::Subsd => format!("({left} - {right})"),
        Mnemonic::Mulsd => format!("({left} * {right})"),
        Mnemonic::Divsd => format!("({left} / {right})"),
        Mnemonic::Sqrtsd => format!("sqrt({right})"),
        // Intel MAXSD/MINSD return the source operand for equal values and unordered inputs.
        Mnemonic::Maxsd => format!("({left} > {right} ? {left} : {right})"),
        Mnemonic::Minsd => format!("({left} < {right} ? {left} : {right})"),
        Mnemonic::Cvtsi2sd => format!("(f64)(i{source_bits})({right})"),
        Mnemonic::Cvttsd2si => {
            format!("(i{dest_bits})({right}) /* truncates toward zero; NaN/out-of-range yields i{dest_bits}_min */")
        }
        _ => return None,
    })
}

fn write_float(state: &mut State, ins: &Instruction, block: &mut crate::cfg::Block, expression: &str) -> bool {
    if ins.op0_kind() != OpKind::Register || !is_xmm_register(ins.op0_register()) {
        return false;
    }
    let register = ins.op0_register().full_register();
    let name = format!("fp_{:x}", ins.ip());
    block.stmts.push(format!("f64 {name} = {expression};"));
    state.inline_regs.remove(&register);
    state.rodata_ptrs.remove(&register);
    state.set_reg(register, name);
    let _ = state.reg(register);
    true
}

fn operand(image: &Image, ins: &Instruction, index: u32, operand: String) -> String {
    if index != 1
        || ins.op_kind(index) != OpKind::Memory
        || !matches!(
            ins.mnemonic(),
            Mnemonic::Movsd
                | Mnemonic::Addsd
                | Mnemonic::Subsd
                | Mnemonic::Mulsd
                | Mnemonic::Divsd
                | Mnemonic::Sqrtsd
                | Mnemonic::Maxsd
                | Mnemonic::Minsd
                | Mnemonic::Ucomisd
                | Mnemonic::Comisd
                | Mnemonic::Cvttsd2si
        )
    {
        return operand;
    }
    let address = if ins.is_ip_rel_memory_operand() {
        Some(ins.ip_rel_memory_address())
    } else if ins.memory_base() == Register::None && ins.memory_index() == Register::None {
        Some(ins.memory_displacement64())
    } else {
        None
    };
    address.and_then(|va| read_only_data(image, va)).map_or(operand, double_literal)
}

pub fn lift_operand(image: &Image, ins: &Instruction, index: u32, expression: String) -> String {
    operand(image, ins, index, expression)
}

pub fn step(
    ctx: &FnCtx<'_>,
    state: &mut State,
    ins: &Instruction,
    ins_idx: usize,
    block: &mut crate::cfg::Block,
) -> bool {
    let mnemonic = ins.mnemonic();
    if !scalar_double(mnemonic) {
        return false;
    }
    if mnemonic == Mnemonic::Movapd && (ins.op0_kind() != OpKind::Register || ins.op1_kind() != OpKind::Register) {
        return false;
    }
    let left = ctx.op(state, ins, 0);
    let right = ctx.op(state, ins, 1);
    if matches!(mnemonic, Mnemonic::Ucomisd | Mnemonic::Comisd) {
        state.flags = Some(Flags::float_cmp(left, right));
        return true;
    }
    let source_bits = u32::try_from(if ins.op1_kind() == OpKind::Memory {
        ins.memory_size().size() * 8
    } else {
        ins.op1_register().size() * 8
    })
    .unwrap_or(64);
    let dest_bits = u32::try_from(if ins.op0_kind() == OpKind::Register { ins.op0_register().size() * 8 } else { 64 })
        .unwrap_or(64);
    let Some(expression) = expression(mnemonic, &left, &right, source_bits, dest_bits) else { return false };
    if mnemonic == Mnemonic::Movsd && ins.op0_kind() != OpKind::Register {
        return false;
    }
    if ins.op0_kind() == OpKind::Register && is_xmm_register(ins.op0_register()) {
        let _ = write_float(state, ins, block, &expression);
    } else {
        let _ = assign(ctx, state, ins, ins_idx, expression, &mut block.stmts);
    }
    true
}

pub fn rip_memory_address(ins: &Instruction) -> Option<u64> {
    if ins.op1_kind() != OpKind::Memory {
        return None;
    }
    if ins.is_ip_rel_memory_operand() {
        Some(ins.ip_rel_memory_address())
    } else if ins.memory_base() == Register::None && ins.memory_index() == Register::None {
        Some(ins.memory_displacement64())
    } else {
        None
    }
}

mod u64_idiom;
pub use u64_idiom::step_u64_conversion_idiom;

pub fn local_declarations(ssa: &SsaCfg) -> Vec<String> {
    let mut registers = std::collections::BTreeSet::new();
    for ins in &ssa.insns {
        if !scalar_double(ins.mnemonic()) {
            continue;
        }
        for operand in 0..ins.op_count() {
            if ins.op_kind(operand) == OpKind::Register {
                let name = reg_name(ins.op_register(operand));
                if is_xmm_register(ins.op_register(operand)) {
                    registers.insert(name);
                }
            }
        }
    }
    registers.into_iter().map(|name| format!("  f64 {name};")).collect()
}

#[cfg(test)]
mod tests {
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
        while decoder.can_decode() { insns.push(decoder.decode()); }

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
}
