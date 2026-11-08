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
    sig::xmm::{F32, F64, read_width},
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

/// The legacy SSE mnemonic of a VEX scalar form (`vaddsd` → `addsd`); others unchanged.
pub const fn legacy(mnemonic: Mnemonic) -> Mnemonic {
    match mnemonic {
        Mnemonic::Vaddsd => Mnemonic::Addsd,
        Mnemonic::Vsubsd => Mnemonic::Subsd,
        Mnemonic::Vmulsd => Mnemonic::Mulsd,
        Mnemonic::Vdivsd => Mnemonic::Divsd,
        Mnemonic::Vsqrtsd => Mnemonic::Sqrtsd,
        Mnemonic::Vmaxsd => Mnemonic::Maxsd,
        Mnemonic::Vminsd => Mnemonic::Minsd,
        Mnemonic::Vmovapd => Mnemonic::Movapd,
        Mnemonic::Vucomisd => Mnemonic::Ucomisd,
        Mnemonic::Vcomisd => Mnemonic::Comisd,
        Mnemonic::Vucomiss => Mnemonic::Ucomiss,
        Mnemonic::Vcomiss => Mnemonic::Comiss,
        Mnemonic::Vmovsd => Mnemonic::Movsd,
        Mnemonic::Vmovss => Mnemonic::Movss,
        Mnemonic::Vcvtsi2sd => Mnemonic::Cvtsi2sd,
        Mnemonic::Vcvttsd2si => Mnemonic::Cvttsd2si,
        Mnemonic::Vcvtss2sd => Mnemonic::Cvtss2sd,
        Mnemonic::Vaddss => Mnemonic::Addss,
        Mnemonic::Vsubss => Mnemonic::Subss,
        Mnemonic::Vmulss => Mnemonic::Mulss,
        Mnemonic::Vdivss => Mnemonic::Divss,
        Mnemonic::Vsqrtss => Mnemonic::Sqrtss,
        Mnemonic::Vmaxss => Mnemonic::Maxss,
        Mnemonic::Vminss => Mnemonic::Minss,
        Mnemonic::Vcvtsi2ss => Mnemonic::Cvtsi2ss,
        Mnemonic::Vcvttss2si => Mnemonic::Cvttss2si,
        Mnemonic::Vcvtsd2ss => Mnemonic::Cvtsd2ss,
        Mnemonic::Vmovaps => Mnemonic::Movaps,
        Mnemonic::Vmovups => Mnemonic::Movups,
        Mnemonic::Vmovdqa => Mnemonic::Movdqa,
        Mnemonic::Vmovdqu => Mnemonic::Movdqu,
        Mnemonic::Vmovupd => Mnemonic::Movupd,
        Mnemonic::Vroundsd => Mnemonic::Roundsd,
        Mnemonic::Vroundss => Mnemonic::Roundss,
        other => other,
    }
}

/// Operand indices of the left and right scalar sources: `op dst, src` reads `dst` and `src`; the
/// VEX form `op dst, left, right[, imm]` writes `dst` from `left` and `right` (for moves,
/// conversions, square roots and rounding `left` only supplies the upper lanes).
pub fn sources(ins: &Instruction) -> (u32, u32) {
    if ins.op_count() >= 3 && legacy(ins.mnemonic()) != ins.mnemonic() { (1, 2) } else { (0, 1) }
}

/// Scalar operations reading both sources as values; the others read only the right one.
const fn binary(mnemonic: Mnemonic) -> bool {
    matches!(
        mnemonic,
        Mnemonic::Addsd
            | Mnemonic::Subsd
            | Mnemonic::Mulsd
            | Mnemonic::Divsd
            | Mnemonic::Maxsd
            | Mnemonic::Minsd
            | Mnemonic::Addss
            | Mnemonic::Subss
            | Mnemonic::Mulss
            | Mnemonic::Divss
            | Mnemonic::Maxss
            | Mnemonic::Minss
            | Mnemonic::Ucomisd
            | Mnemonic::Comisd
            | Mnemonic::Ucomiss
            | Mnemonic::Comiss
    )
}

/// The operand a read-only constant may be loaded from: the right source, or `c` of an FMA.
fn constant_source(ins: &Instruction) -> u32 {
    if fused::fma(ins.mnemonic()).is_some() { 2 } else { sources(ins).1 }
}

/// The type an instruction lifted here writes: scalar SSE, a VEX `vmovss` merge, or an FMA.
fn lifted_type(ins: &Instruction) -> Option<&'static str> {
    if ins.mnemonic() == Mnemonic::Vmovss && ins.op_count() == 3 {
        return Some(F32);
    }
    scalar_float(ins.mnemonic()).or_else(|| fused::fma(ins.mnemonic()).map(|fma| fma.ty))
}

/// Scalar SSE instructions lifted here, with the type of the value they produce.
const fn scalar_float(mnemonic: Mnemonic) -> Option<&'static str> {
    match legacy(mnemonic) {
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
        | Mnemonic::Roundsd
        | Mnemonic::Cvtss2sd => Some(F64),
        Mnemonic::Addss
        | Mnemonic::Subss
        | Mnemonic::Mulss
        | Mnemonic::Divss
        | Mnemonic::Sqrtss
        | Mnemonic::Maxss
        | Mnemonic::Minss
        | Mnemonic::Cvtsi2ss
        | Mnemonic::Cvttss2si
        | Mnemonic::Roundss
        | Mnemonic::Ucomiss
        | Mnemonic::Comiss
        | Mnemonic::Cvtsd2ss => Some(F32),
        _ => None,
    }
}

/// A 128-bit `xmm` operand; `ymm`/`zmm` vector work is not scalar float.
pub fn is_xmm_register(register: Register) -> bool {
    register.is_xmm()
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

fn special_literal(nan: bool, infinite: bool, negative: bool) -> Option<String> {
    match (nan, infinite, negative) {
        (true, _, _) => Some("NAN".to_owned()),
        (false, true, false) => Some("INFINITY".to_owned()),
        (false, true, true) => Some("-INFINITY".to_owned()),
        _ => None,
    }
}

fn double_literal(bits: u64) -> String {
    let value = f64::from_bits(bits);
    special_literal(value.is_nan(), value.is_infinite(), value < 0.0).unwrap_or_else(|| format!("{value:?}"))
}

fn float_literal(bits: u32) -> String {
    let value = f32::from_bits(bits);
    special_literal(value.is_nan(), value.is_infinite(), value < 0.0).unwrap_or_else(|| format!("{value:?}f"))
}

fn expression(mnemonic: Mnemonic, left: &str, right: &str, source_bits: u32, dest_bits: u32) -> Option<String> {
    Some(match mnemonic {
        Mnemonic::Movsd | Mnemonic::Movss | Mnemonic::Movapd => right.to_owned(),
        Mnemonic::Addsd | Mnemonic::Addss => format!("({left} + {right})"),
        Mnemonic::Subsd | Mnemonic::Subss => format!("({left} - {right})"),
        Mnemonic::Mulsd | Mnemonic::Mulss => format!("({left} * {right})"),
        Mnemonic::Divsd | Mnemonic::Divss => format!("({left} / {right})"),
        Mnemonic::Sqrtsd => format!("sqrt({right})"),
        Mnemonic::Sqrtss => format!("sqrtf({right})"),
        // Intel MAXSD/MINSD return the source operand for equal values and unordered inputs.
        Mnemonic::Maxsd | Mnemonic::Maxss => format!("({left} > {right} ? {left} : {right})"),
        Mnemonic::Minsd | Mnemonic::Minss => format!("({left} < {right} ? {left} : {right})"),
        Mnemonic::Cvtsi2sd => format!("(f64)(i{source_bits})({right})"),
        Mnemonic::Cvtsi2ss => format!("(f32)(i{source_bits})({right})"),
        Mnemonic::Cvtss2sd => format!("(f64)({right})"),
        Mnemonic::Cvtsd2ss => format!("(f32)({right})"),
        Mnemonic::Cvttsd2si | Mnemonic::Cvttss2si => {
            format!("(i{dest_bits})({right}) /* truncates toward zero; NaN/out-of-range yields i{dest_bits}_min */")
        }
        _ => return None,
    })
}

fn write_float(state: &mut State, ins: &Instruction, block: &mut crate::cfg::Block, expression: &str, ty: &str) {
    let register = ins.op0_register().full_register();
    let name = format!("fp_{:x}", ins.ip());
    block.stmts.push(format!("{ty} {name} = {expression};"));
    state.inline_regs.remove(&register);
    state.rodata_ptrs.remove(&register);
    state.set_reg(register, name);
    let _ = state.reg(register);
}

/// Width of a floating-point memory source that may be a read-only constant.
fn constant_width(mnemonic: Mnemonic) -> Option<&'static str> {
    if let Some(fma) = fused::fma(mnemonic) {
        return Some(fma.ty);
    }
    match legacy(mnemonic) {
        Mnemonic::Cvtsi2sd | Mnemonic::Cvtsi2ss | Mnemonic::Movapd => None,
        Mnemonic::Movss | Mnemonic::Ucomiss | Mnemonic::Comiss | Mnemonic::Roundss => Some(F32),
        Mnemonic::Roundsd => Some(F64),
        m => scalar_float(m).and_then(|_| read_width(m)),
    }
}

fn operand(image: &Image, ins: &Instruction, index: u32, operand: String) -> String {
    let Some(width) = constant_width(ins.mnemonic()) else { return operand };
    if index != constant_source(ins) || ins.op_kind(index) != OpKind::Memory {
        return operand;
    }
    let address = if ins.is_ip_rel_memory_operand() {
        Some(ins.ip_rel_memory_address())
    } else if ins.memory_base() == Register::None && ins.memory_index() == Register::None {
        Some(ins.memory_displacement64())
    } else {
        None
    };
    if width == F32 {
        let constant = address.and_then(|va| read_only_bytes(image, va, 4)).and_then(|b| b.try_into().ok());
        return constant.map_or_else(
            || operand.strip_prefix("*(u64 *)").map_or_else(|| operand.clone(), |rest| format!("*(f32 *){rest}")),
            |bytes| float_literal(u32::from_le_bytes(bytes)),
        );
    }
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
    let mnemonic = legacy(ins.mnemonic());
    // `vmovss dst, merge, src` takes the scalar from `src`; the two-operand `movss` forms are moves.
    let Some(ty) = lifted_type(ins) else { return false };
    if (0..ins.op_count()).any(|i| ins.op_kind(i) == OpKind::Register && ins.op_register(i).size() > 16) {
        // `vmovapd ymm0, ymm1`, packed AVX work: not a scalar.
        return false;
    }
    if mnemonic == Mnemonic::Movapd && (ins.op0_kind() != OpKind::Register || ins.op1_kind() != OpKind::Register) {
        return false;
    }
    if let Some(fma) = fused::fma(ins.mnemonic()) {
        let [a, b, c] = fma.order.map(|index| ctx.op(state, ins, index));
        write_float(state, ins, block, &fma.expression([&a, &b, &c]), ty);
        return true;
    }
    let (left_index, right_index) = sources(ins);
    // A merge operand only supplies upper lanes: reading it would mark a register used.
    let left = if binary(mnemonic) { ctx.op(state, ins, left_index) } else { String::new() };
    let right = ctx.op(state, ins, right_index);
    if matches!(mnemonic, Mnemonic::Ucomisd | Mnemonic::Comisd | Mnemonic::Ucomiss | Mnemonic::Comiss) {
        state.flags = Some(Flags::float_cmp(left, right));
        return true;
    }
    if matches!(mnemonic, Mnemonic::Roundsd | Mnemonic::Roundss) {
        let rounded = fused::rounding(ins, mnemonic == Mnemonic::Roundss, &right);
        write_float(state, ins, block, &rounded, ty);
        return true;
    }
    let source_bits = u32::try_from(if ins.op_kind(right_index) == OpKind::Memory {
        ins.memory_size().size() * 8
    } else {
        ins.op_register(right_index).size() * 8
    })
    .unwrap_or(64);
    let dest_bits = u32::try_from(if ins.op0_kind() == OpKind::Register { ins.op0_register().size() * 8 } else { 64 })
        .unwrap_or(64);
    let Some(expression) = expression(mnemonic, &left, &right, source_bits, dest_bits) else { return false };
    if mnemonic == Mnemonic::Movsd && ins.op0_kind() != OpKind::Register {
        return false;
    }
    if ins.op0_kind() == OpKind::Register && is_xmm_register(ins.op0_register()) {
        write_float(state, ins, block, &expression, ty);
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

mod fused;
mod u64_idiom;
pub use u64_idiom::step_u64_conversion_idiom;

/// Adds `f64 zmmN;` (`f32` when every lifted use is single precision) for xmm registers used by
/// lifted scalar instructions, except float parameter registers (`homes`) and names already in `decls`.
pub fn merge_declarations(ssa: &SsaCfg, homes: &[(Register, String)], decls: &mut Vec<String>) {
    let mut registers: std::collections::BTreeMap<String, bool> = std::collections::BTreeMap::new();
    for ins in &ssa.insns {
        let Some(result) = lifted_type(ins) else { continue };
        let fma = fused::fma(ins.mnemonic()).is_some();
        // The upper-lane merge operand of a single-source VEX form holds no scalar value.
        let merge = (!fma && !binary(legacy(ins.mnemonic())) && sources(ins) == (1, 2)).then_some(1);
        for operand in 0..ins.op_count() {
            let register = ins.op_register(operand);
            if ins.op_kind(operand) != OpKind::Register
                || Some(operand) == merge
                || !is_xmm_register(register)
                || homes.iter().any(|(home, _)| *home == register.full_register())
            {
                continue;
            }
            let width = if operand == 0 || fma { result } else { read_width(ins.mnemonic()).unwrap_or(F64) };
            *registers.entry(reg_name(register)).or_insert(true) &= width == F32;
        }
    }
    for (name, single) in registers {
        let declared = decls
            .iter()
            .any(|line| line.split_whitespace().nth(1).is_some_and(|declared| declared.trim_end_matches(';') == name));
        if !declared {
            decls.push(format!("  {} {name};", if single { F32 } else { F64 }));
        }
    }
}

#[cfg(test)]
mod tests;
