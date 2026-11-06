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

/// Scalar SSE instructions lifted here, with the type of the value they produce.
const fn scalar_float(mnemonic: Mnemonic) -> Option<&'static str> {
    match mnemonic {
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
        | Mnemonic::Cvtsd2ss => Some(F32),
        _ => None,
    }
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
        Mnemonic::Movsd | Mnemonic::Movapd => right.to_owned(),
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
    match mnemonic {
        Mnemonic::Cvtsi2sd | Mnemonic::Cvtsi2ss | Mnemonic::Movapd => None,
        Mnemonic::Movss | Mnemonic::Ucomiss | Mnemonic::Comiss => Some(F32),
        m => scalar_float(m).and_then(|_| read_width(m)),
    }
}

fn operand(image: &Image, ins: &Instruction, index: u32, operand: String) -> String {
    let Some(width) = constant_width(ins.mnemonic()) else { return operand };
    if index != 1 || ins.op_kind(index) != OpKind::Memory {
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
    let mnemonic = ins.mnemonic();
    let Some(ty) = scalar_float(mnemonic) else { return false };
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

mod u64_idiom;
pub use u64_idiom::step_u64_conversion_idiom;

/// Adds `f64 zmmN;` (`f32` when every lifted use is single precision) for xmm registers used by
/// lifted scalar instructions, except float parameter registers (`homes`) and names already in `decls`.
pub fn merge_declarations(ssa: &SsaCfg, homes: &[(Register, String)], decls: &mut Vec<String>) {
    let mut registers: std::collections::BTreeMap<String, bool> = std::collections::BTreeMap::new();
    for ins in &ssa.insns {
        let Some(result) = scalar_float(ins.mnemonic()) else { continue };
        for operand in 0..ins.op_count() {
            let register = ins.op_register(operand);
            if ins.op_kind(operand) != OpKind::Register
                || !is_xmm_register(register)
                || homes.iter().any(|(home, _)| *home == register.full_register())
            {
                continue;
            }
            let width = if operand == 0 { result } else { read_width(ins.mnemonic()).unwrap_or(F64) };
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
