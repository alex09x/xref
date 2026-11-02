/*
 * XRef Code — evidence-producing binary analysis
 * Copyright (c) 2026 Alexander Panasenko
 * Contact: alex@prod.codes
 * Author: https://prod.codes/about/
 * Project: https://github.com/alex09x/xref
 * SPDX-License-Identifier: MIT OR Apache-2.0
 */
use super::facts::{State, reg_index};
use iced_x86::{Instruction, Mnemonic, OpKind, Register};

#[cfg(test)]
mod tests;

#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) enum Origin {
    Address { register: usize, displacement: i64 },
    Loaded { register: usize, displacement: i64, width: usize, load_ip: u64 },
}

/// Effective address relative to a full-width entry register, without a dynamic index.
pub(super) fn memory_origin(ins: &Instruction, input: &State) -> Option<(Origin, usize)> {
    if !(0..ins.op_count()).any(|i| ins.op_kind(i) == OpKind::Memory) {
        return None;
    }
    if ins.is_ip_rel_memory_operand() {
        return None;
    }
    if matches!(ins.segment_prefix(), Register::FS | Register::GS) {
        return None;
    }
    if ins.memory_index() != Register::None {
        return None;
    }
    let base = ins.memory_base();
    if base.size() != 8 {
        return None;
    }
    let base_idx = reg_index(base)?;
    let base_fact = &input[base_idx];
    let &Origin::Address { register, displacement: base_disp } = base_fact.origin.as_ref()? else {
        return None;
    };
    let ins_disp = ins.memory_displacement64().cast_signed();
    let displacement = base_disp.checked_add(ins_disp)?;
    Some((Origin::Address { register, displacement }, base_idx))
}

/// Exact address or unmodified loaded-value provenance for the written GPR.
pub(super) fn derive(ins: &Instruction, input: &State) -> Option<(Origin, usize)> {
    let dst = ins.op0_register();
    let dst_size = dst.size();
    match ins.mnemonic() {
        Mnemonic::Mov
            if ins.op0_kind() == OpKind::Register
                && dst_size == 8
                && ins.op1_kind() == OpKind::Register
                && ins.op1_register().size() == 8 =>
        {
            let src_idx = reg_index(ins.op1_register())?;
            let origin = input[src_idx].origin.clone()?;
            Some((origin, src_idx))
        }
        Mnemonic::Lea if ins.op0_kind() == OpKind::Register && dst_size == 8 => memory_origin(ins, input),
        Mnemonic::Add | Mnemonic::Sub if ins.op0_kind() == OpKind::Register && dst_size == 8 => {
            if !matches!(
                ins.op1_kind(),
                OpKind::Immediate8
                    | OpKind::Immediate32
                    | OpKind::Immediate64
                    | OpKind::Immediate8to64
                    | OpKind::Immediate32to64
            ) {
                return None;
            }
            let dst_idx = reg_index(dst)?;
            let &Origin::Address { register, displacement: base_disp } = input[dst_idx].origin.as_ref()? else {
                return None;
            };
            let delta = ins.immediate(1).cast_signed();
            let displacement = if ins.mnemonic() == Mnemonic::Add {
                base_disp.checked_add(delta)?
            } else {
                base_disp.checked_sub(delta)?
            };
            Some((Origin::Address { register, displacement }, dst_idx))
        }
        Mnemonic::Mov
            if ins.op0_kind() == OpKind::Register
                && (dst_size == 4 || dst_size == 8)
                && ins.op1_kind() == OpKind::Memory =>
        {
            let (mem_origin, src_idx) = memory_origin(ins, input)?;
            let Origin::Address { register, displacement } = mem_origin else {
                return None;
            };
            let width = dst_size;
            let load_ip = ins.ip();
            Some((Origin::Loaded { register, displacement, width, load_ip }, src_idx))
        }
        _ => None,
    }
}
