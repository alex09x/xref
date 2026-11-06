/*
 * xref — Ultra blazing fast cross-references of an x86-64 ELF binary
 * Copyright (c) 2026 Alexander Panasenko
 *
 * Contact: alex@prod.codes
 * Author: https://prod.codes/about/
 * Project: https://github.com/alex09x/xref
 * SPDX-License-Identifier: MIT OR Apache-2.0
 */

//! Stack bookkeeping instructions (prologue pushes, `rsp` adjustments) and register/memory moves.

use std::fmt::Write;

use iced_x86::{Instruction, Mnemonic, OpKind, Register};

use super::{FnCtx, assign};
use crate::cfg::Block;
use crate::expr::{CALLEE_SAVED, IGNORED, State};
use crate::source::location_at;

pub(super) fn step_stack(ctx: &FnCtx<'_>, state: &mut State, instruction: &Instruction) -> bool {
    let mnemonic = instruction.mnemonic();
    let dst = instruction.op0_register().full_register();
    if IGNORED.contains(&mnemonic)
        || (mnemonic == Mnemonic::Mov
            && dst == Register::RBP
            && instruction.op1_register().full_register() == Register::RSP)
    {
        return true;
    }
    if mnemonic == Mnemonic::Pop || (matches!(mnemonic, Mnemonic::Add | Mnemonic::Sub) && dst == Register::RSP) {
        state.in_prologue = false;
        state.pushed.clear();
        return true;
    }
    if mnemonic == Mnemonic::Push {
        if !(state.in_prologue
            && instruction.op0_kind() == OpKind::Register
            && (CALLEE_SAVED.contains(&dst) || dst == Register::RAX))
        {
            state.in_prologue = false;
            let val = ctx.op(state, instruction, 0);
            state.pushed.push(val);
        }
        return true;
    }
    state.in_prologue = false;
    false
}

/// `*(f64 *)` / `*(f32 *)` for the destination of a scalar SSE store (`movsd`/`movss` to memory).
pub(super) fn sse_store_lhs(instruction: &Instruction, lhs: String) -> String {
    let ty = match instruction.mnemonic() {
        Mnemonic::Movsd | Mnemonic::Vmovsd => "f64",
        Mnemonic::Movss | Mnemonic::Vmovss => "f32",
        _ => return lhs,
    };
    if instruction.op0_kind() != OpKind::Memory
        || instruction.op1_kind() != OpKind::Register
        || !crate::float_alu::is_xmm_register(instruction.op1_register())
    {
        return lhs;
    }
    lhs.strip_prefix("*(u64 *)")
        .map(|rest| format!("*({ty} *){rest}"))
        .or_else(|| lhs.strip_prefix("((u64 *)").map(|rest| format!("(({ty} *){rest}")))
        .unwrap_or(lhs)
}

pub(super) fn step_move(
    ctx: &FnCtx<'_>,
    state: &mut State,
    ins: &Instruction,
    ins_idx: usize,
    dst_reg: Option<Register>,
    block: &mut Block,
) {
    let src_ro = (ins.mnemonic() == Mnemonic::Mov && ins.op1_kind() == OpKind::Register)
        .then(|| state.rodata_ptrs.get(&ins.op1_register().full_register()).copied())
        .flatten();
    let (rhs, prev_len) = (ctx.op(state, ins, 1), block.stmts.len());
    let _ = assign(ctx, state, ins, ins_idx, rhs, &mut block.stmts);
    if let (Some(r), Some(place)) = (dst_reg, src_ro) {
        state.rodata_ptrs.insert(r, place);
    } else if ins.mnemonic() == Mnemonic::Lea && ins.is_ip_rel_memory_operand() {
        let place = ins.ip_rel_memory_address();
        if location_at(ctx.locations, place).is_none()
            && ctx.image.function_at(place).is_none()
            && ctx.image.slot(place).is_none()
        {
            if let Some(r) = dst_reg {
                state.rodata_ptrs.insert(r, place);
            }
            if block.stmts.len() > prev_len
                && let Some((preview, false)) = ctx.image.rodata_preview(place)
                && let Some(last) = block.stmts.last_mut()
            {
                let short = if preview.len() > 32 { format!("{}...", &preview[..32]) } else { preview };
                let _ = write!(last, " /* rodata preview: {short:?} */");
            }
        }
    }
}
