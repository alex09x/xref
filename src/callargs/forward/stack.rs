/*
 * XRef — Stack-frame steps of the argument walk: reloads, frame writes and rsp moves
 * Copyright (c) 2026 Alexander Panasenko
 * Contact: alex@prod.codes
 * Author: https://prod.codes/about/
 * Project: https://github.com/alex09x/xref
 * SPDX-License-Identifier: MIT OR Apache-2.0
 */

use iced_x86::{Instruction, InstructionInfoFactory, Mnemonic, OpKind, Register};

use super::Walk;
use crate::callargs::flow::{bit, high_byte, written};
use crate::callargs::frame::Held;

impl Walk<'_> {
    /// The register `ins` loads the value into: a wide-enough copy of a holding register, or a
    /// reload of a spill slot.
    pub(super) fn gained(&self, ins: &Instruction, held: &Held) -> u16 {
        if !matches!(ins.mnemonic(), Mnemonic::Mov | Mnemonic::Movzx | Mnemonic::Movsx | Mnemonic::Movsxd)
            || ins.op0_kind() != OpKind::Register
            || high_byte(ins.op0_register())
            || ins.op0_register().size() < self.width
        {
            return 0;
        }
        let source = match ins.op1_kind() {
            OpKind::Register => self.holds(ins.op1_register(), held),
            OpKind::Memory => {
                held.on_frame(ins)
                    && ins.memory_size().size() >= self.width
                    && held.slot(ins).is_some_and(|slot| held.spills.contains_key(&slot))
            }
            _ => false,
        };
        if source { bit(ins.op0_register()).unwrap_or(0) } else { 0 }
    }

    /// Stack writes: a spill of the value adds a slot, any other write over a slot drops it.
    pub(super) fn frame_writes(&self, ins: &Instruction, held: &mut Held, memory: bool) {
        if matches!(ins.op0_kind(), OpKind::MemoryESDI | OpKind::MemoryESEDI | OpKind::MemoryESRDI) {
            // `stos`/`movs` may write the frame.
            held.spills.clear();
            return;
        }
        // A store through a base that may be a frame address (an unplaced `rbp` after `and rsp,
        // -32`) may write over any slot.
        if !memory || !held.may_be_frame(ins) {
            return;
        }
        if ins.memory_index() != Register::None {
            held.spills.clear();
            return;
        }
        // `[rsp+d]` with `rsp` unknown may write over any slot.
        let Some(slot) = held.slot(ins) else {
            held.spills.clear();
            return;
        };
        let size = ins.memory_size().size().max(1) as u64;
        held.overwrite(slot, size);
        if ins.mnemonic() == Mnemonic::Mov && ins.op1_kind() == OpKind::Register && self.holds(ins.op1_register(), held)
        {
            held.spills.insert(slot, size);
        }
    }

    /// Moves of `rsp`: `push`/`pop` (a pushed holding register is a spill, a pop of one a
    /// reload), `sub`/`add rsp, imm`. `and rsp, -align` loses `rsp` but keeps a bound on it (it only
    /// moves down); any other write (`pop rsp`) loses both.
    pub(super) fn frame_moves(&self, ins: &Instruction, held: &mut Held, factory: &mut InstructionInfoFactory) {
        let step = i64::from(ins.stack_pointer_increment());
        let immediate = ins.op_count() == 2
            && ins.op0_kind() == OpKind::Register
            && ins.op0_register() == Register::RSP
            && matches!(ins.op1_kind(), OpKind::Immediate8to64 | OpKind::Immediate32to64);
        let pops_rsp = ins.op_count() == 1
            && ins.op0_kind() == OpKind::Register
            && ins.op0_register().full_register() == Register::RSP;
        let moved = match ins.mnemonic() {
            Mnemonic::Sub if immediate => ins.immediate(1).cast_signed().checked_neg(),
            Mnemonic::Add if immediate => Some(ins.immediate(1).cast_signed()),
            Mnemonic::Push | Mnemonic::Pop if step != 0 && !pops_rsp => Some(step),
            Mnemonic::And if immediate && ins.immediate(1).cast_signed() < 0 => {
                held.frame = None;
                return;
            }
            _ if pops_rsp || written(factory, ins).contains(&Register::RSP) => None,
            _ => return,
        };
        let Some(after) = held.frame.zip(moved).and_then(|(frame, moved)| frame.checked_add(moved)) else {
            // A `push` with `rsp` unknown writes a slot that cannot be placed; a constant move
            // shifts the bound on `rsp`.
            if ins.mnemonic() == Mnemonic::Push {
                held.spills.clear();
            }
            // Only a move down keeps a bound: one up (a `pop` loop) would raise it on every pass
            // and the fixpoint would never settle.
            let upper = moved.filter(|&moved| moved <= 0).and_then(|moved| held.upper?.checked_add(moved));
            held.lose_frame();
            held.upper = upper;
            return;
        };
        let before = held.frame.unwrap_or_default();
        match ins.mnemonic() {
            Mnemonic::Push => {
                held.overwrite(after, step.unsigned_abs());
                if ins.op0_kind() == OpKind::Register && step == -8 && self.holds(ins.op0_register(), held) {
                    held.spills.insert(after, 8);
                }
            }
            Mnemonic::Pop if ins.op0_kind() == OpKind::Register && step == 8 && held.spills.contains_key(&before) => {
                held.regs |= bit(ins.op0_register()).unwrap_or(0);
            }
            _ => {}
        }
        held.set_frame(Some(after));
    }
}

/// `rsp` set back from a frame pointer: the frame it gets, `None` when the pointer's frame address is
/// unknown.
pub(super) struct Restored(pub(super) Option<i64>);

/// `leave` (`mov rsp, rbp; pop rbp`), `mov rsp, reg` or `lea rsp, [rbp-d]` (the epilogue of an aligned
/// frame that saved registers below `rbp`), read before `ins` writes anything.
pub(super) fn restored_rsp(ins: &Instruction, held: &Held) -> Option<Restored> {
    match ins.mnemonic() {
        Mnemonic::Leave => Some(Restored(held.addrs.get(&Register::RBP).and_then(|rbp| rbp.checked_add(8)))),
        Mnemonic::Mov
            if ins.op_count() == 2
                && ins.op0_kind() == OpKind::Register
                && ins.op0_register() == Register::RSP
                && ins.op1_kind() == OpKind::Register =>
        {
            Some(Restored(held.addrs.get(&ins.op1_register().full_register()).copied()))
        }
        Mnemonic::Lea if ins.op0_register() == Register::RSP && ins.memory_base() != Register::RSP => {
            Some(Restored(held.on_frame(ins).then(|| held.slot(ins)).flatten()))
        }
        _ => None,
    }
}
