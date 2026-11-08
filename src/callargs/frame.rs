/*
 * XRef — Stack-frame state for following an argument through a function
 * Copyright (c) 2026 Alexander Panasenko
 * Contact: alex@prod.codes
 * Author: https://prod.codes/about/
 * Project: https://github.com/alex09x/xref
 * SPDX-License-Identifier: MIT OR Apache-2.0
 */

//! Offsets are relative to `rsp` at the function's entry. [`Held`] is where the followed value may
//! be at one point (registers and spill slots); [`FrameUse`] is what the whole function does with
//! its frame (reads and addresses taken), which tells a spill from a field of an object built on
//! the stack.

use std::collections::BTreeMap;

use iced_x86::{Instruction, InstructionInfoFactory, Mnemonic, OpAccess, OpKind, Register};

/// Where the value may be at a point of the function.
#[derive(Clone, PartialEq, Eq)]
pub struct Held {
    /// General-purpose registers holding it, as a `flow::bit` mask.
    pub regs: u16,
    /// `rsp` relative to its value at entry, while every path agrees on it.
    pub frame: Option<i64>,
    /// Spill slots holding it: entry-relative stack offset → bytes written there.
    pub spills: BTreeMap<i64, u64>,
}

impl Held {
    pub const fn entry(regs: u16) -> Self {
        Self { regs, frame: Some(0), spills: BTreeMap::new() }
    }

    /// Joins `other` into `self`; true when `self` grew.
    pub fn join(&mut self, other: &Self) -> bool {
        let before = self.clone();
        self.regs |= other.regs;
        if self.frame == other.frame {
            for (offset, size) in &other.spills {
                // The wider write, so that a later partial overwrite of its upper bytes drops it.
                self.spills.entry(*offset).and_modify(|known| *known = (*known).max(*size)).or_insert(*size);
            }
        } else {
            // Paths disagree on the frame: the slots no longer line up.
            self.lose_frame();
        }
        *self != before
    }

    pub fn lose_frame(&mut self) {
        self.frame = None;
        self.spills.clear();
    }

    /// The slot `[rsp + displacement]` of `ins` as an entry-relative offset.
    pub fn slot(&self, ins: &Instruction) -> Option<i64> {
        self.frame.and_then(|frame| frame.checked_add(ins.memory_displacement64().cast_signed()))
    }

    /// Forgets the spills `[offset, offset + size)` overlaps.
    pub fn overwrite(&mut self, offset: i64, size: u64) {
        let end = offset.saturating_add_unsigned(size);
        self.spills.retain(|start, len| start.saturating_add_unsigned(*len) <= offset || *start >= end);
    }

    /// A call pushes its return address and runs the callee's frame below `rsp`: slots there are gone.
    pub fn after_call(&mut self) {
        if let Some(frame) = self.frame {
            self.spills.retain(|offset, _| *offset >= frame);
        }
    }
}

/// How the function uses its frame, over every path.
#[derive(Default)]
pub struct FrameUse {
    /// `[rsp+d]` ranges read (explicitly, by `pop`, or as a source of any instruction).
    reads: Vec<(i64, u64)>,
    /// A frame read the walk cannot place: indexed (`[rsp + rcx]`) or after the frame was lost.
    unplaced_read: bool,
    /// Frame addresses taken: `lea reg, [rsp + d]`, `mov reg, rsp`.
    anchors: Vec<i64>,
}

impl FrameUse {
    /// Records the frame reads and the frame addresses `ins` takes, with the frame before it.
    pub fn record(&mut self, ins: &Instruction, held: &Held, factory: &mut InstructionInfoFactory) {
        let to_other = ins.op_count() == 2
            && ins.op0_kind() == OpKind::Register
            && ins.op0_register().full_register() != Register::RSP;
        if to_other && ins.mnemonic() == Mnemonic::Lea && ins.memory_base() == Register::RSP {
            if ins.memory_index() == Register::None
                && let Some(slot) = held.slot(ins)
            {
                self.anchors.push(slot);
            }
            return;
        }
        if to_other
            && ins.mnemonic() == Mnemonic::Mov
            && ins.op1_kind() == OpKind::Register
            && ins.op1_register() == Register::RSP
            && let Some(frame) = held.frame
        {
            self.anchors.push(frame);
        }
        for used in factory.info(ins).used_memory() {
            if used.base() != Register::RSP
                || !matches!(used.access(), OpAccess::Read | OpAccess::CondRead | OpAccess::ReadWrite | OpAccess::ReadCondWrite)
            {
                continue;
            }
            let size = used.memory_size().size().max(1) as u64;
            match held.frame.and_then(|frame| frame.checked_add(used.displacement().cast_signed())) {
                Some(slot) if used.index() == Register::None => self.reads.push((slot, size)),
                _ => self.unplaced_read = true,
            }
        }
        if ins.mnemonic() == Mnemonic::Pop
            && let Some(frame) = held.frame
        {
            self.reads.push((frame, 8));
        }
    }

    /// A `width`-byte store at `slot` is a field of an object built on the stack: the function
    /// never reads those bytes back (not a spill) and takes a frame address at or below them (it
    /// can hand the object out by pointer or copy it; an outgoing stack argument has no such
    /// address).
    pub fn stack_object(&self, slot: i64, width: u64) -> bool {
        let end = slot.saturating_add_unsigned(width);
        !self.unplaced_read
            && !self.reads.iter().any(|&(at, size)| at < end && slot < at.saturating_add_unsigned(size))
            && self.anchors.iter().any(|&anchor| anchor <= slot)
    }
}
