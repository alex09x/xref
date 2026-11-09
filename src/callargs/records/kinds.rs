/*
 * XRef — What the registers hold while walking fixed-size records: scaled indexes and elements
 * Copyright (c) 2026 Alexander Panasenko
 * Contact: alex@prod.codes
 * Author: https://prod.codes/about/
 * Project: https://github.com/alex09x/xref
 * SPDX-License-Identifier: MIT OR Apache-2.0
 */

//! A register is a scaled index once `imul reg, x, stride` (or `shl reg, log2(stride)`) writes it,
//! and an element address once a scaled index is added to a base. An element register has a
//! phase: the byte of the record it points at, modulo the record size (`lea r13, [rbx-0x2c0]`
//! with `rbx` at an element is 8 into one). These are must-facts over every path into a block.

use iced_x86::{Instruction, Mnemonic, OpKind, Register};

use crate::callargs::flow::{Join, bit};

/// What is known about the registers before an instruction.
#[derive(Clone, Copy, Default, PartialEq, Eq)]
pub(super) struct Kinds {
    /// An index scaled by the record size (`imul rax, rcx, 0x2c8`, `shl rax, 9`): a byte offset,
    /// not yet an address.
    pub scaled: u16,
    /// An element address.
    pub elements: u16,
    /// For each element register (by `flow::GPRS` index), the byte of the record it points at.
    phase: [u64; 16],
}

impl Join for Kinds {
    /// Keeps what every path agrees on: the same kind, and for an element the same phase.
    fn join(&mut self, other: &Self) -> bool {
        let before = *self;
        self.scaled &= other.scaled;
        let same = (0..16).filter(|&i| self.phase[i] == other.phase[i]).fold(0u16, |mask, i| mask | (1 << i));
        self.elements &= other.elements & same;
        *self != before
    }
}

impl Kinds {
    pub fn is(mask: u16, register: Register) -> bool {
        bit(register).is_some_and(|b| mask & b != 0)
    }

    /// The phase of an element register.
    pub fn phase_of(&self, register: Register) -> Option<u64> {
        let b = bit(register)?;
        (self.elements & b != 0).then(|| self.phase[b.trailing_zeros() as usize])
    }

    pub fn set_element(&mut self, register: Register, phase: u64) {
        if let Some(b) = bit(register) {
            self.elements |= b;
            self.phase[b.trailing_zeros() as usize] = phase;
        }
    }

    pub fn drop_register(&mut self, register: Register) {
        let b = bit(register).unwrap_or(0);
        self.scaled &= !b;
        self.elements &= !b;
    }

    /// Records what `ins` makes of its destination, after its writes were dropped.
    pub fn gain(&mut self, ins: &Instruction, gain: Gain) {
        match gain {
            Gain::Scaled => self.scaled |= bit(ins.op0_register()).unwrap_or(0),
            Gain::Element(phase) => self.set_element(ins.op0_register(), phase),
            Gain::Nothing => {}
        }
    }
}

/// `[element + displacement]` with the element at `phase` is the field at `offset`: in this
/// element, or in the one before (a pointer already stepped past it).
pub(super) fn at_field(phase: u64, displacement: i64, offset: u64, stride: u64) -> bool {
    let at = i128::from(phase) + i128::from(displacement);
    at == i128::from(offset) || at == i128::from(offset) - i128::from(stride)
}

/// `(phase + by) mod stride`, for a step of at most a record.
pub(super) fn shifted(phase: u64, by: i64, stride: u64) -> Option<u64> {
    let stride = i128::from(stride);
    (stride > 0 && i128::from(by).abs() <= stride)
        .then(|| u64::try_from((i128::from(phase) + i128::from(by)).rem_euclid(stride)).ok())
        .flatten()
}

/// What an instruction makes of its 64-bit destination register.
#[derive(Clone, Copy)]
pub(super) enum Gain {
    Nothing,
    Scaled,
    Element(u64),
}

/// What `ins` makes of its destination: a scaled index (`imul reg, x, stride`, `shl reg,
/// log2(stride)`), or an element address (a scaled index added to a base by `add`/`lea`, a copy of
/// one, or one moved by at most a record: `lea r13, [rbx-0x2c0]`, `add rbx, 0x2c8`).
pub(super) fn gained(ins: &Instruction, stride: u64, now: &Kinds) -> Gain {
    if ins.op_count() == 0
        || ins.op0_kind() != OpKind::Register
        || ins.op0_register().size() != 8
        || matches!(ins.op0_register(), Register::RSP | Register::RBP)
    {
        return Gain::Nothing;
    }
    let scaled = |r: Register| Kinds::is(now.scaled, r);
    let phase = |r: Register| now.phase_of(r);
    let source = (ins.op_count() > 1 && ins.op1_kind() == OpKind::Register).then(|| ins.op1_register());
    let element = |phase: Option<u64>| phase.map_or(Gain::Nothing, Gain::Element);
    match ins.mnemonic() {
        Mnemonic::Imul if ins.op_count() == 3 && ins.immediate(2) == stride => Gain::Scaled,
        // A power-of-two record size scales the index with a shift: `shl rdi, 9` for 0x200.
        Mnemonic::Shl
            if stride.is_power_of_two()
                && ins.op1_kind() == OpKind::Immediate8
                && ins.immediate(1) == u64::from(stride.trailing_zeros()) =>
        {
            Gain::Scaled
        }
        Mnemonic::Mov if source.is_some_and(scaled) => Gain::Scaled,
        Mnemonic::Mov => element(source.and_then(phase)),
        // `add rbx, 0x2c8`: the element moved by a constant.
        Mnemonic::Add if matches!(ins.op1_kind(), OpKind::Immediate8to64 | OpKind::Immediate32to64) => {
            element(phase(ins.op0_register()).and_then(|p| shifted(p, ins.immediate(1).cast_signed(), stride)))
        }
        // `add rdi, [vec.ptr]`, `add rax, rbx`: a scaled index plus a base (an element, or a plain
        // pointer at an element's start); any other offset leaves no element.
        Mnemonic::Add => {
            let destination = ins.op0_register();
            match (scaled(destination), source) {
                // Scaled index plus a base in memory or a register.
                (true, None) if ins.op1_kind() == OpKind::Memory => Gain::Element(0),
                (true, Some(other)) if !scaled(other) => Gain::Element(phase(other).unwrap_or(0)),
                // A base plus a scaled index.
                (false, Some(other)) if scaled(other) => Gain::Element(phase(destination).unwrap_or(0)),
                _ => Gain::Nothing,
            }
        }
        Mnemonic::Lea => {
            let (base, index) = (ins.memory_base(), ins.memory_index());
            let displacement = ins.memory_displacement64().cast_signed();
            if index == Register::None {
                return element(phase(base).and_then(|p| shifted(p, displacement, stride)));
            }
            if base == Register::None || ins.memory_index_scale() != 1 || displacement != 0 {
                return Gain::Nothing;
            }
            // `lea rdi, [base + scaled index]`: the base is the array's (an element, or a plain
            // pointer at an element's start).
            match (scaled(base), scaled(index)) {
                (true, false) => Gain::Element(phase(index).unwrap_or(0)),
                (false, true) => Gain::Element(phase(base).unwrap_or(0)),
                _ => Gain::Nothing,
            }
        }
        _ => Gain::Nothing,
    }
}
