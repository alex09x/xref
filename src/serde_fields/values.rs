/*
 * XRef — Bounded input-relative values and stack-spill facts
 * Copyright (c) 2026 Alexander Panasenko
 * Contact: alex@prod.codes
 * Author: https://prod.codes/about/
 * Project: https://github.com/alex09x/xref
 * SPDX-License-Identifier: MIT OR Apache-2.0
 */
use crate::expr::ABI_ARGS;
use iced_x86::{Instruction, OpKind, Register};
use std::collections::BTreeMap;

const REGISTERS: [Register; 16] = [
    Register::RAX,
    Register::RCX,
    Register::RDX,
    Register::RBX,
    Register::RSP,
    Register::RBP,
    Register::RSI,
    Register::RDI,
    Register::R8,
    Register::R9,
    Register::R10,
    Register::R11,
    Register::R12,
    Register::R13,
    Register::R14,
    Register::R15,
];
pub(super) const MAX_SPILLS: usize = 128;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Value {
    Input {
        argument: usize,
        offset: i64,
    },
    Loaded {
        argument: usize,
        offset: i64,
        width: usize,
    },
    Constant(u64),
    Stack(i64),
    /// Storage origin only: the contents may have changed. This is NOT object/value identity.
    StackCell(i64),
}

impl Value {
    pub fn add(self, displacement: i64) -> Option<Self> {
        match self {
            Self::Input { argument, offset } => {
                offset.checked_add(displacement).map(|offset| Self::Input { argument, offset })
            }
            Self::Stack(offset) => offset.checked_add(displacement).map(Self::Stack),
            Self::Constant(value) => value.checked_add_signed(displacement).map(Self::Constant),
            Self::Loaded { .. } | Self::StackCell(_) => None,
        }
    }
    pub const fn argument(self) -> Option<usize> {
        match self {
            Self::Input { argument, .. } | Self::Loaded { argument, .. } => Some(argument),
            _ => None,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct Spill {
    pub value: Value,
    pub width: usize,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct State {
    registers: [Option<Value>; 16],
    pub stack: BTreeMap<i64, Spill>,
    pub limited: bool,
    pub escaped_stack: bool,
}

impl State {
    pub fn initial() -> Self {
        let mut state = Self { registers: [None; 16], stack: BTreeMap::new(), limited: false, escaped_stack: false };
        for (argument, register) in ABI_ARGS.iter().enumerate() {
            state.set(*register, Some(Value::Input { argument, offset: 0 }));
        }
        state.set(Register::RSP, Some(Value::Stack(0)));
        state
    }
    pub fn get(&self, register: Register) -> Option<Value> {
        let index = REGISTERS.iter().position(|r| *r == register.full_register())?;
        let value = self.registers[index]?;
        if register.size() != 8 && matches!(value, Value::Input { .. } | Value::Stack(_) | Value::StackCell(_)) {
            return None;
        }
        if matches!(register, Register::AH | Register::BH | Register::CH | Register::DH) {
            return None;
        }
        match value {
            Value::Constant(bits) if register.size() < 8 => Some(Value::Constant(bits & low_mask(register.size()))),
            _ => Some(value),
        }
    }
    pub fn set(&mut self, register: Register, value: Option<Value>) {
        if let Some(index) = REGISTERS.iter().position(|r| *r == register.full_register()) {
            self.registers[index] = value;
        }
    }
    pub fn meet(&mut self, other: &Self) -> bool {
        let before = self.clone();
        for (slot, incoming) in self.registers.iter_mut().zip(&other.registers) {
            if *slot != *incoming {
                *slot = None;
            }
        }
        self.stack.retain(|position, value| other.stack.get(position) == Some(value));
        self.limited |= other.limited;
        self.escaped_stack |= other.escaped_stack;
        *self != before
    }
    pub fn invalidate_stack(&mut self, start: i64, width: usize) {
        let end = i64::try_from(width).ok().and_then(|size| start.checked_add(size));
        self.stack.retain(|position, spill| {
            let prior_end = i64::try_from(spill.width).ok().and_then(|size| position.checked_add(size));
            matches!((end, prior_end), (Some(end), Some(prior)) if prior <= start || *position >= end)
        });
    }
    pub fn address(&self, instruction: &Instruction) -> Option<Value> {
        if matches!(instruction.memory_segment(), Register::FS | Register::GS) {
            return None;
        }
        if instruction.is_ip_rel_memory_operand() {
            return Some(Value::Constant(instruction.ip_rel_memory_address()));
        }
        let base = instruction.memory_base();
        let mut value = if base == Register::None { Value::Constant(0) } else { self.get(base)? };
        let index = instruction.memory_index();
        if index != Register::None {
            let Value::Constant(bits) = self.get(index)? else { return None };
            let amount = bits.checked_mul(u64::from(instruction.memory_index_scale()))?;
            value = value.add(i64::try_from(amount).ok()?)?;
        }
        value.add(instruction.memory_displacement64().cast_signed())
    }
    pub fn operand(&self, instruction: &Instruction, operand: u32) -> Option<Value> {
        match instruction.op_kind(operand) {
            OpKind::Register => self.get(instruction.op_register(operand)),
            OpKind::Immediate8
            | OpKind::Immediate16
            | OpKind::Immediate32
            | OpKind::Immediate64
            | OpKind::Immediate8to16
            | OpKind::Immediate8to32
            | OpKind::Immediate8to64
            | OpKind::Immediate32to64 => Some(Value::Constant(instruction.immediate(operand))),
            _ => None,
        }
    }
}

pub(super) const fn low_mask(bytes: usize) -> u64 {
    match bytes {
        1 => 0xff,
        2 => 0xffff,
        4 => 0xffff_ffff,
        _ => u64::MAX,
    }
}
