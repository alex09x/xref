/*
 * XRef — Constant call arguments across a whole binary
 * Copyright (c) 2026 Alexander Panasenko
 * Contact: alex@prod.codes
 * Author: https://prod.codes/about/
 * Project: https://github.com/alex09x/xref
 * SPDX-License-Identifier: MIT OR Apache-2.0
 */

//! Every call (or tail jump) with a resolved target, and the argument registers and stack slots
//! holding a known constant when it is made: set in the call's straight-line run by `mov reg, imm`,
//! `xor reg, reg`, a copy of such a register, a `mov [rsp+8k], imm` or a `push imm`. Any other
//! write of a register (explicit or implicit) or of a stack slot forgets it, and so does a join.

use std::collections::BTreeMap;
use std::fmt;
use std::ops::Range;

use iced_x86::{FlowControl, Instruction, InstructionInfoFactory, Mnemonic, OpKind, Register};
use rayon::prelude::*;

use super::flow::{targets, written};
use crate::expr::{ABI_ARGS, reg_name};
use crate::graph::call_target;
use crate::image::Image;
use crate::listing::is_call;
use crate::scan::decode;

/// Stack argument slots tracked before a call.
pub const STACK_SLOTS: usize = 8;
/// `[rsp + 8k]` slots held: one more than the arguments, for a tail jump's return address.
const HELD_SLOTS: u64 = STACK_SLOTS as u64 + 1;

pub const VOLATILE: [Register; 9] = [
    Register::RAX,
    Register::RCX,
    Register::RDX,
    Register::RSI,
    Register::RDI,
    Register::R8,
    Register::R9,
    Register::R10,
    Register::R11,
];

/// A System V AMD64 argument position: a register (index into `rdi..r9`) or a stack slot.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Slot {
    Reg(usize),
    Stack(usize),
}

impl Slot {
    /// `rdi`, `rsi`, `rdx`, `rcx`, `r8`, `r9` or `stack0`..`stack7`.
    pub fn parse(text: &str) -> Result<Self, String> {
        if let Some(index) = ABI_ARGS.iter().position(|register| reg_name(*register) == text) {
            return Ok(Self::Reg(index));
        }
        text.strip_prefix("stack")
            .and_then(|n| n.parse::<usize>().ok())
            .filter(|n| *n < STACK_SLOTS)
            .map(Self::Stack)
            .ok_or_else(|| format!("{text}: expected rdi, rsi, rdx, rcx, r8, r9 or stack0..stack{}", STACK_SLOTS - 1))
    }

    pub const fn register(self) -> Option<Register> {
        match self {
            Self::Reg(index) => Some(ABI_ARGS[index]),
            Self::Stack(_) => None,
        }
    }
}

impl fmt::Display for Slot {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Reg(index) => f.write_str(&reg_name(ABI_ARGS[*index])),
            Self::Stack(index) => write!(f, "stack{index}"),
        }
    }
}

pub struct Call {
    pub ip: u64,
    pub function: Range<u64>,
    pub callee: u64,
    /// A jump leaving the function rather than a `call`.
    pub tail: bool,
    /// Argument positions holding a known constant, in `rdi..r9, stack0..` order.
    pub args: Vec<(Slot, u64)>,
}

/// Which calls to keep, from the callee and the constant arguments.
pub type Keep<'a> = dyn Fn(u64, &[(Slot, u64)]) -> bool + Sync + 'a;

/// Calls of every function that `keep(callee, constant args)` accepts, in address order.
pub fn calls(image: &Image, keep: &Keep<'_>) -> Vec<Call> {
    let mut found: Vec<Call> = image
        .functions
        .par_iter()
        .filter_map(|f| Some((f, image.code(f)?)))
        .flat_map_iter(|(f, bytes)| in_function(image, f, bytes, keep))
        .collect();
    found.sort_by_key(|call| call.ip);
    found
}

fn in_function(image: &Image, f: &Range<u64>, bytes: &[u8], keep: &Keep<'_>) -> Vec<Call> {
    let mut code = Vec::new();
    decode(bytes, f.start, |ins| code.push(*ins));
    let leaders = targets(image, f, &code);
    let mut factory = InstructionInfoFactory::new();
    let mut held = Held::default();
    let mut found = Vec::new();
    for ins in &code {
        if leaders.contains(&ins.ip()) {
            // A join: the value may come from another path.
            held.clear();
        }
        if is_call(ins, f) {
            let tail = !matches!(ins.flow_control(), FlowControl::Call | FlowControl::IndirectCall);
            if let Some(callee) = call_target(image, ins) {
                let args = held.args(tail);
                if keep(callee, &args) {
                    found.push(Call { ip: ins.ip(), function: f.clone(), callee, tail, args });
                }
            }
            if tail {
                held.clear();
            } else {
                held.after_call();
            }
            continue;
        }
        match ins.flow_control() {
            FlowControl::Next => held.step(ins, &mut factory),
            FlowControl::ConditionalBranch => {}
            _ => held.clear(),
        }
    }
    found
}

#[derive(Default)]
struct Held {
    regs: BTreeMap<Register, u64>,
    /// `[rsp + 8 * k]` for `k < HELD_SLOTS`.
    slots: BTreeMap<u64, u64>,
}

impl Held {
    fn clear(&mut self) {
        self.regs.clear();
        self.slots.clear();
    }

    fn after_call(&mut self) {
        for register in VOLATILE {
            self.regs.remove(&register);
        }
        self.slots.clear();
    }

    /// At a `call`, `[rsp + 8k]` is the callee's `stack{k}`; at a tail jump `[rsp]` already holds
    /// the return address, so `stack{k}` is `[rsp + 8(k + 1)]`.
    fn args(&self, tail: bool) -> Vec<(Slot, u64)> {
        let mut args: Vec<(Slot, u64)> = ABI_ARGS
            .iter()
            .enumerate()
            .filter_map(|(index, register)| Some((Slot::Reg(index), *self.regs.get(register)?)))
            .collect();
        for (index, slot) in (u64::from(tail)..HELD_SLOTS).enumerate().take(STACK_SLOTS) {
            if let Some(value) = self.slots.get(&slot) {
                args.push((Slot::Stack(index), *value));
            }
        }
        args
    }

    /// The constant operand `index` holds: an immediate or a register holding one.
    fn value(&self, ins: &Instruction, index: u32) -> Option<u64> {
        match ins.op_kind(index) {
            OpKind::Register => self.regs.get(&ins.op_register(index).full_register()).copied(),
            OpKind::Immediate8
            | OpKind::Immediate16
            | OpKind::Immediate32
            | OpKind::Immediate64
            | OpKind::Immediate8to16
            | OpKind::Immediate8to32
            | OpKind::Immediate8to64
            | OpKind::Immediate32to64 => Some(ins.immediate(index)),
            _ => None,
        }
    }

    /// The constant a register write leaves in the whole register.
    fn loaded(&self, ins: &Instruction) -> Option<(Register, u64)> {
        if ins.op_count() == 0 || ins.op0_kind() != OpKind::Register {
            return None;
        }
        let register = ins.op0_register();
        if register.size() < 4 {
            return None;
        }
        let same = ins.op_count() > 1 && ins.op1_kind() == OpKind::Register && ins.op1_register() == register;
        let value = match ins.mnemonic() {
            Mnemonic::Xor | Mnemonic::Sub if same => 0,
            // A 32-bit write zero-extends into the whole register.
            Mnemonic::Mov => self.value(ins, 1).map(|v| if register.size() == 4 { v & 0xffff_ffff } else { v })?,
            _ => return None,
        };
        Some((register.full_register(), value))
    }

    fn step(&mut self, ins: &Instruction, factory: &mut InstructionInfoFactory) {
        let loaded = self.loaded(ins);
        let writes = written(factory, ins);
        match (ins.mnemonic(), ins.stack_pointer_increment()) {
            (Mnemonic::Push, -8) => {
                let value = self.value(ins, 0);
                self.shift(1);
                if let Some(value) = value {
                    self.slots.insert(0, value);
                }
            }
            (Mnemonic::Pop, 8) => self.shift(-1),
            // The frame moved some other way (`sub rsp`, `leave`, a narrow push): slots no longer line up.
            _ if writes.contains(&Register::RSP) => self.slots.clear(),
            _ => {}
        }
        if ins.op_count() > 0 && ins.op0_kind() == OpKind::Memory {
            self.store(ins);
        } else if matches!(ins.op0_kind(), OpKind::MemoryESDI | OpKind::MemoryESEDI | OpKind::MemoryESRDI) {
            // `stos`/`movs` may write the stack.
            self.slots.clear();
        }
        for register in writes {
            self.regs.remove(&register);
        }
        if let Some((register, value)) = loaded {
            self.regs.insert(register, value);
        }
    }

    /// `rsp` moved by `by` slots the other way: `[rsp + 8k]` is now `[rsp + 8(k + by)]`.
    fn shift(&mut self, by: i64) {
        let slots = std::mem::take(&mut self.slots);
        self.slots = slots
            .into_iter()
            .filter_map(|(slot, value)| {
                let moved = slot.checked_add_signed(by)?;
                (moved < HELD_SLOTS).then_some((moved, value))
            })
            .collect();
    }

    fn store(&mut self, ins: &Instruction) {
        if ins.memory_base() != Register::RSP {
            return;
        }
        if ins.memory_index() != Register::None {
            self.slots.clear();
            return;
        }
        let displacement = ins.memory_displacement64();
        let width = ins.memory_size().size().max(1) as u64;
        if displacement >= HELD_SLOTS * 8 {
            return;
        }
        // Every slot the write overlaps.
        let first = displacement / 8;
        let last = (displacement + width - 1) / 8;
        self.slots.retain(|slot, _| *slot < first || *slot > last);
        if ins.mnemonic() == Mnemonic::Mov
            && displacement.is_multiple_of(8)
            && matches!(width, 4 | 8)
            && let Some(value) = self.value(ins, 1)
        {
            self.slots.insert(first, if width == 4 { value & 0xffff_ffff } else { value });
        }
    }
}
