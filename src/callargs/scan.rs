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
//! `xor reg, reg`, a copy of such a register, a `mov [rsp+8k], imm` or a `push imm`.

use std::collections::{BTreeMap, HashMap, HashSet};
use std::fmt;
use std::ops::Range;

use iced_x86::{FlowControl, Instruction, Mnemonic, OpKind, Register};
use rayon::prelude::*;

use crate::expr::{ABI_ARGS, reg_name};
use crate::graph::call_target;
use crate::image::Image;
use crate::listing::is_call;
use crate::scan::{branch_target, decode};

/// Stack argument slots tracked before a call.
pub const STACK_SLOTS: usize = 8;

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
    let leaders: HashSet<u64> = code.iter().filter_map(branch_target).filter(|t| f.contains(t)).collect();
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
                let args = held.args();
                if keep(callee, &args) {
                    found.push(Call { ip: ins.ip(), function: f.clone(), callee, tail, args });
                }
            }
            held.after_call();
            continue;
        }
        match ins.flow_control() {
            FlowControl::Next => held.step(ins),
            FlowControl::ConditionalBranch => {}
            _ => held.clear(),
        }
    }
    found
}

#[derive(Default)]
struct Held {
    regs: HashMap<Register, u64>,
    /// `[rsp + 8 * slot]` stores.
    slots: BTreeMap<u64, u64>,
    pushed: Vec<Option<u64>>,
}

impl Held {
    fn clear(&mut self) {
        self.regs.clear();
        self.slots.clear();
        self.pushed.clear();
    }

    fn after_call(&mut self) {
        for register in VOLATILE {
            self.regs.remove(&register);
        }
        self.slots.clear();
        self.pushed.clear();
    }

    fn args(&self) -> Vec<(Slot, u64)> {
        let mut args: Vec<(Slot, u64)> = ABI_ARGS
            .iter()
            .enumerate()
            .filter_map(|(index, register)| Some((Slot::Reg(index), *self.regs.get(register)?)))
            .collect();
        if self.pushed.is_empty() {
            args.extend(
                self.slots.iter().filter_map(|(slot, value)| Some((Slot::Stack(usize::try_from(*slot).ok()?), *value))),
            );
        } else {
            let pushed = self.pushed.iter().rev().take(STACK_SLOTS).enumerate();
            args.extend(pushed.filter_map(|(index, value)| Some((Slot::Stack(index), (*value)?))));
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

    fn step(&mut self, ins: &Instruction) {
        let mnemonic = ins.mnemonic();
        if mnemonic == Mnemonic::Push {
            let value = self.value(ins, 0);
            self.pushed.push(value);
            return;
        }
        if ins.op_count() > 0 && ins.op0_kind() == OpKind::Register && ins.op0_register() == Register::RSP {
            // The frame moved: earlier slots and pushes no longer line up with the call's arguments.
            self.slots.clear();
            self.pushed.clear();
            return;
        }
        if mnemonic == Mnemonic::Pop {
            self.pushed.pop();
        }
        if ins.op_count() > 0 && ins.op0_kind() == OpKind::Memory {
            self.store(ins);
            return;
        }
        if matches!(
            mnemonic,
            Mnemonic::Mul | Mnemonic::Imul | Mnemonic::Div | Mnemonic::Idiv | Mnemonic::Cqo | Mnemonic::Cdq
        ) {
            self.regs.remove(&Register::RAX);
            self.regs.remove(&Register::RDX);
        }
        if matches!(mnemonic, Mnemonic::Xchg | Mnemonic::Xadd) && ins.op1_kind() == OpKind::Register {
            self.regs.remove(&ins.op1_register().full_register());
        }
        if ins.op_count() == 0 || ins.op0_kind() != OpKind::Register || reads_only(mnemonic) {
            return;
        }
        let register = ins.op0_register();
        let whole = register.size() >= 4;
        let same = ins.op_count() > 1 && ins.op1_kind() == OpKind::Register && ins.op1_register() == register;
        let value = if !whole {
            None
        } else if matches!(mnemonic, Mnemonic::Xor | Mnemonic::Sub) && same {
            Some(0)
        } else if mnemonic == Mnemonic::Mov {
            // A 32-bit write zero-extends into the whole register.
            self.value(ins, 1).map(|v| if register.size() == 4 { v & 0xffff_ffff } else { v })
        } else {
            None
        };
        match value {
            Some(value) => self.regs.insert(register.full_register(), value),
            None => self.regs.remove(&register.full_register()),
        };
    }

    fn store(&mut self, ins: &Instruction) {
        if ins.memory_base() != Register::RSP || ins.memory_index() != Register::None {
            return;
        }
        let displacement = ins.memory_displacement64();
        if !displacement.is_multiple_of(8) || displacement / 8 >= STACK_SLOTS as u64 {
            return;
        }
        let slot = displacement / 8;
        let width = ins.memory_size().size();
        match (ins.mnemonic() == Mnemonic::Mov && width >= 4).then(|| self.value(ins, 1)).flatten() {
            Some(value) => self.slots.insert(slot, if width == 4 { value & 0xffff_ffff } else { value }),
            None => self.slots.remove(&slot),
        };
    }
}

pub const fn reads_only(mnemonic: Mnemonic) -> bool {
    matches!(mnemonic, Mnemonic::Cmp | Mnemonic::Test | Mnemonic::Bt | Mnemonic::Push)
}
