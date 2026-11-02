/*
 * XRef Code — evidence-producing binary analysis
 * Copyright (c) 2026 Alexander Panasenko
 * Contact: alex@prod.codes
 * Author: https://prod.codes/about/
 * Project: https://github.com/alex09x/xref
 * SPDX-License-Identifier: MIT OR Apache-2.0
 */
use super::super::{ApiError, Cancellation};
use super::{flow::Flow, types::Value};
use super::origin::Origin;
use iced_x86::{FlowControl, Instruction, InstructionInfoFactory, Mnemonic, OpAccess, OpKind, Register};
use std::collections::{BTreeSet, VecDeque};

pub(super) const REGS: [Register; 16] = [
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
pub(super) const NAMES: [&str; 16] =
    ["rax", "rcx", "rdx", "rbx", "rsp", "rbp", "rsi", "rdi", "r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15"];
pub(super) fn reg_index(r: Register) -> Option<usize> {
    REGS.iter().position(|&v| v == r.full_register())
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct Fact {
    pub value: Value,
    pub origin: Option<Origin>,
    pub defs: BTreeSet<usize>,
    pub truncated: bool,
}
impl Fact {
    fn unknown(at: usize) -> Self {
        Self { value: Value::Unknown, origin: None, defs: BTreeSet::from([at]), truncated: false }
    }
    fn add(&mut self, at: usize) {
        self.defs.insert(at);
        if self.defs.len() > 8 {
            self.defs.pop_last();
            self.truncated = true;
        }
    }
    fn merge(&mut self, other: &Self) {
        if self.value != other.value {
            self.value = Value::Unknown;
        }
        self.truncated |= other.truncated;
        for &d in &other.defs {
            self.add(d);
        }
    }
}
pub(super) type State = [Fact; 16];

fn initial() -> State {
    std::array::from_fn(|i| Fact {
        value: if i == 4 { Value::Unknown } else { Value::EntryRegister { register: NAMES[i] } },
        origin: None,
        defs: BTreeSet::new(),
        truncated: false,
    })
}
fn step(ins: &Instruction, at: usize, input: &State, factory: &mut InstructionInfoFactory) -> State {
    let mut output = input.clone();
    for u in factory.info(ins).used_registers() {
        if matches!(u.access(), OpAccess::Write | OpAccess::ReadWrite | OpAccess::CondWrite | OpAccess::ReadCondWrite)
            && let Some(k) = reg_index(u.register())
        {
            output[k] = Fact::unknown(at);
        }
    }
    if matches!(ins.flow_control(), FlowControl::Call | FlowControl::IndirectCall) {
        for k in [0, 1, 2, 6, 7, 8, 9, 10, 11] {
            output[k] = Fact::unknown(at);
        }
        return output;
    }
    let dst = ins.op0_register();
    if ins.op0_kind() != OpKind::Register || dst.size() < 4 {
        return output;
    }
    let Some(k) = reg_index(dst) else { return output };
    let value = match ins.mnemonic() {
        Mnemonic::Mov if ins.op1_kind() == OpKind::Register && ins.op1_register().size() == 8 && dst.size() == 8 => {
            reg_index(ins.op1_register()).map(|s| input[s].clone())
        }
        Mnemonic::Mov
            if matches!(ins.op1_kind(), OpKind::Immediate32 | OpKind::Immediate64 | OpKind::Immediate32to64) =>
        {
            let mut v = ins.immediate(1);
            if dst.size() == 4 {
                v &= 0xffff_ffff;
            }
            Some(Fact { value: Value::Constant { bits: format!("{v:#x}") }, origin: None, defs: BTreeSet::new(), truncated: false })
        }
        Mnemonic::Xor if ins.op1_kind() == OpKind::Register && ins.op1_register() == dst => {
            Some(Fact { value: Value::Constant { bits: "0x0".into() }, origin: None, defs: BTreeSet::new(), truncated: false })
        }
        Mnemonic::Lea if dst.size() == 8 && ins.is_ip_rel_memory_operand() => Some(Fact {
            value: Value::Address { address: format!("{:#x}", ins.ip_rel_memory_address()) },
            origin: None,
            defs: BTreeSet::new(),
            truncated: false,
        }),
        _ => None,
    };
    if let Some(mut value) = value {
        value.add(at);
        output[k] = value;
    }
    output
}
pub(super) fn at_call(
    insns: &[Instruction],
    flow: &Flow,
    call: usize,
    cancel: &Cancellation,
) -> Result<Option<State>, ApiError> {
    Ok(solve(insns, flow, cancel)?.and_then(|mut states| states.get_mut(call).and_then(Option::take)))
}
pub(super) fn solve(
    insns: &[Instruction],
    flow: &Flow,
    cancel: &Cancellation,
) -> Result<Option<Vec<Option<State>>>, ApiError> {
    let mut incoming: Vec<Option<State>> = vec![None; insns.len()];
    incoming[0] = Some(initial());
    let mut queue = VecDeque::from([0]);
    let mut queued = vec![false; insns.len()];
    queued[0] = true;
    let mut factory = InstructionInfoFactory::new();
    let mut work = 0;
    while let Some(i) = queue.pop_front() {
        cancel.checkpoint()?;
        if work >= 100_000 {
            return Ok(None);
        }
        work += 1;
        queued[i] = false;
        let Some(state) = &incoming[i] else { continue };
        let output = step(&insns[i], i, state, &mut factory);
        for &next in &flow.successors[i] {
            let (merged, changed) = incoming[next].take().map_or_else(
                || (output.clone(), true),
                |mut old| {
                    let before = old.clone();
                    for (a, b) in old.iter_mut().zip(&output) {
                        a.merge(b);
                    }
                    let changed = old != before;
                    (old, changed)
                },
            );
            incoming[next] = Some(merged);
            if changed && !queued[next] {
                queue.push_back(next);
                queued[next] = true;
            }
        }
    }
    Ok(Some(incoming))
}
