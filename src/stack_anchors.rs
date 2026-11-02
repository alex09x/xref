/*
 * XRef Code — Explicit stack address anchors
 * Copyright (c) 2026 Alexander Panasenko
 * Contact: alex@prod.codes
 * Author: https://prod.codes/about/
 * Project: https://github.com/alex09x/xref
 * SPDX-License-Identifier: MIT OR Apache-2.0
 */

use crate::scan::{branch_target, immediates};
use iced_x86::{FlowControl, Instruction, InstructionInfoFactory, Mnemonic, OpAccess, OpKind, Register};
use std::collections::{HashMap, VecDeque};

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct StackAnchor {
    pub frame_offset: i64,
    pub base: Register,
    pub displacement: u64,
    pub ip: u64,
}

pub struct StackAccess {
    pub coordinate: i64,
    pub anchors: Vec<StackAnchor>,
}

#[derive(Default)]
pub struct StackAnchors {
    accesses: HashMap<u64, StackAccess>,
}

#[derive(Clone, PartialEq, Eq)]
struct State {
    sp: Option<i64>,
    bp: Option<i64>,
    anchors: Vec<StackAnchor>,
}

impl State {
    fn merge(&mut self, incoming: &Self) -> bool {
        let previous = self.clone();
        if self.sp != incoming.sp {
            self.sp = None;
        }
        if self.bp != incoming.bp {
            self.bp = None;
        }
        self.anchors.retain(|a| incoming.anchors.contains(a));
        *self != previous
    }

    const fn coordinate(&self, base: Register, has_fp: bool) -> Option<i64> {
        match base {
            Register::RSP => self.sp,
            Register::RBP if has_fp => self.bp,
            _ => None,
        }
    }

    fn address(&self, ins: &Instruction, has_fp: bool) -> Option<i64> {
        self.coordinate(ins.memory_base(), has_fp)
            .map(|base| base.wrapping_add(ins.memory_displacement64().cast_signed()))
    }

    fn with_anchor(mut self, ins: &Instruction, has_fp: bool) -> Self {
        let dst = ins.op0_register();
        if (has_fp && dst == Register::RBP)
            || !matches!(
                dst,
                Register::RAX
                    | Register::RBX
                    | Register::RCX
                    | Register::RDX
                    | Register::RBP
                    | Register::RSI
                    | Register::RDI
                    | Register::R8
                    | Register::R9
                    | Register::R10
                    | Register::R11
                    | Register::R12
                    | Register::R13
                    | Register::R14
                    | Register::R15
            )
        {
            return self;
        }
        let source = match ins.mnemonic() {
            Mnemonic::Lea if ins.memory_index() == Register::None => {
                self.address(ins, has_fp).map(|coordinate| (coordinate, ins.memory_base(), ins.memory_displacement64()))
            }
            Mnemonic::Mov if ins.op1_kind() == OpKind::Register => {
                self.coordinate(ins.op1_register(), has_fp).map(|coordinate| (coordinate, ins.op1_register(), 0))
            }
            _ => None,
        };
        if let Some((frame_offset, base, displacement)) = source {
            let anchor = StackAnchor { frame_offset, base, displacement, ip: ins.ip() };
            if !self.anchors.contains(&anchor) {
                self.anchors.push(anchor);
            }
        }
        self
    }
}

const fn writes(access: OpAccess) -> bool {
    matches!(access, OpAccess::Write | OpAccess::CondWrite | OpAccess::ReadWrite | OpAccess::ReadCondWrite)
}

fn advance(ins: &Instruction, state: &State, has_fp: bool, factory: &mut InstructionInfoFactory) -> State {
    let mut next = state.clone();
    if matches!(ins.flow_control(), FlowControl::Call | FlowControl::IndirectCall) {
        return next;
    }
    let info = factory.info(ins);
    for reg in info.used_registers().iter().filter(|reg| writes(reg.access())) {
        match reg.register().full_register() {
            Register::RSP => next.sp = None,
            Register::RBP => next.bp = None,
            _ => {}
        }
    }
    let dst = ins.op0_register();
    let source_reg = ins.op1_register();
    match ins.mnemonic() {
        Mnemonic::Push => next.sp = state.sp.map(|sp| sp.wrapping_add(i64::from(ins.stack_pointer_increment()))),
        Mnemonic::Pop if dst.full_register() != Register::RSP => {
            next.sp = state.sp.map(|sp| sp.wrapping_add(i64::from(ins.stack_pointer_increment())));
        }
        Mnemonic::Add | Mnemonic::Sub if dst == Register::RSP => {
            next.sp = state.sp.zip(immediates(ins).next()).map(|(sp, immediate)| {
                let delta = immediate.cast_signed();
                if ins.mnemonic() == Mnemonic::Add { sp.wrapping_add(delta) } else { sp.wrapping_sub(delta) }
            });
        }
        Mnemonic::Mov if ins.op1_kind() == OpKind::Register => {
            let value = match source_reg {
                Register::RSP => state.sp,
                Register::RBP => state.bp,
                _ => None,
            };
            if dst == Register::RSP {
                next.sp = value;
            }
            if dst == Register::RBP {
                next.bp = value;
            }
        }
        Mnemonic::Lea if ins.memory_index() == Register::None => {
            let value = state.address(ins, has_fp);
            if dst == Register::RSP {
                next.sp = value;
            }
            if dst == Register::RBP {
                next.bp = value;
            }
        }
        Mnemonic::Leave => {
            next.sp = info.used_memory().first().and_then(|m| {
                let width = i64::try_from(m.memory_size().size()).ok()?;
                (width > 0).then(|| state.bp.map(|bp| bp.wrapping_add(width))).flatten()
            });
            next.bp = None;
        }
        _ => {}
    }
    next
}

impl StackAnchors {
    pub fn analyze(insns: &[Instruction], has_fp: bool) -> Self {
        let mut out = Self::default();
        if insns.is_empty() {
            return out;
        }
        let by_ip: HashMap<u64, usize> = insns.iter().enumerate().map(|(i, ins)| (ins.ip(), i)).collect();
        let mut incoming = vec![None; insns.len()];
        incoming[0] = Some(State { sp: Some(0), bp: None, anchors: Vec::new() });
        let (mut pending, mut queued) = (VecDeque::from([0]), vec![false; insns.len()]);
        queued[0] = true;
        let mut factory = InstructionInfoFactory::new();
        while let Some(index) = pending.pop_front() {
            queued[index] = false;
            let Some(state) = incoming[index].clone() else {
                continue;
            };
            let ins = &insns[index];
            let state = state.with_anchor(ins, has_fp);
            let next = advance(ins, &state, has_fp, &mut factory);
            let mut successors = Vec::with_capacity(2);
            match ins.flow_control() {
                FlowControl::ConditionalBranch | FlowControl::UnconditionalBranch => {
                    successors.extend(branch_target(ins).and_then(|ip| by_ip.get(&ip).copied()));
                }
                _ => {}
            }
            if matches!(
                ins.flow_control(),
                FlowControl::Next | FlowControl::Call | FlowControl::IndirectCall | FlowControl::ConditionalBranch
            ) && let Some(&index) = by_ip.get(&ins.next_ip())
            {
                successors.push(index);
            }
            for successor in successors {
                let changed = match &mut incoming[successor] {
                    Some(previous) => previous.merge(&next),
                    slot @ None => {
                        *slot = Some(next.clone());
                        true
                    }
                };
                if changed && !queued[successor] {
                    pending.push_back(successor);
                    queued[successor] = true;
                }
            }
        }
        for (ins, state) in insns.iter().zip(incoming).filter_map(|(ins, state)| state.map(|state| (ins, state))) {
            let state = state.with_anchor(ins, has_fp);
            if let Some(mut coordinate) = state.address(ins, has_fp) {
                // POP memory destinations based on RSP use the incremented RSP.
                if ins.mnemonic() == Mnemonic::Pop && ins.memory_base() == Register::RSP {
                    coordinate = coordinate.wrapping_add(i64::from(ins.stack_pointer_increment()));
                }
                out.accesses.insert(ins.ip(), StackAccess { coordinate, anchors: state.anchors });
            }
        }
        out
    }

    pub fn access(&self, ip: u64) -> Option<&StackAccess> {
        self.accesses.get(&ip)
    }
}

#[cfg(test)]
mod tests;
