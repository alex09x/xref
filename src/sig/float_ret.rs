/*
 * xref — Ultra blazing fast cross-references of an x86-64 ELF binary
 * Copyright (c) 2026 Alexander Panasenko
 *
 * Contact: alex@prod.codes
 * Author: https://prod.codes/about/
 * Project: https://github.com/alex09x/xref
 * SPDX-License-Identifier: MIT OR Apache-2.0
 */

//! Scalar floating-point return detection: a forward dataflow over the CFG that tracks what last
//! wrote each of `xmm0`..`xmm15` (and whether `rax` holds a non-call write) up to every `ret`.

use std::ops::Range;

use iced_x86::{FlowControl, Instruction, InstructionInfoFactory, Mnemonic, OpAccess, Register};

use super::xmm::{F32, F64, FloatParam, FloatRet, is_reg_copy, reg_operand, result_width, xmm_rw, xmm_zero_idiom};
use crate::scan::branch_target;
use crate::sig::zero_idiom_reg;

/// Not written since the entry.
const ENTRY: u8 = 1;
const K_F64: u8 = 2;
const K_F32: u8 = 4;
/// `xorps x, x`: zero of either width.
const ZERO: u8 = 8;
/// Written by a non-floating instruction or clobbered by a call.
const OTHER: u8 = 16;
const RAX_SET: u8 = 1;
const RAX_NONE: u8 = 2;

fn width_bit(ty: &str) -> u8 {
    if ty == F32 { K_F32 } else { K_F64 }
}

#[derive(Clone, PartialEq, Eq)]
struct RetState {
    kinds: [u8; 16],
    rax: u8,
}

impl RetState {
    fn merged(&self, other: &Self) -> Self {
        let mut m = self.clone();
        for (k, v) in m.kinds.iter_mut().zip(other.kinds) {
            *k |= v;
        }
        m.rax |= other.rax;
        m
    }
}

pub struct RetScan<'a> {
    pub insns: &'a [Instruction],
    pub function: &'a Range<u64>,
    pub starts: &'a [u64],
    pub succs: &'a [Vec<usize>],
    pub params: &'a [FloatParam],
    /// Float type returned by the direct callee of a call at this ip.
    pub call_ret: &'a dyn Fn(u64) -> Option<&'static str>,
    /// Some path leaves the function by a tail call (`jmp` to another function, indirect `jmp`).
    pub has_tail: bool,
}

/// A non-call write of `rax`; `pop rax` (the epilogue of a `push rax` stack alignment) restores
/// rather than produces a value.
fn writes_rax(factory: &mut InstructionInfoFactory, ins: &Instruction) -> bool {
    if ins.mnemonic() == Mnemonic::Pop {
        return false;
    }
    zero_idiom_reg(ins) == Some(Register::RAX)
        || factory.info(ins).used_registers().iter().any(|u| {
            u.register().full_register() == Register::RAX
                && matches!(
                    u.access(),
                    OpAccess::Write | OpAccess::CondWrite | OpAccess::ReadWrite | OpAccess::ReadCondWrite
                )
        })
}

impl RetScan<'_> {
    fn transfer(&self, factory: &mut InstructionInfoFactory, st: &mut RetState, ins: &Instruction) {
        if matches!(ins.flow_control(), FlowControl::Call | FlowControl::IndirectCall) {
            st.kinds = [OTHER; 16];
            st.kinds[0] = (self.call_ret)(ins.ip()).map_or(OTHER, width_bit);
            st.rax = RAX_NONE;
            return;
        }
        if writes_rax(factory, ins) {
            st.rax = RAX_SET;
        }
        if let Some(d) = xmm_zero_idiom(ins) {
            st.kinds[usize::from(d)] = ZERO;
            return;
        }
        let (_, w) = xmm_rw(factory, ins);
        let dest = reg_operand(ins, 0);
        for i in (0..16u8).filter(|i| w & (1 << i) != 0) {
            st.kinds[usize::from(i)] = if dest != Some(i) {
                OTHER
            } else if is_reg_copy(ins) {
                reg_operand(ins, 1).map_or(OTHER, |s| self.resolve_entry(st.kinds[usize::from(s)], s))
            } else {
                result_width(ins.mnemonic()).map_or(OTHER, width_bit)
            };
        }
    }

    /// A register copy of an unwritten parameter register carries the parameter's type.
    fn resolve_entry(&self, kind: u8, src: u8) -> u8 {
        if kind & ENTRY == 0 {
            return kind;
        }
        let param = self.params.iter().find(|p| p.index == src).map_or(OTHER, |p| width_bit(p.ty));
        (kind & !ENTRY) | param
    }

    /// Scalar float type in `xmm0` at every reachable `ret`, or `None` when some path leaves it
    /// unwritten, writes it with a non-floating instruction, or leaves the function by a tail call.
    pub fn run(&self) -> Option<FloatRet> {
        let n = self.starts.len();
        if self.has_tail || n == 0 {
            return None;
        }
        let idx_range = |b: usize| {
            let lo = self.insns.partition_point(|i| i.ip() < self.starts[b]);
            let end = self.starts.get(b + 1).copied().unwrap_or(self.function.end);
            lo..self.insns.partition_point(|i| i.ip() < end)
        };
        let mut factory = InstructionInfoFactory::new();
        let mut in_state: Vec<Option<RetState>> = vec![None; n];
        in_state[0] = Some(RetState { kinds: [ENTRY; 16], rax: RAX_NONE });
        let (mut work, mut ret_kinds, mut ret_rax, mut any_ret) = (vec![0usize], 0u8, 0u8, false);
        while let Some(b) = work.pop() {
            let Some(mut st) = in_state[b].clone() else { continue };
            for ins in &self.insns[idx_range(b)] {
                match ins.flow_control() {
                    FlowControl::Return => {
                        (ret_kinds, ret_rax, any_ret) = (ret_kinds | st.kinds[0], ret_rax | st.rax, true);
                    }
                    FlowControl::ConditionalBranch | FlowControl::UnconditionalBranch
                        if branch_target(ins).is_some_and(|t| !self.function.contains(&t)) =>
                    {
                        return None;
                    }
                    _ => self.transfer(&mut factory, &mut st, ins),
                }
            }
            for &s in &self.succs[b] {
                let merged = in_state[s].as_ref().map_or_else(|| st.clone(), |old| old.merged(&st));
                if in_state[s].as_ref() != Some(&merged) {
                    in_state[s] = Some(merged);
                    work.push(s);
                }
            }
        }
        if !any_ret || ret_kinds & (ENTRY | OTHER) != 0 {
            return None;
        }
        let ty = match ret_kinds & (K_F64 | K_F32) {
            K_F64 => F64,
            K_F32 => F32,
            _ => return None,
        };
        Some(FloatRet { ty, rax_written: ret_rax & RAX_SET != 0 })
    }
}
