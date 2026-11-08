/*
 * XRef — Control-flow and register-write helpers for argument tracking
 * Copyright (c) 2026 Alexander Panasenko
 * Contact: alex@prod.codes
 * Author: https://prod.codes/about/
 * Project: https://github.com/alex09x/xref
 * SPDX-License-Identifier: MIT OR Apache-2.0
 */

use std::collections::hash_map::Entry;
use std::collections::{BTreeSet, HashMap, HashSet};
use std::ops::Range;

use iced_x86::{FlowControl, Instruction, InstructionInfoFactory, OpAccess, Register};

use crate::image::Image;
use crate::listing::is_call;
use crate::scan::{branch_target, decode};
use crate::tables::tables;

pub const GPRS: [Register; 16] = [
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

/// The bit of a general-purpose register in a `u16` mask.
pub fn bit(register: Register) -> Option<u16> {
    GPRS.iter().position(|r| *r == register.full_register()).map(|index| 1 << index)
}

/// `AH`, `BH`, `CH`, `DH`: bits 8..15 of their register, never its low bytes.
pub const fn high_byte(register: Register) -> bool {
    matches!(register, Register::AH | Register::BH | Register::CH | Register::DH)
}

/// Full registers `ins` writes, explicitly or implicitly (`rep stos` writes rcx and rdi,
/// `lock xadd [m], r` writes r, `cmpxchg` writes rax).
pub fn written(factory: &mut InstructionInfoFactory, ins: &Instruction) -> Vec<Register> {
    factory
        .info(ins)
        .used_registers()
        .iter()
        .filter(|used| {
            matches!(
                used.access(),
                OpAccess::Write | OpAccess::ReadWrite | OpAccess::CondWrite | OpAccess::ReadCondWrite
            )
        })
        .map(|used| used.register().full_register())
        .collect()
}

/// Block starts inside `f`: direct branch targets and, when the function jumps through a table,
/// the table's arms.
pub fn targets(image: &Image, f: &Range<u64>, code: &[Instruction]) -> BTreeSet<u64> {
    let mut found: BTreeSet<u64> = code.iter().filter_map(branch_target).filter(|t| f.contains(t)).collect();
    if code.iter().any(|ins| ins.flow_control() == FlowControl::IndirectBranch && !ins.is_ip_rel_memory_operand()) {
        for table in tables(image, f) {
            found.extend(table.arms.iter().copied().filter(|arm| f.contains(arm)));
        }
    }
    found
}

/// Arms of every jump table of `f`: the successors taken for any indirect jump in it.
pub fn arms_of(image: &Image, f: &Range<u64>) -> Vec<u64> {
    tables(image, f).into_iter().flat_map(|table| table.arms).filter(|arm| f.contains(arm)).collect()
}

/// A dataflow state at a block start: `join` merges another path's state in, true when it changed.
pub trait Join: Clone {
    fn join(&mut self, other: &Self) -> bool;
}

/// A may-analysis over the basic blocks of `f` from `code[start]` with `state`: `transfer` steps
/// each instruction, and states flow along fallthrough, branches and jump-table arms, never past a
/// return or a jump leaving the function, until no block start changes.
pub fn propagate<S: Join>(
    image: &Image,
    f: &Range<u64>,
    code: &[Instruction],
    start: usize,
    state: S,
    mut transfer: impl FnMut(&Instruction, &mut S),
) {
    if start >= code.len() {
        return;
    }
    let at: HashMap<u64, usize> = code.iter().enumerate().map(|(i, ins)| (ins.ip(), i)).collect();
    let mut starts: HashSet<usize> = targets(image, f, code).iter().filter_map(|t| at.get(t)).copied().collect();
    starts.extend((1..code.len()).filter(|&i| code[i - 1].flow_control() != FlowControl::Next));
    let arms: Vec<usize> = if code.iter().any(|i| i.flow_control() == FlowControl::IndirectBranch) {
        arms_of(image, f).iter().filter_map(|arm| at.get(arm)).copied().collect()
    } else {
        Vec::new()
    };
    let mut entry: HashMap<usize, S> = HashMap::from([(start, state)]);
    let mut work = vec![start];
    while let Some(first) = work.pop() {
        let mut held = entry[&first].clone();
        let mut index = first;
        loop {
            let ins = &code[index];
            transfer(ins, &mut held);
            let next = index + 1;
            let successors: Vec<usize> = match ins.flow_control() {
                _ if is_call(ins, f) && !matches!(ins.flow_control(), FlowControl::Call | FlowControl::IndirectCall) => {
                    Vec::new()
                }
                FlowControl::Next | FlowControl::Call | FlowControl::IndirectCall => {
                    if next < code.len() && !starts.contains(&next) {
                        index = next;
                        continue;
                    }
                    vec![next]
                }
                FlowControl::ConditionalBranch => {
                    branch_target(ins).and_then(|t| at.get(&t)).copied().into_iter().chain([next]).collect()
                }
                FlowControl::UnconditionalBranch => {
                    branch_target(ins).and_then(|t| at.get(&t)).copied().into_iter().collect()
                }
                FlowControl::IndirectBranch => arms.clone(),
                _ => Vec::new(),
            };
            for successor in successors.into_iter().filter(|s| *s < code.len()) {
                let grew = match entry.entry(successor) {
                    Entry::Occupied(mut known) => known.get_mut().join(&held),
                    Entry::Vacant(slot) => {
                        slot.insert(held.clone());
                        true
                    }
                };
                if grew {
                    work.push(successor);
                }
            }
            break;
        }
    }
}

/// The decoded instructions of the function starting exactly at `start`.
pub fn function_code(image: &Image, start: u64) -> Option<(Range<u64>, Vec<Instruction>)> {
    let f = image.function_at(start).filter(|f| f.start == start)?;
    let bytes = image.code(&f)?;
    let mut code = Vec::new();
    decode(bytes, f.start, |ins| code.push(*ins));
    Some((f, code))
}
