/*
 * XRef — Where a function stores a value it receives in an argument register
 * Copyright (c) 2026 Alexander Panasenko
 * Contact: alex@prod.codes
 * Author: https://prod.codes/about/
 * Project: https://github.com/alex09x/xref
 * SPDX-License-Identifier: MIT OR Apache-2.0
 */

//! Stores of an incoming argument. The registers that may hold it (the argument and its copies
//! wide enough to keep the stored width) are propagated over the function's basic blocks: along
//! branches, jump-table arms and fallthrough, never past a return or a jump leaving the function.
//! Any write of a register drops it, and a call drops the volatile ones. A value passed on to
//! another function in an argument register is followed one call deeper.

use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};
use std::ops::Range;

use iced_x86::{FlowControl, Instruction, InstructionInfoFactory, Mnemonic, OpKind, Register};

use super::flow::{arms_of, bit, high_byte, targets, written};
use super::scan::{Slot, VOLATILE};
use crate::expr::ABI_ARGS;
use crate::graph::call_target;
use crate::image::Image;
use crate::listing::is_call;
use crate::scan::{self, branch_target, decode};

#[derive(Clone)]
pub struct ArgStore {
    pub ip: u64,
    pub text: String,
    pub base: Register,
    pub indexed: bool,
    pub displacement: u64,
    /// The function the value was passed on to, and in which argument, when the store is there.
    pub via: Option<(u64, Slot)>,
}

impl ArgStore {
    /// A store at `displacement` of an object that is not the stack frame.
    pub const fn at_object_offset(&self, displacement: u64) -> bool {
        self.object_field() && self.displacement == displacement
    }

    /// A field of an object: not the stack frame or a global, and no index register (an element
    /// of a buffer).
    pub const fn object_field(&self) -> bool {
        !self.indexed && !matches!(self.base, Register::RSP | Register::RBP | Register::RIP | Register::None)
    }
}

/// `width`-byte stores of the value the function starting at `callee` receives in `slot`, and,
/// with `forward`, of the functions it passes the value on to.
pub fn arg_stores(image: &Image, callee: u64, slot: Slot, width: usize, forward: bool) -> Vec<ArgStore> {
    let Some(start) = slot.register().and_then(bit) else { return Vec::new() };
    let Some(f) = image.function_at(callee).filter(|f| f.start == callee) else { return Vec::new() };
    let Some(bytes) = image.code(&f) else { return Vec::new() };
    let mut code = Vec::new();
    decode(bytes, f.start, |ins| code.push(*ins));
    let mut walk = Walk { image, f: &f, callee, width, forward, stores: BTreeMap::new(), passed: BTreeSet::new() };
    walk.run(&code, start);
    let Walk { stores, passed, .. } = walk;
    let mut found: Vec<ArgStore> = stores.into_values().collect();
    for (target, argument) in passed {
        for mut store in arg_stores(image, target, argument, width, false) {
            store.via = Some((target, argument));
            found.push(store);
        }
    }
    found
}

struct Walk<'a> {
    image: &'a Image,
    f: &'a Range<u64>,
    callee: u64,
    width: usize,
    forward: bool,
    stores: BTreeMap<u64, ArgStore>,
    passed: BTreeSet<(u64, Slot)>,
}

impl Walk<'_> {
    fn run(&mut self, code: &[Instruction], start: u16) {
        let at: HashMap<u64, usize> = code.iter().enumerate().map(|(i, ins)| (ins.ip(), i)).collect();
        let mut starts: HashSet<usize> =
            targets(self.image, self.f, code).iter().filter_map(|t| at.get(t)).copied().collect();
        starts.extend((1..code.len()).filter(|&i| code[i - 1].flow_control() != FlowControl::Next));
        let arms: Vec<usize> = if code.iter().any(|i| i.flow_control() == FlowControl::IndirectBranch) {
            arms_of(self.image, self.f).iter().filter_map(|arm| at.get(arm)).copied().collect()
        } else {
            Vec::new()
        };
        let mut factory = InstructionInfoFactory::new();
        let mut entry: HashMap<usize, u16> = HashMap::from([(0, start)]);
        let mut work = vec![0];
        while let Some(first) = work.pop() {
            let mut mask = entry[&first];
            let mut index = first;
            loop {
                let ins = &code[index];
                self.transfer(ins, &mut mask, &mut factory);
                let next = index + 1;
                let successors: Vec<usize> = match ins.flow_control() {
                    _ if is_call(ins, self.f)
                        && !matches!(ins.flow_control(), FlowControl::Call | FlowControl::IndirectCall) =>
                    {
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
                    let known = entry.entry(successor).or_insert(0);
                    if *known | mask != *known {
                        *known |= mask;
                        work.push(successor);
                    }
                }
                break;
            }
        }
    }

    fn transfer(&mut self, ins: &Instruction, mask: &mut u16, factory: &mut InstructionInfoFactory) {
        let holds =
            |register: Register, mask: u16| !high_byte(register) && bit(register).is_some_and(|b| mask & b != 0);
        if is_call(ins, self.f) {
            if self.forward
                && let Some(target) = call_target(self.image, ins).filter(|t| *t != self.callee)
            {
                for (index, argument) in ABI_ARGS.iter().enumerate() {
                    if holds(*argument, *mask) {
                        self.passed.insert((target, Slot::Reg(index)));
                    }
                }
            }
            for volatile in VOLATILE {
                *mask &= !bit(volatile).unwrap_or(0);
            }
            return;
        }
        if ins.mnemonic() == Mnemonic::Mov
            && ins.op0_kind() == OpKind::Memory
            && ins.op1_kind() == OpKind::Register
            && holds(ins.op1_register(), *mask)
            && ins.memory_size().size() == self.width
        {
            self.stores.entry(ins.ip()).or_insert_with(|| ArgStore {
                ip: ins.ip(),
                text: scan::format(ins),
                base: ins.memory_base().full_register(),
                indexed: ins.memory_index() != Register::None,
                displacement: ins.memory_displacement64(),
                via: None,
            });
        }
        // A copy keeps the value when both registers are at least as wide as the stored width.
        let copy = (matches!(ins.mnemonic(), Mnemonic::Mov | Mnemonic::Movzx | Mnemonic::Movsx | Mnemonic::Movsxd)
            && ins.op0_kind() == OpKind::Register
            && ins.op1_kind() == OpKind::Register
            && holds(ins.op1_register(), *mask)
            && !high_byte(ins.op0_register())
            && ins.op1_register().size() >= self.width
            && ins.op0_register().size() >= self.width)
            .then(|| bit(ins.op0_register()))
            .flatten();
        for register in written(factory, ins) {
            *mask &= !bit(register).unwrap_or(0);
        }
        if let Some(copy) = copy {
            *mask |= copy;
        }
    }
}
