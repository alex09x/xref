/*
 * XRef — Readers of a field through a pointer that is handed around
 * Copyright (c) 2026 Alexander Panasenko
 * Contact: alex@prod.codes
 * Author: https://prod.codes/about/
 * Project: https://github.com/alex09x/xref
 * SPDX-License-Identifier: MIT OR Apache-2.0
 */

//! After a value is copied into an object at `offset`, the code that later reads it reads
//! `[ptr + offset]` through some register holding the object's address. The registers holding it
//! are propagated over the function's blocks (64-bit copies keep it, any write drops it, a call
//! drops the volatile ones) and into callees that receive it in an argument register.

use std::collections::{BTreeSet, HashSet};
use std::ops::Range;

use iced_x86::{FlowControl, Instruction, InstructionInfoFactory, Mnemonic, OpAccess, OpKind, Register};

use super::flow::{Join, bit, function_code, propagate, targets, written};
use super::scan::{Slot, VOLATILE};
use crate::expr::ABI_ARGS;
use crate::graph::call_target;
use crate::image::Image;
use crate::listing::is_call;
use crate::scan;

/// Functions walked for one pointer at most.
const MAX_FUNCTIONS: usize = 64;
/// Instructions scanned back from a call for copies of an argument.
const ALIAS_WINDOW: usize = 64;

/// A read of `[ptr + offset]` with the value's width.
#[derive(Clone, Debug)]
pub struct Reader {
    pub ip: u64,
    pub function: Range<u64>,
    pub text: String,
    /// The functions the pointer was passed to on the way, and in which argument.
    pub via: Vec<(u64, Slot)>,
}

/// Registers holding the pointer, as a `flow::bit` mask.
#[derive(Clone, Copy, PartialEq, Eq)]
struct Mask(u16);

impl Join for Mask {
    fn join(&mut self, other: &Self) -> bool {
        let before = self.0;
        self.0 |= other.0;
        self.0 != before
    }
}

/// Registers equal to `register` just before `code[index]`: it, and registers it was copied from
/// or to (`mov rbx, rdi; ...; mov rdi, rbx`) that are not written again before `index`, within the
/// straight-line run before it.
pub fn aliases_at(image: &Image, f: &Range<u64>, code: &[Instruction], index: usize, register: Register) -> u16 {
    let leaders = targets(image, f, code);
    let mut factory = InstructionInfoFactory::new();
    let (mut chain, mut aliases) = (bit(register).unwrap_or(0), bit(register).unwrap_or(0));
    let mut later: u16 = 0;
    for i in (index.saturating_sub(ALIAS_WINDOW)..index).rev() {
        let ins = &code[i];
        if ins.flow_control() != FlowControl::Next {
            break;
        }
        let writes = written(&mut factory, ins).iter().fold(0, |mask, r| mask | bit(*r).unwrap_or(0));
        let copy = (ins.mnemonic() == Mnemonic::Mov
            && ins.op_count() == 2
            && ins.op0_kind() == OpKind::Register
            && ins.op1_kind() == OpKind::Register
            && ins.op0_register().size() == 8
            && ins.op1_register().size() == 8)
            .then(|| (bit(ins.op0_register()).unwrap_or(0), bit(ins.op1_register()).unwrap_or(0)));
        match copy {
            // `mov d, s` defines a holder from `s`: before it, `s` held the value.
            Some((d, s)) if chain & d != 0 => {
                chain = (chain & !d) | s;
                if later & s == 0 {
                    aliases |= s;
                }
            }
            // `mov d, s` from a holder: `d` holds it too, unless written again before the call.
            Some((d, s)) if chain & s != 0 && later & d == 0 => aliases |= d,
            _ => chain &= !writes,
        }
        later |= writes;
        if chain == 0 || leaders.contains(&ins.ip()) {
            break;
        }
    }
    aliases
}

/// Reads of `[holder + offset]`, `width` bytes, from `code[start]` on in `f`, and in callees the
/// pointer is passed to, up to `depth` calls deeper.
#[allow(clippy::too_many_arguments)]
pub fn readers(
    image: &Image,
    f: &Range<u64>,
    code: &[Instruction],
    start: usize,
    holders: u16,
    offset: u64,
    width: usize,
    depth: usize,
) -> Vec<Reader> {
    let mut seen = HashSet::new();
    let mut found = Vec::new();
    walk(image, f, code, start, holders, &Want { offset, width }, depth, &[], &mut seen, &mut found);
    found
}

struct Want {
    offset: u64,
    width: usize,
}

#[allow(clippy::too_many_arguments)]
fn walk(
    image: &Image,
    f: &Range<u64>,
    code: &[Instruction],
    start: usize,
    holders: u16,
    want: &Want,
    depth: usize,
    via: &[(u64, Slot)],
    seen: &mut HashSet<(u64, Slot)>,
    found: &mut Vec<Reader>,
) {
    let mut factory = InstructionInfoFactory::new();
    let mut passed: BTreeSet<(u64, Slot)> = BTreeSet::new();
    let mut hits: BTreeSet<u64> = BTreeSet::new();
    let mut texts = Vec::new();
    propagate(image, f, code, start, Mask(holders), |ins, mask| {
        let holds = |register: Register| bit(register).is_some_and(|b| mask.0 & b != 0);
        for used in factory.info(ins).used_memory() {
            if holds(used.base())
                && used.index() == Register::None
                && used.displacement() == want.offset
                && used.memory_size().size() == want.width
                && matches!(used.access(), OpAccess::Read | OpAccess::CondRead | OpAccess::ReadWrite)
                && hits.insert(ins.ip())
            {
                texts.push((ins.ip(), scan::format(ins)));
            }
        }
        if is_call(ins, f) {
            if let Some(target) = call_target(image, ins) {
                for (index, argument) in ABI_ARGS.iter().enumerate() {
                    if holds(*argument) {
                        passed.insert((target, Slot::Reg(index)));
                    }
                }
            }
            for volatile in VOLATILE {
                mask.0 &= !bit(volatile).unwrap_or(0);
            }
            return;
        }
        let copy = ins.mnemonic() == Mnemonic::Mov
            && ins.op_count() == 2
            && ins.op0_kind() == OpKind::Register
            && ins.op1_kind() == OpKind::Register
            && ins.op0_register().size() == 8
            && holds(ins.op1_register());
        let gained = if copy { bit(ins.op0_register()).unwrap_or(0) } else { 0 };
        for register in written(&mut factory, ins) {
            mask.0 &= !bit(register).unwrap_or(0);
        }
        mask.0 |= gained;
    });
    found.extend(texts.into_iter().map(|(ip, text)| Reader { ip, function: f.clone(), text, via: via.to_vec() }));
    if depth == 0 {
        return;
    }
    for hop in passed {
        if seen.len() >= MAX_FUNCTIONS || !seen.insert(hop) {
            continue;
        }
        let Some((callee, callee_code)) = function_code(image, hop.0) else { continue };
        let Some(start_bit) = hop.1.register().and_then(bit) else { continue };
        let mut path = via.to_vec();
        path.push(hop);
        walk(image, &callee, &callee_code, 0, start_bit, want, depth - 1, &path, seen, found);
    }
}
