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

use super::flow::{GPRS, Join, bit, function_code, propagate, targets, written};
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
    /// How the read reaches the field when not directly: `copy-in at 0x… to [rsp+0x470], field
    /// +0x110`.
    pub note: Option<String>,
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

/// Registers equal to `register` just before `code[index]`, within the basic block holding it:
/// a forward value numbering from the block's start (at most `ALIAS_WINDOW` instructions back),
/// where a 64-bit `mov d, s` gives `d` the value of `s` and any other write a fresh value. Siblings
/// copied from a common source (`mov rdi, rax; mov rbx, rax`) share it too.
pub fn aliases_at(image: &Image, f: &Range<u64>, code: &[Instruction], index: usize, register: Register) -> u16 {
    let Some(wanted) = GPRS.iter().position(|r| *r == register.full_register()) else { return 0 };
    let leaders = targets(image, f, code);
    // The block start: stop at a branch target, or after an instruction that does not fall through.
    let mut first = index;
    while first > 0
        && index - first < ALIAS_WINDOW
        && !leaders.contains(&code[first].ip())
        && code[first - 1].flow_control() == FlowControl::Next
    {
        first -= 1;
    }
    let mut factory = InstructionInfoFactory::new();
    let mut value: [usize; 16] = std::array::from_fn(|i| i);
    let mut fresh = value.len();
    for ins in &code[first..index] {
        let copy = (ins.mnemonic() == Mnemonic::Mov
            && ins.op_count() == 2
            && ins.op0_kind() == OpKind::Register
            && ins.op1_kind() == OpKind::Register
            && ins.op0_register().size() == 8
            && ins.op1_register().size() == 8)
            .then(|| {
                let at = |r: Register| GPRS.iter().position(|g| *g == r.full_register());
                at(ins.op0_register()).zip(at(ins.op1_register()))
            })
            .flatten();
        let source = copy.map(|(_, s)| value[s]);
        for written in written(&mut factory, ins) {
            if let Some(at) = GPRS.iter().position(|g| *g == written) {
                value[at] = fresh;
                fresh += 1;
            }
        }
        if let (Some((d, _)), Some(source)) = (copy, source) {
            value[d] = source;
        }
    }
    (0..16).filter(|&i| value[i] == value[wanted]).fold(0, |mask, i| mask | (1 << i))
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
    let mut copies_in: BTreeSet<u64> = BTreeSet::new();
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
            // `memcpy(&local, ptr, n)`: the field is read from the copy on this frame.
            if super::copy::copy_op(image, ins).is_some_and(|op| op.call && holds(op.source)) {
                copies_in.insert(ins.ip());
            }
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
    found.extend(texts.into_iter().map(|(ip, text)| Reader {
        ip,
        function: f.clone(),
        text,
        via: via.to_vec(),
        note: None,
    }));
    if !copies_in.is_empty() {
        let frames = super::copy_in::frames(image, f, code);
        for at in copies_in {
            let Some(call) = code.iter().position(|ins| ins.ip() == at) else { continue };
            found.extend(
                super::copy_in::copy_in_readers(image, f, code, &frames, call, want.offset, want.width, depth)
                    .into_iter()
                    .map(|mut reader| {
                        let mut path = via.to_vec();
                        path.append(&mut reader.via);
                        reader.via = path;
                        reader
                    }),
            );
        }
    }
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
