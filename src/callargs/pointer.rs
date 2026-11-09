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
use super::spill;
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

/// Registers holding the pointer (a `flow::bit` mask), and the frame slots it is spilled to
/// (entry-relative `rsp` offsets).
#[derive(Clone, PartialEq, Eq)]
struct Mask(u16, BTreeSet<i64>);

impl Join for Mask {
    fn join(&mut self, other: &Self) -> bool {
        let before = (self.0, self.1.len());
        self.0 |= other.0;
        self.1.extend(other.1.iter().copied());
        (self.0, self.1.len()) != before
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

/// A field of an object: its offset and width, in an object of `size` bytes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Field {
    pub offset: u64,
    pub width: usize,
    pub size: u64,
}

/// Reads of `[holder + field.offset]`, `field.width` bytes, from `code[start]` on in `f`, and in
/// callees the pointer is passed to, up to `depth` calls deeper; through a copy of the object onto
/// a frame too (`copy_in`).
pub fn readers(
    image: &Image,
    f: &Range<u64>,
    code: &[Instruction],
    start: usize,
    holders: u16,
    field: Field,
    depth: usize,
) -> Vec<Reader> {
    let mut seen = HashSet::new();
    let mut found = Vec::new();
    walk(image, f, code, start, (holders, 0), field, depth, &[], &mut seen, &mut found);
    found
}

/// Reads of the field from `code[start]` on, where `code[start - 1]` is an instruction the pointer
/// survives (a call, a copy): `holders` hold it at `code[start]`, and a slot one of `spilled` (the
/// registers holding it before that instruction) was spilled to holds it too.
#[allow(clippy::too_many_arguments)]
pub fn readers_after(
    image: &Image,
    f: &Range<u64>,
    code: &[Instruction],
    start: usize,
    holders: u16,
    spilled: u16,
    field: Field,
    depth: usize,
) -> Vec<Reader> {
    let mut seen = HashSet::new();
    let mut found = Vec::new();
    walk(image, f, code, start, (holders, spilled), field, depth, &[], &mut seen, &mut found);
    found
}

/// Reads of the field after `code[call]` in `f`, through `aliases` (the registers holding the pointer
/// at the call): the callee-saved ones keep it across the call, and a slot any of them was spilled
/// to before the call holds it too (`mov [rsp+8], rdi; call; mov rdi, [rsp+8]`).
pub fn readers_after_call(
    image: &Image,
    f: &Range<u64>,
    code: &[Instruction],
    call: usize,
    aliases: u16,
    field: Field,
    depth: usize,
) -> Vec<Reader> {
    let volatile = VOLATILE.iter().fold(0u16, |mask, r| mask | bit(*r).unwrap_or(0));
    readers_after(image, f, code, call + 1, aliases & !volatile, aliases, field, depth)
}

#[allow(clippy::too_many_arguments)]
fn walk(
    image: &Image,
    f: &Range<u64>,
    code: &[Instruction],
    start: usize,
    // The registers holding the pointer at `start`, and those whose earlier spills count.
    (holders, spilled): (u16, u16),
    want: Field,
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
    // Frame facts, for a pointer kept in a stack slot across a call (`mov [rsp+8], rdi; call;
    // mov rdi, [rsp+8]`).
    let facts = super::copy_in::facts(image, f, code);
    let seeded = spill::spilled_before(image, code, &facts, start, spilled);
    if holders == 0 && seeded.is_empty() {
        return;
    }
    propagate(image, f, code, start, Mask(holders, seeded), |ins, mask| {
        let held = facts.get(&ins.ip());
        let holders = mask.0;
        let holds = |register: Register| bit(register).is_some_and(|b| holders & b != 0);
        // A reload of a slot holding the pointer, a spill of a holder, and what the write ends.
        let reload = ins.mnemonic() == Mnemonic::Mov
            && ins.op_count() == 2
            && ins.op0_kind() == OpKind::Register
            && ins.op0_register().size() == 8
            && ins.op1_kind() == OpKind::Memory
            && spill::slot(ins, held).is_some_and(|at| mask.1.contains(&at));
        let spilled_to = spill::spill_slot(ins, held, holds);
        let writes = spill::frame_writes(image, ins, held, &mut factory);
        spill::clobber(&mut mask.1, writes.as_deref());
        if let Some(at) = spilled_to {
            mask.1.insert(at);
        }
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
        // A copy of a holder, or a reload of a slot the pointer was spilled to.
        let copy = reload
            || (ins.mnemonic() == Mnemonic::Mov
                && ins.op_count() == 2
                && ins.op0_kind() == OpKind::Register
                && ins.op0_register().size() == 8
                && ins.op1_kind() == OpKind::Register
                && holds(ins.op1_register()));
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
        for at in copies_in {
            let Some(call) = code.iter().position(|ins| ins.ip() == at) else { continue };
            found.extend(super::copy_in::copy_in_readers(image, f, code, &facts, call, want, depth).into_iter().map(
                |mut reader| {
                    let mut path = via.to_vec();
                    path.append(&mut reader.via);
                    reader.via = path;
                    reader
                },
            ));
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
        walk(image, &callee, &callee_code, 0, (start_bit, start_bit), want, depth - 1, &path, seen, found);
    }
}
