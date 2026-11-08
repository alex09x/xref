/*
 * XRef — Reads of a field after a record is copied onto the reader's own stack (copy-in)
 * Copyright (c) 2026 Alexander Panasenko
 * Contact: alex@prod.codes
 * Author: https://prod.codes/about/
 * Project: https://github.com/alex09x/xref
 * SPDX-License-Identifier: MIT OR Apache-2.0
 */

//! A reader of a record often copies it onto its own frame first (`lea rdi, [rsp+0x470]; mov rsi,
//! r14; mov edx, 0x2c8; call memcpy`, or `mov rbx, rsp; mov rdi, rbx` as LLVM writes it) and reads
//! the field there (`movzx eax, byte [rsp+0x580]`). The frame facts before every instruction
//! (`rsp`, registers holding frame addresses, constants) come from a dataflow (`facts`). From the
//! copy on, a second one follows the copy while it lives: its field read off `rsp` or off a
//! register holding the copy's address is a reader, a callee handed that address is searched too,
//! and any write over the field (or a call clobbering it below `rsp`) ends it.

use std::collections::{BTreeSet, HashMap};
use std::ops::Range;

use iced_x86::{FlowControl, Instruction, InstructionInfoFactory, Mnemonic, OpAccess, OpKind, Register};

use super::copy::copy_op;
use super::flow::{Join, bit, function_code, propagate, settled, written};
use super::frame::Held;
use super::pointer::{Field, Reader, readers};
use super::scan::{Slot, VOLATILE};
use crate::expr::ABI_ARGS;
use crate::graph::call_target;
use crate::image::Image;
use crate::listing::is_call;
use crate::scan;

/// The frame facts before each instruction of `f` (`rsp`, frame addresses and constants in
/// registers), settled over every path.
pub fn facts(image: &Image, f: &Range<u64>, code: &[Instruction]) -> HashMap<u64, Held> {
    let mut at = HashMap::new();
    let mut factory = InstructionInfoFactory::new();
    settled(image, f, code, 0, Held::entry(0), |ins, held, record| {
        if record {
            at.insert(ins.ip(), held.clone());
        }
        step(ins, held, &mut factory);
    });
    at
}

/// The frame facts after `ins`: `rsp` moves (`push`/`pop reg`, `sub`/`add rsp, imm`; any other
/// write loses it), facts about written registers dropped, new ones learned, volatile registers
/// dropped at a call.
fn step(ins: &Instruction, held: &mut Held, factory: &mut InstructionInfoFactory) {
    if matches!(ins.flow_control(), FlowControl::Call | FlowControl::IndirectCall) {
        for volatile in VOLATILE {
            held.forget(volatile);
        }
        return;
    }
    let learned = held.learned(ins);
    let immediate = ins.op_count() == 2
        && ins.op0_kind() == OpKind::Register
        && ins.op0_register() == Register::RSP
        && matches!(ins.op1_kind(), OpKind::Immediate8to64 | OpKind::Immediate32to64);
    let pops_rsp = ins.op_count() == 1
        && ins.op0_kind() == OpKind::Register
        && ins.op0_register().full_register() == Register::RSP;
    let writes = written(factory, ins);
    if writes.contains(&Register::RSP) {
        let moved = match ins.mnemonic() {
            Mnemonic::Sub if immediate => ins.immediate(1).cast_signed().checked_neg(),
            Mnemonic::Add if immediate => Some(ins.immediate(1).cast_signed()),
            Mnemonic::Push | Mnemonic::Pop if !pops_rsp && ins.stack_pointer_increment() != 0 => {
                Some(i64::from(ins.stack_pointer_increment()))
            }
            _ => None,
        };
        let frame = held.frame.zip(moved).and_then(|(frame, moved)| frame.checked_add(moved));
        held.set_frame(frame);
    }
    for register in writes {
        if register != Register::RSP {
            held.forget(register);
        }
    }
    held.learn(learned);
}

/// The copy, while it lives on a path: registers holding its address (a `flow::bit` mask).
#[derive(Clone, Copy, PartialEq, Eq)]
struct Live {
    alive: bool,
    holders: u16,
}

impl Join for Live {
    fn join(&mut self, other: &Self) -> bool {
        let before = *self;
        self.alive |= other.alive;
        self.holders |= other.holders;
        *self != before
    }
}

/// The reads of `field` of a record (`field.size` bytes) copied onto the frame by the copy call at
/// `code[call]` (destination in `rdi`, size in `rdx`), after the copy in `f` and in callees handed
/// the copy's address (up to `depth` calls deeper).
pub fn copy_in_readers(
    image: &Image,
    f: &Range<u64>,
    code: &[Instruction],
    facts: &HashMap<u64, Held>,
    call: usize,
    field: Field,
    depth: usize,
) -> Vec<Reader> {
    // A tail jump to the copy routine never comes back to read the copy.
    if !matches!(code[call].flow_control(), FlowControl::Call | FlowControl::IndirectCall) {
        return Vec::new();
    }
    let Some(before) = facts.get(&code[call].ip()) else { return Vec::new() };
    let (Some(&destination), Some(&size), Some(frame)) =
        (before.addrs.get(&Register::RDI), before.consts.get(&Register::RDX), before.frame)
    else {
        return Vec::new();
    };
    // A copy of this record, into this function's own frame above `rsp`.
    let end = destination.checked_add_unsigned(size);
    if size != field.size || destination < frame || end.is_none_or(|end| end > 0) || field.offset >= size {
        return Vec::new();
    }
    let Some(at) = destination.checked_add_unsigned(field.offset) else { return Vec::new() };
    let field_end = at.saturating_add_unsigned(field.width as u64);
    let note =
        format!("copy-in at {:#x} to [rsp+{:#x}], field +{:#x}", code[call].ip(), destination - frame, field.offset);
    // After the call: `rax` returns the destination, and callee-saved registers holding it keep it.
    let volatile = VOLATILE.iter().fold(0u16, |mask, r| mask | bit(*r).unwrap_or(0));
    let holders = before
        .addrs
        .iter()
        .filter(|(_, address)| **address == destination)
        .fold(0u16, |mask, (register, _)| mask | bit(*register).unwrap_or(0))
        & !volatile
        | bit(Register::RAX).unwrap_or(0);
    let mut follow = Follow {
        image,
        f,
        facts,
        destination,
        at,
        field_end,
        width: field.width as u64,
        volatile,
        factory: InstructionInfoFactory::new(),
        hits: BTreeSet::new(),
        texts: Vec::new(),
        callees: BTreeSet::new(),
    };
    propagate(image, f, code, call + 1, Live { alive: true, holders }, |ins, live| follow.step(ins, live));
    let Follow { texts, callees, .. } = follow;
    let mut found: Vec<Reader> = texts
        .into_iter()
        .map(|(ip, text)| Reader { ip, function: f.clone(), text, via: Vec::new(), note: Some(note.clone()) })
        .collect();
    if depth > 0 {
        for (callee, slot) in callees {
            let Some((g, callee_code)) = function_code(image, callee) else { continue };
            let Some(start) = slot.register().and_then(bit) else { continue };
            found.extend(readers(image, &g, &callee_code, 0, start, field, depth - 1).into_iter().map(|mut r| {
                r.via.insert(0, (callee, slot));
                // A callee that copies it again keeps its own note after this one.
                r.note = Some(r.note.map_or_else(|| note.clone(), |inner| format!("{note}, then {inner}")));
                r
            }));
        }
    }
    found
}

/// Following one copy: where it is, and what was found.
struct Follow<'a> {
    image: &'a Image,
    f: &'a Range<u64>,
    facts: &'a HashMap<u64, Held>,
    /// Entry-relative: the copy, its field and the end of the field.
    destination: i64,
    at: i64,
    field_end: i64,
    width: u64,
    volatile: u16,
    factory: InstructionInfoFactory,
    hits: BTreeSet<u64>,
    texts: Vec<(u64, String)>,
    callees: BTreeSet<(u64, Slot)>,
}

impl Follow<'_> {
    fn step(&mut self, ins: &Instruction, live: &mut Live) {
        if !live.alive {
            return;
        }
        let (image, f, destination, at, field_end, volatile) =
            (self.image, self.f, self.destination, self.at, self.field_end, self.volatile);
        let state = self.facts.get(&ins.ip());
        let rsp = state.and_then(|state| state.frame);
        let holders = live.holders;
        let holds = |register: Register| bit(register).is_some_and(|b| holders & b != 0);
        let explicit = (0..ins.op_count()).any(|k| ins.op_kind(k) == OpKind::Memory);
        let mut ends = false;
        let (hits, texts, factory) = (&mut self.hits, &mut self.texts, &mut self.factory);
        for used in factory.info(ins).used_memory() {
            let reads = matches!(
                used.access(),
                OpAccess::Read | OpAccess::CondRead | OpAccess::ReadWrite | OpAccess::ReadCondWrite
            );
            let writes = matches!(
                used.access(),
                OpAccess::Write | OpAccess::CondWrite | OpAccess::ReadWrite | OpAccess::ReadCondWrite
            );
            // Where the access lands, entry-relative: off `rsp`, or off a register holding the copy.
            let place = if used.index() != Register::None {
                None
            } else if used.base() == Register::RSP {
                rsp.and_then(|rsp| rsp.checked_add(used.displacement().cast_signed()))
            } else if holds(used.base()) {
                destination.checked_add(used.displacement().cast_signed())
            } else {
                continue;
            };
            let size = used.memory_size().size().max(1) as u64;
            if reads && explicit && place == Some(at) && size == self.width && hits.insert(ins.ip()) {
                texts.push((ins.ip(), scan::format(ins)));
            }
            // A write over the field ends the copy; so does one that cannot be placed.
            let overlaps = place.is_none_or(|place| place < field_end && at < place.saturating_add_unsigned(size));
            if writes && overlaps {
                ends = true;
            }
        }
        if matches!(ins.op0_kind(), OpKind::MemoryESDI | OpKind::MemoryESEDI | OpKind::MemoryESRDI) {
            ends = true;
        }
        if is_call(ins, f) {
            if let Some(target) = call_target(image, ins) {
                for (index, argument) in ABI_ARGS.iter().enumerate() {
                    if holds(*argument) {
                        self.callees.insert((target, Slot::Reg(index)));
                    }
                }
            }
            // Another copy into this frame may overwrite it; a callee's frame below `rsp` would.
            let copies_over = copy_op(image, ins)
                .is_some_and(|_| state.and_then(|s| s.addrs.get(&Register::RDI)).is_none_or(|d| *d < field_end));
            if copies_over || rsp.is_none_or(|rsp| rsp > at) {
                ends = true;
            }
            live.holders &= !volatile;
        } else {
            let copy = ins.mnemonic() == Mnemonic::Mov
                && ins.op_count() == 2
                && ins.op0_kind() == OpKind::Register
                && ins.op1_kind() == OpKind::Register
                && ins.op0_register().size() == 8
                && holds(ins.op1_register());
            let gained = if copy { bit(ins.op0_register()).unwrap_or(0) } else { 0 };
            for register in written(&mut self.factory, ins) {
                live.holders &= !bit(register).unwrap_or(0);
            }
            live.holders |= gained;
        }
        if ends {
            live.alive = false;
        }
    }
}
