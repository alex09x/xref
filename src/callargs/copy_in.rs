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

use super::copy::{copy_op_at, loads_copy_routine};
use super::flow::{Join, bit, function_code, propagate, settled, written};
use super::frame::Held;
use super::pointer::{Field, Reader, field_read, readers};
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
        step(image, ins, held, &mut factory);
    });
    at
}

/// The frame facts after `ins`: `rsp` moves (`push`/`pop reg`, `sub`/`add rsp, imm`; any other
/// write loses it), facts about written registers dropped, new ones learned, volatile registers
/// dropped at a call.
fn step(image: &Image, ins: &Instruction, held: &mut Held, factory: &mut InstructionInfoFactory) {
    if matches!(ins.flow_control(), FlowControl::Call | FlowControl::IndirectCall) {
        for volatile in VOLATILE {
            held.forget(volatile);
        }
        return;
    }
    let learned = held.learned(ins);
    let frame_pointer = held.frame_pointer(ins);
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
    if let Some((register, routine)) = loads_copy_routine(image, ins) {
        held.copiers.insert(register, routine);
    }
    if let Some(register) = frame_pointer {
        held.frame_ptrs |= bit(register).unwrap_or(0);
    }
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

/// Copies of a copy followed at most (`memcpy(&a, element, n); memcpy(&b, &a, n)`).
const MAX_MOVES: usize = 4;

/// The reads of `field` of a record (`field.size` bytes) copied onto the frame by the copy call at
/// `code[call]` (destination in `rdi`, size in `rdx`), after the copy in `f` and in callees handed
/// the copy's address (up to `depth` calls deeper). The copy takes the record's bytes from `from`
/// on (`memcpy(&local, element + 8, 0x2c0)`), so the field lands at `destination + field - from`;
/// it is followed again through a copy of the copy that carries the field.
#[allow(clippy::too_many_arguments)]
pub fn copy_in_readers(
    image: &Image,
    f: &Range<u64>,
    code: &[Instruction],
    facts: &HashMap<u64, Held>,
    call: usize,
    from: u64,
    field: Field,
    depth: usize,
) -> Vec<Reader> {
    let Some(before) = facts.get(&code[call].ip()) else { return Vec::new() };
    let (Some(&destination), Some(&size), Some(frame)) =
        (before.addrs.get(&Register::RDI), before.consts.get(&Register::RDX), before.frame)
    else {
        return Vec::new();
    };
    // Bytes of this record that hold the field, into this function's own frame above `rsp`.
    let (width, end) = (field.width as u64, destination.checked_add_unsigned(size));
    let covers = from <= field.offset
        && field.offset.saturating_add(width) <= from.saturating_add(size)
        && from.saturating_add(size) <= field.size;
    if !covers || destination < frame || end.is_none_or(|end| end > 0) {
        return Vec::new();
    }
    let Some(base) = destination.checked_sub_unsigned(from) else { return Vec::new() };
    let note =
        format!("copy-in at {:#x} to [rsp+{:#x}], field +{:#x}", code[call].ip(), destination - frame, field.offset);
    let mut seen = BTreeSet::new();
    follow(image, f, code, facts, (call, base, destination), field, depth, &note, &mut seen)
}

/// The reads of `field` after the copy at `code[call]`, with the record (as if copied whole) at
/// entry-relative `base`; then after each copy of it that carries the field.
#[allow(clippy::too_many_arguments)]
fn follow(
    image: &Image,
    f: &Range<u64>,
    code: &[Instruction],
    facts: &HashMap<u64, Held>,
    (call, base, low): (usize, i64, i64),
    field: Field,
    depth: usize,
    note: &str,
    seen: &mut BTreeSet<(u64, i64)>,
) -> Vec<Reader> {
    // A tail jump to the copy routine never comes back to read the copy.
    if !matches!(code[call].flow_control(), FlowControl::Call | FlowControl::IndirectCall) {
        return Vec::new();
    }
    let Some(before) = facts.get(&code[call].ip()) else { return Vec::new() };
    let Some(at) = base.checked_add_unsigned(field.offset) else { return Vec::new() };
    let field_end = at.saturating_add_unsigned(field.width as u64);
    // After the call: `rax` returns the destination, and callee-saved registers holding the
    // record's address keep it.
    let volatile = VOLATILE.iter().fold(0u16, |mask, r| mask | bit(*r).unwrap_or(0));
    let returned = if before.addrs.get(&Register::RDI) == Some(&base) { bit(Register::RAX).unwrap_or(0) } else { 0 };
    let holders = before
        .addrs
        .iter()
        .filter(|(_, address)| **address == base)
        .fold(0u16, |mask, (register, _)| mask | bit(*register).unwrap_or(0))
        & !volatile
        | returned;
    let mut walk = Follow {
        image,
        f,
        facts,
        destination: base,
        low,
        at,
        field_end,
        width: field.width as u64,
        volatile,
        factory: InstructionInfoFactory::new(),
        hits: BTreeSet::new(),
        texts: Vec::new(),
        callees: BTreeSet::new(),
        moves: Vec::new(),
    };
    propagate(image, f, code, call + 1, Live { alive: true, holders }, |ins, live| walk.step(ins, live));
    let Follow { texts, callees, moves, .. } = walk;
    let mut found: Vec<Reader> = texts
        .into_iter()
        .map(|(ip, text, how)| {
            let note = how.map_or_else(|| note.to_owned(), |how| format!("{note}, {how}"));
            Reader { ip, function: f.clone(), text, via: Vec::new(), note: Some(note) }
        })
        .collect();
    for (ip, moved, into) in moves {
        if seen.len() >= MAX_MOVES || !seen.insert((ip, moved)) {
            continue;
        }
        let Some(index) = code.iter().position(|ins| ins.ip() == ip) else { continue };
        let frame = facts.get(&ip).and_then(|held| held.frame).unwrap_or(0);
        let then = format!("{note}, then copied at {ip:#x} to [rsp+{:#x}]", into - frame);
        found.extend(follow(image, f, code, facts, (index, moved, into), field, depth, &then, seen));
    }
    if depth > 0 {
        for (callee, slot, offset) in callees {
            let Some((g, callee_code)) = function_code(image, callee) else { continue };
            let Some(start) = slot.register().and_then(bit) else { continue };
            let field = Field { offset, ..field };
            found.extend(readers(image, &g, &callee_code, 0, start, field, depth - 1).into_iter().map(|mut r| {
                r.via.insert(0, (callee, slot));
                // A callee that copies it again keeps its own note after this one.
                r.note = Some(r.note.map_or_else(|| note.to_owned(), |inner| format!("{note}, then {inner}")));
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
    /// Entry-relative: the record's base (as if copied whole), the first byte copied, the field
    /// and the end of the field.
    destination: i64,
    low: i64,
    at: i64,
    field_end: i64,
    width: u64,
    volatile: u16,
    factory: InstructionInfoFactory,
    hits: BTreeSet<u64>,
    texts: Vec<(u64, String, Option<String>)>,
    /// Callees handed the record, or an address inside the copy before the field (an enum's
    /// payload): the argument, and the field's distance from that address.
    callees: BTreeSet<(u64, Slot, u64)>,
    /// Copies of the field elsewhere on the frame: the copy call, the record's base there and the
    /// copy's destination.
    moves: Vec<(u64, i64, i64)>,
}

impl Follow<'_> {
    /// A call, with the frame facts before it and the registers holding the record's address:
    /// a callee handed the record (or an address inside the copy before the field) may read it, a
    /// copy whose source holds the field moves it elsewhere on the frame, and a copy whose
    /// destination may reach the field (`into_frame`: `rdi` may address the frame) ends it.
    fn at_call(&mut self, ins: &Instruction, state: Option<&Held>, holders: u16, into_frame: bool) -> bool {
        let (image, destination, at, field_end) = (self.image, self.destination, self.at, self.field_end);
        let holds = |register: Register| bit(register).is_some_and(|b| holders & b != 0);
        let address = |register: Register| {
            if holds(register) { Some(destination) } else { state.and_then(|s| s.addrs.get(&register).copied()) }
        };
        // A call that returns: it may read the copy through its arguments. A tail jump cannot be
        // handed this frame's object.
        if matches!(ins.flow_control(), FlowControl::Call | FlowControl::IndirectCall)
            && let Some(target) = call_target(image, ins)
        {
            for (index, argument) in ABI_ARGS.iter().enumerate() {
                if let Some(address) = address(*argument).filter(|&a| a == destination || (self.low <= a && a <= at)) {
                    self.callees.insert((target, Slot::Reg(index), (at - address).cast_unsigned()));
                }
            }
        }
        let Some(op) = copy_op_at(image, ins, state) else { return false };
        let rsp = state.and_then(|s| s.frame);
        let into = state.and_then(|s| s.addrs.get(&Register::RDI).copied());
        let bytes = state.and_then(|s| s.consts.get(&Register::RDX).copied());
        // The record's base where the copy puts the field: its destination less the field's
        // distance into the source.
        if op.call
            && let (Some(source), Some(into), Some(bytes)) = (address(Register::RSI), into, bytes)
            && source <= at
            && field_end <= source.saturating_add_unsigned(bytes)
            && rsp.is_some_and(|rsp| rsp <= into && into.saturating_add_unsigned(bytes) <= 0)
        {
            self.moves.push((ins.ip(), into + (at - source) - (at - destination), into));
        }
        into_frame
            && match (into, bytes) {
                (Some(into), Some(bytes)) => into < field_end && at < into.saturating_add_unsigned(bytes),
                _ => true,
            }
    }

    fn step(&mut self, ins: &Instruction, live: &mut Live) {
        if !live.alive {
            return;
        }
        let (f, destination, at, field_end, volatile) =
            (self.f, self.destination, self.at, self.field_end, self.volatile);
        let state = self.facts.get(&ins.ip());
        let rsp = state.and_then(|state| state.frame);
        // Once `rsp` is above the field (the frame released), the copy is gone.
        if rsp.is_some_and(|rsp| rsp > at) {
            *live = Live { alive: false, holders: 0 };
            return;
        }
        let holders = live.holders;
        let holds = |register: Register| bit(register).is_some_and(|b| holders & b != 0);
        // A base that may address the frame: rsp, a holder of the copy, or a frame pointer.
        let framed = |base: Register| {
            base == Register::RSP
                || holds(base)
                || state
                    .is_some_and(|s| s.addrs.contains_key(&base) || bit(base).is_some_and(|b| s.frame_ptrs & b != 0))
        };
        let explicit = (0..ins.op_count()).any(|k| ins.op_kind(k) == OpKind::Memory);
        let mut ends = false;
        let (hits, texts, factory) = (&mut self.hits, &mut self.texts, &mut self.factory);
        for used in factory.info(ins).used_memory() {
            if !framed(used.base()) {
                continue;
            }
            let reads = matches!(
                used.access(),
                OpAccess::Read | OpAccess::CondRead | OpAccess::ReadWrite | OpAccess::ReadCondWrite
            );
            let writes = matches!(
                used.access(),
                OpAccess::Write | OpAccess::CondWrite | OpAccess::ReadWrite | OpAccess::ReadCondWrite
            );
            // Where the access lands, entry-relative: off a holder of the copy, or off the frame.
            let base = if holds(used.base()) {
                Some(destination)
            } else if used.base() == Register::RSP {
                rsp
            } else {
                state.and_then(|s| s.addrs.get(&used.base()).copied())
            };
            let place = base
                .filter(|_| used.index() == Register::None)
                .and_then(|base| base.checked_add(used.displacement().cast_signed()));
            let size = used.memory_size().size().max(1) as u64;
            if reads
                && explicit
                && let Some(how) = place.and_then(|place| field_read(ins, place, size, at, self.width))
                && hits.insert(ins.ip())
            {
                texts.push((ins.ip(), scan::format(ins), how.note()));
            }
            // A write over the field ends the copy; so does a frame write that cannot be placed.
            let overlaps = place.is_none_or(|place| place < field_end && at < place.saturating_add_unsigned(size));
            if writes && overlaps {
                ends = true;
            }
        }
        // `stos`/`movs` into what may be the frame.
        if matches!(ins.op0_kind(), OpKind::MemoryESDI | OpKind::MemoryESEDI | OpKind::MemoryESRDI)
            && framed(Register::RDI)
        {
            ends = true;
        }
        if is_call(ins, f) {
            ends |= self.at_call(ins, state, holders, framed(Register::RDI));
            live.holders &= !volatile;
        } else {
            // A copy of a holder, or the copy's address formed again off the frame (`lea rdi,
            // [rsp+d]`, `mov rdi, rsp`).
            let gains = ins.op_count() == 2
                && ins.op0_kind() == OpKind::Register
                && ins.op0_register().size() == 8
                && match ins.mnemonic() {
                    Mnemonic::Mov if ins.op1_kind() == OpKind::Register => {
                        holds(ins.op1_register()) || (ins.op1_register() == Register::RSP && rsp == Some(destination))
                    }
                    Mnemonic::Lea => state.is_some_and(|s| s.on_frame(ins) && s.slot(ins) == Some(destination)),
                    _ => false,
                };
            let gained = if gains { bit(ins.op0_register()).unwrap_or(0) } else { 0 };
            for register in written(&mut self.factory, ins) {
                live.holders &= !bit(register).unwrap_or(0);
            }
            live.holders |= gained;
        }
        if ends {
            *live = Live { alive: false, holders: 0 };
        }
    }
}
