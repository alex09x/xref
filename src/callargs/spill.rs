/*
 * XRef — Frame slots a pointer is spilled to, and the writes that end them
 * Copyright (c) 2026 Alexander Panasenko
 * Contact: alex@prod.codes
 * Author: https://prod.codes/about/
 * Project: https://github.com/alex09x/xref
 * SPDX-License-Identifier: MIT OR Apache-2.0
 */

//! A pointer kept across a call in a stack slot (`mov [rsp+8], rdi; call; mov rdi, [rsp+8]`, as gcc
//! 15 writes it) lives in that slot until something may write it: any store placed over it (off
//! `rsp`, off a register holding a frame address, `push`, the return address of a call), a store into
//! the frame that cannot be placed (indexed, through a frame pointer, `stos`/`movs`, a copy routine
//! into the frame), or a call, whose frame lies below `rsp`. Slots are entry-relative `rsp` offsets.

use std::collections::{BTreeSet, HashMap};

use iced_x86::{FlowControl, Instruction, InstructionInfoFactory, Mnemonic, OpAccess, OpKind, Register};

use super::copy::copy_op;
use super::flow::{bit, written};
use super::frame::Held;
use crate::image::Image;

/// Instructions scanned back from the walk's start for spills.
const SPILL_WINDOW: usize = 64;
/// Bytes of a spilled pointer.
const SLOT: i64 = 8;

/// Frame bytes `ins` may write, as entry-relative ranges; `None` when it may write the frame at a
/// place that cannot be told.
pub(super) fn frame_writes(
    image: &Image,
    ins: &Instruction,
    held: Option<&Held>,
    factory: &mut InstructionInfoFactory,
) -> Option<Vec<(i64, i64)>> {
    let frame = held.and_then(|held| held.frame);
    // A base that may address the frame: rsp, a register holding a frame address, a frame pointer.
    let framed = |base: Register| {
        base == Register::RSP
            || held.is_some_and(|held| {
                held.addrs.contains_key(&base) || bit(base).is_some_and(|b| held.frame_ptrs & b != 0)
            })
    };
    let mut ranges = Vec::new();
    for used in factory.info(ins).used_memory() {
        let writes = matches!(
            used.access(),
            OpAccess::Write | OpAccess::CondWrite | OpAccess::ReadWrite | OpAccess::ReadCondWrite
        );
        if !writes || !framed(used.base()) {
            continue;
        }
        let base = if used.base() == Register::RSP {
            frame
        } else {
            held.and_then(|held| held.addrs.get(&used.base()).copied())
        };
        let at = base
            .filter(|_| used.index() == Register::None)
            .and_then(|base| base.checked_add(used.displacement().cast_signed()))?;
        let size = i64::try_from(used.memory_size().size().max(1)).unwrap_or(i64::MAX);
        ranges.push((at, at.saturating_add(size)));
    }
    if matches!(ins.op0_kind(), OpKind::MemoryESDI | OpKind::MemoryESEDI | OpKind::MemoryESRDI) && framed(Register::RDI)
    {
        return None;
    }
    if matches!(ins.flow_control(), FlowControl::Call | FlowControl::IndirectCall) {
        // The callee's frame is everything below `rsp`.
        ranges.push((i64::MIN, frame?));
        if copy_op(image, ins).is_some() && framed(Register::RDI) {
            let into = held.and_then(|held| held.addrs.get(&Register::RDI).copied())?;
            let bytes = held.and_then(|held| held.consts.get(&Register::RDX).copied())?;
            ranges.push((into, into.saturating_add_unsigned(bytes)));
        }
    }
    Some(ranges)
}

/// Drops the slots `writes` may overwrite (all of them when it cannot be told).
pub(super) fn clobber(slots: &mut BTreeSet<i64>, writes: Option<&[(i64, i64)]>) {
    match writes {
        None => slots.clear(),
        Some(ranges) => slots.retain(|s| !overlaps(ranges, *s)),
    }
}

fn overlaps(ranges: &[(i64, i64)], slot: i64) -> bool {
    ranges.iter().any(|(lo, hi)| *lo < slot.saturating_add(SLOT) && slot < *hi)
}

/// The slot `ins` spills a holder of the pointer to: `mov [rsp+d], reg64` (or off a register
/// holding a frame address), placed.
pub(super) fn spill_slot(ins: &Instruction, held: Option<&Held>, holds: impl Fn(Register) -> bool) -> Option<i64> {
    let spills = ins.mnemonic() == Mnemonic::Mov
        && ins.op_count() == 2
        && ins.op0_kind() == OpKind::Memory
        && ins.op1_kind() == OpKind::Register
        && ins.op1_register().size() == 8
        && holds(ins.op1_register());
    spills.then(|| slot(ins, held)).flatten()
}

/// The placed frame slot the memory operand of `ins` addresses.
pub(super) fn slot(ins: &Instruction, held: Option<&Held>) -> Option<i64> {
    if ins.memory_index() != Register::None || !(0..ins.op_count()).any(|k| ins.op_kind(k) == OpKind::Memory) {
        return None;
    }
    let base =
        if ins.memory_base() == Register::RSP { held?.frame } else { held?.addrs.get(&ins.memory_base()).copied() };
    base?.checked_add(ins.memory_displacement64().cast_signed())
}

/// Slots holding the pointer at `code[start]`: spills of a register in `holders` in the straight-line
/// code just before it (across the call the walk starts after), with the register not written since
/// and the slot not overwritten since; the scan stops at a frame write it cannot place.
pub(super) fn spilled_before(
    image: &Image,
    code: &[Instruction],
    facts: &HashMap<u64, Held>,
    start: usize,
    holders: u16,
) -> BTreeSet<i64> {
    let mut factory = InstructionInfoFactory::new();
    let (mut slots, mut rewritten, mut covered) = (BTreeSet::new(), 0u16, Vec::<(i64, i64)>::new());
    for (back, ins) in code[start.saturating_sub(SPILL_WINDOW)..start].iter().rev().enumerate() {
        let the_call = back == 0 && matches!(ins.flow_control(), FlowControl::Call | FlowControl::IndirectCall);
        if ins.flow_control() != FlowControl::Next && !the_call {
            break;
        }
        let held = facts.get(&ins.ip());
        let holds = |register: Register| bit(register).is_some_and(|b| holders & b != 0 && rewritten & b == 0);
        // A store met first, walking back, is the later one: it wins over an earlier spill.
        if let Some(at) = spill_slot(ins, held, holds)
            && !overlaps(&covered, at)
        {
            slots.insert(at);
        }
        let Some(writes) = frame_writes(image, ins, held, &mut factory) else { break };
        covered.extend(writes);
        // The instruction the walk starts after (a call, `rep movs`) is the one the pointer survives:
        // `holders` name it before that instruction.
        if back > 0 {
            for register in written(&mut factory, ins) {
                rewritten |= bit(register).unwrap_or(0);
            }
        }
    }
    slots
}
