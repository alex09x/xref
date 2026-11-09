/*
 * XRef — Readers of a field of fixed-size records (Vec elements) across a binary
 * Copyright (c) 2026 Alexander Panasenko
 * Contact: alex@prod.codes
 * Author: https://prod.codes/about/
 * Project: https://github.com/alex09x/xref
 * SPDX-License-Identifier: MIT OR Apache-2.0
 */

//! A value copied into a computed destination (`imul rdi, len, 0x2c8; add rdi, [vec.ptr];
//! memcpy`) lands in an element of an array of `stride`-byte records, and the code reading it is
//! elsewhere: it computes the element the same way, or walks the elements with a pointer stepped
//! by the record size, and reads `[element + offset]`. What the registers hold ([`kinds`]) is a
//! must-fact over the function's blocks; a read of `[element + offset]` (or `[element + other +
//! offset]`) with the value's width is a reader.
//!
//! An element register has a phase: the byte of the record it points at, modulo the record size
//! (`lea r13, [rbx-0x2c0]` with `rbx` at an element is 8 into the record; a pointer stepped by the
//! stride before the body, `[rbx-0x2c8]`, is at the next element). A read `[element + d]` is the
//! field's when phase + d is the field's offset, in this element or the one before. A copy routine
//! called through a register (`mov r15, [rip + memcpy@got]; call r15`) is a copy too, and a copy of
//! part of an element (`memcpy(&local, element + 8, 0x2c0)`) carries the field when it covers it.

mod kinds;
mod loops;

use std::collections::BTreeSet;

use iced_x86::{FlowControl, Instruction, InstructionInfoFactory, OpAccess, Register};
use rayon::prelude::*;

use self::kinds::{Kinds, at_field, gained};
use self::loops::stepped_loops;
use super::flow::{GPRS, bit, function_code, settled, written};
use super::pointer::{Field, Reader, readers};
use super::scan::{Slot, VOLATILE};
use crate::expr::ABI_ARGS;
use crate::graph::call_target;
use crate::image::Image;
use crate::listing::is_call;
use crate::scan::{self, decode};

/// A function an element address is passed to, in which argument, and the address's phase.
type Hop = (u64, Slot, u64);

/// Element readers reported at most, binary-wide.
pub const MAX_READERS: usize = 64;

/// Calls an element address is followed into to find its readers.
const CALLEE_DEPTH: usize = 1;

pub fn element_readers(image: &Image, stride: u64, offset: u64, width: usize) -> Vec<Reader> {
    let (direct, passed): (Vec<Vec<Reader>>, Vec<Vec<Hop>>) = image
        .functions
        .par_iter()
        .filter_map(|f| Some((f, image.code(f)?)))
        .map(|(f, bytes)| {
            let mut code = Vec::new();
            decode(bytes, f.start, |ins| code.push(*ins));
            in_function(image, f, &code, stride, offset, width)
        })
        .unzip();
    let mut found: Vec<Reader> = direct.into_iter().flatten().collect();
    // Element addresses handed to a function: its reads of `[argument + offset]`.
    let callees: BTreeSet<Hop> = passed.into_iter().flatten().collect();
    let through: Vec<Reader> = callees
        .par_iter()
        .flat_map_iter(|&(callee, slot, phase)| {
            let Some((f, code)) = function_code(image, callee) else { return Vec::new() };
            let Some(start) = slot.register().and_then(bit) else { return Vec::new() };
            // Handed `element + phase`, the callee reads the field `offset - phase` past it.
            let Some(into) = offset.checked_sub(phase) else { return Vec::new() };
            readers(image, &f, &code, 0, start, Field { offset: into, width, size: stride }, CALLEE_DEPTH)
                .into_iter()
                .map(|mut reader| {
                    reader.via.insert(0, (callee, slot));
                    reader
                })
                .collect()
        })
        .collect();
    found.extend(through);
    found.sort_by_key(|reader| reader.ip);
    found.dedup_by_key(|reader| reader.ip);
    found.truncate(MAX_READERS);
    found
}

/// What one function does with elements: its reads of the field, the calls it hands an element
/// to, and the copies of an element onto its frame (the call, and the record byte it starts at).
#[derive(Default)]
struct Found {
    readers: Vec<Reader>,
    passed: Vec<Hop>,
    copies_in: Vec<(u64, u64)>,
}

pub(super) fn in_function(
    image: &Image,
    f: &std::ops::Range<u64>,
    code: &[Instruction],
    stride: u64,
    offset: u64,
    width: usize,
) -> (Vec<Reader>, Vec<Hop>) {
    let loops = stepped_loops(code, f, stride);
    // Without an index scaled by the stride or a pointer stepped by it, no register is an element.
    let scales = code.iter().any(|ins| matches!(gained(ins, stride, &Kinds::default()), kinds::Gain::Scaled));
    if loops.is_empty() && !scales {
        return (Vec::new(), Vec::new());
    }
    // Frame facts, for a copy routine called through a register; only where one is loaded.
    let facts = code
        .iter()
        .any(|ins| super::copy::loads_copy_routine(image, ins).is_some())
        .then(|| super::copy_in::facts(image, f, code));
    let mut factory = InstructionInfoFactory::new();
    let mut found = Found::default();
    settled(image, f, code, 0, Kinds::default(), |ins, kinds, record| {
        // A pointer stepped by the stride inside a loop is an element address throughout it.
        for (_, regs, phases) in loops.iter().filter(|(span, ..)| span.contains(&ins.ip())) {
            for (index, register) in GPRS.iter().enumerate() {
                if regs & (1 << index) != 0 && kinds.phase_of(*register).is_none() {
                    kinds.set_element(*register, phases[index]);
                }
            }
        }
        if record {
            let held = facts.as_ref().and_then(|facts| facts.get(&ins.ip()));
            look(image, f, ins, kinds, held, (stride, offset, width), &mut factory, &mut found);
        }
        if is_call(ins, f) {
            if matches!(ins.flow_control(), FlowControl::Call | FlowControl::IndirectCall) {
                for volatile in VOLATILE {
                    kinds.drop_register(volatile);
                }
            } else {
                *kinds = Kinds::default();
            }
            return;
        }
        let gain = gained(ins, stride, kinds);
        for register in written(&mut factory, ins) {
            kinds.drop_register(register);
        }
        kinds.gain(ins, gain);
    });
    let Found { mut readers, passed, copies_in } = found;
    if !copies_in.is_empty() {
        let facts = facts.unwrap_or_else(|| super::copy_in::facts(image, f, code));
        let field = Field { offset, width, size: stride };
        for (at, phase) in copies_in {
            let Some(call) = code.iter().position(|ins| ins.ip() == at) else { continue };
            readers.extend(super::copy_in::copy_in_readers(image, f, code, &facts, call, phase, field, CALLEE_DEPTH));
        }
    }
    (readers, passed)
}

/// What `ins` does with the elements `kinds` knows: reads the field, copies an element onto the
/// frame, or hands one to a call.
#[allow(clippy::too_many_arguments)]
fn look(
    image: &Image,
    f: &std::ops::Range<u64>,
    ins: &Instruction,
    kinds: &Kinds,
    held: Option<&super::frame::Held>,
    (stride, offset, width): (u64, u64, usize),
    factory: &mut InstructionInfoFactory,
    found: &mut Found,
) {
    let reads = factory.info(ins).used_memory().iter().any(|used| {
        let indexed = used.scale() == 1 && Kinds::is(kinds.scaled | kinds.elements, used.index());
        let phase = if indexed {
            (used.base() != Register::None)
                .then(|| kinds.phase_of(used.base()).or_else(|| kinds.phase_of(used.index())).unwrap_or(0))
        } else {
            kinds.phase_of(used.base())
        };
        phase.is_some_and(|phase| at_field(phase, used.displacement().cast_signed(), offset, stride))
            && used.memory_size().size() == width
            && matches!(used.access(), OpAccess::Read | OpAccess::CondRead | OpAccess::ReadWrite)
    });
    if reads {
        found.readers.push(Reader {
            ip: ins.ip(),
            function: f.clone(),
            text: scan::format(ins),
            via: Vec::new(),
            note: None,
        });
    }
    if !is_call(ins, f) {
        return;
    }
    // The element, or part of it, copied onto this frame first (`memcpy(&local, element, n)`).
    if let Some(op) = super::copy::copy_op_at(image, ins, held).filter(|op| op.call)
        && let Some(phase) = kinds.phase_of(op.source)
    {
        found.copies_in.push((ins.ip(), phase));
    }
    if let Some(target) = call_target(image, ins) {
        for (index, argument) in ABI_ARGS.iter().enumerate() {
            if let Some(phase) = kinds.phase_of(*argument) {
                found.passed.push((target, Slot::Reg(index), phase));
            }
        }
    }
}
