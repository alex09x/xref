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
//! elsewhere: it computes the element the same way and reads `[element + offset]`. Within each
//! straight-line run, a register is an element address once `imul reg, x, stride` writes it, and
//! stays one through `add`/`lea` with another register; a read of `[element + offset]` (or
//! `[element + other + offset]`) with the value's width is a reader.

use std::collections::BTreeSet;

use iced_x86::{FlowControl, Instruction, InstructionInfoFactory, Mnemonic, OpAccess, OpKind, Register};
use rayon::prelude::*;

use super::flow::{bit, function_code, targets, written};
use super::pointer::{Reader, readers};
use super::scan::{Slot, VOLATILE};
use crate::expr::ABI_ARGS;
use crate::graph::call_target;
use crate::image::Image;
use crate::listing::is_call;
use crate::scan::{self, decode};

/// A function an element address is passed to, and in which argument.
type Hop = (u64, Slot);

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
    let callees: BTreeSet<(u64, Slot)> = passed.into_iter().flatten().collect();
    let through: Vec<Reader> = callees
        .par_iter()
        .flat_map_iter(|&(callee, slot)| {
            let Some((f, code)) = function_code(image, callee) else { return Vec::new() };
            let Some(start) = slot.register().and_then(bit) else { return Vec::new() };
            readers(image, &f, &code, 0, start, offset, width, CALLEE_DEPTH)
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

/// What is known about the registers in a straight-line run.
#[derive(Clone, Copy, Default)]
struct Kinds {
    /// An index scaled by the record size (`imul rax, rcx, 0x2c8`, `shl rax, 9`): a byte offset,
    /// not yet an address.
    scaled: u16,
    /// An element address: a scaled index added to a base.
    elements: u16,
}

impl Kinds {
    fn is(mask: u16, register: Register) -> bool {
        bit(register).is_some_and(|b| mask & b != 0)
    }
}

pub(super) fn in_function(
    image: &Image,
    f: &std::ops::Range<u64>,
    code: &[Instruction],
    stride: u64,
    offset: u64,
    width: usize,
) -> (Vec<Reader>, Vec<Hop>) {
    let leaders: BTreeSet<u64> = targets(image, f, code);
    let loops = stepped_loops(code, f, stride);
    let mut passed = Vec::new();
    let mut factory = InstructionInfoFactory::new();
    let mut kinds = Kinds::default();
    let mut found = Vec::new();
    for ins in code {
        if leaders.contains(&ins.ip()) {
            kinds = Kinds::default();
        }
        // A pointer stepped by the stride inside a loop is an element address throughout it.
        let stepped =
            loops.iter().filter(|(span, _)| span.contains(&ins.ip())).fold(0u16, |mask, (_, regs)| mask | regs);
        let elements = kinds.elements | stepped;
        let reads = factory.info(ins).used_memory().iter().any(|used| {
            let indexed = used.scale() == 1 && Kinds::is(kinds.scaled | elements, used.index());
            (Kinds::is(elements, used.base()) || (used.base() != Register::None && indexed))
                && used.displacement() == offset
                && used.memory_size().size() == width
                && matches!(used.access(), OpAccess::Read | OpAccess::CondRead | OpAccess::ReadWrite)
        });
        if reads {
            found.push(Reader { ip: ins.ip(), function: f.clone(), text: scan::format(ins), via: Vec::new() });
        }
        if is_call(ins, f) {
            if let Some(target) = call_target(image, ins) {
                for (index, argument) in ABI_ARGS.iter().enumerate() {
                    if Kinds::is(elements, *argument) {
                        passed.push((target, Slot::Reg(index)));
                    }
                }
            }
            if matches!(ins.flow_control(), FlowControl::Call | FlowControl::IndirectCall) {
                for volatile in VOLATILE {
                    kinds.scaled &= !bit(volatile).unwrap_or(0);
                    kinds.elements &= !bit(volatile).unwrap_or(0);
                }
            } else {
                kinds = Kinds::default();
            }
            continue;
        }
        if ins.flow_control() != FlowControl::Next {
            kinds = Kinds::default();
            continue;
        }
        let gained = gained(ins, stride, kinds, elements);
        for register in written(&mut factory, ins) {
            kinds.scaled &= !bit(register).unwrap_or(0);
            kinds.elements &= !bit(register).unwrap_or(0);
        }
        kinds.scaled |= gained.scaled;
        kinds.elements |= gained.elements;
    }
    (found, passed)
}

/// Loops (a backward branch to `target`, the span up to it) and the registers each steps by the
/// stride with every write of theirs inside it (`add rbx, 0x2c8`): a call inside the loop drops
/// the volatile ones.
fn stepped_loops(code: &[Instruction], f: &std::ops::Range<u64>, stride: u64) -> Vec<(std::ops::Range<u64>, u16)> {
    let mut factory = InstructionInfoFactory::new();
    let mut loops = Vec::new();
    for back in code {
        let Some(target) = crate::scan::branch_target(back).filter(|t| f.contains(t) && *t <= back.ip()) else {
            continue;
        };
        let span = target..back.next_ip();
        let body: Vec<&Instruction> = code.iter().filter(|ins| span.contains(&ins.ip())).collect();
        let (mut steps, mut other) = (0u16, 0u16);
        for ins in &body {
            if steps_by(ins, stride) {
                steps |= bit(ins.op0_register()).unwrap_or(0);
                continue;
            }
            for register in written(&mut factory, ins) {
                other |= bit(register).unwrap_or(0);
            }
            if matches!(ins.flow_control(), FlowControl::Call | FlowControl::IndirectCall) {
                other |= VOLATILE.iter().fold(0, |mask, r| mask | bit(*r).unwrap_or(0));
            }
        }
        if steps & !other != 0 {
            loops.push((span, steps & !other));
        }
    }
    loops
}

/// `add reg, stride` or `lea reg, [reg + stride]` on a 64-bit register.
fn steps_by(ins: &Instruction, stride: u64) -> bool {
    if ins.op_count() < 2 || ins.op0_kind() != OpKind::Register || ins.op0_register().size() != 8 {
        return false;
    }
    // `add rsp, 0x2c8` frees a frame of that size; it walks no records.
    if matches!(ins.op0_register(), Register::RSP | Register::RBP) {
        return false;
    }
    match ins.mnemonic() {
        Mnemonic::Add => {
            matches!(ins.op1_kind(), OpKind::Immediate32to64 | OpKind::Immediate8to64) && ins.immediate(1) == stride
        }
        Mnemonic::Lea => {
            ins.memory_base() == ins.op0_register()
                && ins.memory_index() == Register::None
                && ins.memory_displacement64() == stride
        }
        _ => false,
    }
}

/// What `ins` makes of its destination: a scaled index (`imul reg, x, stride`, `shl reg,
/// log2(stride)`), or an element address (a scaled index added to a base by `add`/`lea`, or a
/// copy or offset of one).
fn gained(ins: &Instruction, stride: u64, kinds: Kinds, elements: u16) -> Kinds {
    let none = Kinds::default();
    if ins.op_count() == 0 || ins.op0_kind() != OpKind::Register || ins.op0_register().size() != 8 {
        return none;
    }
    let destination = bit(ins.op0_register()).unwrap_or(0);
    let scaled = |r: Register| Kinds::is(kinds.scaled, r);
    let element = |r: Register| Kinds::is(elements, r);
    let source = (ins.op_count() > 1 && ins.op1_kind() == OpKind::Register).then(|| ins.op1_register());
    let (is_scaled, is_element) = match ins.mnemonic() {
        Mnemonic::Imul => (ins.op_count() == 3 && ins.immediate(2) == stride, false),
        // A power-of-two record size scales the index with a shift: `shl rdi, 9` for 0x200.
        Mnemonic::Shl => (
            stride.is_power_of_two()
                && ins.op1_kind() == OpKind::Immediate8
                && ins.immediate(1) == u64::from(stride.trailing_zeros()),
            false,
        ),
        Mnemonic::Mov => (source.is_some_and(scaled), source.is_some_and(element)),
        // `add rdi, [vec.ptr]`, `add rax, rbx`: a scaled index plus a base; an element plus an offset.
        Mnemonic::Add => {
            let operand_is_base = ins.op1_kind() == OpKind::Memory || source.is_some();
            let with_scaled = (scaled(ins.op0_register()) && operand_is_base) || source.is_some_and(scaled);
            (false, with_scaled || element(ins.op0_register()) || source.is_some_and(element))
        }
        Mnemonic::Lea => {
            let (base, index) = (ins.memory_base(), ins.memory_index());
            let unit = ins.memory_index_scale() == 1;
            let combined = base != Register::None
                && index != Register::None
                && unit
                && (scaled(base) || scaled(index) || element(base) || element(index));
            (false, ins.memory_displacement64() == 0 && (combined || (element(base) && index == Register::None)))
        }
        _ => (false, false),
    };
    Kinds { scaled: if is_scaled { destination } else { 0 }, elements: if is_element { destination } else { 0 } }
}
