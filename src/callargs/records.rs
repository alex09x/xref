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
//!
//! An element register has a phase: the byte of the record it points at, modulo the record size
//! (`lea r13, [rbx-0x2c0]` with `rbx` at an element is 8 into the record; a pointer stepped by the
//! stride before the body, `[rbx-0x2c8]`, is at the next element). A read `[element + d]` is the
//! field's when phase + d is the field's offset, in this element or the one before. A copy routine
//! called through a register (`mov r15, [rip + memcpy@got]; call r15`) is a copy too, and a copy of
//! part of an element (`memcpy(&local, element + 8, 0x2c0)`) carries the field when it covers it.

use std::collections::BTreeSet;

use iced_x86::{FlowControl, Instruction, InstructionInfoFactory, Mnemonic, OpAccess, OpKind, Register};
use rayon::prelude::*;

use super::flow::{bit, function_code, targets, written};
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

/// What is known about the registers in a straight-line run.
#[derive(Clone, Copy, Default)]
struct Kinds {
    /// An index scaled by the record size (`imul rax, rcx, 0x2c8`, `shl rax, 9`): a byte offset,
    /// not yet an address.
    scaled: u16,
    /// An element address: a scaled index added to a base.
    elements: u16,
    /// For each element register (by `flow::GPRS` index), the byte of the record it points at.
    phase: [u64; 16],
}

impl Kinds {
    fn is(mask: u16, register: Register) -> bool {
        bit(register).is_some_and(|b| mask & b != 0)
    }

    /// The phase of an element register.
    fn phase_of(&self, register: Register) -> Option<u64> {
        let b = bit(register)?;
        (self.elements & b != 0).then(|| self.phase[b.trailing_zeros() as usize])
    }

    fn set_element(&mut self, register: Register, phase: u64) {
        if let Some(b) = bit(register) {
            self.elements |= b;
            self.phase[b.trailing_zeros() as usize] = phase;
        }
    }

    fn drop_register(&mut self, register: Register) {
        let b = bit(register).unwrap_or(0);
        self.scaled &= !b;
        self.elements &= !b;
    }
}

/// `[element + displacement]` with the element at `phase` is the field at `offset`: in this
/// element, or in the one before (a pointer already stepped past it).
fn at_field(phase: u64, displacement: i64, offset: u64, stride: u64) -> bool {
    let at = i128::from(phase) + i128::from(displacement);
    at == i128::from(offset) || at == i128::from(offset) - i128::from(stride)
}

/// `(phase + by) mod stride`, for a step of at most a record.
fn shifted(phase: u64, by: i64, stride: u64) -> Option<u64> {
    let stride = i128::from(stride);
    (stride > 0 && i128::from(by).abs() <= stride)
        .then(|| u64::try_from((i128::from(phase) + i128::from(by)).rem_euclid(stride)).ok())
        .flatten()
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
    // Copies of an element onto the frame: the call and the record byte the copy starts at.
    let mut copies_in: Vec<(u64, u64)> = Vec::new();
    // Frame facts, for a copy routine called through a register; only where one is loaded.
    let facts = code
        .iter()
        .any(|ins| super::copy::loads_copy_routine(image, ins).is_some())
        .then(|| super::copy_in::facts(image, f, code));
    for ins in code {
        if leaders.contains(&ins.ip()) {
            kinds = Kinds::default();
        }
        // A pointer stepped by the stride inside a loop is an element address throughout it.
        let mut now = kinds;
        for (_, regs, phases) in loops.iter().filter(|(span, ..)| span.contains(&ins.ip())) {
            for (index, register) in super::flow::GPRS.iter().enumerate() {
                if regs & (1 << index) != 0 && now.phase_of(*register).is_none() {
                    now.set_element(*register, phases[index]);
                }
            }
        }
        let reads = factory.info(ins).used_memory().iter().any(|used| {
            let indexed = used.scale() == 1 && Kinds::is(now.scaled | now.elements, used.index());
            let phase = if indexed {
                (used.base() != Register::None).then(|| now.phase_of(used.base()).or(now.phase_of(used.index())).unwrap_or(0))
            } else {
                now.phase_of(used.base())
            };
            phase.is_some_and(|phase| at_field(phase, used.displacement().cast_signed(), offset, stride))
                && used.memory_size().size() == width
                && matches!(used.access(), OpAccess::Read | OpAccess::CondRead | OpAccess::ReadWrite)
        });
        if reads {
            found.push(Reader {
                ip: ins.ip(),
                function: f.clone(),
                text: scan::format(ins),
                via: Vec::new(),
                note: None,
            });
        }
        if is_call(ins, f) {
            // The element, or part of it, copied onto this frame first (`memcpy(&local, element, n)`).
            let held = facts.as_ref().and_then(|facts| facts.get(&ins.ip()));
            if let Some(op) = super::copy::copy_op_at(image, ins, held).filter(|op| op.call)
                && let Some(phase) = now.phase_of(op.source)
            {
                copies_in.push((ins.ip(), phase));
            }
            if let Some(target) = call_target(image, ins) {
                for (index, argument) in ABI_ARGS.iter().enumerate() {
                    if let Some(phase) = now.phase_of(*argument) {
                        passed.push((target, Slot::Reg(index), phase));
                    }
                }
            }
            if matches!(ins.flow_control(), FlowControl::Call | FlowControl::IndirectCall) {
                for volatile in VOLATILE {
                    kinds.drop_register(volatile);
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
        let gain = gained(ins, stride, &now);
        for register in written(&mut factory, ins) {
            kinds.drop_register(register);
        }
        match gain {
            Gain::Scaled => kinds.scaled |= bit(ins.op0_register()).unwrap_or(0),
            Gain::Element(phase) => kinds.set_element(ins.op0_register(), phase),
            Gain::Nothing => {}
        }
    }
    if !copies_in.is_empty() {
        let facts = facts.unwrap_or_else(|| super::copy_in::facts(image, f, code));
        let field = Field { offset, width, size: stride };
        for (at, phase) in copies_in {
            let Some(call) = code.iter().position(|ins| ins.ip() == at) else { continue };
            found.extend(super::copy_in::copy_in_readers(image, f, code, &facts, call, phase, field, CALLEE_DEPTH));
        }
    }
    (found, passed)
}

/// What an instruction makes of its 64-bit destination register.
enum Gain {
    Nothing,
    Scaled,
    Element(u64),
}

/// A loop's span, the registers it steps by the stride, and the phase of each at the loop.
type Stepped = (std::ops::Range<u64>, u16, [u64; 16]);

/// Instructions scanned back from a loop for its pointer's setup.
const SETUP_WINDOW: usize = 32;

/// Loops (a backward branch to `target`, the span up to it) and the registers each steps by the
/// stride with every write of theirs inside it (`add rbx, 0x2c8`): a call inside the loop drops
/// the volatile ones. A stepped pointer's phase comes from its setup before the loop: `lea rbx,
/// [rdi+8]` walks the records 8 bytes in, `add rbx, 0x2c8` one record ahead (phase 0).
fn stepped_loops(code: &[Instruction], f: &std::ops::Range<u64>, stride: u64) -> Vec<Stepped> {
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
        let regs = steps & !other;
        if regs != 0 {
            let head = code.iter().position(|ins| ins.ip() == target).unwrap_or(0);
            let mut phases = [0u64; 16];
            for (index, register) in super::flow::GPRS.iter().enumerate() {
                if regs & (1 << index) != 0 {
                    phases[index] = setup_phase(code, head, *register, stride);
                }
            }
            loops.push((span, regs, phases));
        }
    }
    loops
}

/// The phase `register` has at `code[head]`: the constant its setup just before adds to the
/// address it starts from (`mov rbx, rdi; add rbx, 0x2c8`; `lea rbx, [rdi+8]`), taken to be an
/// element's start; 0 when the setup is not seen.
fn setup_phase(code: &[Instruction], head: usize, register: Register, stride: u64) -> u64 {
    let mut factory = InstructionInfoFactory::new();
    let mut added = 0i64;
    for ins in code[head.saturating_sub(SETUP_WINDOW)..head].iter().rev() {
        if !matches!(ins.flow_control(), FlowControl::Next | FlowControl::ConditionalBranch) {
            break;
        }
        if !written(&mut factory, ins).contains(&register) {
            continue;
        }
        let to_register = ins.op_count() == 2 && ins.op0_kind() == OpKind::Register && ins.op0_register() == register;
        let immediate = matches!(ins.op1_kind(), OpKind::Immediate8to64 | OpKind::Immediate32to64);
        match ins.mnemonic() {
            Mnemonic::Add if to_register && immediate => added = added.wrapping_add(ins.immediate(1).cast_signed()),
            Mnemonic::Sub if to_register && immediate => added = added.wrapping_sub(ins.immediate(1).cast_signed()),
            Mnemonic::Lea if to_register && ins.memory_index() == Register::None => {
                added = added.wrapping_add(ins.memory_displacement64().cast_signed());
                if ins.memory_base() != register {
                    break;
                }
            }
            // A copy of a pointer, or one loaded (a Vec's buffer).
            Mnemonic::Mov if to_register && matches!(ins.op1_kind(), OpKind::Register | OpKind::Memory) => break,
            // Set some other way: no known start.
            _ => return 0,
        }
    }
    u64::try_from(i128::from(added).rem_euclid(i128::from(stride.max(1)))).unwrap_or(0)
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
/// log2(stride)`), or an element address (a scaled index added to a base by `add`/`lea`, a copy of
/// one, or one moved by less than a record: `lea r13, [rbx-0x2c0]`, `add rbx, 0x2c8`).
fn gained(ins: &Instruction, stride: u64, now: &Kinds) -> Gain {
    if ins.op_count() == 0 || ins.op0_kind() != OpKind::Register || ins.op0_register().size() != 8 {
        return Gain::Nothing;
    }
    let scaled = |r: Register| Kinds::is(now.scaled, r);
    let phase = |r: Register| now.phase_of(r);
    let source = (ins.op_count() > 1 && ins.op1_kind() == OpKind::Register).then(|| ins.op1_register());
    let element = |phase: Option<u64>| phase.map_or(Gain::Nothing, Gain::Element);
    match ins.mnemonic() {
        Mnemonic::Imul if ins.op_count() == 3 && ins.immediate(2) == stride => Gain::Scaled,
        // A power-of-two record size scales the index with a shift: `shl rdi, 9` for 0x200.
        Mnemonic::Shl
            if stride.is_power_of_two()
                && ins.op1_kind() == OpKind::Immediate8
                && ins.immediate(1) == u64::from(stride.trailing_zeros()) =>
        {
            Gain::Scaled
        }
        Mnemonic::Mov if source.is_some_and(scaled) => Gain::Scaled,
        Mnemonic::Mov => element(source.and_then(phase)),
        // `add rbx, 0x2c8`: the element moved by a constant.
        Mnemonic::Add if matches!(ins.op1_kind(), OpKind::Immediate8to64 | OpKind::Immediate32to64) => {
            element(phase(ins.op0_register()).and_then(|p| shifted(p, ins.immediate(1).cast_signed(), stride)))
        }
        // `add rdi, [vec.ptr]`, `add rax, rbx`: a scaled index plus a base; an element plus an offset.
        Mnemonic::Add => {
            let operand_is_base = ins.op1_kind() == OpKind::Memory || source.is_some();
            let with_scaled = (scaled(ins.op0_register()) && operand_is_base) || source.is_some_and(scaled);
            match phase(ins.op0_register()).or_else(|| source.and_then(phase)) {
                Some(p) => Gain::Element(p),
                None if with_scaled => Gain::Element(0),
                None => Gain::Nothing,
            }
        }
        Mnemonic::Lea => {
            let (base, index) = (ins.memory_base(), ins.memory_index());
            let displacement = ins.memory_displacement64().cast_signed();
            if index == Register::None {
                return element(phase(base).and_then(|p| shifted(p, displacement, stride)));
            }
            let combined = base != Register::None
                && ins.memory_index_scale() == 1
                && (scaled(base) || scaled(index) || phase(base).is_some() || phase(index).is_some());
            if combined && displacement == 0 {
                Gain::Element(phase(base).or_else(|| phase(index)).unwrap_or(0))
            } else {
                Gain::Nothing
            }
        }
        _ => Gain::Nothing,
    }
}
