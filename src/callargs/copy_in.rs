/*
 * XRef — Reads of a field after a record is copied onto the reader's own stack (copy-in)
 * Copyright (c) 2026 Alexander Panasenko
 * Contact: alex@prod.codes
 * Author: https://prod.codes/about/
 * Project: https://github.com/alex09x/xref
 * SPDX-License-Identifier: MIT OR Apache-2.0
 */

//! A reader of a record often copies it onto its own frame first (`lea rdi, [rsp+0x470]; mov rsi,
//! r14; mov edx, 0x2c8; call memcpy`) and reads the field there (`movzx eax, byte [rsp+0x580]`).
//! The frame offset of every instruction comes from a dataflow over `rsp` (`frames`); the copy's
//! destination is the frame address in `rdi` set in the call's block, and a read of
//! `destination + field` after the copy, or a callee handed the copy's address, is a reader.

use std::collections::{BTreeMap, HashMap, HashSet};
use std::ops::Range;

use iced_x86::{FlowControl, Instruction, InstructionInfoFactory, Mnemonic, OpAccess, OpKind, Register};

use super::flow::{Join, bit, function_code, settled, targets, written};
use super::pointer::{Reader, readers};
use super::scan::Slot;
use crate::expr::ABI_ARGS;
use crate::graph::call_target;
use crate::image::Image;
use crate::listing::is_call;
use crate::scan;

/// `rsp` relative to its entry value, when every path agrees on it.
#[derive(Clone, Copy, PartialEq, Eq)]
struct Frame(Option<i64>);

impl Join for Frame {
    fn join(&mut self, other: &Self) -> bool {
        if self.0 != other.0 && self.0.is_some() {
            self.0 = None;
            return true;
        }
        false
    }
}

/// The entry-relative `rsp` before each instruction of `f`, where it is known.
pub fn frames(image: &Image, f: &Range<u64>, code: &[Instruction]) -> HashMap<u64, i64> {
    let mut at = HashMap::new();
    let mut factory = InstructionInfoFactory::new();
    settled(image, f, code, 0, Frame(Some(0)), |ins, frame, record| {
        if record && let Some(value) = frame.0 {
            at.insert(ins.ip(), value);
        }
        frame.0 = step(ins, frame.0, &mut factory);
    });
    at
}

/// `rsp` after `ins`: `push`/`pop`/`call`-neutral, `sub`/`add rsp, imm`; any other write loses it.
fn step(ins: &Instruction, frame: Option<i64>, factory: &mut InstructionInfoFactory) -> Option<i64> {
    if matches!(ins.flow_control(), FlowControl::Call | FlowControl::IndirectCall) {
        return frame;
    }
    let immediate = ins.op_count() == 2
        && ins.op0_kind() == OpKind::Register
        && ins.op0_register() == Register::RSP
        && matches!(ins.op1_kind(), OpKind::Immediate8to64 | OpKind::Immediate32to64);
    let pops_rsp = ins.op_count() == 1 && ins.op0_kind() == OpKind::Register && ins.op0_register() == Register::RSP;
    let moved = match ins.mnemonic() {
        Mnemonic::Sub if immediate => ins.immediate(1).cast_signed().checked_neg(),
        Mnemonic::Add if immediate => Some(ins.immediate(1).cast_signed()),
        Mnemonic::Push | Mnemonic::Pop if !pops_rsp && ins.stack_pointer_increment() != 0 => {
            Some(i64::from(ins.stack_pointer_increment()))
        }
        _ if written(factory, ins).contains(&Register::RSP) => None,
        _ => return frame,
    };
    frame.zip(moved).and_then(|(frame, moved)| frame.checked_add(moved))
}

/// The frame address `rdi` holds and the constant `rdx` holds at `code[call]`, from their last
/// writes in the call's block: `lea rdi, [rsp+d]` / `mov rdi, rsp` and `mov edx, imm`.
fn destination_and_size(
    code: &[Instruction],
    leaders: &std::collections::BTreeSet<u64>,
    frames: &HashMap<u64, i64>,
    call: usize,
) -> Option<(i64, u64)> {
    let mut factory = InstructionInfoFactory::new();
    let (mut destination, mut size) = (None, None);
    let mut first = call;
    while first > 0 && !leaders.contains(&code[first].ip()) && code[first - 1].flow_control() == FlowControl::Next {
        first -= 1;
    }
    for ins in &code[first..call] {
        let writes = written(&mut factory, ins);
        if writes.contains(&Register::RDI) {
            destination = frame_address(ins, frames);
        }
        if writes.contains(&Register::RDX) {
            size = (ins.mnemonic() == Mnemonic::Mov
                && matches!(ins.op1_kind(), OpKind::Immediate32 | OpKind::Immediate64 | OpKind::Immediate32to64))
            .then(|| ins.immediate(1));
        }
    }
    destination.zip(size)
}

/// The entry-relative frame address `lea reg, [rsp+d]` or `mov reg, rsp` gives its destination.
fn frame_address(ins: &Instruction, frames: &HashMap<u64, i64>) -> Option<i64> {
    let frame = *frames.get(&ins.ip())?;
    match ins.mnemonic() {
        Mnemonic::Lea if ins.memory_base() == Register::RSP && ins.memory_index() == Register::None => {
            frame.checked_add(ins.memory_displacement64().cast_signed())
        }
        Mnemonic::Mov if ins.op1_kind() == OpKind::Register && ins.op1_register() == Register::RSP => Some(frame),
        _ => None,
    }
}

/// The reads of field `offset` (`width` bytes) of a record copied onto the frame by the copy call
/// at `code[call]` (destination in `rdi`, size in `rdx`), after the copy in `f` and in callees
/// handed the copy's address (up to `depth` calls deeper).
#[allow(clippy::too_many_arguments)]
pub fn copy_in_readers(
    image: &Image,
    f: &Range<u64>,
    code: &[Instruction],
    frames: &HashMap<u64, i64>,
    call: usize,
    offset: u64,
    width: usize,
    depth: usize,
) -> Vec<Reader> {
    let leaders = targets(image, f, code);
    let Some((destination, size)) = destination_and_size(code, &leaders, frames, call) else { return Vec::new() };
    if offset.saturating_add(width as u64) > size {
        return Vec::new();
    }
    let Some(field) = destination.checked_add_unsigned(offset) else { return Vec::new() };
    // Named as `[rsp+d]` at the copy, as the code addresses it.
    let at_call = frames.get(&code[call].ip()).and_then(|frame| destination.checked_sub(*frame)).unwrap_or(destination);
    let note = format!("copy-in at {:#x} to [rsp+{at_call:#x}], field +{offset:#x}", code[call].ip());
    let mut factory = InstructionInfoFactory::new();
    let mut found = Vec::new();
    // Registers holding the copy's address in the current block: handed to a call, the callee
    // reads the field off its argument.
    let mut copies: BTreeMap<Register, i64> = BTreeMap::new();
    let mut callees: HashSet<(u64, Slot)> = HashSet::new();
    for ins in &code[call + 1..] {
        if leaders.contains(&ins.ip()) {
            copies.clear();
        }
        let Some(&frame) = frames.get(&ins.ip()) else { continue };
        let reads = factory.info(ins).used_memory().iter().any(|used| {
            used.base() == Register::RSP
                && used.index() == Register::None
                && used.memory_size().size() == width
                && frame.checked_add(used.displacement().cast_signed()) == Some(field)
                && matches!(used.access(), OpAccess::Read | OpAccess::CondRead | OpAccess::ReadWrite)
        });
        if reads {
            found.push(Reader {
                ip: ins.ip(),
                function: f.clone(),
                text: scan::format(ins),
                via: Vec::new(),
                note: Some(note.clone()),
            });
        }
        if is_call(ins, f) {
            if let Some(target) = call_target(image, ins) {
                for (index, argument) in ABI_ARGS.iter().enumerate() {
                    if copies.get(argument) == Some(&destination) {
                        callees.insert((target, Slot::Reg(index)));
                    }
                }
            }
            copies.clear();
            continue;
        }
        let address = frame_address(ins, frames);
        for register in written(&mut factory, ins) {
            copies.remove(&register);
        }
        if let (Some(address), true) = (address, ins.op0_kind() == OpKind::Register) {
            copies.insert(ins.op0_register().full_register(), address);
        }
    }
    if depth > 0 {
        for (callee, slot) in callees {
            let Some((g, callee_code)) = function_code(image, callee) else { continue };
            let Some(start) = slot.register().and_then(bit) else { continue };
            found.extend(readers(image, &g, &callee_code, 0, start, offset, width, depth - 1).into_iter().map(
                |mut r| {
                    r.via.insert(0, (callee, slot));
                    r.note = Some(note.clone());
                    r
                },
            ));
        }
    }
    found
}
