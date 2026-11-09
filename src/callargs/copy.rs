/*
 * XRef — Copies of a stack object holding a followed value
 * Copyright (c) 2026 Alexander Panasenko
 * Contact: alex@prod.codes
 * Author: https://prod.codes/about/
 * Project: https://github.com/alex09x/xref
 * SPDX-License-Identifier: MIT OR Apache-2.0
 */

//! A struct built on the stack is often copied whole into its real home: `memcpy(dst, &obj, n)` (a
//! Vec slot, a caller's out-parameter) or an inline `rep movsq`. The value stored at `obj + k` then
//! lives at `dst + k`, and the code that matters reads it there.

use iced_x86::{FlowControl, Instruction, Mnemonic, OpKind, Register};

use super::frame::Held;
use super::pointer::Reader;
use crate::graph::call_target;
use crate::image::{Image, Slot as ImageSlot};

/// Library copy routines by name (any `@version` suffix is ignored).
const COPY_FUNCTIONS: [&str; 4] = ["memcpy", "memmove", "__memcpy_chk", "__memmove_chk"];

/// Where a copy writes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Dest {
    /// An object the function received in argument `rdi..r9` index: the caller's.
    Param(usize),
    /// An address the function computed (a Vec slot, a heap block).
    Computed,
}

/// The value copied out of a stack object.
#[derive(Clone, Debug)]
pub struct Copied {
    pub ip: u64,
    /// `memcpy`, `rep movsq`, ...
    pub how: String,
    pub size: u64,
    /// Where the value sits in the destination.
    pub offset: u64,
    pub dest: Dest,
    /// Reads of `[destination + offset]` found after the copy.
    pub readers: Vec<Reader>,
}

impl Copied {
    pub fn describe(&self) -> String {
        let into = match self.dest {
            Dest::Param(index) => {
                format!("the object passed in {}", crate::expr::reg_name(crate::expr::ABI_ARGS[index]))
            }
            // A computed destination of the copy's size is an element of an array of such records.
            Dest::Computed => {
                return format!(
                    "copied by {} at {:#x} to +{:#x} of a {:#x}-byte record",
                    self.how, self.ip, self.offset, self.size
                );
            }
        };
        format!("copied by {} at {:#x} to +{:#x} of {into} ({:#x} bytes)", self.how, self.ip, self.offset, self.size)
    }
}

/// A copy instruction: its name, and the registers holding the source, the destination and the
/// count, with the bytes per count unit.
pub struct CopyOp {
    pub how: String,
    pub source: Register,
    pub destination: Register,
    pub count: Register,
    pub unit: u64,
    /// A call: `rax` returns the destination, and the volatile registers are gone afterwards.
    pub call: bool,
}

pub fn copy_op(image: &Image, ins: &Instruction) -> Option<CopyOp> {
    let unit = match ins.mnemonic() {
        Mnemonic::Movsb => 1,
        Mnemonic::Movsw => 2,
        Mnemonic::Movsd if ins.op_count() == 2 && ins.op0_kind() == iced_x86::OpKind::MemoryESRDI => 4,
        Mnemonic::Movsq => 8,
        _ => 0,
    };
    if unit != 0 && ins.has_rep_prefix() {
        return Some(CopyOp {
            how: format!("rep {}", format!("{:?}", ins.mnemonic()).to_ascii_lowercase()),
            source: Register::RSI,
            destination: Register::RDI,
            count: Register::RCX,
            unit,
            call: false,
        });
    }
    let name = copy_name(image, ins)?;
    Some(CopyOp {
        how: name,
        source: Register::RSI,
        destination: Register::RDI,
        count: Register::RDX,
        unit: 1,
        call: true,
    })
}

/// The copy routine a call or tail jump reaches: an imported slot, a PLT stub or a symbol.
fn copy_name(image: &Image, ins: &Instruction) -> Option<String> {
    if !matches!(
        ins.flow_control(),
        iced_x86::FlowControl::Call
            | iced_x86::FlowControl::IndirectCall
            | iced_x86::FlowControl::UnconditionalBranch
            | iced_x86::FlowControl::IndirectBranch
    ) {
        return None;
    }
    let routine = if ins.is_ip_rel_memory_operand() { copy_routine_at(image, ins.ip_rel_memory_address()) } else { None };
    routine.or_else(|| routine_named(image, call_target(image, ins)?)).map(str::to_owned)
}

/// The copy routine at `target`: a PLT stub of one, or its symbol.
fn routine_named(image: &Image, target: u64) -> Option<&'static str> {
    crate::runtime::plt_import(image, target)
        .or_else(|| image.symbols.iter().find(|(at, _)| *at == target).map(|(_, name)| name.as_str()))
        .and_then(known)
}

/// `name` (any `@version` suffix ignored) when it is a library copy routine.
fn known(name: &str) -> Option<&'static str> {
    let base = name.split('@').next().unwrap_or_default();
    COPY_FUNCTIONS.iter().find(|routine| **routine == base).copied()
}

/// The copy routine a data slot points to: an imported one (`memcpy@got`, or a function-pointer
/// variable relocated to `memcpy`), or one whose PLT stub or symbol the slot holds.
pub fn copy_routine_at(image: &Image, slot: u64) -> Option<&'static str> {
    match image.slot(slot) {
        Some(ImageSlot::Import(name)) => known(name),
        Some(ImageSlot::Pointer(target)) => routine_named(image, target),
        None => {
            let bytes: [u8; 8] = image.read(slot, 8)?.try_into().ok()?;
            routine_named(image, u64::from_le_bytes(bytes))
        }
    }
}

/// The register `ins` loads a copy routine into: `mov r15, [rip + memcpy@got]`, as LLVM hoists it
/// out of a loop that copies every element.
pub fn loads_copy_routine(image: &Image, ins: &Instruction) -> Option<(Register, &'static str)> {
    let load = ins.mnemonic() == Mnemonic::Mov
        && ins.op_count() == 2
        && ins.op0_kind() == OpKind::Register
        && ins.op0_register().size() == 8
        && ins.op1_kind() == OpKind::Memory
        && ins.memory_index() == Register::None;
    // `[rip + slot]`, or an absolute `[slot]` in a non-PIE binary.
    let slot = match ins.memory_base() {
        _ if !load => return None,
        Register::RIP => ins.ip_rel_memory_address(),
        Register::None => ins.memory_displacement64(),
        _ => return None,
    };
    copy_routine_at(image, slot).map(|name| (ins.op0_register(), name))
}

/// [`copy_op`], or a call through a register `held` says holds a copy routine (`call r15`).
pub fn copy_op_at(image: &Image, ins: &Instruction, held: Option<&Held>) -> Option<CopyOp> {
    copy_op(image, ins).or_else(|| {
        let through = ins.flow_control() == FlowControl::IndirectCall && ins.op0_kind() == OpKind::Register;
        let name = held?.copiers.get(&ins.op0_register().full_register()).filter(|_| through)?;
        Some(CopyOp {
            how: format!("{name} (through {})", crate::expr::reg_name(ins.op0_register())),
            source: Register::RSI,
            destination: Register::RDI,
            count: Register::RDX,
            unit: 1,
            call: true,
        })
    })
}
