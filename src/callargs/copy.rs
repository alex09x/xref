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

use iced_x86::{Instruction, Mnemonic, Register};

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
    let name = if ins.is_ip_rel_memory_operand() {
        match image.slot(ins.ip_rel_memory_address()) {
            Some(ImageSlot::Import(name)) => Some(name.to_owned()),
            _ => None,
        }
    } else {
        None
    }
    .or_else(|| {
        let target = call_target(image, ins)?;
        crate::runtime::plt_import(image, target)
            .map(str::to_owned)
            .or_else(|| image.symbols.iter().find(|(at, _)| *at == target).map(|(_, name)| name.clone()))
    })?;
    let base = name.split('@').next().unwrap_or_default();
    COPY_FUNCTIONS.contains(&base).then(|| base.to_owned())
}
