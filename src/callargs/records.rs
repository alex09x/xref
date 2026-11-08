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

use super::flow::{bit, targets, written};
use super::pointer::Reader;
use super::scan::VOLATILE;
use crate::image::Image;
use crate::scan::{self, decode};

/// Element readers reported at most, binary-wide.
pub const MAX_READERS: usize = 64;

pub fn element_readers(image: &Image, stride: u64, offset: u64, width: usize) -> Vec<Reader> {
    let mut found: Vec<Reader> = image
        .functions
        .par_iter()
        .filter_map(|f| Some((f, image.code(f)?)))
        .flat_map_iter(|(f, bytes)| {
            let mut code = Vec::new();
            decode(bytes, f.start, |ins| code.push(*ins));
            in_function(image, f, &code, stride, offset, width)
        })
        .collect();
    found.sort_by_key(|reader| reader.ip);
    found.truncate(MAX_READERS);
    found
}

fn in_function(
    image: &Image,
    f: &std::ops::Range<u64>,
    code: &[Instruction],
    stride: u64,
    offset: u64,
    width: usize,
) -> Vec<Reader> {
    let leaders: BTreeSet<u64> = targets(image, f, code);
    // A loop over the records steps a pointer by the stride (`add rbx, 0x2c8`), usually after
    // the reads at the loop head: such a register is a record pointer anywhere in the function.
    let stepped = code.iter().filter(|ins| steps_by(ins, stride)).fold(0u16, |mask, ins| {
        mask | bit(ins.op0_register()).unwrap_or(0)
    });
    let mut factory = InstructionInfoFactory::new();
    let mut elements: u16 = 0;
    let mut found = Vec::new();
    for ins in code {
        if leaders.contains(&ins.ip()) {
            elements = 0;
        }
        let holds = |register: Register| bit(register).is_some_and(|b| (elements | stepped) & b != 0);
        let reads = factory.info(ins).used_memory().iter().any(|used| {
            (holds(used.base()) || (holds(used.index()) && used.scale() == 1))
                && used.displacement() == offset
                && used.memory_size().size() == width
                && matches!(used.access(), OpAccess::Read | OpAccess::CondRead | OpAccess::ReadWrite)
        });
        if reads {
            found.push(Reader { ip: ins.ip(), function: f.clone(), text: scan::format(ins), via: Vec::new() });
        }
        if matches!(ins.flow_control(), FlowControl::Call | FlowControl::IndirectCall) {
            for volatile in VOLATILE {
                elements &= !bit(volatile).unwrap_or(0);
            }
            continue;
        }
        if ins.flow_control() != FlowControl::Next {
            elements = 0;
            continue;
        }
        let gained = element_write(ins, stride, &holds);
        for register in written(&mut factory, ins) {
            elements &= !bit(register).unwrap_or(0);
        }
        elements |= gained;
    }
    found
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

/// The register `ins` makes an element address: `imul reg, x, stride`, or an `add`/`lea`/`mov` of
/// one that already is.
fn element_write(ins: &Instruction, stride: u64, holds: &dyn Fn(Register) -> bool) -> u16 {
    if ins.op_count() == 0 || ins.op0_kind() != OpKind::Register || ins.op0_register().size() != 8 {
        return 0;
    }
    let destination = bit(ins.op0_register()).unwrap_or(0);
    let element = match ins.mnemonic() {
        Mnemonic::Imul => ins.op_count() == 3 && ins.immediate(2) == stride,
        Mnemonic::Add => holds(ins.op0_register()) || (ins.op1_kind() == OpKind::Register && holds(ins.op1_register())),
        Mnemonic::Mov => ins.op1_kind() == OpKind::Register && holds(ins.op1_register()),
        Mnemonic::Lea => {
            ins.memory_displacement64() == 0
                && (holds(ins.memory_base()) || (holds(ins.memory_index()) && ins.memory_index_scale() == 1))
        }
        _ => false,
    };
    if element { destination } else { 0 }
}
