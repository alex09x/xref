/*
 * xref — Ultra blazing fast cross-references of an x86-64 ELF binary
 * Copyright (c) 2026 Alexander Panasenko
 *
 * Contact: alex@prod.codes
 * Author: https://prod.codes/about/
 * Project: https://github.com/alex09x/xref
 * SPDX-License-Identifier: MIT OR Apache-2.0
 */

//! Stores of a tag value, with the layout evidence that they write an enum value: the store sits
//! at the tag's offset of a non-stack object, or a payload store to the same object is next to
//! it. A store without evidence may be any unrelated byte, flag or field holding the same number.

use std::collections::HashMap;
use std::ops::Range;

use iced_x86::{FlowControl, Instruction, Mnemonic, OpKind, Register};
use rayon::prelude::*;

use super::dispatch::Tag;
use crate::image::Image;
use crate::scan::{self, decode};

/// Instructions searched on each side of a tag store for a payload store to the same object.
const NEIGHBOURS: usize = 8;
/// Bytes past the tag a payload store may be at.
const PAYLOAD_SPAN: u64 = 0x40;

pub struct Store {
    pub ip: u64,
    pub function: Range<u64>,
    pub text: String,
    /// Why the store is taken for this enum's tag; empty when nothing but the value matches.
    pub evidence: Vec<String>,
}

/// Every `mov [mem], value` of the tag's width, directly or through a register loaded with the
/// constant in the same straight-line run.
pub fn stores(image: &Image, tag: &Tag, value: u64) -> Vec<Store> {
    let mask = tag.mask();
    let mut found: Vec<Store> = image
        .functions
        .par_iter()
        .flat_map_iter(|f| {
            let mut code: Vec<Instruction> = Vec::new();
            if let Some(bytes) = image.code(f) {
                decode(bytes, f.start, |ins| code.push(*ins));
            }
            let mut held: HashMap<Register, u64> = HashMap::new();
            let mut hits = Vec::new();
            for (at, ins) in code.iter().enumerate() {
                if stored(ins, tag.width, &held).is_some_and(|v| v & mask == value) {
                    hits.push(at);
                }
                track(ins, &mut held);
            }
            hits.into_iter()
                .map(|at| Store {
                    ip: code[at].ip(),
                    function: f.clone(),
                    text: scan::format(&code[at]),
                    evidence: evidence(&code, at, tag),
                })
                .collect::<Vec<_>>()
        })
        .collect();
    found.sort_by_key(|s| s.ip);
    found
}

/// The value `ins` stores, when it is a `mov` to memory of `width` bytes from an immediate or a
/// register holding a known constant.
fn stored(ins: &Instruction, width: usize, held: &HashMap<Register, u64>) -> Option<u64> {
    if ins.mnemonic() != Mnemonic::Mov || ins.op0_kind() != OpKind::Memory || ins.memory_size().size() != width {
        return None;
    }
    match ins.op1_kind() {
        OpKind::Register => held.get(&ins.op1_register().full_register()).copied(),
        OpKind::Immediate8 | OpKind::Immediate16 | OpKind::Immediate32 | OpKind::Immediate32to64 => {
            Some(ins.immediate(1))
        }
        _ => None,
    }
}

/// Registers holding a `mov reg, imm` constant of 32 or 64 bits (which sets the whole register),
/// forgotten at any other write, a partial-register write or control flow.
fn track(ins: &Instruction, held: &mut HashMap<Register, u64>) {
    if ins.flow_control() != FlowControl::Next {
        held.clear();
        return;
    }
    if matches!(
        ins.mnemonic(),
        Mnemonic::Mul | Mnemonic::Imul | Mnemonic::Div | Mnemonic::Idiv | Mnemonic::Cqo | Mnemonic::Cdq
    ) {
        held.remove(&Register::RAX);
        held.remove(&Register::RDX);
    }
    if matches!(ins.mnemonic(), Mnemonic::Xchg | Mnemonic::Xadd) && ins.op1_kind() == OpKind::Register {
        held.remove(&ins.op1_register().full_register());
    }
    if ins.op_count() == 0 || ins.op0_kind() != OpKind::Register || reads_only(ins.mnemonic()) {
        return;
    }
    let register = ins.op0_register();
    let whole = register.size() >= 4;
    if whole && ins.mnemonic() == Mnemonic::Mov && !matches!(ins.op1_kind(), OpKind::Register | OpKind::Memory) {
        held.insert(register.full_register(), ins.immediate(1));
    } else {
        held.remove(&register.full_register());
    }
}

const fn reads_only(mnemonic: Mnemonic) -> bool {
    matches!(mnemonic, Mnemonic::Cmp | Mnemonic::Test | Mnemonic::Bt | Mnemonic::Push)
}

/// Layout evidence of the store at `code[at]`: the tag offset of a non-stack object, and the
/// nearest payload store to the same object in the same straight-line run.
fn evidence(code: &[Instruction], at: usize, tag: &Tag) -> Vec<String> {
    let ins = &code[at];
    let base = ins.memory_base().full_register();
    if base == Register::None || ins.memory_index() != Register::None || ins.is_ip_rel_memory_operand() {
        return Vec::new();
    }
    let displacement = ins.memory_displacement64();
    let mut found = Vec::new();
    if !matches!(base, Register::RSP | Register::RBP) && displacement == tag.displacement {
        found.push("tag offset".to_owned());
    }
    let payload = |other: &Instruction| {
        let offset = other.memory_displacement64().wrapping_sub(displacement);
        (writes_memory(other)
            && other.memory_base().full_register() == base
            && other.memory_index() == Register::None
            && (1..=PAYLOAD_SPAN).contains(&offset))
        .then_some(offset)
    };
    let after = code[at + 1..].iter().take(NEIGHBOURS).take_while(|o| !ends_run(o, base));
    let before = code[..at].iter().rev().take(NEIGHBOURS).take_while(|o| !ends_run(o, base));
    if let Some(offset) = after.chain(before).find_map(payload) {
        found.push(format!("payload +{offset:#x}"));
    }
    found
}

/// Control flow or a write of the object's base register ends the run the payload belongs to.
fn ends_run(ins: &Instruction, base: Register) -> bool {
    ins.flow_control() != FlowControl::Next
        || (ins.op_count() > 0
            && ins.op0_kind() == OpKind::Register
            && ins.op0_register().full_register() == base
            && !reads_only(ins.mnemonic()))
}

fn writes_memory(ins: &Instruction) -> bool {
    use Mnemonic::{
        Mov, Movapd, Movaps, Movd, Movdqa, Movdqu, Movq, Movsd, Movss, Movupd, Movups, Vmovdqa, Vmovdqu, Vmovups,
    };
    ins.op_count() > 0
        && ins.op0_kind() == OpKind::Memory
        && matches!(
            ins.mnemonic(),
            Mov | Movapd
                | Movaps
                | Movd
                | Movdqa
                | Movdqu
                | Movq
                | Movsd
                | Movss
                | Movupd
                | Movups
                | Vmovdqa
                | Vmovdqu
                | Vmovups
        )
}
