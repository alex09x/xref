/*
 * xref — Ultra blazing fast cross-references of an x86-64 ELF binary
 * Copyright (c) 2026 Alexander Panasenko
 *
 * Contact: alex@prod.codes
 * Author: https://prod.codes/about/
 * SPDX-License-Identifier: MIT OR Apache-2.0
 */

//! Instruction facts (RIP-relative references, branch targets, immediates, stores and compares)
//! of every function, decoded in parallel.

use std::ops::Range;

use iced_x86::{Decoder, DecoderOptions, FlowControl, Formatter, Instruction, IntelFormatter, Mnemonic, OpKind};
use rayon::prelude::*;

use crate::image::Image;

pub struct Hit {
    pub ip: u64,
    pub function: Range<u64>,
    /// The RIP-relative memory address the instruction names.
    pub memory: Option<u64>,
    pub text: String,
}

/// What to look for in one instruction.
pub enum Query {
    /// RIP-relative memory operand at one of these sorted addresses.
    Ref(Vec<u64>),
    /// An immediate operand with this value; `store` / `cmp` narrow it to `mov [mem], imm` / `cmp`.
    Imm { value: u64, store: bool, cmp: bool },
    /// A call or jump to this address.
    Branch(u64),
}

/// Decode `bytes` located at `ip`, visiting every instruction.
pub fn decode(bytes: &[u8], ip: u64, mut visit: impl FnMut(&Instruction)) {
    let mut decoder = Decoder::with_ip(64, bytes, ip, DecoderOptions::NONE);
    let mut instruction = Instruction::default();
    while decoder.can_decode() {
        decoder.decode_out(&mut instruction);
        visit(&instruction);
    }
}

pub fn format(instruction: &Instruction) -> String {
    let mut formatter = IntelFormatter::new();
    let options = formatter.options_mut();
    options.set_hex_prefix("0x");
    options.set_hex_suffix("");
    options.set_uppercase_hex(false);
    options.set_space_after_operand_separator(true);
    options.set_branch_leading_zeros(false);
    let mut text = String::new();
    formatter.format(instruction, &mut text);
    text
}

fn immediates(instruction: &Instruction) -> impl Iterator<Item = u64> + '_ {
    (0..instruction.op_count())
        .filter(move |&index| {
            matches!(
                instruction.op_kind(index),
                OpKind::Immediate8
                    | OpKind::Immediate16
                    | OpKind::Immediate32
                    | OpKind::Immediate64
                    | OpKind::Immediate8to16
                    | OpKind::Immediate8to32
                    | OpKind::Immediate8to64
                    | OpKind::Immediate32to64
            )
        })
        .map(move |index| instruction.immediate(index))
}

/// The direct target of a call or jump.
pub fn branch_target(instruction: &Instruction) -> Option<u64> {
    matches!(
        instruction.flow_control(),
        FlowControl::Call | FlowControl::UnconditionalBranch | FlowControl::ConditionalBranch
    )
    .then(|| instruction.op0_kind())
    .filter(|kind| matches!(kind, OpKind::NearBranch16 | OpKind::NearBranch32 | OpKind::NearBranch64))
    .map(|_| instruction.near_branch_target())
}

pub fn matches(query: &Query, instruction: &Instruction) -> bool {
    match query {
        Query::Ref(targets) => {
            instruction.is_ip_rel_memory_operand()
                && targets.binary_search(&instruction.ip_rel_memory_address()).is_ok()
        }
        Query::Imm { value, store, cmp } => {
            (!store || (instruction.mnemonic() == Mnemonic::Mov && instruction.op0_kind() == OpKind::Memory))
                && (!cmp || instruction.mnemonic() == Mnemonic::Cmp)
                && immediates(instruction).any(|immediate| immediate == *value)
        }
        Query::Branch(target) => branch_target(instruction) == Some(*target),
    }
}

/// Every instruction of `functions` matching `query`, by address.
pub fn search_in(image: &Image, functions: &[Range<u64>], query: &Query) -> Vec<Hit> {
    let mut hits: Vec<Hit> = functions
        .par_iter()
        .flat_map_iter(|function| {
            let mut found = Vec::new();
            if let Some(bytes) = image.code(function) {
                decode(bytes, function.start, |instruction| {
                    if matches(query, instruction) {
                        let memory =
                            instruction.is_ip_rel_memory_operand().then(|| instruction.ip_rel_memory_address());
                        found.push(Hit {
                            ip: instruction.ip(),
                            function: function.clone(),
                            memory,
                            text: format(instruction),
                        });
                    }
                });
            }
            found
        })
        .collect();
    hits.sort_by_key(|hit| hit.ip);
    hits.dedup_by_key(|hit| hit.ip);
    hits
}

/// Every instruction of every function matching `query`, by address.
pub fn search(image: &Image, query: &Query) -> Vec<Hit> {
    search_in(image, &image.functions, query)
}

#[cfg(test)]
mod tests {
    use super::{Query, decode, matches};

    fn first(bytes: &[u8], ip: u64) -> iced_x86::Instruction {
        let mut found = None;
        decode(bytes, ip, |instruction| {
            found.get_or_insert(*instruction);
        });
        found.unwrap_or_default()
    }

    #[test]
    fn rip_references_stores_compares_and_calls_are_recognized() {
        // lea rsi,[rip+0x10] at 0x1000 refers to 0x1017.
        let lea = first(&[0x48, 0x8d, 0x35, 0x10, 0, 0, 0], 0x1000);
        assert!(matches(&Query::Ref(vec![0x17, 0x1017]), &lea));
        assert!(!matches(&Query::Ref(vec![0x1016]), &lea));
        // mov word ptr [rbx],0x194: storing enum variant 404.
        let store = first(&[0x66, 0xc7, 0x03, 0x94, 0x01], 0x2000);
        assert!(matches(&Query::Imm { value: 0x194, store: true, cmp: false }, &store));
        assert!(!matches(&Query::Imm { value: 0x194, store: false, cmp: true }, &store));
        // cmp qword ptr [rbx],9: a length limit.
        let compare = first(&[0x48, 0x83, 0x3b, 0x09], 0x3000);
        assert!(matches(&Query::Imm { value: 9, store: false, cmp: true }, &compare));
        // call rel32 0 at 0x4000 targets 0x4005.
        let call = first(&[0xe8, 0, 0, 0, 0], 0x4000);
        assert!(matches(&Query::Branch(0x4005), &call));
    }
}
