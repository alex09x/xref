/*
 * xref — Ultra blazing fast cross-references of an x86-64 ELF binary
 * Copyright (c) 2026 Alexander Panasenko
 *
 * Contact: alex@prod.codes
 * Author: https://prod.codes/about/
 * Project: https://github.com/alex09x/xref
 * SPDX-License-Identifier: MIT OR Apache-2.0
 */

//! A hash of a function's instruction stream with its addresses abstracted, so a function that
//! did not change between two builds hashes the same in both although its data, its callees and
//! the function itself moved: RIP-relative operands, branches leaving the function and immediates
//! pointing into the image count only by kind; branches inside it count by their offset from the
//! function start; opcodes, registers, other immediates and displacements count as they are.

use std::hash::{DefaultHasher, Hash, Hasher};
use std::ops::Range;

use iced_x86::{Instruction, OpKind};

use crate::image::Image;

/// Functions shorter than this many instructions get no hash: stubs like `mov eax, edi; ret`
/// repeat everywhere and say nothing about which copy is which.
const MIN_INSTRUCTIONS: usize = 4;

/// Feeds one instruction of the function `f` into the running hash.
pub(super) fn add(image: &Image, f: &Range<u64>, ins: &Instruction, h: &mut DefaultHasher) {
    (ins.code() as u32).hash(h);
    for i in 0..ins.op_count() {
        let kind = ins.op_kind(i);
        (kind as u8).hash(h);
        match kind {
            OpKind::Register => (ins.op_register(i) as u32).hash(h),
            OpKind::NearBranch16 | OpKind::NearBranch32 | OpKind::NearBranch64 => {
                let target = ins.near_branch_target();
                // Inside the function the offset is the same in an unchanged copy; outside it the
                // callee moved with everything else.
                f.contains(&target).then(|| target - f.start).hash(h);
            }
            OpKind::Memory => {
                (ins.memory_size() as u32).hash(h);
                (ins.segment_prefix() as u32).hash(h);
                if !ins.is_ip_rel_memory_operand() {
                    (ins.memory_base() as u32).hash(h);
                    (ins.memory_index() as u32).hash(h);
                    ins.memory_index_scale().hash(h);
                    let disp = ins.memory_displacement64();
                    (!in_image(image, disp)).then_some(disp).hash(h);
                }
            }
            OpKind::Immediate8
            | OpKind::Immediate8_2nd
            | OpKind::Immediate16
            | OpKind::Immediate32
            | OpKind::Immediate64
            | OpKind::Immediate8to16
            | OpKind::Immediate8to32
            | OpKind::Immediate8to64
            | OpKind::Immediate32to64 => {
                let value = ins.immediate(i);
                (!in_image(image, value)).then_some(value).hash(h);
            }
            _ => {}
        }
    }
}

/// The finished hash, or 0 (no hash) for a function too short to tell copies apart.
pub(super) fn finish(h: &DefaultHasher, instructions: usize) -> u64 {
    if instructions < MIN_INSTRUCTIONS { 0 } else { h.finish().max(1) }
}

/// An address in a loaded segment (an absolute pointer in a non-PIE binary).
fn in_image(image: &Image, value: u64) -> bool {
    value >= 0x1000 && image.segments.iter().any(|s| (s.va..s.va + s.size as u64).contains(&value))
}
