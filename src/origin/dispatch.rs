/*
 * xref — Ultra blazing fast cross-references of an x86-64 ELF binary
 * Copyright (c) 2026 Alexander Panasenko
 *
 * Contact: alex@prod.codes
 * Author: https://prod.codes/about/
 * Project: https://github.com/alex09x/xref
 * SPDX-License-Identifier: MIT OR Apache-2.0
 */

//! How a jump table turns an enum value into its index: the tag load feeding the dispatch, its
//! width, and the niche bias (`mov rax,[x]; sub rax,K; mov ecx,D; cmovae rcx,rax`).

use std::ops::Range;

use iced_x86::{Instruction, Mnemonic, OpKind, Register};

use crate::image::Image;
use crate::scan::decode;

/// How many instructions before the dispatch the tag load may be.
const LOOKBACK: usize = 24;

/// The enum tag a jump table dispatches on: `index = tag - bias`, except the `dataful` index,
/// which the niche encoding gives every tag below `bias` (the variant holding the payload).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Tag {
    /// Bytes of the tag load: 1, 2, 4 or 8.
    pub width: usize,
    pub base: Register,
    pub displacement: u64,
    pub bias: u64,
    pub dataful: Option<u64>,
}

impl Tag {
    /// The tag value stored for a variant index, or `None` for the dataful variant.
    pub fn value(&self, index: usize) -> Option<u64> {
        let index = index as u64;
        if self.dataful == Some(index) {
            return None;
        }
        Some(index.wrapping_add(self.bias) & self.mask())
    }

    pub const fn mask(&self) -> u64 {
        if self.width >= 8 { u64::MAX } else { (1u64 << (self.width * 8)) - 1 }
    }

    pub const fn type_name(&self) -> &'static str {
        match self.width {
            1 => "u8",
            2 => "u16",
            4 => "u32",
            _ => "u64",
        }
    }
}

/// The tag behind the dispatch at `dispatch` (`movsxd rX, [rT+rI*4]`) of `function`.
pub fn tag_of(image: &Image, function: &Range<u64>, dispatch: u64) -> Option<Tag> {
    let bytes = image.code(function)?;
    let mut before: Vec<Instruction> = Vec::new();
    let mut found = None;
    decode(bytes, function.start, |instruction| {
        if found.is_some() {
            return;
        }
        if instruction.ip() == dispatch {
            found = Some(*instruction);
        } else {
            before.push(*instruction);
        }
    });
    let dispatch = found?;
    let window = &before[before.len().saturating_sub(LOOKBACK)..];
    trace_back(window, dispatch.memory_index().full_register())
}

/// Walks back from the dispatch through the moves and adjustments of the index register to the load.
fn trace_back(window: &[Instruction], index: Register) -> Option<Tag> {
    let (mut track, mut bias, mut dataful, mut default_reg) = (index, 0u64, None, None);
    for instruction in window.iter().rev() {
        if instruction.op_count() == 0 || instruction.op0_kind() != OpKind::Register {
            if is_barrier(instruction) {
                return None;
            }
            continue;
        }
        let written = instruction.op0_register().full_register();
        if default_reg == Some(written)
            && instruction.mnemonic() == Mnemonic::Mov
            && is_immediate(instruction.op1_kind())
        {
            dataful = Some(instruction.immediate(1));
            default_reg = None;
            continue;
        }
        if written != track || reads_only(instruction.mnemonic()) {
            if is_barrier(instruction) {
                return None;
            }
            continue;
        }
        match (instruction.mnemonic(), instruction.op1_kind()) {
            (Mnemonic::Movzx | Mnemonic::Mov | Mnemonic::Movsx | Mnemonic::Movsxd, OpKind::Memory) => {
                if instruction.is_ip_rel_memory_operand() || instruction.memory_index() != Register::None {
                    return None;
                }
                let width = instruction.memory_size().size();
                return matches!(width, 1 | 2 | 4 | 8).then(|| Tag {
                    width,
                    base: instruction.memory_base(),
                    displacement: instruction.memory_displacement64(),
                    bias,
                    dataful,
                });
            }
            (Mnemonic::Mov | Mnemonic::Movzx, OpKind::Register) => track = instruction.op1_register().full_register(),
            (Mnemonic::Sub, kind) if is_immediate(kind) => bias = bias.wrapping_add(instruction.immediate(1)),
            (Mnemonic::Add, kind) if is_immediate(kind) => bias = bias.wrapping_sub(instruction.immediate(1)),
            (Mnemonic::Lea, OpKind::Memory) if instruction.memory_index() == Register::None => {
                bias = bias.wrapping_sub(instruction.memory_displacement64());
                track = instruction.memory_base().full_register();
            }
            (m, OpKind::Register) if is_cmov(m) => {
                // `cmovCC rI, rS`: rI keeps its earlier constant (the dataful index) when CC fails.
                default_reg = Some(written);
                track = instruction.op1_register().full_register();
            }
            _ => return None,
        }
    }
    None
}

const fn is_immediate(kind: OpKind) -> bool {
    matches!(
        kind,
        OpKind::Immediate8
            | OpKind::Immediate8to32
            | OpKind::Immediate8to64
            | OpKind::Immediate32
            | OpKind::Immediate32to64
    )
}

const fn reads_only(mnemonic: Mnemonic) -> bool {
    matches!(mnemonic, Mnemonic::Cmp | Mnemonic::Test | Mnemonic::Bt | Mnemonic::Push)
}

const fn is_cmov(mnemonic: Mnemonic) -> bool {
    use Mnemonic::{
        Cmova, Cmovae, Cmovb, Cmovbe, Cmove, Cmovg, Cmovge, Cmovl, Cmovle, Cmovne, Cmovno, Cmovnp, Cmovns, Cmovo,
        Cmovp, Cmovs,
    };
    matches!(
        mnemonic,
        Cmova
            | Cmovae
            | Cmovb
            | Cmovbe
            | Cmove
            | Cmovg
            | Cmovge
            | Cmovl
            | Cmovle
            | Cmovne
            | Cmovno
            | Cmovnp
            | Cmovns
            | Cmovo
            | Cmovp
            | Cmovs
    )
}

/// A jump, call or return between the load and the dispatch ends the straight-line trace; a
/// conditional branch (the bounds check before a dispatch) falls through to it.
fn is_barrier(instruction: &Instruction) -> bool {
    use iced_x86::FlowControl;
    !matches!(instruction.flow_control(), FlowControl::Next | FlowControl::ConditionalBranch)
}
