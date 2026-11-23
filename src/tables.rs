/*
 * xref — Ultra blazing fast cross-references of an x86-64 ELF binary
 * Copyright (c) 2026 Alexander Panasenko
 *
 * Contact: alex@prod.codes
 * Author: https://prod.codes/about/
 * SPDX-License-Identifier: MIT OR Apache-2.0
 */

//! Relative jump tables (`lea rT,[rip+T]; movsxd rX,dword ptr [rT+rI*4]`) of a function and the
//! table indices an address belongs to: a Rust `match` arm, e.g. an error enum variant.

use std::collections::HashMap;
use std::ops::Range;

use iced_x86::{FlowControl, Instruction, Mnemonic, OpKind, Register};

use crate::image::Image;
use crate::scan::decode;

pub struct Table {
    pub dispatch: u64,
    pub base: u64,
    /// Arm address of every index.
    pub arms: Vec<u64>,
}

/// The jump tables dispatched inside `function`. Entries are read while their target stays in it,
/// up to the dispatch's range check (`cmp idx, 4; ja default` allows 5) and never into the next
/// address the function names RIP-relative: adjacent tables of one `match` point into the same
/// function, so the target test alone runs from one table into the next.
pub fn tables(image: &Image, function: &Range<u64>) -> Vec<Table> {
    let Some(bytes) = image.code(function) else { return Vec::new() };
    let mut leas: HashMap<Register, u64> = HashMap::new();
    // Registers checked by `cmp r, imm` + an unsigned jump: how many indices pass, and the
    // instruction count at the check. A check counts only for a dispatch close after it in the
    // same straight-line run, so one from another block cannot cut a later table.
    let mut bounds: HashMap<Register, (u64, usize)> = HashMap::new();
    let mut compared: Option<(Register, u64)> = None;
    let mut named: Vec<u64> = Vec::new();
    let mut dispatches: Vec<(u64, u64, Option<u64>)> = Vec::new();
    let mut count = 0usize;
    decode(bytes, function.start, |instruction| {
        count += 1;
        if instruction.is_ip_rel_memory_operand() {
            named.push(instruction.ip_rel_memory_address());
        }
        if matches!(
            instruction.flow_control(),
            FlowControl::Call
                | FlowControl::IndirectCall
                | FlowControl::Return
                | FlowControl::UnconditionalBranch
                | FlowControl::IndirectBranch
                | FlowControl::Interrupt
        ) {
            // A call clobbers the checked register; after a jump or return the next instruction
            // starts a block reached some other way.
            bounds.clear();
        }
        let checked = compared.take();
        match instruction.mnemonic() {
            Mnemonic::Cmp if instruction.op0_kind() == OpKind::Register => {
                compared = immediate(instruction, 1).map(|v| (instruction.op0_register().full_register(), v));
            }
            Mnemonic::Ja | Mnemonic::Jbe | Mnemonic::Jae | Mnemonic::Jb => {
                if let Some((register, limit)) = checked {
                    let inclusive = matches!(instruction.mnemonic(), Mnemonic::Ja | Mnemonic::Jbe);
                    bounds.insert(register, (if inclusive { limit.saturating_add(1) } else { limit }, count));
                }
            }
            Mnemonic::Lea if instruction.is_ip_rel_memory_operand() => {
                let register = instruction.op0_register().full_register();
                leas.insert(register, instruction.ip_rel_memory_address());
                bounds.remove(&register);
            }
            Mnemonic::Movsxd
                if instruction.memory_index_scale() == 4
                    && leas.contains_key(&instruction.memory_base().full_register()) =>
            {
                let base = leas[&instruction.memory_base().full_register()];
                let bound = bounds
                    .get(&instruction.memory_index().full_register())
                    .filter(|(_, at)| count - at <= CHECK_WINDOW)
                    .map(|(bound, _)| *bound);
                dispatches.push((instruction.ip(), base, bound));
            }
            Mnemonic::Mov
                if instruction.op0_kind() == OpKind::Register && instruction.op1_kind() == OpKind::Register =>
            {
                // `mov ecx, eax` after the check carries it.
                let bound = bounds.get(&instruction.op1_register().full_register()).copied();
                let register = instruction.op0_register().full_register();
                match bound {
                    Some(bound) => bounds.insert(register, bound),
                    None => bounds.remove(&register),
                };
            }
            Mnemonic::Test | Mnemonic::Push => {}
            _ if instruction.op0_kind() == OpKind::Register => {
                bounds.remove(&instruction.op0_register().full_register());
            }
            _ => {}
        }
    });
    dispatches
        .into_iter()
        .map(|(dispatch, base, bound)| {
            let next = named.iter().copied().filter(|&at| at > base).min();
            let room = next.map_or(MAX_ENTRIES, |next| (next - base) / 4);
            let count = bound.unwrap_or(MAX_ENTRIES).min(room).min(MAX_ENTRIES);
            let arms = (0..count)
                .map_while(|index| {
                    let entry = image.read(base + index * 4, 4)?;
                    let offset = i32::from_le_bytes(entry.try_into().ok()?);
                    let arm = base.checked_add_signed(i64::from(offset))?;
                    function.contains(&arm).then_some(arm)
                })
                .collect();
            Table { dispatch, base, arms }
        })
        .collect()
}

const MAX_ENTRIES: u64 = 8192;

/// Instructions between a range check and its dispatch: `cmp; ja; [mov; cdqe;] lea; movsxd` is
/// a handful, so a check further back belongs to other code.
const CHECK_WINDOW: usize = 12;

/// Operand `index` as an immediate, if it is one.
fn immediate(instruction: &Instruction, index: u32) -> Option<u64> {
    matches!(
        instruction.op_kind(index),
        OpKind::Immediate8
            | OpKind::Immediate16
            | OpKind::Immediate32
            | OpKind::Immediate8to16
            | OpKind::Immediate8to32
            | OpKind::Immediate8to64
            | OpKind::Immediate32to64
    )
    .then(|| instruction.immediate(index))
}

/// Indices whose arm is the closest one at or before `addr` (shared arms give several).
pub fn arm_indices(arms: &[u64], addr: u64) -> Vec<usize> {
    let Some(arm) = arms.iter().copied().filter(|arm| *arm <= addr).max() else { return Vec::new() };
    arms.iter().enumerate().filter(|(_, candidate)| **candidate == arm).map(|(index, _)| index).collect()
}

#[cfg(test)]
mod tests {
    use super::{arm_indices, tables};
    use crate::image::{Image, Segment};

    /// Two dispatches over adjacent tables: the first checked by `cmp eax, 4; ja`, the second
    /// unchecked but followed by a third table the function also names (#203).
    #[test]
    #[allow(clippy::cast_possible_truncation)] // Small fixture offsets.
    fn a_table_ends_at_its_range_check_or_at_the_next_named_address() {
        let mut data = vec![0xc3u8; 0x300];
        let code: &[u8] = &[
            0x83, 0xf8, 0x02, // 0x1000: cmp eax, 2 (3 of the 5 entries before the next table)
            0x77, 0x4b, // 0x1003: ja 0x1050
            0x48, 0x8d, 0x0d, 0xf4, 0x01, 0x00, 0x00, // 0x1005: lea rcx, [rip+0x1f4] (0x1200)
            0x48, 0x63, 0x04, 0x81, // 0x100c: movsxd rax, dword [rcx+rax*4]
            0x48, 0x01, 0xc8, // 0x1010: add rax, rcx
            0xff, 0xe0, // 0x1013: jmp rax
            0x48, 0x8d, 0x15, 0xf8, 0x01, 0x00, 0x00, // 0x1015: lea rdx, [rip+0x1f8] (0x1214)
            0x48, 0x63, 0x04, 0x9a, // 0x101c: movsxd rax, dword [rdx+rbx*4]
            0x48, 0x01, 0xd0, // 0x1020: add rax, rdx
            0xff, 0xe0, // 0x1023: jmp rax
            0x48, 0x8d, 0x35, 0xf8, 0x01, 0x00, 0x00, // 0x1025: lea rsi, [rip+0x1f8] (0x1224)
        ];
        data[..code.len()].copy_from_slice(code);
        // Five entries at 0x1200, four at 0x1214, two at 0x1224; every arm is in the function.
        let mut put = |base: u64, arms: &[u64]| {
            for (i, &arm) in (0u64..).zip(arms) {
                let at = (base - 0x1000 + i * 4) as usize;
                let offset = (arm.cast_signed() - base.cast_signed()) as i32;
                data[at..at + 4].copy_from_slice(&offset.to_le_bytes());
            }
        };
        put(0x1200, &[0x1030, 0x1038, 0x1040, 0x1048, 0x1050]);
        put(0x1214, &[0x1060, 0x1068, 0x1070, 0x1078]);
        put(0x1224, &[0x1080, 0x1088]);
        let image = Image {
            data,
            segments: vec![Segment { va: 0x1000, offset: 0, size: 0x300 }],
            functions: vec![0x1000..0x1100, 0x1100..0x1101],
            ..Image::default()
        };
        let found = tables(&image, &(0x1000..0x1100));
        assert_eq!(found.len(), 2);
        assert_eq!((found[0].base, found[0].arms.len()), (0x1200, 3), "range check cmp eax, 2; ja");
        assert_eq!((found[1].base, found[1].arms.len()), (0x1214, 4), "stops at the next named table");
    }

    /// A check followed by a call says nothing about the register the call returns, so the table
    /// after it keeps all four entries (review of #206).
    #[test]
    #[allow(clippy::cast_possible_truncation)] // Small fixture offsets.
    fn a_range_check_before_a_call_does_not_bound_a_later_table() {
        let mut data = vec![0xc3u8; 0x300];
        let code: &[u8] = &[
            0x83, 0xf8, 0x01, // 0x1000: cmp eax, 1
            0x72, 0x10, // 0x1003: jb 0x1015
            0xe8, 0x00, 0x00, 0x00, 0x00, // 0x1005: call 0x100a
            0x48, 0x8d, 0x0d, 0xef, 0x01, 0x00, 0x00, // 0x100a: lea rcx, [rip+0x1ef] (0x1200)
            0x48, 0x63, 0x04, 0x81, // 0x1011: movsxd rax, dword [rcx+rax*4]
            0x48, 0x01, 0xc8, // 0x1015: add rax, rcx
            0xff, 0xe0, // 0x1018: jmp rax
        ];
        data[..code.len()].copy_from_slice(code);
        for (i, arm) in (0u64..).zip([0x1030u64, 0x1038, 0x1040, 0x1048]) {
            let at = (0x200 + i * 4) as usize;
            data[at..at + 4].copy_from_slice(&((arm.cast_signed() - 0x1200) as i32).to_le_bytes());
        }
        data[0x210..0x214].copy_from_slice(&0i32.to_le_bytes()); // ends the table
        let image = Image {
            data,
            segments: vec![Segment { va: 0x1000, offset: 0, size: 0x300 }],
            functions: vec![0x1000..0x1100, 0x1100..0x1101],
            ..Image::default()
        };
        let found = tables(&image, &(0x1000..0x1100));
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].arms.len(), 4, "a check before a call must not bound the table");
    }

    #[test]
    fn an_address_belongs_to_the_closest_preceding_arm() {
        let arms = [0x100, 0x180, 0x140, 0x180];
        assert_eq!(arm_indices(&arms, 0x185), [1, 3]);
        assert_eq!(arm_indices(&arms, 0x17f), [2]);
        assert_eq!(arm_indices(&arms, 0xff), Vec::<usize>::new());
    }
}
