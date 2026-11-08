/*
 * XRef — Control-flow and register-write helpers for argument tracking
 * Copyright (c) 2026 Alexander Panasenko
 * Contact: alex@prod.codes
 * Author: https://prod.codes/about/
 * Project: https://github.com/alex09x/xref
 * SPDX-License-Identifier: MIT OR Apache-2.0
 */

use std::collections::BTreeSet;
use std::ops::Range;

use iced_x86::{FlowControl, Instruction, InstructionInfoFactory, OpAccess, Register};

use crate::image::Image;
use crate::scan::branch_target;
use crate::tables::tables;

pub const GPRS: [Register; 16] = [
    Register::RAX,
    Register::RCX,
    Register::RDX,
    Register::RBX,
    Register::RSP,
    Register::RBP,
    Register::RSI,
    Register::RDI,
    Register::R8,
    Register::R9,
    Register::R10,
    Register::R11,
    Register::R12,
    Register::R13,
    Register::R14,
    Register::R15,
];

/// The bit of a general-purpose register in a `u16` mask.
pub fn bit(register: Register) -> Option<u16> {
    GPRS.iter().position(|r| *r == register.full_register()).map(|index| 1 << index)
}

/// `AH`, `BH`, `CH`, `DH`: bits 8..15 of their register, never its low bytes.
pub const fn high_byte(register: Register) -> bool {
    matches!(register, Register::AH | Register::BH | Register::CH | Register::DH)
}

/// Full registers `ins` writes, explicitly or implicitly (`rep stos` writes rcx and rdi,
/// `lock xadd [m], r` writes r, `cmpxchg` writes rax).
pub fn written(factory: &mut InstructionInfoFactory, ins: &Instruction) -> Vec<Register> {
    factory
        .info(ins)
        .used_registers()
        .iter()
        .filter(|used| {
            matches!(
                used.access(),
                OpAccess::Write | OpAccess::ReadWrite | OpAccess::CondWrite | OpAccess::ReadCondWrite
            )
        })
        .map(|used| used.register().full_register())
        .collect()
}

/// Block starts inside `f`: direct branch targets and, when the function jumps through a table,
/// the table's arms.
pub fn targets(image: &Image, f: &Range<u64>, code: &[Instruction]) -> BTreeSet<u64> {
    let mut found: BTreeSet<u64> = code.iter().filter_map(branch_target).filter(|t| f.contains(t)).collect();
    if code.iter().any(|ins| ins.flow_control() == FlowControl::IndirectBranch && !ins.is_ip_rel_memory_operand()) {
        for table in tables(image, f) {
            found.extend(table.arms.iter().copied().filter(|arm| f.contains(arm)));
        }
    }
    found
}

/// Arms of every jump table of `f`: the successors taken for any indirect jump in it.
pub fn arms_of(image: &Image, f: &Range<u64>) -> Vec<u64> {
    tables(image, f).into_iter().flat_map(|table| table.arms).filter(|arm| f.contains(arm)).collect()
}
