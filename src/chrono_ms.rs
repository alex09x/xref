/*
 * xref — Ultra blazing fast cross-references of an x86-64 ELF binary
 * Copyright (c) 2026 Alexander Panasenko
 *
 * Contact: alex@prod.codes
 * Author: https://prod.codes/about/
 * Project: https://github.com/alex09x/xref
 * SPDX-License-Identifier: MIT OR Apache-2.0
 */

//! chrono's `NaiveDateTime::and_utc().timestamp_millis()` inlined: a dozen lines of date
//! arithmetic in the pseudo-C. The date is packed as `year << 13 | ordinal << 4 | flags`; the
//! days since the epoch come from the year (`* 1461 >> 2`, `/ 100` as `* 0x51eb851f`, `/ 400`)
//! and the ordinal, then `days * 86400 + secs`, `* 1000 + nanos / 1_000_000` (`* 0x431bde83 >>
//! 50`). The constants find it; the lifter then says what the result is, with its three inputs.

use std::cell::RefCell;
use std::collections::HashMap;

use iced_x86::{Instruction, Mnemonic, OpKind};

use crate::c_step::FnCtx;
use crate::expr::State;

/// The sequences of one function and the inputs read so far (kept across blocks: the date is
/// often read before a branch of the leap-year rule).
#[derive(Default)]
pub struct Chrono {
    pub found: Vec<ChronoMs>,
    pub inputs: RefCell<HashMap<u64, String>>,
}

impl Chrono {
    #[must_use]
    pub fn new(insns: &[Instruction]) -> Self {
        Self { found: find(insns), inputs: RefCell::default() }
    }
}

/// Seconds per day.
const DAY: u64 = 86_400;
/// `x * NANOS_MAGIC >> 50` is `x / 1_000_000` for 32-bit `x`.
const NANOS_MAGIC: u64 = 0x431b_de83;
/// `x * CENTURY_MAGIC >> 37` is `x / 100`.
const CENTURY_MAGIC: u64 = 0x51eb_851f;
/// Instructions searched around the `* 86400`.
const WINDOW: usize = 80;

/// One inlined `timestamp_millis`: the instructions whose inputs are named, and the result.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[allow(clippy::struct_field_names)] // Every field is the address of one instruction.
pub struct ChronoMs {
    /// `sar r, 13`: its register holds the packed date.
    pub date_ip: u64,
    /// `add r, secs` right after `* 86400`.
    pub secs_ip: u64,
    /// `imul r, nanos, 0x431bde83`.
    pub nanos_ip: u64,
    /// The `add` of `secs * 1000` and `nanos / 1_000_000`.
    pub result_ip: u64,
}

/// The immediate multiplier of `imul` (two- or three-operand form).
fn multiplier(instruction: &Instruction) -> Option<u64> {
    if instruction.mnemonic() != Mnemonic::Imul {
        return None;
    }
    (1..instruction.op_count()).find_map(|index| {
        matches!(
            instruction.op_kind(index),
            OpKind::Immediate8to32 | OpKind::Immediate8to64 | OpKind::Immediate32 | OpKind::Immediate32to64
        )
        .then(|| instruction.immediate(index) & 0xffff_ffff)
    })
}

fn register(instruction: &Instruction, index: u32) -> Option<iced_x86::Register> {
    (instruction.op_kind(index) == OpKind::Register).then(|| instruction.op_register(index).full_register())
}

/// Every inlined `timestamp_millis` in `insns` (one function, in address order).
#[must_use]
pub fn find(insns: &[Instruction]) -> Vec<ChronoMs> {
    let mut found = Vec::new();
    for (day, instruction) in insns.iter().enumerate() {
        if multiplier(instruction) != Some(DAY) {
            continue;
        }
        let Some(days) = register(instruction, 0) else { continue };
        let around = day.saturating_sub(WINDOW)..(day + WINDOW).min(insns.len());
        let before = &insns[day.saturating_sub(WINDOW)..day];
        let Some(secs) = insns[day + 1..(day + 4).min(insns.len())]
            .iter()
            .find(|i| i.mnemonic() == Mnemonic::Add && register(i, 0) == Some(days))
        else {
            continue;
        };
        let Some(date) = before.iter().rev().find(|i| {
            matches!(i.mnemonic(), Mnemonic::Sar | Mnemonic::Shr)
                && i.op1_kind() == OpKind::Immediate8
                && i.immediate(1) == 13
        }) else {
            continue;
        };
        if !before.iter().any(|i| multiplier(i) == Some(CENTURY_MAGIC)) {
            continue;
        }
        let Some(nanos) = insns[around.clone()].iter().find(|i| multiplier(i) == Some(NANOS_MAGIC)) else { continue };
        // `secs * 1000` and the add joining it with the quotient.
        let after = &insns[day + 1..around.end];
        let Some(milli) = after.iter().position(|i| multiplier(i) == Some(1000)) else { continue };
        let millis = register(&after[milli], 0);
        let Some(result) = after[milli + 1..].iter().take(8).find(|i| {
            i.mnemonic() == Mnemonic::Add
                && i.op1_kind() == OpKind::Register
                && (register(i, 0) == millis || register(i, 1) == millis)
        }) else {
            continue;
        };
        found.push(ChronoMs { date_ip: date.ip(), secs_ip: secs.ip(), nanos_ip: nanos.ip(), result_ip: result.ip() });
    }
    found
}

/// Before `instruction` is lifted: remember the inputs it reads, and for the result instruction
/// return the comment to put after its statement.
pub fn before(ctx: &FnCtx<'_>, state: &mut State, instruction: &Instruction) -> Option<String> {
    let ip = instruction.ip();
    let found = ctx.chrono.found.iter().find(|c| [c.date_ip, c.secs_ip, c.nanos_ip, c.result_ip].contains(&ip))?;
    let input = match ip {
        _ if ip == found.date_ip => Some(ctx.op(state, instruction, 0)),
        _ if ip == found.secs_ip || ip == found.nanos_ip => Some(ctx.op(state, instruction, 1)),
        _ => None,
    };
    let mut inputs = ctx.chrono.inputs.borrow_mut();
    if let Some(value) = input {
        inputs.insert(ip, value);
        return None;
    }
    let named = |at: u64| inputs.get(&at).cloned().unwrap_or_else(|| "?".to_owned());
    Some(format!(
        "/* ms = timestamp_millis(date {}, secs {}, nanos {}): chrono NaiveDateTime, (days * 86400 + secs) * 1000 + nanos / 1000000 */",
        named(found.date_ip),
        named(found.secs_ip),
        named(found.nanos_ip)
    ))
}

#[cfg(test)]
#[path = "chrono_ms_tests.rs"]
mod tests;
