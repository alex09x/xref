/*
 * xref — Ultra blazing fast cross-references of an x86-64 ELF binary
 * Copyright (c) 2026 Alexander Panasenko
 *
 * Contact: alex@prod.codes
 * Author: https://prod.codes/about/
 * Project: https://github.com/alex09x/xref
 * SPDX-License-Identifier: MIT OR Apache-2.0
 */

//! Short straight-line scans after a call site: does the caller read a result register?

use std::ops::Range;

use iced_x86::{FlowControl, InstructionInfoFactory, OpAccess, Register};

use super::zero_idiom_reg;
use crate::image::Image;
use crate::scan::{branch_target, decode};

fn slice_reads_reg(bytes: &[u8], start_ip: u64, limit: usize, reg: Register) -> (bool, Option<u64>) {
    let mut factory = InstructionInfoFactory::new();
    let (mut count, mut stopped, mut found_read, mut first_cond) = (0usize, false, false, None);
    decode(bytes, start_ip, |ins| {
        if stopped || count >= limit {
            stopped = true;
            return;
        }
        count += 1;
        if zero_idiom_reg(ins) == Some(reg) {
            stopped = true;
            return;
        }
        for u in factory.info(ins).used_registers() {
            if u.register().full_register() == reg {
                let acc = u.access();
                found_read =
                    matches!(acc, OpAccess::Read | OpAccess::CondRead | OpAccess::ReadWrite | OpAccess::ReadCondWrite);
                stopped = true;
                return;
            }
        }
        match ins.flow_control() {
            FlowControl::ConditionalBranch if first_cond.is_none() => first_cond = branch_target(ins),
            FlowControl::Next | FlowControl::ConditionalBranch => {}
            _ => stopped = true,
        }
    });
    (found_read, first_cond)
}

/// Whether code immediately following `after_ip` inside `function` reads `reg` before overwriting it.
pub fn call_reads_reg(image: &Image, function: &Range<u64>, after_ip: u64, reg: Register) -> bool {
    let Some(bytes) = (after_ip < function.end)
        .then(|| image.read(after_ip, usize::try_from(function.end - after_ip).unwrap_or(0)))
        .flatten()
    else {
        return false;
    };
    let (read_fall, cond_target) = slice_reads_reg(bytes, after_ip, 12, reg);
    read_fall
        || cond_target
            .filter(|t| function.contains(t))
            .and_then(|t| Some((t, image.read(t, usize::try_from(function.end - t).unwrap_or(0))?)))
            .is_some_and(|(t, tbytes)| slice_reads_reg(tbytes, t, 8, reg).0)
}

pub fn call_reads_rdx(image: &Image, function: &Range<u64>, after_ip: u64) -> bool {
    call_reads_reg(image, function, after_ip, Register::RDX)
}
