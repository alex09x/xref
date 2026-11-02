/*
 * xref — Ultra blazing fast cross-references of an x86-64 ELF binary
 * Copyright (c) 2026 Alexander Panasenko
 *
 * Contact: alex@prod.codes
 * Author: https://prod.codes/about/
 * Project: https://github.com/alex09x/xref
 * SPDX-License-Identifier: MIT OR Apache-2.0
 */

//! Struct field and stack displacement searches, filtering by access mode and stride.

use std::cell::RefCell;
use std::ops::Range;

use iced_x86::{FlowControl, Instruction, InstructionInfoFactory, Mnemonic, OpAccess, OpKind, Register};
use rayon::prelude::*;

use crate::expr::ABI_ARGS;
use crate::image::Image;
use crate::listing::{describe_branch, is_call};
use crate::scan::{DispHit, Hit, decode, format, immediates};
use crate::sig::has_frame_pointer;

/// Options controlling displacement search behavior.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct DispOptions {
    pub write: bool,
    pub lea: bool,
    pub stride: Option<u64>,
    pub stack: bool,
}

/// Determine whether the memory operand at `op_index` is written by `instruction`.
#[must_use]
pub fn is_mem_write(instruction: &Instruction, op_index: u32) -> bool {
    thread_local! {
        static FACTORY: RefCell<InstructionInfoFactory> =
            RefCell::new(InstructionInfoFactory::new());
    }
    FACTORY.with(|f| {
        let mut factory = f.borrow_mut();
        let info = factory.info(instruction);
        matches!(
            info.op_access(op_index),
            OpAccess::Write | OpAccess::CondWrite | OpAccess::ReadWrite | OpAccess::ReadCondWrite
        )
    })
}

pub fn update_stride(instruction: &Instruction, s: u64, stride_regs: &mut Vec<Register>) {
    let dst = instruction.op0_register().full_register();
    let has_stride = match instruction.mnemonic() {
        Mnemonic::Imul => immediates(instruction).any(|imm| imm == s),
        Mnemonic::Shl => immediates(instruction).any(|imm| imm < 64 && (1u64 << imm) == s),
        Mnemonic::Lea => {
            instruction.memory_displacement64() == s
                || u64::from(instruction.memory_index_scale()) == s
                || stride_regs.contains(&instruction.memory_base().full_register())
                || stride_regs.contains(&instruction.memory_index().full_register())
        }
        Mnemonic::Add => {
            instruction.op1_kind() == OpKind::Register
                && stride_regs.contains(&instruction.op1_register().full_register())
        }
        Mnemonic::Mov => {
            let from_stride = instruction.op1_kind() == OpKind::Register
                && stride_regs.contains(&instruction.op1_register().full_register());
            if !from_stride {
                stride_regs.retain(|r| *r != dst);
            }
            from_stride
        }
        _ => false,
    };
    if has_stride && dst != Register::None && !stride_regs.contains(&dst) {
        stride_regs.push(dst);
    }
}

#[must_use]
pub fn lea_callee(image: &Image, function: &Range<u64>, insns: &[Instruction], idx: usize) -> Option<String> {
    let mut holders = vec![insns[idx].op0_register().full_register()];
    let mut spills: Vec<i64> = Vec::new();
    let mut pushed = false;
    for next in &insns[idx + 1..(idx + 17).min(insns.len())] {
        if is_call(next, function) {
            return (pushed || ABI_ARGS.iter().any(|r| holders.contains(r))).then(|| describe_branch(image, next));
        }
        if matches!(
            next.flow_control(),
            FlowControl::Return | FlowControl::Interrupt | FlowControl::Exception | FlowControl::UnconditionalBranch
        ) {
            return None;
        }
        let m = next.mnemonic();
        if m == Mnemonic::Push
            && next.op0_kind() == OpKind::Register
            && holders.contains(&next.op0_register().full_register())
        {
            pushed = true;
        } else if m == Mnemonic::Mov {
            let is_rsp = !next.is_ip_rel_memory_operand()
                && next.memory_base().full_register() == Register::RSP
                && next.memory_index() == Register::None;
            let disp = next.memory_displacement64().cast_signed();
            if next.op0_kind() == OpKind::Register {
                let dst = next.op0_register().full_register();
                let keep = (next.op1_kind() == OpKind::Register
                    && holders.contains(&next.op1_register().full_register()))
                    || (next.op1_kind() == OpKind::Memory && is_rsp && spills.contains(&disp));
                holders.retain(|r| *r != dst);
                if keep {
                    holders.push(dst);
                }
            } else if is_rsp && next.op1_kind() == OpKind::Register {
                spills.retain(|d| *d != disp);
                if holders.contains(&next.op1_register().full_register()) {
                    spills.push(disp);
                }
            }
        } else if next.op0_kind() == OpKind::Register && !matches!(m, Mnemonic::Cmp | Mnemonic::Test) {
            holders.retain(|r| *r != next.op0_register().full_register());
        }
    }
    None
}

/// Search for instructions accessing displacements in `offsets` within `functions`.
#[must_use]
pub fn search(image: &Image, functions: &[Range<u64>], offsets: &[u64], options: DispOptions) -> Vec<DispHit> {
    let mut hits: Vec<DispHit> = functions
        .par_iter()
        .filter_map(|f| Some((f, image.code(f)?)))
        .flat_map_iter(|(function, bytes)| {
            let has_fp = has_frame_pointer(bytes, function.start);
            let mut insns = Vec::new();
            decode(bytes, function.start, |i| insns.push(*i));
            let mut found = Vec::new();
            let mut stride_regs = Vec::new();
            for (idx, instruction) in insns.iter().enumerate() {
                let off = instruction.memory_displacement64();
                let base = instruction.memory_base().full_register();
                let memory = (0..instruction.op_count()).find(|&index| instruction.op_kind(index) == OpKind::Memory);

                if let Some(mem_idx) = memory
                    && !instruction.is_ip_rel_memory_operand()
                    && base != Register::None
                {
                    let is_stack = base == Register::RSP || (has_fp && base == Register::RBP);
                    let stack_allowed = !is_stack || options.stack;
                    let is_lea = instruction.mnemonic() == Mnemonic::Lea;
                    let mode_matches = match (options.write, options.lea) {
                        (false, false) => true,
                        (true, false) => is_mem_write(instruction, mem_idx),
                        (false, true) => is_lea,
                        (true, true) => is_lea || is_mem_write(instruction, mem_idx),
                    };
                    let stride_matches = options.stride.is_none_or(|s| {
                        stride_regs.contains(&base)
                            || stride_regs.contains(&instruction.memory_index().full_register())
                            || u64::from(instruction.memory_index_scale()) == s
                    });

                    if stack_allowed && offsets.contains(&off) && mode_matches && stride_matches {
                        let mut text = format(instruction);
                        if is_lea && let Some(callee) = lea_callee(image, function, &insns, idx) {
                            text = format!("{text}  ; -> {callee}");
                        }
                        if is_stack && options.stack {
                            text.push_str("  ; stack");
                        }
                        found.push(DispHit {
                            hit: Hit { ip: instruction.ip(), function: function.clone(), memory: None, text },
                            offset: off,
                            base,
                            stack: is_stack,
                        });
                    }
                }
                if let Some(s) = options.stride {
                    update_stride(instruction, s, &mut stride_regs);
                }
            }
            found
        })
        .collect();
    hits.sort_by_key(|d| d.hit.ip);
    hits.dedup_by_key(|d| d.hit.ip);
    hits
}
