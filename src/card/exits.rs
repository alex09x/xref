/*
 * XRef — Function exit and return register analysis
 * Copyright (c) 2026 Alexander Panasenko
 * Contact: alex@prod.codes
 * Author: https://prod.codes/about/
 * Project: https://github.com/alex09x/xref
 * SPDX-License-Identifier: MIT OR Apache-2.0
 */

use std::collections::{BTreeSet, HashSet};
use std::ops::Range;

use iced_x86::{FlowControl, Instruction, Mnemonic, OpKind, Register};

use super::model::ExitInfo;
use crate::image::Image;
use crate::scan::{branch_target, decode, immediates};

fn writes_reg(ins: &Instruction, target_reg: Register) -> bool {
    if ins.op0_kind() == OpKind::Register && ins.op0_register().full_register() == target_reg {
        return true;
    }
    if ins.mnemonic() == Mnemonic::Call {
        return target_reg == Register::RAX || target_reg == Register::RDX;
    }
    false
}

fn scan_rax_constant(insns: &[Instruction]) -> (bool, Option<i64>) {
    for ins in insns.iter().rev() {
        let m = ins.mnemonic();
        if matches!(m, Mnemonic::Leave | Mnemonic::Nop | Mnemonic::Endbr64) {
            continue;
        }
        if m == Mnemonic::Pop && ins.op0_kind() == OpKind::Register {
            let r = ins.op0_register().full_register();
            if r != Register::RAX && r != Register::RDX {
                continue;
            }
        }
        if matches!(m, Mnemonic::Add | Mnemonic::Sub)
            && ins.op0_kind() == OpKind::Register
            && ins.op0_register().full_register() == Register::RSP
        {
            continue;
        }

        if m == Mnemonic::Xor
            && ins.op0_kind() == OpKind::Register
            && ins.op1_kind() == OpKind::Register
            && ins.op0_register() == ins.op1_register()
            && ins.op0_register().full_register() == Register::RAX
        {
            return (true, Some(0));
        }

        if m == Mnemonic::Mov
            && ins.op0_kind() == OpKind::Register
            && ins.op0_register().full_register() == Register::RAX
        {
            if let Some(imm) = immediates(ins).next() {
                if ins.op0_register().size() == 4 {
                    let u = u32::try_from(imm & 0xffff_ffff).unwrap_or(0);
                    return (true, Some(i64::from(u.cast_signed())));
                }
                if ins.op0_register().size() == 1 {
                    let u = u8::try_from(imm & 0xff).unwrap_or(0);
                    return (true, Some(i64::from(u)));
                }
                return (true, Some(imm.cast_signed()));
            }
            return (true, None);
        }

        if (m == Mnemonic::Or || m == Mnemonic::Mov)
            && ins.op0_kind() == OpKind::Register
            && ins.op0_register().full_register() == Register::RAX
            && immediates(ins).next() == Some(0xffff_ffff_ffff_ffff)
        {
            return (true, Some(-1));
        }

        if writes_reg(ins, Register::RAX) {
            return (true, None);
        }
    }
    (false, None)
}

fn scan_rdx_write(insns: &[Instruction]) -> bool {
    for ins in insns.iter().rev() {
        let m = ins.mnemonic();
        if matches!(m, Mnemonic::Leave | Mnemonic::Nop | Mnemonic::Endbr64) {
            continue;
        }
        if m == Mnemonic::Pop
            && ins.op0_kind() == OpKind::Register
            && ins.op0_register().full_register() != Register::RDX
        {
            continue;
        }
        if writes_reg(ins, Register::RDX) {
            return true;
        }
    }
    false
}

/// Analyze exits in `function`, returning overall return registers and per-exit details.
#[must_use]
pub fn analyze_exits(image: &Image, function: &Range<u64>) -> (Vec<String>, Vec<ExitInfo>) {
    let Some(bytes) = image.code(function) else { return (Vec::new(), Vec::new()) };
    let mut insns = Vec::new();
    let mut leaders = BTreeSet::new();
    leaders.insert(function.start);

    decode(bytes, function.start, |ins| {
        if let Some(target) = branch_target(ins).filter(|t| function.contains(t)) {
            leaders.insert(target);
        }
        if !matches!(ins.flow_control(), FlowControl::Next | FlowControl::Call | FlowControl::IndirectCall) {
            let next = ins.next_ip();
            if function.contains(&next) {
                leaders.insert(next);
            }
        }
        insns.push(*ins);
    });

    let ret_indices: Vec<usize> = insns
        .iter()
        .enumerate()
        .filter(|(_, ins)| ins.flow_control() == FlowControl::Return)
        .map(|(idx, _)| idx)
        .collect();

    let mut exits = Vec::new();
    let mut all_return_regs = HashSet::new();

    for ret_idx in ret_indices {
        let ret_ip = insns[ret_idx].ip();
        let leader = leaders.range(..=ret_ip).next_back().copied().unwrap_or(function.start);
        let block_start = insns.iter().position(|i| i.ip() == leader).unwrap_or(0);
        let block_insns = &insns[block_start..ret_idx];

        let (returns_rax, constant_code) = scan_rax_constant(block_insns);
        let writes_secondary_rdx = scan_rdx_write(block_insns);

        if returns_rax {
            let mut ret_regs = vec!["rax".to_owned()];
            all_return_regs.insert("rax".to_owned());
            if writes_secondary_rdx {
                ret_regs.push("rdx".to_owned());
                all_return_regs.insert("rdx".to_owned());
            }
            let is_error = constant_code.is_some_and(|c| c != 0);
            exits.push(ExitInfo { ip: ret_ip, return_registers: ret_regs, constant_code, is_error });
        } else {
            // Check predecessor blocks jumping to leader
            let mut found_preds = false;
            for (p_idx, p_ins) in insns.iter().enumerate() {
                let jumps_to_leader = (p_ins.flow_control() == FlowControl::UnconditionalBranch
                    && branch_target(p_ins) == Some(leader))
                    || (p_ins.next_ip() == leader && p_idx + 1 == block_start);

                if jumps_to_leader {
                    let pred_leader = leaders.range(..=p_ins.ip()).next_back().copied().unwrap_or(function.start);
                    let pred_start = insns.iter().position(|i| i.ip() == pred_leader).unwrap_or(0);
                    let (pred_returns_rax, pred_code) = scan_rax_constant(&insns[pred_start..=p_idx]);
                    if pred_returns_rax {
                        found_preds = true;
                        all_return_regs.insert("rax".to_owned());
                        let is_error = pred_code.is_some_and(|c| c != 0);
                        exits.push(ExitInfo {
                            ip: ret_ip,
                            return_registers: vec!["rax".to_owned()],
                            constant_code: pred_code,
                            is_error,
                        });
                    }
                }
            }
            if !found_preds {
                exits.push(ExitInfo { ip: ret_ip, return_registers: Vec::new(), constant_code: None, is_error: false });
            }
        }
    }

    let mut return_registers: Vec<String> = all_return_regs.into_iter().collect();
    return_registers.sort();
    (return_registers, exits)
}
