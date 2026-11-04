/*
 * XRef — Forward instruction operand tracker for call-site argument recovery
 * Copyright (c) 2026 Alexander Panasenko
 * Contact: alex@prod.codes
 * Author: https://prod.codes/about/
 * Project: https://github.com/alex09x/xref
 * SPDX-License-Identifier: MIT OR Apache-2.0
 */

use std::collections::{BTreeMap, HashMap};

use iced_x86::{ConditionCode, FlowControl, Instruction, Mnemonic, OpKind, Register};

use super::resolve::{cc_op, fmt_imm, fmt_rip};
use crate::expr::{ABI_ARGS, reg_name};
use crate::image::Image;
use crate::locations::Location;
use crate::scan::immediates;

pub const VOLATILE: [Register; 9] = [
    Register::RAX,
    Register::RCX,
    Register::RDX,
    Register::RSI,
    Register::RDI,
    Register::R8,
    Register::R9,
    Register::R10,
    Register::R11,
];

pub fn op_val(
    image: &Image,
    locs: &[Location],
    regs: &HashMap<Register, String>,
    instruction: &Instruction,
    idx: u32,
) -> String {
    match instruction.op_kind(idx) {
        OpKind::Register => {
            let r = instruction.op_register(idx).full_register();
            regs.get(&r).cloned().unwrap_or_else(|| format!("{} (dynamic)", reg_name(r)))
        }
        OpKind::Memory if instruction.is_ip_rel_memory_operand() => {
            fmt_rip(image, locs, instruction.ip_rel_memory_address())
        }
        OpKind::Memory => "mem (dynamic)".to_owned(),
        _ => fmt_imm(immediates(instruction).next().unwrap_or(0)),
    }
}

pub struct Tracker {
    pub regs: HashMap<Register, String>,
    pub stack: BTreeMap<u64, String>,
    pub pushed: Vec<String>,
    pub last_cmp: Option<(String, String)>,
}

impl Default for Tracker {
    fn default() -> Self {
        Self::new()
    }
}

impl Tracker {
    #[must_use]
    pub fn new() -> Self {
        Self { regs: HashMap::new(), stack: BTreeMap::new(), pushed: Vec::new(), last_cmp: None }
    }

    pub fn step(&mut self, image: &Image, locs: &[Location], instruction: &Instruction, max_stack: usize) {
        let m = instruction.mnemonic();
        if m == Mnemonic::Push {
            let val = op_val(image, locs, &self.regs, instruction, 0);
            self.pushed.push(val);
            return;
        }
        if matches!(m, Mnemonic::Sub | Mnemonic::Add | Mnemonic::Pop)
            && instruction.op0_register().full_register() == Register::RSP
        {
            self.pushed.clear();
            return;
        }
        if m == Mnemonic::Cmp {
            let lhs = op_val(image, locs, &self.regs, instruction, 0).replace(" (dynamic)", "");
            let rhs = op_val(image, locs, &self.regs, instruction, 1).replace(" (dynamic)", "");
            self.last_cmp = Some((lhs, rhs));
            return;
        }
        if m == Mnemonic::Test && instruction.op0_register() == instruction.op1_register() {
            let lhs = op_val(image, locs, &self.regs, instruction, 0).replace(" (dynamic)", "");
            self.last_cmp = Some((lhs, "0".to_owned()));
            return;
        }
        if matches!(m, Mnemonic::Mov | Mnemonic::Movzx | Mnemonic::Movsx | Mnemonic::Movsxd)
            && instruction.op0_kind() == OpKind::Memory
        {
            if instruction.memory_base().full_register() == Register::RSP
                && instruction.memory_index() == Register::None
            {
                let disp = instruction.memory_displacement64();
                if let Ok(limit) = u64::try_from(max_stack)
                    && disp.is_multiple_of(8)
                    && disp < limit.saturating_mul(8)
                {
                    let val = op_val(image, locs, &self.regs, instruction, 1);
                    self.stack.insert(disp / 8, val);
                }
            }
            return;
        }
        if instruction.op0_kind() != OpKind::Register {
            return;
        }
        let dst = instruction.op0_register().full_register();
        if m == Mnemonic::Xor && instruction.op0_register() == instruction.op1_register() {
            self.regs.insert(dst, "0".to_owned());
        } else if matches!(m, Mnemonic::Mov | Mnemonic::Movzx | Mnemonic::Movsx | Mnemonic::Movsxd) {
            let val = op_val(image, locs, &self.regs, instruction, 1);
            self.regs.insert(dst, val);
        } else if m == Mnemonic::Lea {
            let val = if instruction.is_ip_rel_memory_operand() {
                fmt_rip(image, locs, instruction.ip_rel_memory_address())
            } else if instruction.memory_base().full_register() == Register::RSP {
                format!("&rsp[{:#x}] (dynamic)", instruction.memory_displacement64())
            } else {
                format!("{} (dynamic)", reg_name(dst))
            };
            self.regs.insert(dst, val);
        } else if instruction.condition_code() != ConditionCode::None
            && instruction.flow_control() == FlowControl::Next
            && let Some((lhs, rhs)) = &self.last_cmp
        {
            let op = cc_op(instruction.condition_code());
            self.regs.insert(dst, format!("{lhs}{op}{rhs}"));
        } else {
            self.regs.remove(&dst);
        }
    }

    pub fn snapshot(&self, max_stack: usize) -> Vec<String> {
        let mut items = Vec::new();
        for &reg in &ABI_ARGS {
            if let Some(val) = self.regs.get(&reg) {
                items.push(format!("{}={val}", reg_name(reg)));
            }
        }
        if self.pushed.is_empty() {
            for idx in 0..max_stack {
                if let Ok(slot_idx) = u64::try_from(idx)
                    && let Some(val) = self.stack.get(&slot_idx)
                {
                    items.push(format!("stack{idx}={val}"));
                }
            }
        } else {
            for (idx, val) in self.pushed.iter().rev().take(max_stack).enumerate() {
                items.push(format!("stack{idx}={val}"));
            }
        }
        items
    }
}
