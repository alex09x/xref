/*
 * XRef — One-step backward symbolic expression and copy resolution within caller blocks
 * Copyright (c) 2026 Alexander Panasenko
 * Contact: alex@prod.codes
 * Author: https://prod.codes/about/
 * Project: https://github.com/alex09x/xref
 * SPDX-License-Identifier: MIT OR Apache-2.0
 */

use std::collections::HashSet;

use iced_x86::{ConditionCode, FlowControl, Instruction, MemorySize, Mnemonic, OpKind, Register};

use crate::expr::{ABI_ARGS, reg_name};
use crate::image::{Image, Slot};
use crate::locations::Location;
use crate::scan::immediates;
use crate::source::location_at;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ResolvedArg {
    pub expr: String,
    pub const_val: Option<u64>,
}

#[must_use]
pub fn fmt_imm(v: u64) -> String {
    if v < 10 { format!("{v}") } else { format!("{v:#x}") }
}

#[must_use]
pub fn fmt_rip(image: &Image, locs: &[Location], addr: u64) -> String {
    if let Some(loc) = location_at(locs, addr) {
        return format!("{addr:#x} ({}:{}:{})", loc.file, loc.line, loc.col);
    }
    let target = match image.slot(addr) {
        Some(Slot::Pointer(t)) => t,
        _ => addr,
    };
    image.preview(target).map_or_else(|| format!("{target:#x}"), |text| format!("{target:#x} ({text:?})"))
}

#[must_use]
pub const fn cc_op(cc: ConditionCode) -> &'static str {
    match cc {
        ConditionCode::e => "==",
        ConditionCode::ne => "!=",
        ConditionCode::g | ConditionCode::a => ">",
        ConditionCode::ge | ConditionCode::ae => ">=",
        ConditionCode::l | ConditionCode::b => "<",
        ConditionCode::le | ConditionCode::be => "<=",
        _ => "?",
    }
}

/// `SETcc` writes a 0/1 result of its condition. `CMOVcc` (two operands) selects one of two
/// values and `Jcc` changes control flow; neither is a boolean of the comparison.
#[must_use]
pub fn is_setcc(ins: &Instruction) -> bool {
    ins.condition_code() != ConditionCode::None && ins.flow_control() == FlowControl::Next && ins.op_count() == 1
}

#[must_use]
pub const fn evaluate_cc(cc: ConditionCode, lhs: u64, rhs: u64) -> Option<bool> {
    match cc {
        ConditionCode::e => Some(lhs == rhs),
        ConditionCode::ne => Some(lhs != rhs),
        ConditionCode::a => Some(lhs > rhs),
        ConditionCode::ae => Some(lhs >= rhs),
        ConditionCode::b => Some(lhs < rhs),
        ConditionCode::be => Some(lhs <= rhs),
        // Signed predicates depend on the comparison width, which the resolved constants do not
        // carry; an unknown result never turns into a false preflight proof.
        _ => None,
    }
}

#[must_use]
pub fn size_prefix(size: MemorySize, reg_size: usize) -> &'static str {
    match match size.size() {
        0 => reg_size,
        n => n,
    } {
        1 => "u8",
        2 => "u16",
        4 => "u32",
        8 => "u64",
        16 => "u128",
        _ => "mem",
    }
}

fn resolve_base_register_name(
    base: Register,
    prior_writes_in_caller: &HashSet<Register>,
    block_insns: &[Instruction],
) -> String {
    if base == Register::RSP {
        return "rsp".to_owned();
    }
    if let Some(pos) = ABI_ARGS.iter().position(|&r| r == base)
        && !prior_writes_in_caller.contains(&base)
    {
        let arg_num = pos.saturating_add(1);
        return format!("arg{arg_num}");
    }
    for ins in block_insns.iter().rev() {
        if ins.op0_kind() == OpKind::Register && ins.op0_register().full_register() == base {
            if ins.mnemonic() == Mnemonic::Mov && ins.op1_kind() == OpKind::Register {
                let src = ins.op1_register().full_register();
                if let Some(pos) = ABI_ARGS.iter().position(|&r| r == src)
                    && !prior_writes_in_caller.contains(&src)
                {
                    let arg_num = pos.saturating_add(1);
                    return format!("arg{arg_num}");
                }
            }
            break;
        }
    }
    reg_name(base)
}

fn resolve_mov_op(
    image: &Image,
    locs: &[Location],
    block_insns: &[Instruction],
    prior_writes_in_caller: &HashSet<Register>,
    def: &Instruction,
    def_idx: usize,
) -> Option<ResolvedArg> {
    match def.op1_kind() {
        OpKind::Immediate8
        | OpKind::Immediate8_2nd
        | OpKind::Immediate16
        | OpKind::Immediate32
        | OpKind::Immediate64
        | OpKind::Immediate8to16
        | OpKind::Immediate8to32
        | OpKind::Immediate8to64
        | OpKind::Immediate32to64 => {
            Some(ResolvedArg { expr: fmt_imm(immediates(def).next().unwrap_or(0)), const_val: immediates(def).next() })
        }
        OpKind::Memory => {
            let prefix = size_prefix(def.memory_size(), def.op0_register().size());
            if def.is_ip_rel_memory_operand() {
                // A load reads the global's contents at run time; only LEA yields the address.
                let addr = def.ip_rel_memory_address();
                return Some(ResolvedArg {
                    expr: format!("{prefix} [{}]", fmt_rip(image, locs, addr)),
                    const_val: None,
                });
            }
            let base = def.memory_base().full_register();
            let disp = def.memory_displacement64().cast_signed();
            let base_name = resolve_base_register_name(base, prior_writes_in_caller, &block_insns[..def_idx]);
            let disp_part = match disp.cmp(&0) {
                std::cmp::Ordering::Equal => String::new(),
                std::cmp::Ordering::Greater => format!("+{disp:#x}"),
                std::cmp::Ordering::Less => format!("-{:#x}", disp.wrapping_neg().cast_unsigned()),
            };
            Some(ResolvedArg { expr: format!("{prefix} [{base_name}{disp_part}]"), const_val: None })
        }
        OpKind::Register => {
            let src = def.op1_register().full_register();
            if let Some(prior_def) =
                resolve_arg_in_block(image, locs, &block_insns[..def_idx], prior_writes_in_caller, src)
            {
                return Some(prior_def);
            }
            if let Some(pos) = ABI_ARGS.iter().position(|&r| r == src)
                && !prior_writes_in_caller.contains(&src)
            {
                let arg_num = pos.saturating_add(1);
                return Some(ResolvedArg { expr: format!("arg{arg_num}"), const_val: None });
            }
            Some(ResolvedArg { expr: reg_name(src), const_val: None })
        }
        _ => None,
    }
}

fn resolve_and_op(
    image: &Image,
    locs: &[Location],
    block_insns: &[Instruction],
    prior_writes_in_caller: &HashSet<Register>,
    def: &Instruction,
    def_idx: usize,
    reg: Register,
) -> ResolvedArg {
    let imm = immediates(def).next().unwrap_or(0);
    let imm_str = fmt_imm(imm);
    if let Some(prev) = resolve_arg_in_block(image, locs, &block_insns[..def_idx], prior_writes_in_caller, reg) {
        if let Some(c) = prev.const_val {
            let res = c & imm;
            return ResolvedArg { expr: fmt_imm(res), const_val: Some(res) };
        }
        return ResolvedArg { expr: format!("{} & {imm_str}", prev.expr), const_val: None };
    }
    if let Some(pos) = ABI_ARGS.iter().position(|&r| r == reg)
        && !prior_writes_in_caller.contains(&reg)
    {
        let arg_num = pos.saturating_add(1);
        return ResolvedArg { expr: format!("arg{arg_num} & {imm_str}"), const_val: None };
    }
    ResolvedArg { expr: format!("{} & {imm_str}", reg_name(reg)), const_val: None }
}

fn resolve_cc_op(
    image: &Image,
    locs: &[Location],
    block_insns: &[Instruction],
    prior_writes_in_caller: &HashSet<Register>,
    def: &Instruction,
    def_idx: usize,
) -> Option<ResolvedArg> {
    // The flags come from the last flag-writing instruction; when that is not CMP/TEST (for
    // example `cmp; add; sete`) the condition is not derived from a comparison we can read.
    let cmp_idx = block_insns[..def_idx].iter().rposition(|ins| ins.rflags_modified() != 0)?;
    let cmp_ins = &block_insns[cmp_idx];
    if !matches!(cmp_ins.mnemonic(), Mnemonic::Cmp | Mnemonic::Test) {
        return None;
    }
    let op = cc_op(def.condition_code());
    if cmp_ins.mnemonic() == Mnemonic::Cmp {
        let lhs = resolve_operand_summary(image, locs, &block_insns[..cmp_idx], prior_writes_in_caller, cmp_ins, 0);
        let rhs = resolve_operand_summary(image, locs, &block_insns[..cmp_idx], prior_writes_in_caller, cmp_ins, 1);
        let const_val = if let (Some(l), Some(r)) = (lhs.const_val, rhs.const_val) {
            evaluate_cc(def.condition_code(), l, r).map(u64::from)
        } else {
            None
        };
        return Some(ResolvedArg { expr: format!("{}{op}{}", lhs.expr, rhs.expr), const_val });
    }
    if cmp_ins.mnemonic() == Mnemonic::Test && cmp_ins.op0_register() == cmp_ins.op1_register() {
        let lhs = resolve_operand_summary(image, locs, &block_insns[..cmp_idx], prior_writes_in_caller, cmp_ins, 0);
        let const_val = lhs.const_val.and_then(|l| evaluate_cc(def.condition_code(), l, 0).map(u64::from));
        return Some(ResolvedArg { expr: format!("{}{op}0", lhs.expr), const_val });
    }
    None
}

fn resolve_lea_op(image: &Image, locs: &[Location], def: &Instruction, reg: Register) -> ResolvedArg {
    if def.is_ip_rel_memory_operand() {
        let addr = def.ip_rel_memory_address();
        return ResolvedArg { expr: fmt_rip(image, locs, addr), const_val: Some(addr) };
    }
    if def.memory_base().full_register() == Register::RSP {
        let disp = def.memory_displacement64();
        return ResolvedArg { expr: format!("&rsp[{disp:#x}] (dynamic)"), const_val: None };
    }
    ResolvedArg { expr: format!("{} (dynamic)", reg_name(reg)), const_val: None }
}

pub fn resolve_arg_in_block(
    image: &Image,
    locs: &[Location],
    block_insns: &[Instruction],
    prior_writes_in_caller: &HashSet<Register>,
    reg: Register,
) -> Option<ResolvedArg> {
    let def_idx = block_insns
        .iter()
        .rposition(|ins| ins.op0_kind() == OpKind::Register && ins.op0_register().full_register() == reg)?;
    let def = &block_insns[def_idx];
    // 8- and 16-bit writes keep the register's upper bits, so they never prove a full value;
    // 32-bit writes zero-extend and 64-bit writes replace the whole register.
    if def.op0_register().size() < 4 {
        return resolve_full_width_def(image, locs, block_insns, prior_writes_in_caller, def, def_idx, reg).map(
            |resolved| ResolvedArg {
                expr: format!("{} (low {} bits)", resolved.expr, def.op0_register().size() * 8),
                const_val: None,
            },
        );
    }
    resolve_full_width_def(image, locs, block_insns, prior_writes_in_caller, def, def_idx, reg)
}

fn resolve_full_width_def(
    image: &Image,
    locs: &[Location],
    block_insns: &[Instruction],
    prior_writes_in_caller: &HashSet<Register>,
    def: &Instruction,
    def_idx: usize,
    reg: Register,
) -> Option<ResolvedArg> {
    let m = def.mnemonic();
    if (m == Mnemonic::Xor || m == Mnemonic::Sub) && def.op0_register() == def.op1_register() {
        return Some(ResolvedArg { expr: "0".to_owned(), const_val: Some(0) });
    }
    if matches!(m, Mnemonic::Mov | Mnemonic::Movzx | Mnemonic::Movsx | Mnemonic::Movsxd) {
        return resolve_mov_op(image, locs, block_insns, prior_writes_in_caller, def, def_idx);
    }
    if m == Mnemonic::And {
        return Some(resolve_and_op(image, locs, block_insns, prior_writes_in_caller, def, def_idx, reg));
    }
    // Only SETcc yields the comparison's boolean; CMOVcc selects between two values (unknown here).
    if is_setcc(def) {
        return resolve_cc_op(image, locs, block_insns, prior_writes_in_caller, def, def_idx);
    }
    if m == Mnemonic::Lea {
        return Some(resolve_lea_op(image, locs, def, reg));
    }
    None
}

fn resolve_operand_summary(
    image: &Image,
    locs: &[Location],
    block_insns: &[Instruction],
    prior_writes_in_caller: &HashSet<Register>,
    ins: &Instruction,
    op_idx: u32,
) -> ResolvedArg {
    match ins.op_kind(op_idx) {
        OpKind::Register => {
            let r = ins.op_register(op_idx).full_register();
            if let Some(resolved) = resolve_arg_in_block(image, locs, block_insns, prior_writes_in_caller, r) {
                return resolved;
            }
            if let Some(pos) = ABI_ARGS.iter().position(|&arg| arg == r)
                && !prior_writes_in_caller.contains(&r)
            {
                let arg_num = pos.saturating_add(1);
                return ResolvedArg { expr: format!("arg{arg_num}"), const_val: None };
            }
            ResolvedArg { expr: reg_name(r), const_val: None }
        }
        OpKind::Memory if ins.is_ip_rel_memory_operand() => {
            let addr = ins.ip_rel_memory_address();
            ResolvedArg { expr: fmt_rip(image, locs, addr), const_val: Some(addr) }
        }
        OpKind::Memory => ResolvedArg { expr: "mem (dynamic)".to_owned(), const_val: None },
        _ => {
            let imm = immediates(ins).next().unwrap_or(0);
            ResolvedArg { expr: fmt_imm(imm), const_val: Some(imm) }
        }
    }
}
