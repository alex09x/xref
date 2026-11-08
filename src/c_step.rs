/*
 * xref — Ultra blazing fast cross-references of an x86-64 ELF binary
 * Copyright (c) 2026 Alexander Panasenko
 *
 * Contact: alex@prod.codes
 * Author: https://prod.codes/about/
 * Project: https://github.com/alex09x/xref
 * SPDX-License-Identifier: MIT OR Apache-2.0
 */

//! Per-instruction pseudo-C statement lifting, SSA web assignment/inlining, and call/branch lowering.

use std::collections::HashMap;
use std::fmt::Write;
use std::ops::Range;

use iced_x86::{ConditionCode, FlowControl, Instruction, Mnemonic, OpKind, Register};

use crate::callee_meta::{describe_callee, is_target_noreturn};
use crate::calls::{call_expr, call_expr_abi};
use crate::cfg::{Block, Term};
use crate::expr::{Flags, MOVES, State, cond_expr, mem_expr, neg_cond_expr, op_expr, stack_name};
use crate::image::Image;
use crate::listing::is_call;
use crate::locations::Location;
use crate::runtime::RuntimeMap;
use crate::scan::{branch_target, format};
use crate::sig::import_arity;
use crate::simplify::simplify_ternary;
use crate::slice_parse::MarkKind;
use crate::ssa_cfg::gpr_idx;

mod moves;
use crate::ssa_webs::SsaCfg;
use crate::tables::Table;
use crate::type_facts::ReturnKind;
use moves::{step_move, step_stack};

pub struct FnCtx<'a> {
    pub image: &'a Image,
    pub locations: &'a [Location],
    pub runtime: &'a RuntimeMap,
    pub tables: &'a [Table],
    pub function: &'a Range<u64>,
    pub ssa: &'a SsaCfg,
    pub ret_kind: ReturnKind,
    pub partial_slice: bool,
    pub mark_ip: Option<u64>,
    pub mark_targets: Option<&'a HashMap<u64, MarkKind>>,
    /// Scalar float type also left in xmm0 when the integer result was preferred.
    pub xmm0_note: Option<&'static str>,
    /// Set for a float-ABI function: xmm values live at a block end are carried in their homes.
    pub xmm_live: Option<&'a crate::xmm_live::XmmLive>,
}

impl FnCtx<'_> {
    pub fn op(&self, state: &mut State, instruction: &Instruction, idx: u32) -> String {
        crate::float_alu::lift_operand(
            self.image,
            instruction,
            idx,
            op_expr(self.image, self.locations, state, instruction, idx),
        )
    }

    pub fn mark_kind(&self, instruction: &Instruction) -> Option<MarkKind> {
        let ip = instruction.ip();
        self.mark_targets.and_then(|targets| targets.get(&ip).copied()).or_else(|| {
            self.mark_ip.is_some_and(|mip| ip <= mip && mip < instruction.next_ip()).then_some(MarkKind::Exact)
        })
    }

    pub fn is_marked(&self, instruction: &Instruction) -> bool {
        self.mark_kind(instruction).is_some()
    }
}

fn sync_insn_reads(ssa: &SsaCfg, state: &mut State, ins_idx: usize, ip: u64) {
    state.cur_norm_sp = ssa.stack.norm_by_ip.get(&ip).copied();
    let meta = &ssa.metas[ins_idx];
    for &(reg, wid) in &meta.read_webs[..usize::from(meta.read_cnt)] {
        let val = state.inline_regs.remove(&reg).unwrap_or_else(|| ssa.webs[wid].name.clone());
        state.regs.insert(reg, val);
    }
}

pub fn flush_non_gpr_dirty(state: &mut State, lines: &mut Vec<String>) {
    for reg in std::mem::take(&mut state.dirty) {
        if gpr_idx(reg).is_none() {
            let (name, val) = (state.home(reg), state.reg(reg));
            if val != name {
                lines.push(format!("{name} = {val};"));
            }
            state.regs.insert(reg, name);
        }
    }
}

/// Flushes at the end of a block whose last instruction is `ip` (`None`: nothing is read after it).
pub fn flush_block_end(ctx: &FnCtx<'_>, state: &mut State, ip: Option<u64>, lines: &mut Vec<String>) {
    match ctx.xmm_live {
        Some(live) => live.flush(state, ip.map_or(0, |ip| live.after(ip)), ip.unwrap_or(0), lines),
        None => flush_non_gpr_dirty(state, lines),
    }
}

pub fn assign(
    ctx: &FnCtx<'_>,
    state: &mut State,
    instruction: &Instruction,
    ins_idx: usize,
    mut rhs: String,
    lines: &mut Vec<String>,
) -> Option<String> {
    if instruction.op0_kind() == OpKind::Register {
        if instruction.op0_register().size() == 4
            && let Some(v) = rhs
                .strip_prefix("0x")
                .and_then(|h| u64::from_str_radix(h, 16).ok())
                .or_else(|| rhs.parse::<i64>().ok().map(i64::cast_unsigned))
        {
            rhs = crate::expr::num(v & 0xffff_ffff);
        }
        let full = instruction.op0_register().full_register();
        state.rodata_ptrs.remove(&full);
        state.inline_regs.remove(&full);
        if gpr_idx(full).is_none() {
            state.set_reg(full, rhs);
            return None;
        }
        let meta = &ctx.ssa.metas[ins_idx];
        if meta.elide_def {
            return None;
        }
        let wid = meta.def_web?;
        let web = &ctx.ssa.webs[wid];
        if web.defs.len() == 1 {
            state.const_saved.remove(&full);
            if matches!(rhs.as_str(), "-1" | "0xffffffffffffffff" | "0") {
                state.const_saved.insert(full, rhs.clone());
            }
            state.fn_saved.remove(&full);
            if import_arity(&rhs).is_some() || rhs.starts_with("fn_") {
                state.fn_saved.insert(full, rhs.clone());
            }
        }
        if let Some(bits) = meta.partial_merge {
            let (mask_val, mask) = if bits == 8 { (0xffu64, "0xff") } else { (0xffffu64, "0xffff") };
            let wname = &web.name;
            let rp = if rhs.contains(' ') && !rhs.starts_with('(') { format!("({rhs})") } else { rhs.clone() };
            let low = rhs.parse::<u64>().map_or_else(|_| format!("({rp} & {mask})"), |n| format!("{}", n & mask_val));
            let merged =
                if low == "0" { format!("({wname} & ~{mask})") } else { format!("(({wname} & ~{mask}) | {low})") };
            lines.push(format!("{wname} = {merged};"));
            state.regs.insert(full, wname.clone());
            return Some(wname.clone());
        }
        if meta.can_inline
            && !ctx.is_marked(instruction)
            && (instruction.mnemonic() == Mnemonic::Lea || rhs.len() <= 56)
        {
            state.inline_regs.insert(full, rhs);
            return None;
        }
        if web.total_reads == 0 && !ctx.partial_slice && !ctx.is_marked(instruction) {
            return None;
        }
        let wname = web.name.clone();
        if wname != rhs {
            lines.push(format!("{wname} = {rhs};"));
        }
        state.regs.insert(full, wname.clone());
        return Some(wname);
    }
    if let Some(&norm) = ctx.ssa.stack.norm_by_ip.get(&instruction.ip())
        && !instruction.is_ip_rel_memory_operand()
    {
        if ctx.ssa.stack.spill_to_arg.contains_key(&norm) {
            return None;
        }
        if instruction.memory_size().size() == 16 && rhs == "0" && ctx.ssa.stack.split_zero_128.contains(&norm) {
            lines.push(format!("{} = 0;", stack_name(norm)));
            lines.push(format!("{} = 0;", stack_name(norm + 8)));
            return None;
        }
        let sname = stack_name(norm);
        lines.push(format!("{sname} = {rhs};"));
        return Some(sname);
    }
    let lhs = moves::sse_store_lhs(instruction, mem_expr(ctx.image, ctx.locations, state, instruction));
    lines.push(format!("{lhs} = {rhs};"));
    None
}

fn push_callee_note(ctx: &FnCtx<'_>, state: &mut State, target: Option<u64>, stmts: &mut Vec<String>) {
    if let Some(t) = target
        && !state.noted_callees.contains(&t)
        && let Some(note) = describe_callee(ctx.image, ctx.locations, ctx.runtime, t)
    {
        state.noted_callees.push(t);
        stmts.push(format!("/* {note} */"));
    }
}

fn step_flow(ctx: &FnCtx<'_>, state: &mut State, instruction: &Instruction, ins_idx: usize, block: &mut Block) -> bool {
    match instruction.flow_control() {
        FlowControl::Return => {
            // Read xmm0 before the flush so a float result returns its expression, not `zmm0`.
            let float_ret = matches!(ctx.ret_kind, ReturnKind::Float(_));
            let xmm0 = (float_ret || ctx.xmm0_note.is_some()).then(|| state.reg(Register::ZMM0));
            flush_block_end(ctx, state, None, &mut block.stmts);
            let mut ret = match ctx.ret_kind {
                ReturnKind::VoidUnused => "return; /* callers ignore rax */".to_owned(),
                ReturnKind::Pair => format!("return ({}, {});", state.reg(Register::RAX), state.reg(Register::RDX)),
                ReturnKind::Single(_) | ReturnKind::NoReturn => format!("return {};", state.reg(Register::RAX)),
                ReturnKind::Float(_) => format!("return {};", xmm0.clone().unwrap_or_default()),
            };
            if let (Some(ty), Some(value), false) = (ctx.xmm0_note, xmm0, float_ret) {
                let _ = write!(ret, " /* xmm0 = {value} ({ty}) */");
            }
            block.term = Term::Return(ret);
        }
        FlowControl::Interrupt | FlowControl::Exception => {
            if !matches!(&block.term, Term::Return(s) if !s.is_empty()) {
                flush_block_end(ctx, state, None, &mut block.stmts);
                block.term = Term::Return("unreachable();".to_owned());
            }
        }
        FlowControl::Call | FlowControl::IndirectCall => {
            let meta = &ctx.ssa.metas[ins_idx];
            let (target, call, float_ret) =
                call_expr_abi(ctx.image, ctx.locations, ctx.runtime, state, instruction, Some(&meta.call_arg_regs));
            push_callee_note(ctx, state, target, &mut block.stmts);
            state.clear_scratch();
            state.clobber_xmm(ctx.xmm_live.map_or(u16::MAX, |live| live.clobbers(instruction.ip())));
            if !ctx.partial_slice && target.is_some_and(|t| is_target_noreturn(ctx.image, ctx.runtime, t)) {
                flush_block_end(ctx, state, None, &mut block.stmts);
                block.term = Term::Return(format!("{call};"));
            } else if let Some(ty) = float_ret {
                // The callee returns a scalar float in xmm0: name it like a lifted float result.
                let name = format!("fp_{:x}", instruction.ip());
                block.stmts.push(format!("{ty} {name} = {call};"));
                state.set_reg(Register::ZMM0, name);
                let _ = state.reg(Register::ZMM0);
            } else if meta.can_inline && !ctx.is_marked(instruction) && call.len() <= 56 {
                state.inline_regs.insert(Register::RAX, call);
            } else if meta.call_ret_used.1 {
                let wa = meta.def_web.map_or("rax", |w| ctx.ssa.webs[w].name.as_str());
                let wd = meta.rdx_def_web.map_or("rdx", |w| ctx.ssa.webs[w].name.as_str());
                block.stmts.push(format!("({wa}, {wd}) = {call};"));
            } else if meta.call_ret_used.0 || ctx.partial_slice {
                let wa = meta.def_web.map_or("rax", |w| ctx.ssa.webs[w].name.as_str());
                block.stmts.push(format!("{wa} = {call};"));
            } else {
                block.stmts.push(format!("{call};"));
            }
        }
        FlowControl::ConditionalBranch => {
            let cc = instruction.condition_code();
            // Flush first: carrying xmm values may rename what the pending flags read.
            flush_block_end(ctx, state, Some(instruction.ip()), &mut block.stmts);
            let (cond, neg) = (cond_expr(cc, state.flags.as_ref()), neg_cond_expr(cc, state.flags.as_ref()));
            block.term = Term::Cond { cond, neg, target: instruction.near_branch_target() };
        }
        FlowControl::UnconditionalBranch | FlowControl::IndirectBranch => {
            if let Some(table) =
                ctx.tables.iter().find(|t| t.dispatch <= instruction.ip() && instruction.ip() - t.dispatch <= 32)
            {
                let fallback = ctx.op(state, instruction, 0);
                let idx = state.switch_idx.take().unwrap_or(fallback);
                flush_block_end(ctx, state, Some(instruction.ip()), &mut block.stmts);
                block.term = Term::Switch { idx, base: table.base, arms: table.arms.clone() };
            } else if is_call(instruction, ctx.function) || instruction.flow_control() == FlowControl::IndirectBranch {
                let meta = &ctx.ssa.metas[ins_idx];
                let (target, call) =
                    call_expr(ctx.image, ctx.locations, ctx.runtime, state, instruction, Some(&meta.call_arg_regs));
                push_callee_note(ctx, state, target, &mut block.stmts);
                flush_block_end(ctx, state, Some(instruction.ip()), &mut block.stmts);
                if ctx.ret_kind == ReturnKind::VoidUnused {
                    block.stmts.push(format!("{call};"));
                    block.term = Term::Return("return;".to_owned());
                } else {
                    block.term = Term::Return(format!("return {call};"));
                }
            } else if let Some(target) = branch_target(instruction) {
                flush_block_end(ctx, state, Some(instruction.ip()), &mut block.stmts);
                block.term = Term::Jump(target);
            }
        }
        _ => return false,
    }
    true
}

pub fn step(ctx: &FnCtx<'_>, state: &mut State, instruction: &Instruction, ins_idx: usize, block: &mut Block) {
    sync_insn_reads(ctx.ssa, state, ins_idx, instruction.ip());
    if step_stack(ctx, state, instruction) {
        return;
    }
    let mnemonic = instruction.mnemonic();
    if ctx.tables.iter().any(|t| t.dispatch == instruction.ip()) {
        let _ = state.reg(instruction.memory_base());
        state.switch_idx = Some(state.reg(instruction.memory_index()));
        return;
    }
    if step_flow(ctx, state, instruction, ins_idx, block) {
        return;
    }
    if crate::float_alu::step_u64_conversion_idiom(ctx, state, instruction, ins_idx, block) {
        return;
    }
    if crate::float_alu::step(ctx, state, instruction, ins_idx, block) {
        return;
    }
    if let Some(&rsp_off) = ctx.ssa.stack.rsp_copy_by_ip.get(&instruction.ip()) {
        let _ = assign(ctx, state, instruction, ins_idx, format!("&{}", stack_name(rsp_off)), &mut block.stmts);
        return;
    }
    let compare = crate::float_alu::legacy(mnemonic);
    if matches!(compare, Mnemonic::Cmp | Mnemonic::Ucomisd | Mnemonic::Ucomiss | Mnemonic::Comisd | Mnemonic::Comiss) {
        let bits = u8::try_from(crate::wide_alu::op_byte_width(instruction) * 8).unwrap_or(64);
        let (lhs, rhs) = (ctx.op(state, instruction, 0), ctx.op(state, instruction, 1));
        state.flags = Some(Flags::from_cmp_width(compare, lhs, rhs, bits));
        return;
    }
    if mnemonic == Mnemonic::Test {
        let bits = u8::try_from(crate::wide_alu::op_byte_width(instruction) * 8).unwrap_or(64);
        let (lhs, rhs) = (ctx.op(state, instruction, 0), ctx.op(state, instruction, 1));
        state.flags = Some(Flags::test_width(if lhs == rhs { lhs } else { format!("({lhs} & {rhs})") }, bits));
        return;
    }
    if instruction.condition_code() != ConditionCode::None {
        let cond = cond_expr(instruction.condition_code(), state.flags.as_ref());
        let expr = if instruction.op_count() == 1 {
            cond
        } else {
            let (prev, mut src) = (ctx.op(state, instruction, 0), ctx.op(state, instruction, 1));
            if instruction.op1_kind() == OpKind::Register
                && let Some(c) = state.const_saved.get(&instruction.op1_register().full_register())
            {
                src.clone_from(c);
            }
            simplify_ternary(&cond, &src, &prev)
        };
        let _ = assign(ctx, state, instruction, ins_idx, expr, &mut block.stmts);
        return;
    }
    let dst_reg = (instruction.op0_kind() == OpKind::Register).then(|| instruction.op0_register().full_register());
    let zeroing = (matches!(mnemonic, Mnemonic::Xor | Mnemonic::Sub | Mnemonic::Xorps | Mnemonic::Xorpd | Mnemonic::Pxor)
        && dst_reg.is_some()
        && instruction.op1_kind() == OpKind::Register
        && instruction.op0_register() == instruction.op1_register())
        // `vxorps x, y, y`: the VEX form zeroes `x` from two equal sources.
        || (instruction.op_count() == 3 && crate::sig::xmm::xmm_zero_idiom(instruction).is_some());
    if zeroing {
        let _ = assign(ctx, state, instruction, ins_idx, "0".to_owned(), &mut block.stmts);
        state.flags = Some(Flags::test("0".to_owned()));
        return;
    }
    if MOVES.contains(&mnemonic) {
        step_move(ctx, state, instruction, ins_idx, dst_reg, block);
        return;
    }
    if crate::wide_alu::step_wide_or_carry(ctx, state, instruction, ins_idx, block)
        || crate::carry_alu::step_bin(ctx, state, instruction, ins_idx, block)
        || crate::carry_alu::step_unary(ctx, state, instruction, ins_idx, block)
    {
        return;
    }
    block.stmts.push(format!("/* {} */", format(instruction)));
}
