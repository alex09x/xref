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

use std::ops::Range;

use iced_x86::{ConditionCode, FlowControl, Instruction, Mnemonic, OpKind, Register};

use crate::callee_meta::{describe_callee, is_target_noreturn};
use crate::calls::call_expr;
use crate::cfg::{Block, Term};
use crate::expr::{
    BIN_OPS, CALLEE_SAVED, FlagOp, Flags, IGNORED, MOVES, State, UNARY_OPS, cond_expr, mem_expr, neg_cond_expr,
    op_expr, reg_name, stack_name, wrap_unary,
};
use crate::image::Image;
use crate::listing::is_call;
use crate::locations::Location;
use crate::runtime::RuntimeMap;
use crate::scan::{branch_target, format};
use crate::sig::import_arity;
use crate::simplify::{simplify_linear, simplify_ternary};
use crate::source::location_at;
use crate::ssa_cfg::gpr_idx;
use crate::ssa_webs::SsaCfg;
use crate::tables::Table;
use crate::type_facts::ReturnKind;

pub struct FnCtx<'a> {
    pub image: &'a Image,
    pub locations: &'a [Location],
    pub runtime: &'a RuntimeMap,
    pub tables: &'a [Table],
    pub function: &'a Range<u64>,
    pub ssa: &'a SsaCfg,
    pub ret_kind: ReturnKind,
    pub partial_slice: bool,
}

impl FnCtx<'_> {
    fn op(&self, state: &mut State, instruction: &Instruction, idx: u32) -> String {
        op_expr(self.image, self.locations, state, instruction, idx)
    }
}

fn sync_insn_reads(ssa: &SsaCfg, state: &mut State, ins_idx: usize, ip: u64) {
    state.cur_norm_sp = ssa.stack.norm_by_ip.get(&ip).copied();
    let meta = &ssa.metas[ins_idx];
    for k in 0..usize::from(meta.read_cnt) {
        let (reg, wid) = meta.read_webs[k];
        if let Some(inlined) = state.inline_regs.remove(&reg) {
            state.regs.insert(reg, inlined);
        } else {
            state.regs.insert(reg, ssa.webs[wid].name.clone());
        }
    }
}

pub fn flush_non_gpr_dirty(state: &mut State, lines: &mut Vec<String>) {
    for reg in std::mem::take(&mut state.dirty) {
        if gpr_idx(reg).is_none() {
            let (name, val) = (reg_name(reg), state.reg(reg));
            if val != name {
                lines.push(format!("{name} = {val};"));
            }
            state.regs.insert(reg, name);
        }
    }
}

fn assign(
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
            if matches!(rhs.as_str(), "-1" | "0xffffffffffffffff" | "0") {
                state.const_saved.insert(full, rhs.clone());
            } else {
                state.const_saved.remove(&full);
            }
            if import_arity(&rhs).is_some() || rhs.starts_with("fn_") {
                state.fn_saved.insert(full, rhs.clone());
            } else {
                state.fn_saved.remove(&full);
            }
        }
        if let Some(bits) = meta.partial_merge {
            let (mask_val, mask) = if bits == 8 { (0xffu64, "0xff") } else { (0xffffu64, "0xffff") };
            let wname = &web.name;
            let low = rhs.parse::<u64>().map_or_else(|_| format!("({rhs} & {mask})"), |n| format!("{}", n & mask_val));
            let merged =
                if low == "0" { format!("({wname} & ~{mask})") } else { format!("(({wname} & ~{mask}) | {low})") };
            lines.push(format!("{wname} = {merged};"));
            state.regs.insert(full, wname.clone());
            return Some(wname.clone());
        }
        if meta.can_inline && rhs.len() <= 56 {
            state.inline_regs.insert(full, rhs);
            return None;
        }
        if web.total_reads == 0 && !ctx.partial_slice {
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
    let lhs = mem_expr(ctx.image, ctx.locations, state, instruction);
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
            flush_non_gpr_dirty(state, &mut block.stmts);
            let ret = match ctx.ret_kind {
                ReturnKind::VoidUnused => "return; /* callers ignore rax */".to_owned(),
                ReturnKind::Pair => {
                    let (ra, rd) = (state.reg(Register::RAX), state.reg(Register::RDX));
                    format!("return ({ra}, {rd});")
                }
                ReturnKind::Single(_) | ReturnKind::NoReturn => format!("return {};", state.reg(Register::RAX)),
            };
            block.term = Term::Return(ret);
        }
        FlowControl::Interrupt | FlowControl::Exception => {
            if !matches!(&block.term, Term::Return(s) if !s.is_empty()) {
                flush_non_gpr_dirty(state, &mut block.stmts);
                block.term = Term::Return("unreachable();".to_owned());
            }
        }
        FlowControl::Call | FlowControl::IndirectCall => {
            let meta = &ctx.ssa.metas[ins_idx];
            let (target, call) =
                call_expr(ctx.image, ctx.locations, ctx.runtime, state, instruction, Some(&meta.call_arg_regs));
            push_callee_note(ctx, state, target, &mut block.stmts);
            state.clear_scratch();
            if !ctx.partial_slice && target.is_some_and(|t| is_target_noreturn(ctx.image, ctx.runtime, t)) {
                flush_non_gpr_dirty(state, &mut block.stmts);
                block.term = Term::Return(format!("{call};"));
            } else if meta.can_inline && call.len() <= 56 {
                state.inline_regs.insert(Register::RAX, call);
            } else if meta.call_ret_used.1 {
                let wa = meta.def_web.map_or_else(|| "rax".to_owned(), |w| ctx.ssa.webs[w].name.clone());
                let wd = meta.rdx_def_web.map_or_else(|| "rdx".to_owned(), |w| ctx.ssa.webs[w].name.clone());
                block.stmts.push(format!("({wa}, {wd}) = {call};"));
            } else if meta.call_ret_used.0 || ctx.partial_slice {
                let wa = meta.def_web.map_or_else(|| "rax".to_owned(), |w| ctx.ssa.webs[w].name.clone());
                block.stmts.push(format!("{wa} = {call};"));
            } else {
                block.stmts.push(format!("{call};"));
            }
        }
        FlowControl::ConditionalBranch => {
            let cc = instruction.condition_code();
            let (cond, neg) = (cond_expr(cc, state.flags.as_ref()), neg_cond_expr(cc, state.flags.as_ref()));
            flush_non_gpr_dirty(state, &mut block.stmts);
            block.term = Term::Cond { cond, neg, target: instruction.near_branch_target() };
        }
        FlowControl::UnconditionalBranch | FlowControl::IndirectBranch => {
            if let Some(table) =
                ctx.tables.iter().find(|t| t.dispatch <= instruction.ip() && instruction.ip() - t.dispatch <= 32)
            {
                let fallback = ctx.op(state, instruction, 0);
                let idx = state.switch_idx.take().unwrap_or(fallback);
                flush_non_gpr_dirty(state, &mut block.stmts);
                block.term = Term::Switch { idx, base: table.base, arms: table.arms.clone() };
            } else if is_call(instruction, ctx.function) || instruction.flow_control() == FlowControl::IndirectBranch {
                let meta = &ctx.ssa.metas[ins_idx];
                let (target, call) =
                    call_expr(ctx.image, ctx.locations, ctx.runtime, state, instruction, Some(&meta.call_arg_regs));
                push_callee_note(ctx, state, target, &mut block.stmts);
                flush_non_gpr_dirty(state, &mut block.stmts);
                if ctx.ret_kind == ReturnKind::VoidUnused {
                    block.stmts.push(format!("{call};"));
                    block.term = Term::Return("return;".to_owned());
                } else {
                    block.term = Term::Return(format!("return {call};"));
                }
            } else if let Some(target) = branch_target(instruction) {
                flush_non_gpr_dirty(state, &mut block.stmts);
                block.term = Term::Jump(target);
            }
        }
        _ => return false,
    }
    true
}

fn step_stack(ctx: &FnCtx<'_>, state: &mut State, instruction: &Instruction) -> bool {
    let mnemonic = instruction.mnemonic();
    let dst = instruction.op0_register().full_register();
    if IGNORED.contains(&mnemonic)
        || (mnemonic == Mnemonic::Mov
            && dst == Register::RBP
            && instruction.op1_register().full_register() == Register::RSP)
    {
        return true;
    }
    if mnemonic == Mnemonic::Pop || (matches!(mnemonic, Mnemonic::Add | Mnemonic::Sub) && dst == Register::RSP) {
        state.in_prologue = false;
        state.pushed.clear();
        return true;
    }
    if mnemonic == Mnemonic::Push {
        if !(state.in_prologue
            && instruction.op0_kind() == OpKind::Register
            && (CALLEE_SAVED.contains(&dst) || dst == Register::RAX))
        {
            state.in_prologue = false;
            let val = ctx.op(state, instruction, 0);
            state.pushed.push(val);
        }
        return true;
    }
    state.in_prologue = false;
    false
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
    if let Some(&rsp_off) = ctx.ssa.stack.rsp_copy_by_ip.get(&instruction.ip()) {
        let _ = assign(ctx, state, instruction, ins_idx, format!("&{}", stack_name(rsp_off)), &mut block.stmts);
        return;
    }
    if matches!(mnemonic, Mnemonic::Cmp | Mnemonic::Ucomisd | Mnemonic::Ucomiss | Mnemonic::Comisd | Mnemonic::Comiss) {
        let (lhs, rhs) = (ctx.op(state, instruction, 0), ctx.op(state, instruction, 1));
        state.flags = Some(Flags::from_cmp(mnemonic, lhs, rhs));
        return;
    }
    if mnemonic == Mnemonic::Test {
        let (lhs, rhs) = (ctx.op(state, instruction, 0), ctx.op(state, instruction, 1));
        state.flags = Some(Flags::test(if lhs == rhs { lhs } else { format!("({lhs} & {rhs})") }));
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
    if matches!(mnemonic, Mnemonic::Xor | Mnemonic::Sub | Mnemonic::Xorps | Mnemonic::Xorpd | Mnemonic::Pxor)
        && dst_reg.is_some()
        && instruction.op1_kind() == OpKind::Register
        && instruction.op0_register() == instruction.op1_register()
    {
        let _ = assign(ctx, state, instruction, ins_idx, "0".to_owned(), &mut block.stmts);
        state.flags = Some(Flags::test("0".to_owned()));
        return;
    }
    if MOVES.contains(&mnemonic) {
        let src_ro = (mnemonic == Mnemonic::Mov && instruction.op1_kind() == OpKind::Register)
            .then(|| state.rodata_ptrs.get(&instruction.op1_register().full_register()).copied())
            .flatten();
        let rhs = ctx.op(state, instruction, 1);
        let _ = assign(ctx, state, instruction, ins_idx, rhs, &mut block.stmts);
        if let (Some(r), Some(place)) = (dst_reg, src_ro) {
            state.rodata_ptrs.insert(r, place);
        } else if mnemonic == Mnemonic::Lea
            && instruction.is_ip_rel_memory_operand()
            && let Some(r) = dst_reg
        {
            let place = instruction.ip_rel_memory_address();
            if location_at(ctx.locations, place).is_none()
                && ctx.image.function_at(place).is_none()
                && ctx.image.slot(place).is_none()
            {
                state.rodata_ptrs.insert(r, place);
            }
        }
        return;
    }
    if let Some((_, op)) = BIN_OPS.iter().find(|(m, _)| *m == mnemonic) {
        let base = u32::from(instruction.op_count() == 3);
        let (lhs, rhs) = (ctx.op(state, instruction, base), ctx.op(state, instruction, base + 1));
        let raw = rhs
            .strip_prefix('-')
            .filter(|_| *op == "+")
            .map_or_else(|| format!("({lhs} {op} {rhs})"), |neg| format!("({lhs} - {neg})"));
        let expr = simplify_linear(&raw);
        let emitted = assign(ctx, state, instruction, ins_idx, expr.clone(), &mut block.stmts);
        state.flags = Some(Flags::arith(FlagOp::from_bin(mnemonic), emitted.unwrap_or(expr), lhs, rhs));
        return;
    }
    if let Some((_, pre, post)) = UNARY_OPS.iter().find(|(m, _, _)| *m == mnemonic) {
        let val = ctx.op(state, instruction, u32::from(instruction.op_count() > 1));
        let expr = wrap_unary(pre, &val, post);
        let emitted = assign(ctx, state, instruction, ins_idx, expr.clone(), &mut block.stmts);
        state.flags = Some(Flags::unary(mnemonic, emitted.unwrap_or(expr), val));
        return;
    }
    block.stmts.push(format!("/* {} */", format(instruction)));
}
