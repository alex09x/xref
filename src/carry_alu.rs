/*
 * xref — Ultra blazing fast cross-references of an x86-64 ELF binary
 * Copyright (c) 2026 Alexander Panasenko
 *
 * Contact: alex@prod.codes
 * Author: https://prod.codes/about/
 * Project: https://github.com/alex09x/xref
 * SPDX-License-Identifier: MIT OR Apache-2.0
 */

//! Carry/borrow (`add`, `sub`, `adc`, `sbb`) and partial-flag unary (`inc`, `dec`, `not`, `bswap`)
//! pseudo-C lifting with width-aware `CF`/`OF` propagation and pre-mutation snapshotting.

use iced_x86::{ConditionCode, FlowControl, Instruction, Mnemonic, OpKind};

use crate::c_step::{FnCtx, assign};
use crate::cfg::Block;
use crate::expr::{BIN_OPS, FlagOp, Flags, State, UNARY_OPS, cond_expr, wrap_unary};
use crate::scan::branch_target;
use crate::simplify::simplify_linear;
use crate::wide_alu::{op_byte_width, wrap_atom};

/// Instructions (beyond `MOVES`) that leave `CF` intact.
pub const KEEPS_CF: &[Mnemonic] = &[
    Mnemonic::Push,
    Mnemonic::Pop,
    Mnemonic::Inc,
    Mnemonic::Dec,
    Mnemonic::Not,
    Mnemonic::Bswap,
    Mnemonic::Xchg,
    Mnemonic::Cqo,
    Mnemonic::Cdq,
    Mnemonic::Cdqe,
    Mnemonic::Cwde,
    Mnemonic::Cbw,
    Mnemonic::Cwd,
];

fn has_ident(expr: &str, ident: &str) -> bool {
    !ident.is_empty()
        && expr.match_indices(ident).any(|(idx, _)| {
            let prev_ok =
                idx == 0 || !expr.as_bytes()[idx - 1].is_ascii_alphanumeric() && expr.as_bytes()[idx - 1] != b'_';
            let end = idx + ident.len();
            let next_ok =
                end == expr.len() || !expr.as_bytes()[end].is_ascii_alphanumeric() && expr.as_bytes()[end] != b'_';
            prev_ok && next_ok
        })
}

fn replace_ident(expr: &str, ident: &str, rep: &str) -> String {
    if !has_ident(expr, ident) {
        return expr.to_owned();
    }
    let (mut out, mut last) = (String::with_capacity(expr.len()), 0);
    for (idx, _) in expr.match_indices(ident) {
        let prev_ok = idx == 0 || !expr.as_bytes()[idx - 1].is_ascii_alphanumeric() && expr.as_bytes()[idx - 1] != b'_';
        let end = idx + ident.len();
        let next_ok =
            end == expr.len() || !expr.as_bytes()[end].is_ascii_alphanumeric() && expr.as_bytes()[end] != b'_';
        if prev_ok && next_ok {
            out.push_str(&expr[last..idx]);
            out.push_str(rep);
            last = end;
        }
    }
    out.push_str(&expr[last..]);
    out
}

fn kills_cf_without_read(ins: &Instruction) -> bool {
    if matches!(
        ins.flow_control(),
        FlowControl::Return
            | FlowControl::Call
            | FlowControl::IndirectCall
            | FlowControl::Interrupt
            | FlowControl::Exception
    ) {
        return true;
    }
    matches!(
        ins.mnemonic(),
        Mnemonic::Cmp
            | Mnemonic::Test
            | Mnemonic::Add
            | Mnemonic::Sub
            | Mnemonic::And
            | Mnemonic::Or
            | Mnemonic::Xor
            | Mnemonic::Shl
            | Mnemonic::Shr
            | Mnemonic::Sar
            | Mnemonic::Neg
            | Mnemonic::Mul
            | Mnemonic::Imul
            | Mnemonic::Div
            | Mnemonic::Idiv
            | Mnemonic::Tzcnt
            | Mnemonic::Lzcnt
            | Mnemonic::Popcnt
    )
}

fn push_insn_writes(ctx: &FnCtx<'_>, k: usize, webs: &mut Vec<String>, mem: &mut bool) {
    let ki = &ctx.ssa.insns[k];
    if ki.op0_kind() == OpKind::Memory && !matches!(ki.mnemonic(), Mnemonic::Cmp | Mnemonic::Test | Mnemonic::Lea) {
        *mem = true;
    }
    for wid in [ctx.ssa.metas[k].def_web, ctx.ssa.metas[k].rdx_def_web].into_iter().flatten() {
        let wn = &ctx.ssa.webs[wid].name;
        if !wn.is_empty() && !webs.iter().any(|x| x == wn) {
            webs.push(wn.clone());
        }
    }
}

fn classify_flag_reader(ins: &Instruction, is_sub: bool, cf: &mut bool, ovf: &mut bool) {
    let cc = ins.condition_code();
    if matches!(ins.mnemonic(), Mnemonic::Adc | Mnemonic::Sbb)
        || matches!(cc, ConditionCode::b | ConditionCode::ae | ConditionCode::be | ConditionCode::a)
    {
        *cf = true;
    }
    if matches!(cc, ConditionCode::o | ConditionCode::no)
        || (is_sub && matches!(cc, ConditionCode::l | ConditionCode::ge | ConditionCode::le | ConditionCode::g))
    {
        *ovf = true;
    }
}

fn scan_succ_flags(ctx: &FnCtx<'_>, start_ip: u64, is_sub: bool, cf: &mut bool, ovf: &mut bool) {
    let Ok(mut k) = ctx.ssa.insns.binary_search_by_key(&start_ip, Instruction::ip) else { return };
    let blk = ctx.ssa.metas[k].block;
    while k < ctx.ssa.insns.len() && ctx.ssa.metas[k].block == blk {
        let ki = &ctx.ssa.insns[k];
        classify_flag_reader(ki, is_sub, cf, ovf);
        if kills_cf_without_read(ki) {
            break;
        }
        k += 1;
    }
}

fn flag_lifetime_mutations(ctx: &FnCtx<'_>, ins_idx: usize) -> (bool, Vec<String>, Vec<String>, bool) {
    let (mut any_read, mut killed, mut k) = (false, false, ins_idx + 1);
    let (mut all_mut, mut later_mut, mut mem) = (Vec::new(), Vec::new(), false);
    push_insn_writes(ctx, ins_idx, &mut all_mut, &mut mem);
    let blk = ctx.ssa.metas[ins_idx].block;
    while k < ctx.ssa.insns.len() && ctx.ssa.metas[k].block == blk {
        let ki = &ctx.ssa.insns[k];
        if ki.condition_code() != ConditionCode::None || matches!(ki.mnemonic(), Mnemonic::Adc | Mnemonic::Sbb) {
            any_read = true;
        }
        if kills_cf_without_read(ki) {
            killed = true;
            break;
        }
        push_insn_writes(ctx, k, &mut all_mut, &mut mem);
        push_insn_writes(ctx, k, &mut later_mut, &mut mem);
        k += 1;
    }
    (any_read || !killed, all_mut, later_mut, mem)
}

fn bin_flag_needs(ctx: &FnCtx<'_>, ins_idx: usize, is_sub: bool) -> (bool, bool, Vec<String>, Vec<String>, bool) {
    let (mut cf, mut ovf, mut killed, mut mem) = (false, false, false, false);
    let (mut all_mut, mut later_mut) = (Vec::new(), Vec::new());
    push_insn_writes(ctx, ins_idx, &mut all_mut, &mut mem);
    let blk = ctx.ssa.metas[ins_idx].block;
    let mut k = ins_idx + 1;
    while k < ctx.ssa.insns.len() && ctx.ssa.metas[k].block == blk {
        let ki = &ctx.ssa.insns[k];
        classify_flag_reader(ki, is_sub, &mut cf, &mut ovf);
        if kills_cf_without_read(ki) {
            killed = true;
            break;
        }
        push_insn_writes(ctx, k, &mut all_mut, &mut mem);
        push_insn_writes(ctx, k, &mut later_mut, &mut mem);
        k += 1;
    }
    if !killed {
        let last = &ctx.ssa.insns[k - 1];
        if matches!(last.flow_control(), FlowControl::Next | FlowControl::ConditionalBranch) {
            scan_succ_flags(ctx, last.next_ip(), is_sub, &mut cf, &mut ovf);
        }
        if matches!(last.flow_control(), FlowControl::UnconditionalBranch | FlowControl::ConditionalBranch)
            && let Some(bt) = branch_target(last)
        {
            scan_succ_flags(ctx, bt, is_sub, &mut cf, &mut ovf);
        }
    }
    (cf, ovf, all_mut, later_mut, mem)
}

fn is_dirty(expr: &str, webs: &[String], mem: bool) -> bool {
    (mem && expr.contains('*')) || webs.iter().any(|w| has_ident(expr, w))
}

fn cast_u(expr: &str, bits: u8) -> String {
    let pfx = format!("(u{bits})");
    if expr.starts_with(&pfx) { expr.to_owned() } else { format!("{pfx}{}", wrap_atom(expr)) }
}

fn fmt_bin_expr(lhs: &str, op: &str, rhs: &str) -> String {
    let raw = rhs
        .strip_prefix('-')
        .filter(|_| op == "+")
        .map_or_else(|| format!("({lhs} {op} {rhs})"), |neg| format!("({lhs} - {neg})"));
    simplify_linear(&raw)
}

pub fn step_bin(ctx: &FnCtx<'_>, state: &mut State, ins: &Instruction, ins_idx: usize, block: &mut Block) -> bool {
    let m = ins.mnemonic();
    let Some((_, op)) = BIN_OPS.iter().find(|(bm, _)| *bm == m) else { return false };
    let base = u32::from(ins.op_count() == 3);
    let (lhs, rhs) = (ctx.op(state, ins, base), ctx.op(state, ins, base + 1));
    let expr = fmt_bin_expr(&lhs, op, &rhs);
    let bits = u8::try_from(op_byte_width(ins) * 8).unwrap_or(64);
    let fop = FlagOp::from_bin_width(m, bits);
    if !matches!(m, Mnemonic::Add | Mnemonic::Sub) {
        let emitted = assign(ctx, state, ins, ins_idx, expr.clone(), &mut block.stmts);
        state.flags = Some(Flags::arith_width(fop, bits, emitted.unwrap_or(expr), lhs, rhs));
        return true;
    }
    let is_sub = m == Mnemonic::Sub;
    let (reads_cf, reads_ovf, all_mut, later_mut, mem_mut) = bin_flag_needs(ctx, ins_idx, is_sub);
    let (mut safe_l, mut safe_r, mut swap_add) = (lhs, rhs, false);
    if !is_sub
        && reads_cf
        && !reads_ovf
        && is_dirty(&safe_l, &all_mut, mem_mut)
        && !is_dirty(&safe_r, &all_mut, mem_mut)
        && !safe_r.starts_with('-')
    {
        swap_add = true;
    } else if reads_cf || reads_ovf {
        if is_dirty(&safe_l, &all_mut, mem_mut) {
            let lv = format!("lhs_{:x}", ins.ip());
            block.stmts.push(format!("u{bits} {lv} = {};", cast_u(&safe_l, bits)));
            safe_l = lv;
        }
        if (is_sub || reads_ovf) && is_dirty(&safe_r, &all_mut, mem_mut) {
            let rv = format!("rhs_{:x}", ins.ip());
            block.stmts.push(format!("u{bits} {rv} = {};", cast_u(&safe_r, bits)));
            safe_r = rv;
        }
    }
    let em = assign(ctx, state, ins, ins_idx, expr, &mut block.stmts);
    let pm = ctx.ssa.metas[ins_idx].partial_merge;
    let flag_lhs = match em {
        Some(w) if !is_dirty(&w, &later_mut, mem_mut) => {
            if let Some(b) = pm {
                format!("(u{b}){w}")
            } else {
                w
            }
        }
        _ => fmt_bin_expr(&safe_l, op, &safe_r),
    };
    let (ovf_a, ovf_b) = if swap_add { (safe_r, safe_l) } else { (safe_l, safe_r) };
    state.flags = Some(Flags::arith(fop, flag_lhs, ovf_a, ovf_b));
    true
}

pub fn step_carry(ctx: &FnCtx<'_>, state: &mut State, ins: &Instruction, ins_idx: usize, block: &mut Block) -> bool {
    let m = ins.mnemonic();
    if !matches!(m, Mnemonic::Adc | Mnemonic::Sbb) {
        return false;
    }
    let mut cf = cond_expr(ConditionCode::b, state.flags.as_ref());
    let sz = op_byte_width(ins);
    let bits = u8::try_from(sz * 8).unwrap_or(64);
    let same_sub = m == Mnemonic::Sbb
        && ins.op0_kind() == OpKind::Register
        && ins.op1_kind() == OpKind::Register
        && ins.op0_register() == ins.op1_register();
    let (mut raw_l, mut raw_r) = (ctx.op(state, ins, 0), ctx.op(state, ins, 1));
    let (flags_live, all_mut, later_mut, mem_mut) = flag_lifetime_mutations(ctx, ins_idx);
    if flags_live {
        if is_dirty(&cf, &all_mut, mem_mut) {
            let cv = format!("cf_{:x}", ins.ip());
            block.stmts.push(format!("u8 {cv} = {};", wrap_atom(&cf)));
            cf = cv;
        }
        if !same_sub && is_dirty(&raw_l, &all_mut, mem_mut) {
            let lv = format!("lhs_{:x}", ins.ip());
            block.stmts.push(format!("u{bits} {lv} = {};", cast_u(&raw_l, bits)));
            raw_l = lv;
        }
        if !same_sub && is_dirty(&raw_r, &all_mut, mem_mut) {
            let rv = format!("rhs_{:x}", ins.ip());
            block.stmts.push(format!("u{bits} {rv} = {};", cast_u(&raw_r, bits)));
            raw_r = rv;
        }
    }
    let cfp = wrap_atom(&cf);
    let expr = if same_sub {
        match sz {
            1 => format!("({cf} ? 0xff : 0)"),
            2 => format!("({cf} ? 0xffff : 0)"),
            4 => format!("({cf} ? 0xffffffff : 0)"),
            _ => format!("(-{cfp})"),
        }
    } else {
        let (lhs, rhs) = (wrap_atom(&raw_l), wrap_atom(&raw_r));
        let op = if m == Mnemonic::Adc { "+" } else { "-" };
        let body = if rhs == "0" { format!("({lhs} {op} {cfp})") } else { format!("({lhs} {op} {rhs} {op} {cfp})") };
        if sz == 4 { format!("(u32){body}") } else { body }
    };
    let fop = if m == Mnemonic::Adc { FlagOp::Adc(bits) } else { FlagOp::Sbb(bits) };
    let em = assign(ctx, state, ins, ins_idx, expr.clone(), &mut block.stmts);
    let flag_lhs = match em {
        Some(w) if !is_dirty(&w, &later_mut, mem_mut) => w,
        _ => expr,
    };
    state.flags = Some(Flags::carry_op(fop, flag_lhs, raw_l, raw_r, cf));
    true
}

pub fn step_unary(ctx: &FnCtx<'_>, state: &mut State, ins: &Instruction, ins_idx: usize, block: &mut Block) -> bool {
    let m = ins.mnemonic();
    let Some((_, pre, post)) = UNARY_OPS.iter().find(|(u, _, _)| *u == m) else { return false };
    let mut val = ctx.op(state, ins, u32::from(ins.op_count() > 1));
    if matches!(m, Mnemonic::Not | Mnemonic::Bswap) {
        if let Some(wid) = ctx.ssa.metas[ins_idx].def_web {
            let wn = &ctx.ssa.webs[wid].name;
            if let Some(f) = state.flags.as_mut()
                && !wn.is_empty()
                && (has_ident(&f.lhs, wn)
                    || has_ident(&f.rhs, wn)
                    || f.carry.as_deref().is_some_and(|c| has_ident(c, wn))
                    || f.ovf.as_ref().is_some_and(|(a, b)| has_ident(a, wn) || has_ident(b, wn)))
            {
                let pv = format!("pre_{:x}", ins.ip());
                block.stmts.push(format!("u64 {pv} = {wn};"));
                f.lhs = replace_ident(&f.lhs, wn, &pv);
                f.rhs = replace_ident(&f.rhs, wn, &pv);
                if let Some(c) = &mut f.carry {
                    *c = replace_ident(c, wn, &pv);
                }
                if let Some((a, b)) = &mut f.ovf {
                    *a = replace_ident(a, wn, &pv);
                    *b = replace_ident(b, wn, &pv);
                }
            }
        }
        let expr = wrap_unary(pre, &val, post);
        let _ = assign(ctx, state, ins, ins_idx, expr, &mut block.stmts);
        return true;
    }
    if matches!(m, Mnemonic::Inc | Mnemonic::Dec) {
        let mut prev_cf = cond_expr(ConditionCode::b, state.flags.as_ref());
        let sz = op_byte_width(ins);
        let bits = u8::try_from(sz * 8).unwrap_or(64);
        let (flags_live, all_mut, later_mut, mem_mut) = flag_lifetime_mutations(ctx, ins_idx);
        if flags_live {
            if is_dirty(&prev_cf, &all_mut, mem_mut) {
                let cv = format!("cf_{:x}", ins.ip());
                block.stmts.push(format!("u8 {cv} = {};", wrap_atom(&prev_cf)));
                prev_cf = cv;
            }
            if is_dirty(&val, &all_mut, mem_mut) {
                let lv = format!("lhs_{:x}", ins.ip());
                block.stmts.push(format!("u{bits} {lv} = {};", cast_u(&val, bits)));
                val = lv;
            }
        }
        let expr = wrap_unary(pre, &val, post);
        let em = assign(ctx, state, ins, ins_idx, expr.clone(), &mut block.stmts);
        let pm = ctx.ssa.metas[ins_idx].partial_merge;
        let flag_lhs = match em {
            Some(w) if !is_dirty(&w, &later_mut, mem_mut) => {
                if let Some(b) = pm {
                    format!("(u{b}){w}")
                } else {
                    w
                }
            }
            _ => {
                if bits < 32 {
                    format!("(u{bits}){expr}")
                } else {
                    expr
                }
            }
        };
        state.flags = Some(Flags::inc_dec_width(m, bits, flag_lhs, val, prev_cf));
        return true;
    }
    let bits = u8::try_from(op_byte_width(ins) * 8).unwrap_or(64);
    let expr = wrap_unary(pre, &val, post);
    let em = assign(ctx, state, ins, ins_idx, expr.clone(), &mut block.stmts);
    state.flags = Some(Flags::unary_width(m, bits, em.unwrap_or(expr), val));
    true
}
