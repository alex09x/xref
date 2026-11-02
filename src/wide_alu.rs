/*
 * xref — Ultra blazing fast cross-references of an x86-64 ELF binary
 * Copyright (c) 2026 Alexander Panasenko
 *
 * Contact: alex@prod.codes
 * Author: https://prod.codes/about/
 * Project: https://github.com/alex09x/xref
 * SPDX-License-Identifier: MIT OR Apache-2.0
 */

//! Widening 1-operand multiply/divide (`mul`, `imul`, `div`, `idiv`) and sign-extension (`cbw`,
//! `cwde`, `cdqe`, `cwd`, `cdq`, `cqo`) pseudo-C lifting.

use iced_x86::{Instruction, Mnemonic, OpKind, Register};

use crate::c_step::FnCtx;
use crate::cfg::Block;
use crate::expr::{FlagOp, Flags, State};
use crate::simplify::simplify_linear;

pub fn wrap_atom(s: &str) -> String {
    if s.contains(' ') && !s.starts_with('(') && !s.starts_with('*') && !s.starts_with('"') {
        format!("({s})")
    } else {
        s.to_owned()
    }
}

fn merge_low_bits(prev: &str, rhs: &str, bits: u8) -> String {
    let (mask_val, mask) = if bits == 8 { (0xffu64, "0xff") } else { (0xffffu64, "0xffff") };
    let (prev_p, rp) = (wrap_atom(prev), wrap_atom(rhs));
    let low = rhs.parse::<u64>().map_or_else(|_| format!("({rp} & {mask})"), |n| format!("{}", n & mask_val));
    if low == "0" { format!("({prev_p} & ~{mask})") } else { format!("(({prev_p} & ~{mask}) | {low})") }
}

fn assign_imp(
    (ctx, state, block): (&FnCtx<'_>, &mut State, &mut Block),
    (instruction, ins_idx): (&Instruction, usize),
    (reg, wid_opt, write_bits): (Register, Option<usize>, u8),
    rhs: String,
) -> Option<String> {
    let prev = state.reg(reg);
    state.rodata_ptrs.remove(&reg);
    state.inline_regs.remove(&reg);
    let meta = &ctx.ssa.metas[ins_idx];
    let wid = wid_opt?;
    let web = &ctx.ssa.webs[wid];
    let pm =
        if reg == Register::RDX && meta.rdx_def_web == wid_opt { meta.rdx_partial_merge } else { meta.partial_merge };
    if let Some(bits) =
        pm.or_else(|| (write_bits < 32 && prev != "0" && web.max_read_bytes * 8 > write_bits).then_some(write_bits))
    {
        let wname = web.name.clone();
        let merged = merge_low_bits(if pm.is_some() { &wname } else { &prev }, &rhs, bits);
        block.stmts.push(format!("{wname} = {merged};"));
        state.regs.insert(reg, wname.clone());
        return Some(wname);
    }
    if meta.can_inline && !ctx.is_marked(instruction) && rhs.len() <= 56 {
        state.inline_regs.insert(reg, rhs);
        return None;
    }
    if web.total_reads == 0 && !ctx.partial_slice && !ctx.is_marked(instruction) {
        return None;
    }
    let wname = web.name.clone();
    if wname != rhs {
        block.stmts.push(format!("{wname} = {rhs};"));
    }
    state.regs.insert(reg, wname.clone());
    Some(wname)
}

pub fn op_byte_width(ins: &Instruction) -> usize {
    if ins.op0_kind() == OpKind::Register {
        ins.op0_register().size()
    } else {
        let s = ins.memory_size().size();
        if s == 0 { 8 } else { s }
    }
}

fn step_wide_mul(ctx: &FnCtx<'_>, state: &mut State, ins: &Instruction, ins_idx: usize, block: &mut Block) {
    let signed = ins.mnemonic() == Mnemonic::Imul;
    let sz = op_byte_width(ins);
    let (rax, src) = (state.reg(Register::RAX), ctx.op(state, ins, 0));
    let (rax_p, src_p) = (wrap_atom(&rax), wrap_atom(&src));
    let fop = if signed { FlagOp::Mul } else { FlagOp::UMul };
    if sz == 1 {
        let expr = if signed {
            format!("(u16)((i16)(i8){rax_p} * (i16)(i8){src_p})")
        } else {
            format!("((u16)(u8){rax_p} * (u16)(u8){src_p})")
        };
        let em = assign_imp(
            (ctx, state, block),
            (ins, ins_idx),
            (Register::RAX, ctx.ssa.metas[ins_idx].def_web, 16),
            expr.clone(),
        );
        state.flags = Some(Flags::arith(fop, em.unwrap_or(expr), rax, src));
        return;
    }
    let wb = u8::try_from(sz * 8).unwrap_or(64);
    let meta = &ctx.ssa.metas[ins_idx];
    let keep_all = ctx.partial_slice || ctx.is_marked(ins);
    let lo_web = meta.def_web.filter(|&w| ctx.ssa.webs[w].total_reads > 0 || keep_all);
    let hi_web = meta.rdx_def_web.filter(|&w| ctx.ssa.webs[w].total_reads > 0 || keep_all);
    let (wide_ty, half_ty, shift, out_cast) = match (sz, signed) {
        (2, false) => ("u32", "(u32)(u16)", 16, "(u16)"),
        (2, true) => ("i32", "(i32)(i16)", 16, "(u16)"),
        (4, false) => ("u64", "(u64)(u32)", 32, "(u32)"),
        (4, true) => ("i64", "(i64)(i32)", 32, "(u32)"),
        (_, false) => ("u128", "(u128)(u64)", 64, "(u64)"),
        (_, true) => ("i128", "(i128)(i64)", 64, "(u64)"),
    };
    match (lo_web, hi_web) {
        (Some(wa), Some(wd)) => {
            let tmp = format!("prod_{:x}", ins.ip());
            block.stmts.push(format!("{wide_ty} {tmp} = {half_ty}{rax_p} * {half_ty}{src_p};"));
            let _ = assign_imp(
                (ctx, state, block),
                (ins, ins_idx),
                (Register::RAX, Some(wa), wb),
                format!("{out_cast}{tmp}"),
            );
            let _ = assign_imp(
                (ctx, state, block),
                (ins, ins_idx),
                (Register::RDX, Some(wd), wb),
                format!("{out_cast}({tmp} >> {shift})"),
            );
        }
        (Some(wa), None) => {
            let _ = (state.rodata_ptrs.remove(&Register::RDX), state.inline_regs.remove(&Register::RDX));
            let low = if sz == 8 {
                simplify_linear(&format!("({rax_p} * {src_p})"))
            } else {
                format!("{out_cast}({rax_p} * {src_p})")
            };
            let _ = assign_imp((ctx, state, block), (ins, ins_idx), (Register::RAX, Some(wa), wb), low);
        }
        (None, Some(wd)) => {
            let _ = (state.rodata_ptrs.remove(&Register::RAX), state.inline_regs.remove(&Register::RAX));
            let hi = format!("{out_cast}(({half_ty}{rax_p} * {half_ty}{src_p}) >> {shift})");
            let _ = assign_imp((ctx, state, block), (ins, ins_idx), (Register::RDX, Some(wd), wb), hi);
        }
        (None, None) => {
            let _ = (state.rodata_ptrs.remove(&Register::RAX), state.inline_regs.remove(&Register::RAX));
            let _ = (state.rodata_ptrs.remove(&Register::RDX), state.inline_regs.remove(&Register::RDX));
        }
    }
    let flag_lhs = lo_web.map_or_else(|| format!("({rax_p} * {src_p})"), |wa| ctx.ssa.webs[wa].name.clone());
    state.flags = Some(Flags::arith(fop, flag_lhs, rax, src));
}

fn proven_sext_dividend(ctx: &FnCtx<'_>, ins_idx: usize, sz: usize) -> bool {
    let meta = &ctx.ssa.metas[ins_idx];
    let Some(rdx_w) = meta.web_of_read(Register::RDX) else { return false };
    let defs = &ctx.ssa.webs[rdx_w].defs;
    if defs.len() != 1 || defs[0] >= ins_idx || ctx.ssa.metas[defs[0]].block != meta.block {
        return false;
    }
    let def_i = defs[0];
    let ok_m =
        matches!((sz, ctx.ssa.insns[def_i].mnemonic()), (2, Mnemonic::Cwd) | (4, Mnemonic::Cdq) | (8, Mnemonic::Cqo));
    ok_m && ctx.ssa.metas[def_i].web_of_read(Register::RAX) == meta.web_of_read(Register::RAX)
        && (def_i + 1..ins_idx).all(|k| {
            let ki = &ctx.ssa.insns[k];
            !matches!(ki.flow_control(), iced_x86::FlowControl::Call | iced_x86::FlowControl::IndirectCall)
                && ctx.ssa.metas[k].rdx_def_web.is_none()
                && ctx.ssa.metas[k]
                    .def_web
                    .is_none_or(|w| !matches!(ctx.ssa.webs[w].reg, Register::RAX | Register::RDX))
                && (ki.op0_kind() != OpKind::Register
                    || !matches!(ki.op0_register().full_register(), Register::RAX | Register::RDX))
        })
}

fn step_wide_div(ctx: &FnCtx<'_>, state: &mut State, ins: &Instruction, ins_idx: usize, block: &mut Block) {
    let signed = ins.mnemonic() == Mnemonic::Idiv;
    let sz = op_byte_width(ins);
    let (lo_reg, hi_reg, divisor) = (state.reg(Register::RAX), state.reg(Register::RDX), ctx.op(state, ins, 0));
    let (lo_expr, hi_expr, div_expr) = (wrap_atom(&lo_reg), wrap_atom(&hi_reg), wrap_atom(&divisor));
    state.flags = None;
    if sz == 1 {
        let expr = if signed {
            format!(
                "((u16)(((i16){lo_expr} / (i16)(i8){div_expr}) & 0xff) | ((u16)(((i16){lo_expr} % (i16)(i8){div_expr}) & 0xff) << 8))"
            )
        } else {
            format!("(((u16){lo_expr} / (u16)(u8){div_expr}) | (((u16){lo_expr} % (u16)(u8){div_expr}) << 8))")
        };
        let _ =
            assign_imp((ctx, state, block), (ins, ins_idx), (Register::RAX, ctx.ssa.metas[ins_idx].def_web, 16), expr);
        return;
    }
    let wb = u8::try_from(sz * 8).unwrap_or(64);
    let meta = &ctx.ssa.metas[ins_idx];
    let keep_all = ctx.partial_slice || ctx.is_marked(ins);
    let lo_live = meta.def_web.filter(|&w| ctx.ssa.webs[w].total_reads > 0 || keep_all);
    let hi_live = meta.rdx_def_web.filter(|&w| ctx.ssa.webs[w].total_reads > 0 || keep_all);
    let is_zero_hi = !signed && hi_reg == "0";
    let is_sext_hi = signed && proven_sext_dividend(ctx, ins_idx, sz);
    let (quot, rem) = if is_zero_hi || is_sext_hi {
        let lo_use = if let (Some(wa), Some(_)) = (lo_live, hi_live)
            && lo_reg == ctx.ssa.webs[wa].name
        {
            let dv = format!("div_{:x}", ins.ip());
            block.stmts.push(format!("u64 {dv} = {lo_reg};"));
            dv
        } else {
            lo_expr
        };
        match (sz, signed) {
            (2, false) => (format!("((u16){lo_use} / (u16){div_expr})"), format!("((u16){lo_use} % (u16){div_expr})")),
            (4, false) => (format!("((u32){lo_use} / (u32){div_expr})"), format!("((u32){lo_use} % (u32){div_expr})")),
            (_, false) => (format!("((u64){lo_use} / (u64){div_expr})"), format!("((u64){lo_use} % (u64){div_expr})")),
            (2, true) => {
                (format!("(u16)((i16){lo_use} / (i16){div_expr})"), format!("(u16)((i16){lo_use} % (i16){div_expr})"))
            }
            (4, true) => {
                (format!("(u32)((i32){lo_use} / (i32){div_expr})"), format!("(u32)((i32){lo_use} % (i32){div_expr})"))
            }
            (_, true) => (format!("((i64){lo_use} / (i64){div_expr})"), format!("((i64){lo_use} % (i64){div_expr})")),
        }
    } else {
        let (ws, sub_u, out_c, sh, sc) = match (sz, signed) {
            (2, false) => ("u32", "(u32)(u16)", "(u16)", 16, "(u32)(u16)"),
            (2, true) => ("i32", "(u32)(u16)", "(u16)", 16, "(i32)(i16)"),
            (4, false) => ("u64", "(u64)(u32)", "(u32)", 32, "(u64)(u32)"),
            (4, true) => ("i64", "(u64)(u32)", "(u32)", 32, "(i64)(i32)"),
            (_, false) => ("u128", "(u128)(u64)", "(u64)", 64, "(u128)(u64)"),
            (_, true) => ("i128", "(u128)(u64)", "(u64)", 64, "(i128)(i64)"),
        };
        let divd = if lo_live.is_some() && hi_live.is_some() {
            let dv = format!("div_{:x}", ins.ip());
            block.stmts.push(format!("{ws} {dv} = ({sub_u}{hi_expr} << {sh}) | {sub_u}{lo_expr};"));
            dv
        } else {
            format!("({ws})(({sub_u}{hi_expr} << {sh}) | {sub_u}{lo_expr})")
        };
        (format!("{out_c}({divd} / {sc}{div_expr})"), format!("{out_c}({divd} % {sc}{div_expr})"))
    };
    let _ = assign_imp((ctx, state, block), (ins, ins_idx), (Register::RAX, meta.def_web, wb), quot);
    let _ = assign_imp((ctx, state, block), (ins, ins_idx), (Register::RDX, meta.rdx_def_web, wb), rem);
}

pub fn step_wide_or_carry(
    ctx: &FnCtx<'_>,
    state: &mut State,
    ins: &Instruction,
    ins_idx: usize,
    block: &mut Block,
) -> bool {
    let m = ins.mnemonic();
    match m {
        Mnemonic::Cbw | Mnemonic::Cwde | Mnemonic::Cdqe | Mnemonic::Cwd | Mnemonic::Cdq | Mnemonic::Cqo => {
            let ax = wrap_atom(&state.reg(Register::RAX));
            let (reg, wb, rhs) = match m {
                Mnemonic::Cbw => (Register::RAX, 16, format!("(u16)(i16)(i8){ax}")),
                Mnemonic::Cwde => (Register::RAX, 32, format!("(u32)(i32)(i16){ax}")),
                Mnemonic::Cdqe => (Register::RAX, 64, format!("(u64)(i64)(i32){ax}")),
                Mnemonic::Cwd => (Register::RDX, 16, format!("(u16)((i16){ax} >> 15)")),
                Mnemonic::Cdq => (Register::RDX, 32, format!("(u32)((i32){ax} >> 31)")),
                _ => (Register::RDX, 64, format!("((i64){ax} >> 63)")),
            };
            let _ = assign_imp((ctx, state, block), (ins, ins_idx), (reg, ctx.ssa.metas[ins_idx].def_web, wb), rhs);
            true
        }
        Mnemonic::Mul | Mnemonic::Imul if ins.op_count() == 1 => {
            step_wide_mul(ctx, state, ins, ins_idx, block);
            true
        }
        Mnemonic::Div | Mnemonic::Idiv if ins.op_count() == 1 => {
            step_wide_div(ctx, state, ins, ins_idx, block);
            true
        }
        _ => crate::carry_alu::step_carry(ctx, state, ins, ins_idx, block),
    }
}

#[cfg(test)]
mod tests {
    use crate::c::c_one;
    use crate::image::{Image, Segment};
    use crate::runtime::RuntimeMap;

    #[test]
    fn lifts_widening_mul_div_sbb_and_preserves_subword_upper_bits() {
        let f1: &[u8] = &[
            0x48, 0x89, 0xf2, 0x48, 0x89, 0xf8, 0x48, 0xb9, 0xf1, 0xde, 0xbc, 0x9a, 0x78, 0x56, 0x34, 0x12, 0x48, 0xf7,
            0xe1, 0x48, 0xc1, 0xea, 0x06, 0x48, 0x89, 0xd0, 0xc3,
        ];
        let f2: &[u8] = &[0x48, 0x89, 0xf8, 0x48, 0xf7, 0xe6, 0xc3];
        let f3: &[u8] = &[0xe8, 0xdb, 0xff, 0xff, 0xff, 0x48, 0x01, 0xd0, 0xc3];
        let f4: &[u8] = &[0x48, 0x39, 0xf7, 0x0f, 0x97, 0xc0, 0x1c, 0x00, 0x48, 0x0f, 0xbe, 0xc0, 0xc3];
        let f5: &[u8] = &[0x48, 0x89, 0xf8, 0x48, 0x99, 0x48, 0xf7, 0xfe, 0x48, 0x01, 0xd0, 0xc3];
        let f6: &[u8] = &[0xb8, 0x00, 0x00, 0x34, 0x12, 0xb0, 0x02, 0xb1, 0x03, 0xf6, 0xe1, 0xc3];
        let f7: &[u8] = &[0xb8, 0x02, 0x00, 0x34, 0x12, 0x66, 0xb9, 0x03, 0x00, 0x66, 0xf7, 0xe1, 0xc3];
        let f8: &[u8] = &[
            0xb8, 0xff, 0x00, 0x34, 0x12, 0xba, 0x00, 0x00, 0x78, 0x56, 0x66, 0x98, 0x66, 0x99, 0x66, 0xb9, 0x03, 0x00,
            0x66, 0xf7, 0xf9, 0xc3,
        ];
        let mut data = vec![0xccu8; 0x140];
        let mut fns = Vec::new();
        for (off, bytes) in
            [(0x00, f1), (0x40, f2), (0x60, f3), (0x80, f4), (0xa0, f5), (0xc0, f6), (0xe0, f7), (0x100, f8)]
        {
            data[off..off + bytes.len()].copy_from_slice(bytes);
            fns.push(0x1000 + off as u64..0x1000 + (off + bytes.len()) as u64);
        }
        let img = Image {
            data,
            segments: vec![Segment { va: 0x1000, offset: 0, size: 0x140 }],
            functions: fns,
            pointers: Vec::new(),
            imports: Vec::new(),
            symbols: Vec::new(),
        };
        let rt = RuntimeMap::detect(&img);
        let (_, c1) = c_one(&img, &[], &rt, 0x1000, None, None).unwrap_or_default();
        assert!(
            !c1.contains("/* mul")
                && c1.contains("(u128)(u64)arg_0")
                && c1.contains(">> 64")
                && !c1.contains("arg_1 >> 6"),
            "{c1}"
        );
        let (_, c2) = c_one(&img, &[], &rt, 0x1040, None, None).unwrap_or_default();
        assert!(
            c2.contains("u128 prod_1043 = (u128)(u64)arg_0 * (u128)(u64)arg_1;") && c2.contains("return ("),
            "{c2}"
        );
        let (_, c4) = c_one(&img, &[], &rt, 0x1080, None, None).unwrap_or_default();
        assert!(!c4.contains("/* sbb") && c4.contains("(arg_0 > arg_1) - (arg_0 < arg_1)"), "{c4}");
        let (_, c5) = c_one(&img, &[], &rt, 0x10a0, None, None).unwrap_or_default();
        assert!(c5.contains("(i64)arg_0 / (i64)arg_1") && c5.contains("(i64)arg_0 % (i64)arg_1"), "{c5}");
        let (_, c6) = c_one(&img, &[], &rt, 0x10c0, None, None).unwrap_or_default();
        assert!(c6.contains("& ~0xffff") && !c6.contains("u16 v_1"), "{c6}");
        let (_, c7) = c_one(&img, &[], &rt, 0x10e0, None, None).unwrap_or_default();
        assert!(c7.matches("& ~0xffff").count() == 2 && !c7.contains("u16 v_") && c7.contains("return ("), "{c7}");
        let (_, c8) = c_one(&img, &[], &rt, 0x1100, None, None).unwrap_or_default();
        assert!(c8.matches("& ~0xffff").count() >= 4 && !c8.contains("/* cbw") && !c8.contains("/* cwd"), "{c8}");
    }
}
