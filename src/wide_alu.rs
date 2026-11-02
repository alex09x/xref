/*
 * xref — Ultra blazing fast cross-references of an x86-64 ELF binary
 * Copyright (c) 2026 Alexander Panasenko
 *
 * Contact: alex@prod.codes
 * Author: https://prod.codes/about/
 * Project: https://github.com/alex09x/xref
 * SPDX-License-Identifier: MIT OR Apache-2.0
 */

//! Widening 1-operand multiply/divide (`mul`, `imul`, `div`, `idiv`), sign-extension (`cqo`,
//! `cdq`, `cdqe`, `cwde`), and carry/borrow (`adc`, `sbb`) pseudo-C lifting.

use iced_x86::{ConditionCode, Instruction, Mnemonic, OpKind, Register};

use crate::c_step::{FnCtx, assign};
use crate::cfg::Block;
use crate::expr::{FlagOp, Flags, State, cond_expr};
use crate::simplify::simplify_linear;

fn wrap_atom(s: &str) -> String {
    if s.contains(' ') && !s.starts_with('(') && !s.starts_with('*') && !s.starts_with('"') {
        format!("({s})")
    } else {
        s.to_owned()
    }
}

fn assign_implicit_reg(
    ctx: &FnCtx<'_>,
    state: &mut State,
    instruction: &Instruction,
    ins_idx: usize,
    (reg, wid_opt): (Register, Option<usize>),
    rhs: String,
    stmts: &mut Vec<String>,
) -> Option<String> {
    state.rodata_ptrs.remove(&reg);
    state.inline_regs.remove(&reg);
    let meta = &ctx.ssa.metas[ins_idx];
    if meta.elide_def {
        return None;
    }
    let wid = wid_opt?;
    let web = &ctx.ssa.webs[wid];
    if meta.can_inline && !ctx.is_marked(instruction) && rhs.len() <= 56 {
        state.inline_regs.insert(reg, rhs);
        return None;
    }
    if web.total_reads == 0 && !ctx.partial_slice && !ctx.is_marked(instruction) {
        return None;
    }
    let wname = web.name.clone();
    if wname != rhs {
        stmts.push(format!("{wname} = {rhs};"));
    }
    state.regs.insert(reg, wname.clone());
    Some(wname)
}

fn op_byte_width(ins: &Instruction) -> usize {
    if ins.op0_kind() == OpKind::Register { ins.op0_register().size() } else { ins.memory_size().size().max(8) }
}

fn step_wide_mul(ctx: &FnCtx<'_>, state: &mut State, ins: &Instruction, ins_idx: usize, block: &mut Block) {
    let signed = ins.mnemonic() == Mnemonic::Imul;
    let sz = if ins.op0_kind() == OpKind::Register { ins.op0_register().size() } else { ins.memory_size().size() };
    let (rax, src) = (state.reg(Register::RAX), ctx.op(state, ins, 0));
    let (rax_p, src_p) = (wrap_atom(&rax), wrap_atom(&src));
    state.rodata_ptrs.remove(&Register::RAX);
    state.inline_regs.remove(&Register::RAX);
    let fop = if signed { FlagOp::Mul } else { FlagOp::UMul };
    if sz == 1 {
        let expr = if signed {
            format!("(u16)((i16)(i8){rax_p} * (i16)(i8){src_p})")
        } else {
            format!("((u16)(u8){rax_p} * (u16)(u8){src_p})")
        };
        let em = assign_implicit_reg(
            ctx,
            state,
            ins,
            ins_idx,
            (Register::RAX, ctx.ssa.metas[ins_idx].def_web),
            expr.clone(),
            &mut block.stmts,
        );
        state.flags = Some(Flags::arith(fop, em.unwrap_or(expr), rax, src));
        return;
    }
    state.rodata_ptrs.remove(&Register::RDX);
    state.inline_regs.remove(&Register::RDX);
    let meta = &ctx.ssa.metas[ins_idx];
    let keep_all = ctx.partial_slice || ctx.is_marked(ins);
    let lo_web = meta.def_web.filter(|&w| ctx.ssa.webs[w].total_reads > 0 || keep_all);
    let hi_web = meta.rdx_def_web.filter(|&w| ctx.ssa.webs[w].total_reads > 0 || keep_all);
    let (wide_ty, half_ty, shift, out_cast) = match (sz, signed) {
        (2, false) => ("u32", "(u32)(u16)", 16, "(u16)"),
        (2, true) => ("i32", "(i32)(i16)", 16, "(u16)"),
        (4, false) => ("u64", "(u64)(u32)", 32, "(u32)"),
        (4, true) => ("i64", "(i64)(i32)", 32, "(u32)"),
        (_, false) => ("u128", "(u128)", 64, "(u64)"),
        (_, true) => ("i128", "(i128)(i64)", 64, "(u64)"),
    };
    match (lo_web, hi_web) {
        (Some(wa), Some(wd)) => {
            let tmp = format!("prod_{:x}", ins.ip());
            let (na, nd) = (ctx.ssa.webs[wa].name.clone(), ctx.ssa.webs[wd].name.clone());
            block.stmts.push(format!("{wide_ty} {tmp} = {half_ty}{rax_p} * {half_ty}{src_p};"));
            block.stmts.push(format!("{na} = {out_cast}{tmp};"));
            block.stmts.push(format!("{nd} = {out_cast}({tmp} >> {shift});"));
            state.regs.insert(Register::RAX, na);
            state.regs.insert(Register::RDX, nd);
        }
        (Some(wa), None) => {
            let low = if sz == 8 {
                simplify_linear(&format!("({rax_p} * {src_p})"))
            } else {
                format!("{out_cast}({rax_p} * {src_p})")
            };
            let na = ctx.ssa.webs[wa].name.clone();
            if na != low {
                block.stmts.push(format!("{na} = {low};"));
            }
            state.regs.insert(Register::RAX, na);
        }
        (None, Some(wd)) => {
            let hi = format!("{out_cast}(({half_ty}{rax_p} * {half_ty}{src_p}) >> {shift})");
            let nd = ctx.ssa.webs[wd].name.clone();
            if nd != hi {
                block.stmts.push(format!("{nd} = {hi};"));
            }
            state.regs.insert(Register::RDX, nd);
        }
        (None, None) => {}
    }
    let flag_lhs = lo_web.map_or_else(|| format!("({rax_p} * {src_p})"), |wa| ctx.ssa.webs[wa].name.clone());
    state.flags = Some(Flags::arith(fop, flag_lhs, rax, src));
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
        let _ = assign_implicit_reg(
            ctx,
            state,
            ins,
            ins_idx,
            (Register::RAX, ctx.ssa.metas[ins_idx].def_web),
            expr,
            &mut block.stmts,
        );
        return;
    }
    let (quot, rem) = if !signed && hi_reg == "0" {
        match sz {
            2 => (format!("((u16){lo_expr} / (u16){div_expr})"), format!("((u16){lo_expr} % (u16){div_expr})")),
            4 => (format!("((u32){lo_expr} / (u32){div_expr})"), format!("((u32){lo_expr} % (u32){div_expr})")),
            _ => (format!("({lo_expr} / {div_expr})"), format!("({lo_expr} % {div_expr})")),
        }
    } else if signed && (hi_reg.ends_with(">> 63)") || hi_reg.ends_with(">> 31)") || hi_reg.ends_with(">> 15)")) {
        match sz {
            2 => {
                (format!("(u16)((i16){lo_expr} / (i16){div_expr})"), format!("(u16)((i16){lo_expr} % (i16){div_expr})"))
            }
            4 => {
                (format!("(u32)((i32){lo_expr} / (i32){div_expr})"), format!("(u32)((i32){lo_expr} % (i32){div_expr})"))
            }
            _ => (format!("((i64){lo_expr} / (i64){div_expr})"), format!("((i64){lo_expr} % (i64){div_expr})")),
        }
    } else {
        let (wu, ws, out_c, sh, sc) = match (sz, signed) {
            (2, false) => ("u32", "u32", "(u16)", 16, "(u32)(u16)"),
            (2, true) => ("u32", "i32", "(u16)", 16, "(i32)(i16)"),
            (4, false) => ("u64", "u64", "(u32)", 32, "(u64)(u32)"),
            (4, true) => ("u64", "i64", "(u32)", 32, "(i64)(i32)"),
            (_, false) => ("u128", "u128", "(u64)", 64, "(u128)"),
            (_, true) => ("u128", "i128", "(u64)", 64, "(i128)(i64)"),
        };
        let divd = format!("({ws})((({wu}){hi_expr} << {sh}) | ({wu}){lo_expr})");
        (format!("{out_c}({divd} / {sc}{div_expr})"), format!("{out_c}({divd} % {sc}{div_expr})"))
    };
    let meta = &ctx.ssa.metas[ins_idx];
    let _ = assign_implicit_reg(ctx, state, ins, ins_idx, (Register::RAX, meta.def_web), quot, &mut block.stmts);
    let _ = assign_implicit_reg(ctx, state, ins, ins_idx, (Register::RDX, meta.rdx_def_web), rem, &mut block.stmts);
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
        Mnemonic::Cqo => {
            let rhs = format!("((i64){} >> 63)", wrap_atom(&state.reg(Register::RAX)));
            let _ = assign_implicit_reg(
                ctx,
                state,
                ins,
                ins_idx,
                (Register::RDX, ctx.ssa.metas[ins_idx].def_web),
                rhs,
                &mut block.stmts,
            );
            true
        }
        Mnemonic::Cdq => {
            let rhs = format!("(u32)((i32){} >> 31)", wrap_atom(&state.reg(Register::RAX)));
            let _ = assign_implicit_reg(
                ctx,
                state,
                ins,
                ins_idx,
                (Register::RDX, ctx.ssa.metas[ins_idx].def_web),
                rhs,
                &mut block.stmts,
            );
            true
        }
        Mnemonic::Cdqe => {
            let rhs = format!("(u64)(i64)(i32){}", wrap_atom(&state.reg(Register::RAX)));
            let _ = assign_implicit_reg(
                ctx,
                state,
                ins,
                ins_idx,
                (Register::RAX, ctx.ssa.metas[ins_idx].def_web),
                rhs,
                &mut block.stmts,
            );
            true
        }
        Mnemonic::Cwde => {
            let rhs = format!("(u32)(i32)(i16){}", wrap_atom(&state.reg(Register::RAX)));
            let _ = assign_implicit_reg(
                ctx,
                state,
                ins,
                ins_idx,
                (Register::RAX, ctx.ssa.metas[ins_idx].def_web),
                rhs,
                &mut block.stmts,
            );
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
        Mnemonic::Sbb | Mnemonic::Adc => {
            let cf = cond_expr(ConditionCode::b, state.flags.as_ref());
            let same_sub = m == Mnemonic::Sbb
                && ins.op0_kind() == OpKind::Register
                && ins.op1_kind() == OpKind::Register
                && ins.op0_register() == ins.op1_register();
            let expr = if same_sub {
                let cfp = wrap_atom(&cf);
                if ins.op0_register().size() == 4 { format!("({cf} ? 0xffffffff : 0)") } else { format!("(-{cfp})") }
            } else {
                let (lhs, rhs) = (wrap_atom(&ctx.op(state, ins, 0)), wrap_atom(&ctx.op(state, ins, 1)));
                let cfp = wrap_atom(&cf);
                let op = if m == Mnemonic::Adc { "+" } else { "-" };
                if rhs == "0" { format!("({lhs} {op} {cfp})") } else { format!("({lhs} {op} {rhs} {op} {cfp})") }
            };
            let em = assign(ctx, state, ins, ins_idx, expr.clone(), &mut block.stmts);
            state.flags = Some(Flags::other(em.unwrap_or(expr), "0".to_owned()));
            true
        }
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use crate::c::c_one;
    use crate::image::{Image, Segment};
    use crate::runtime::RuntimeMap;

    #[test]
    fn lifts_widening_mul_high_half_128_pair_div_and_three_way_sbb() {
        // f1 (0x1000): mov rdx, rsi (stale!); mov rax, rdi; mov rcx, 0x123456789abcdef1; mul rcx; shr rdx, 6; mov rax, rdx; ret
        let f1: &[u8] = &[
            0x48, 0x89, 0xf2, // mov rdx, rsi
            0x48, 0x89, 0xf8, // mov rax, rdi
            0x48, 0xb9, 0xf1, 0xde, 0xbc, 0x9a, 0x78, 0x56, 0x34, 0x12, // movabs rcx, 0x123456789abcdef1
            0x48, 0xf7, 0xe1, // mul rcx
            0x48, 0xc1, 0xea, 0x06, // shr rdx, 6
            0x48, 0x89, 0xd0, // mov rax, rdx
            0xc3,
        ];
        // f2 (0x1040): mov rax, rdi; mul rsi; ret (caller f3 reads rdx -> full 128-bit pair!)
        let f2: &[u8] = &[0x48, 0x89, 0xf8, 0x48, 0xf7, 0xe6, 0xc3];
        // f3 (0x1060): call 0x1040; add rax, rdx; ret
        let f3: &[u8] = &[0xe8, 0xdb, 0xff, 0xff, 0xff, 0x48, 0x01, 0xd0, 0xc3];
        // f4 (0x1080): cmp rdi, rsi; seta al; sbb al, 0; movsx rax, al; ret
        let f4: &[u8] = &[0x48, 0x39, 0xf7, 0x0f, 0x97, 0xc0, 0x1c, 0x00, 0x48, 0x0f, 0xbe, 0xc0, 0xc3];
        // f5 (0x10a0): mov rax, rdi; cqo; idiv rsi; add rax, rdx; ret
        let f5: &[u8] = &[0x48, 0x89, 0xf8, 0x48, 0x99, 0x48, 0xf7, 0xfe, 0x48, 0x01, 0xd0, 0xc3];

        let mut data = vec![0xccu8; 0x100];
        data[..f1.len()].copy_from_slice(f1);
        data[0x40..0x40 + f2.len()].copy_from_slice(f2);
        data[0x60..0x60 + f3.len()].copy_from_slice(f3);
        data[0x80..0x80 + f4.len()].copy_from_slice(f4);
        data[0xa0..0xa0 + f5.len()].copy_from_slice(f5);
        let img = Image {
            data,
            segments: vec![Segment { va: 0x1000, offset: 0, size: 0x100 }],
            functions: vec![
                0x1000..0x1000 + f1.len() as u64,
                0x1040..0x1040 + f2.len() as u64,
                0x1060..0x1060 + f3.len() as u64,
                0x1080..0x1080 + f4.len() as u64,
                0x10a0..0x10a0 + f5.len() as u64,
            ],
            pointers: Vec::new(),
            imports: Vec::new(),
            symbols: Vec::new(),
        };
        let rt = RuntimeMap::detect(&img);
        let (_, c1) = c_one(&img, &[], &rt, 0x1000, None, None).unwrap_or_default();
        assert!(
            !c1.contains("/* mul") && c1.contains("(u128)arg_0") && c1.contains(">> 64") && !c1.contains("arg_1 >> 6"),
            "{c1}"
        );

        let (_, c2) = c_one(&img, &[], &rt, 0x1040, None, None).unwrap_or_default();
        assert!(c2.contains("u128 prod_1043 = (u128)arg_0 * (u128)arg_1;") && c2.contains("return ("), "{c2}");

        let (_, c4) = c_one(&img, &[], &rt, 0x1080, None, None).unwrap_or_default();
        assert!(!c4.contains("/* sbb") && c4.contains("(arg_0 > arg_1) - (arg_0 < arg_1)"), "{c4}");

        let (_, c5) = c_one(&img, &[], &rt, 0x10a0, None, None).unwrap_or_default();
        assert!(c5.contains("(i64)arg_0 / (i64)arg_1") && c5.contains("(i64)arg_0 % (i64)arg_1"), "{c5}");
    }
}
