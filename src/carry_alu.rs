/*
 * xref — Ultra blazing fast cross-references of an x86-64 ELF binary
 * Copyright (c) 2026 Alexander Panasenko
 *
 * Contact: alex@prod.codes
 * Author: https://prod.codes/about/
 * Project: https://github.com/alex09x/xref
 * SPDX-License-Identifier: MIT OR Apache-2.0
 */

//! Carry/borrow (`adc`, `sbb`) and partial-flag unary (`inc`, `dec`, `not`, `bswap`) pseudo-C
//! lifting with width-aware `CF`/`OF` propagation and pre-mutation snapshotting.

use iced_x86::{ConditionCode, FlowControl, Instruction, Mnemonic, OpKind};

use crate::c_step::{FnCtx, assign};
use crate::cfg::Block;
use crate::expr::{FlagOp, Flags, State, UNARY_OPS, cond_expr, wrap_unary};
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

fn flag_lifetime_mutations(ctx: &FnCtx<'_>, ins_idx: usize) -> (bool, Vec<String>, Vec<String>, bool) {
    let (mut all_mut, mut later_mut, mut mem) = (Vec::new(), Vec::new(), false);
    push_insn_writes(ctx, ins_idx, &mut all_mut, &mut mem);
    let blk = ctx.ssa.metas[ins_idx].block;
    let (mut any_read, mut killed, mut k) = (false, false, ins_idx + 1);
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

fn is_dirty(expr: &str, webs: &[String], mem: bool) -> bool {
    (mem && expr.contains('*')) || webs.iter().any(|w| has_ident(expr, w))
}

fn cast_u(expr: &str, bits: u8) -> String {
    let pfx = format!("(u{bits})");
    if expr.starts_with(&pfx) { expr.to_owned() } else { format!("{pfx}{}", wrap_atom(expr)) }
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
        state.flags = Some(Flags::inc_dec(m, flag_lhs, val, prev_cf));
        return true;
    }
    let expr = wrap_unary(pre, &val, post);
    let em = assign(ctx, state, ins, ins_idx, expr.clone(), &mut block.stmts);
    state.flags = Some(Flags::unary(m, em.unwrap_or(expr), val));
    true
}

#[cfg(test)]
mod tests {
    use crate::c::c_one;
    use crate::image::{Image, Segment};
    use crate::runtime::RuntimeMap;

    #[test]
    fn preserves_carry_across_adc_sbb_inc_dec_and_idiv_signext_checks() {
        // f1 (0x1000): mov eax, 0x100; cmp rax, rdi; sbb al, 0; mov [rsi], rax; setc al; movzx eax, al; ret
        let f1: &[u8] = &[
            0xb8, 0x00, 0x01, 0x00, 0x00, 0x48, 0x39, 0xf8, 0x1c, 0x00, 0x48, 0x89, 0x06, 0x0f, 0x92, 0xc0, 0x0f, 0xb6,
            0xc0, 0xc3,
        ];
        // f2 (0x1020): mov eax, 0x101; cmp rax, rdi; sbb al, 0; mov al, 5; mov [rsi], rax; setz al; movzx eax, al; ret
        let f2: &[u8] = &[
            0xb8, 0x01, 0x01, 0x00, 0x00, 0x48, 0x39, 0xf8, 0x1c, 0x00, 0xb0, 0x05, 0x48, 0x89, 0x06, 0x0f, 0x94, 0xc0,
            0x0f, 0xb6, 0xc0, 0xc3,
        ];
        // f3 (0x1040): cmp rdi, rsi; mov rax, -1; adc rax, 0; inc rcx; setc dl; movzx eax, dl; ret (INC preserves CF!)
        let f3: &[u8] = &[
            0x48, 0x39, 0xf7, 0x48, 0xc7, 0xc0, 0xff, 0xff, 0xff, 0xff, 0x48, 0x83, 0xd0, 0x00, 0x48, 0xff, 0xc1, 0x0f,
            0x92, 0xc2, 0x0f, 0xb6, 0xc2, 0xc3,
        ];
        // f4 (0x1060): cmp rdi, rsi; mov rax, -1; adc rax, 0; dec rcx; mov eax, 10; adc rax, 0; ret (ADC -> DEC -> ADC)
        let f4: &[u8] = &[
            0x48, 0x39, 0xf7, 0x48, 0xc7, 0xc0, 0xff, 0xff, 0xff, 0xff, 0x48, 0x83, 0xd0, 0x00, 0x48, 0xff, 0xc9, 0xb8,
            0x0a, 0x00, 0x00, 0x00, 0x48, 0x83, 0xd0, 0x00, 0xc3,
        ];
        // f5 (0x1080): mov eax, 0x100; cmp rax, rdi; sbb al, 0; inc al; mov [rsi], rax; setc al; movzx eax, al; ret
        let f5: &[u8] = &[
            0xb8, 0x00, 0x01, 0x00, 0x00, 0x48, 0x39, 0xf8, 0x1c, 0x00, 0xfe, 0xc0, 0x48, 0x89, 0x06, 0x0f, 0x92, 0xc0,
            0x0f, 0xb6, 0xc0, 0xc3,
        ];
        // f6 (0x10a0): mov rdx, rdi; sar rdx, 63; mov rax, rsi; idiv rcx; ret (div_mixed: (u128)(u64) zero-extension)
        let f6: &[u8] = &[0x48, 0x89, 0xfa, 0x48, 0xc1, 0xfa, 0x3f, 0x48, 0x89, 0xf0, 0x48, 0xf7, 0xf9, 0xc3];
        // f7 (0x10c0): mov eax, 0x12340007; mov cl, 3; div cl; ret (8-bit div preserves upper 16 bits + writes AX)
        let f7: &[u8] = &[0xb8, 0x07, 0x00, 0x34, 0x12, 0xb1, 0x03, 0xf6, 0xf1, 0xc3];

        let (mut data, mut functions) = (vec![0xccu8; 0x100], Vec::new());
        for (off, b) in [(0, f1), (0x20, f2), (0x40, f3), (0x60, f4), (0x80, f5), (0xa0, f6), (0xc0, f7)] {
            data[off..off + b.len()].copy_from_slice(b);
            functions.push(0x1000 + off as u64..0x1000 + (off + b.len()) as u64);
        }
        let img = Image {
            data,
            segments: vec![Segment { va: 0x1000, offset: 0, size: 0x100 }],
            functions,
            pointers: Vec::new(),
            imports: Vec::new(),
            symbols: Vec::new(),
        };
        let rt = RuntimeMap::detect(&img);
        let (_, c1) = c_one(&img, &[], &rt, 0x1000, None, None).unwrap_or_default();
        assert!(
            c1.contains("u8 cf_1008 = (v_1 < arg_0);") && c1.contains("return ((u16)(u8)lhs_1008 < (u16)cf_1008);"),
            "{c1}"
        );

        let (_, c2) = c_one(&img, &[], &rt, 0x1020, None, None).unwrap_or_default();
        assert!(c2.contains("return (u8)(lhs_1028 - cf_1028) == 0;"), "{c2}");

        let (_, c3) = c_one(&img, &[], &rt, 0x1040, None, None).unwrap_or_default();
        assert!(c3.contains("return arg_0 < arg_1;") && !c3.contains("< 0"), "{c3}");

        let (_, c4) = c_one(&img, &[], &rt, 0x1060, None, None).unwrap_or_default();
        assert!(c4.contains("return (10 + (arg_0 < arg_1));"), "{c4}");

        let (_, c5) = c_one(&img, &[], &rt, 0x1080, None, None).unwrap_or_default();
        assert!(
            c5.contains("u8 cf_1088 = (v_1 < arg_0);") && c5.contains("return ((u16)(u8)lhs_1088 < (u16)cf_1088);"),
            "{c5}"
        );

        let (_, c6) = c_one(&img, &[], &rt, 0x10a0, None, None).unwrap_or_default();
        assert!(c6.contains("((u128)(u64)") && c6.contains("| (u128)(u64)arg_1"), "{c6}");

        let (_, c7) = c_one(&img, &[], &rt, 0x10c0, None, None).unwrap_or_default();
        assert!(c7.contains("& ~0xffff") && c7.contains("<< 8"), "{c7}");
    }
}
