/*
 * xref — Ultra blazing fast cross-references of an x86-64 ELF binary
 * Copyright (c) 2026 Alexander Panasenko
 *
 * Contact: alex@prod.codes
 * Author: https://prod.codes/about/
 * Project: https://github.com/alex09x/xref
 * SPDX-License-Identifier: MIT OR Apache-2.0
 */

//! Carry/borrow (`adc`, `sbb`) pseudo-C lifting with width-aware `CF`/`OF` propagation and
//! pre-mutation operand/carry snapshotting across flag lifetimes.

use iced_x86::{ConditionCode, FlowControl, Instruction, Mnemonic, OpKind};

use crate::c_step::{FnCtx, assign};
use crate::cfg::Block;
use crate::expr::{FlagOp, Flags, State, cond_expr};
use crate::wide_alu::{op_byte_width, wrap_atom};

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

fn kills_flags_without_read(ins: &Instruction) -> bool {
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
            | Mnemonic::Inc
            | Mnemonic::Dec
            | Mnemonic::Neg
            | Mnemonic::Mul
            | Mnemonic::Imul
            | Mnemonic::Div
            | Mnemonic::Idiv
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
    let mut any_read = false;
    let mut killed = false;
    let mut k = ins_idx + 1;
    while k < ctx.ssa.insns.len() && ctx.ssa.metas[k].block == blk {
        let ki = &ctx.ssa.insns[k];
        if ki.condition_code() != ConditionCode::None || matches!(ki.mnemonic(), Mnemonic::Adc | Mnemonic::Sbb) {
            any_read = true;
        }
        if kills_flags_without_read(ki) {
            killed = true;
            break;
        }
        push_insn_writes(ctx, k, &mut all_mut, &mut mem);
        push_insn_writes(ctx, k, &mut later_mut, &mut mem);
        k += 1;
    }
    if !killed {
        any_read = true;
    }
    (any_read, all_mut, later_mut, mem)
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

#[cfg(test)]
mod tests {
    use crate::c::c_one;
    use crate::image::{Image, Segment};
    use crate::runtime::RuntimeMap;

    #[test]
    fn snapshots_mutated_carry_in_and_subword_operands_across_sbb_and_adc() {
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
        let (mut data, mut functions) = (vec![0xccu8; 0x60], Vec::new());
        for (off, b) in [(0, f1), (0x20, f2)] {
            data[off..off + b.len()].copy_from_slice(b);
            functions.push(0x1000 + off as u64..0x1000 + (off + b.len()) as u64);
        }
        let img = Image {
            data,
            segments: vec![Segment { va: 0x1000, offset: 0, size: 0x60 }],
            functions,
            pointers: Vec::new(),
            imports: Vec::new(),
            symbols: Vec::new(),
        };
        let rt = RuntimeMap::detect(&img);
        let (_, c1) = c_one(&img, &[], &rt, 0x1000, None, None).unwrap_or_default();
        assert!(c1.contains("u8 cf_1008 = (v_1 < arg_0);") && c1.contains("u8 lhs_1008 = (u8)v_1;"), "{c1}");
        assert!(c1.contains("return ((u16)(u8)lhs_1008 < (u16)cf_1008);"), "{c1}");

        let (_, c2) = c_one(&img, &[], &rt, 0x1020, None, None).unwrap_or_default();
        assert!(c2.contains("return (u8)(lhs_1028 - cf_1028) == 0;"), "{c2}");
    }
}
