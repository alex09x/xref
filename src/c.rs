/*
 * xref — Ultra blazing fast cross-references of an x86-64 ELF binary
 * Copyright (c) 2026 Alexander Panasenko
 *
 * Contact: alex@prod.codes
 * Author: https://prod.codes/about/
 * SPDX-License-Identifier: MIT OR Apache-2.0
 */

//! Pseudo-C decompiler: basic blocks, symbolic register/stack propagation, conditions, calls and
//! jump-table `switch` statements lifted directly from x86-64 machine code.

use std::collections::BTreeSet;
use std::io::Write;
use std::ops::Range;

use iced_x86::{ConditionCode, FlowControl, Instruction, Mnemonic, OpKind, Register};

use crate::cfg::{Block, Term, structure};
use crate::commands::{Res, function};
use crate::expr::{
    ABI_ARGS, BIN_OPS, CALLEE_SAVED, IGNORED, MOVES, State, UNARY_OPS, cond_expr, mem_expr, neg_cond_expr, op_expr,
    params, reg_name, stack_name,
};
use crate::image::{Image, Slot};
use crate::listing::is_call;
use crate::locations::{Location, locations};
use crate::scan::{branch_target, decode, format};
use crate::tables::{Table, tables};

struct FnCtx<'a> {
    image: &'a Image,
    locations: &'a [Location],
    tables: &'a [Table],
    function: &'a Range<u64>,
    stack_lea: bool,
}

impl FnCtx<'_> {
    fn op(&self, state: &mut State, instruction: &Instruction, idx: u32) -> String {
        op_expr(self.image, self.locations, state, instruction, idx)
    }
}

fn leaders_and_stack(bytes: &[u8], function: &Range<u64>, tables: &[Table]) -> (BTreeSet<u64>, bool) {
    let mut leaders: BTreeSet<u64> = tables.iter().flat_map(|t| t.arms.iter().copied()).collect();
    let mut stack_lea = false;
    decode(bytes, function.start, |instruction| {
        if instruction.mnemonic() == Mnemonic::Lea && instruction.memory_base().full_register() == Register::RSP {
            stack_lea = true;
        }
        if let Some(target) = branch_target(instruction)
            && function.contains(&target)
        {
            leaders.insert(target);
        }
        if !matches!(instruction.flow_control(), FlowControl::Next | FlowControl::Call | FlowControl::IndirectCall) {
            let next = instruction.next_ip();
            if next > function.start && function.contains(&next) {
                leaders.insert(next);
            }
        }
    });
    (leaders, stack_lea)
}

fn plt_import(image: &Image, target: u64) -> Option<&str> {
    let bytes = image.read(target, 16)?;
    let mut found = None;
    decode(bytes, target, |ins| {
        if ins.is_ip_rel_memory_operand()
            && let Some(Slot::Import(name)) = image.slot(ins.ip_rel_memory_address())
        {
            found = Some(name);
        }
    });
    found
}

fn callee(ctx: &FnCtx<'_>, state: &mut State, instruction: &Instruction) -> (String, Vec<Register>) {
    let active: Vec<Register> = ABI_ARGS.into_iter().filter(|r| state.regs.contains_key(r)).collect();
    let target = branch_target(instruction).or_else(|| {
        instruction
            .is_ip_rel_memory_operand()
            .then(|| ctx.image.slot(instruction.ip_rel_memory_address()))
            .flatten()
            .and_then(|s| if let Slot::Pointer(t) = s { Some(t) } else { None })
    });
    let Some(target) = target else {
        return (op_expr(ctx.image, ctx.locations, state, instruction, 0), active);
    };
    if let Some(name) = plt_import(ctx.image, target) {
        return (name.to_owned(), active);
    }
    let detected =
        ctx.image.function_at(target).filter(|f| f.start == target).map(|f| params(ctx.image, &f)).unwrap_or_default();
    let args = ABI_ARGS.into_iter().filter(|r| state.regs.contains_key(r) || detected.contains(r)).collect();
    (format!("fn_{target:x}"), args)
}

fn flush_dirty(state: &mut State, lines: &mut Vec<String>) {
    for reg in std::mem::take(&mut state.dirty) {
        lines.push(format!("{} = {};", reg_name(reg), state.reg(reg)));
    }
}

fn assign(ctx: &FnCtx<'_>, state: &mut State, instruction: &Instruction, rhs: String, lines: &mut Vec<String>) {
    if instruction.op0_kind() == OpKind::Register {
        let full = instruction.op0_register().full_register();
        let name = reg_name(full);
        for r in std::mem::take(&mut state.dirty) {
            if r != full && state.regs.get(&r).is_some_and(|v| v.contains(&name)) {
                let v = state.regs.insert(r, reg_name(r)).unwrap_or_default();
                lines.push(format!("{} = {v};", reg_name(r)));
            } else if r != full {
                state.dirty.push(r);
            }
        }
        if CALLEE_SAVED.contains(&full) {
            lines.push(format!("{name} = {rhs};"));
            state.regs.insert(full, name);
        } else {
            state.set_reg(full, rhs);
        }
        return;
    }
    if !instruction.is_ip_rel_memory_operand()
        && instruction.memory_base().full_register() == Register::RSP
        && instruction.memory_index() == Register::None
    {
        let disp = instruction.memory_displacement64().cast_signed();
        state.stack.insert(disp, rhs.clone());
        if ctx.stack_lea {
            lines.push(format!("{} = {rhs};", stack_name(disp)));
        }
        return;
    }
    let lhs = mem_expr(ctx.image, ctx.locations, state, instruction);
    lines.push(format!("{lhs} = {rhs};"));
}

fn step_flow(ctx: &FnCtx<'_>, state: &mut State, instruction: &Instruction, block: &mut Block) -> bool {
    match instruction.flow_control() {
        FlowControl::Return => {
            let ret = state.reg(Register::RAX);
            flush_dirty(state, &mut block.stmts);
            block.term = Term::Return(format!("return {ret};"));
        }
        FlowControl::Interrupt | FlowControl::Exception => {
            flush_dirty(state, &mut block.stmts);
            block.term = Term::Return("unreachable();".to_owned());
        }
        FlowControl::Call | FlowControl::IndirectCall => {
            let (target, args) = callee(ctx, state, instruction);
            let rendered: Vec<String> = args.into_iter().map(|r| state.reg(r)).collect();
            state.clear_scratch();
            block.stmts.push(format!("rax = {target}({});", rendered.join(", ")));
            state.regs.insert(Register::RAX, "rax".to_owned());
        }
        FlowControl::ConditionalBranch => {
            let cc = instruction.condition_code();
            let cond = cond_expr(cc, state.flags.as_ref());
            let neg = neg_cond_expr(cc, state.flags.as_ref());
            flush_dirty(state, &mut block.stmts);
            block.term = Term::Cond { cond, neg, target: instruction.near_branch_target() };
        }
        FlowControl::UnconditionalBranch | FlowControl::IndirectBranch => {
            if let Some(table) =
                ctx.tables.iter().find(|t| t.dispatch <= instruction.ip() && instruction.ip() - t.dispatch <= 32)
            {
                let fallback = ctx.op(state, instruction, 0);
                let idx = state.switch_idx.take().unwrap_or(fallback);
                flush_dirty(state, &mut block.stmts);
                block.term = Term::Switch { idx, base: table.base, arms: table.arms.clone() };
            } else if is_call(instruction, ctx.function) || instruction.flow_control() == FlowControl::IndirectBranch {
                let (target, args) = callee(ctx, state, instruction);
                let rendered: Vec<String> = args.into_iter().map(|r| state.reg(r)).collect();
                flush_dirty(state, &mut block.stmts);
                block.term = Term::Return(format!("return {target}({});", rendered.join(", ")));
            } else if let Some(target) = branch_target(instruction) {
                flush_dirty(state, &mut block.stmts);
                block.term = Term::Jump(target);
            }
        }
        _ => return false,
    }
    true
}

fn step(ctx: &FnCtx<'_>, state: &mut State, instruction: &Instruction, block: &mut Block) {
    let mnemonic = instruction.mnemonic();
    if IGNORED.contains(&mnemonic)
        || (matches!(mnemonic, Mnemonic::Add | Mnemonic::Sub)
            && instruction.op0_register().full_register() == Register::RSP)
        || (mnemonic == Mnemonic::Mov
            && instruction.op0_register().full_register() == Register::RBP
            && instruction.op1_register().full_register() == Register::RSP)
    {
        return;
    }
    let prev_str = state.last_str.take();
    if ctx.tables.iter().any(|t| t.dispatch == instruction.ip()) {
        let _ = state.reg(instruction.memory_base());
        state.switch_idx = Some(state.reg(instruction.memory_index()));
        return;
    }
    if step_flow(ctx, state, instruction, block) {
        return;
    }
    if mnemonic == Mnemonic::Cmp {
        let (lhs, rhs) = (ctx.op(state, instruction, 0), ctx.op(state, instruction, 1));
        state.flags = Some((lhs, rhs));
        return;
    }
    if mnemonic == Mnemonic::Test {
        let (lhs, rhs) = (ctx.op(state, instruction, 0), ctx.op(state, instruction, 1));
        let tested = if lhs == rhs { lhs } else { format!("({lhs} & {rhs})") };
        state.flags = Some((tested, "0".to_owned()));
        return;
    }
    if instruction.condition_code() != ConditionCode::None {
        let cond = cond_expr(instruction.condition_code(), state.flags.as_ref());
        let expr = if instruction.op_count() == 1 {
            cond
        } else {
            let (prev, src) = (ctx.op(state, instruction, 0), ctx.op(state, instruction, 1));
            format!("({cond} ? {src} : {prev})")
        };
        assign(ctx, state, instruction, expr, &mut block.stmts);
        return;
    }
    if matches!(mnemonic, Mnemonic::Xor | Mnemonic::Sub | Mnemonic::Xorps | Mnemonic::Xorpd | Mnemonic::Pxor)
        && instruction.op0_kind() == OpKind::Register
        && instruction.op1_kind() == OpKind::Register
        && instruction.op0_register() == instruction.op1_register()
    {
        assign(ctx, state, instruction, "0".to_owned(), &mut block.stmts);
        state.flags = Some(("0".to_owned(), "0".to_owned()));
        return;
    }
    if MOVES.contains(&mnemonic) {
        let rhs = ctx.op(state, instruction, 1);
        if let Some((str_reg, place)) = prev_str
            && let Ok(len) = rhs.parse::<usize>()
            && (1..=128).contains(&len)
            && let Some(bytes) = ctx.image.read(place, len)
            && bytes.iter().all(|b| (0x20..0x7f).contains(b))
        {
            state.regs.insert(str_reg, format!("{:?}", String::from_utf8_lossy(bytes)));
        }
        assign(ctx, state, instruction, rhs, &mut block.stmts);
        if mnemonic == Mnemonic::Lea
            && instruction.is_ip_rel_memory_operand()
            && instruction.op0_kind() == OpKind::Register
        {
            state.last_str = Some((instruction.op0_register().full_register(), instruction.ip_rel_memory_address()));
        }
        return;
    }
    if let Some((_, op)) = BIN_OPS.iter().find(|(m, _)| *m == mnemonic) {
        let base = u32::from(instruction.op_count() == 3);
        let (lhs, rhs) = (ctx.op(state, instruction, base), ctx.op(state, instruction, base + 1));
        let expr = if *op == "+"
            && let Some(neg) = rhs.strip_prefix('-')
        {
            format!("({lhs} - {neg})")
        } else {
            format!("({lhs} {op} {rhs})")
        };
        assign(ctx, state, instruction, expr.clone(), &mut block.stmts);
        let flag_lhs = if instruction.op0_kind() == OpKind::Register
            && CALLEE_SAVED.contains(&instruction.op0_register().full_register())
        {
            reg_name(instruction.op0_register())
        } else {
            expr
        };
        state.flags = Some((flag_lhs, "0".to_owned()));
        return;
    }
    if let Some((_, pre, post)) = UNARY_OPS.iter().find(|(m, _, _)| *m == mnemonic) {
        let src = u32::from(instruction.op_count() > 1);
        let val = ctx.op(state, instruction, src);
        let expr = format!("{pre}{val}{post}");
        state.flags = Some((expr.clone(), "0".to_owned()));
        assign(ctx, state, instruction, expr, &mut block.stmts);
        return;
    }
    block.stmts.push(format!("/* {} */", format(instruction)));
}

pub fn c(image: &Image, addr: u64, from: Option<u64>, to: Option<u64>, out: &mut dyn Write) -> Res {
    let f = function(image, addr)?;
    let code = image.code(&f).ok_or("function outside the image")?;
    let shown = from.unwrap_or(f.start)..to.unwrap_or(f.end);
    let all_locations = locations(image);
    let found_tables = tables(image, &f);
    let (leaders, stack_lea) = leaders_and_stack(code, &f, &found_tables);
    let ctx = FnCtx { image, locations: &all_locations, tables: &found_tables, function: &f, stack_lea };
    let mut state = State::default();
    let mut blocks: Vec<Block> = Vec::new();
    let mut cur = Block { start: shown.start, stmts: Vec::new(), term: Term::Fall };
    decode(code, f.start, |instruction| {
        let ip = instruction.ip();
        if leaders.contains(&ip) {
            if shown.contains(&ip) {
                flush_dirty(&mut state, &mut cur.stmts);
                let next = Block { start: ip, stmts: Vec::new(), term: Term::Fall };
                let prev = std::mem::replace(&mut cur, next);
                if !prev.stmts.is_empty() || prev.term != Term::Fall || !blocks.is_empty() {
                    blocks.push(prev);
                }
            }
            state = State::default();
        }
        if shown.contains(&ip) {
            step(&ctx, &mut state, instruction, &mut cur);
        }
    });
    flush_dirty(&mut state, &mut cur.stmts);
    blocks.push(cur);
    let lines = structure(blocks);
    let args: Vec<String> = params(image, &f).into_iter().map(reg_name).collect();
    writeln!(out, "function {:#x}..{:#x} ({}) {{", f.start, f.end, args.join(", "))?;
    for line in &lines {
        writeln!(out, "{line}")?;
    }
    writeln!(out, "}}")?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::c;
    use crate::image::{Image, Segment};

    #[test]
    fn decompiles_branches_calls_tables_ops_and_stack_slots() {
        let mut data = vec![0u8; 0x400];
        // PLT stub at 0x1200: jmp [rip + 0x100] -> 0x1306 (import "puts")
        data[0x200..0x206].copy_from_slice(&[0xff, 0x25, 0x00, 0x01, 0x00, 0x00]);
        // Callee at 0x1220: mov rax, rdi; ret
        data[0x220..0x224].copy_from_slice(&[0x48, 0x89, 0xf8, 0xc3]);
        // Jump table at 0x1300: 1 entry -> offset -0x1f3 (arm 0x110d)
        data[0x300..0x304].copy_from_slice(&(-0x1f3i32).to_le_bytes());
        data[0x320..0x329].copy_from_slice(b"hello txt");
        let code: &[u8] = &[
            0x55, 0x48, 0x89, 0xe5, 0x48, 0x83, 0xec, 0x10, 0x49, 0x89, 0xfe, 0x48, 0x89, 0x74, 0x24, 0x08, 0x48, 0x8d,
            0x44, 0x24, 0x08, 0x48, 0x89, 0x07, 0x48, 0x83, 0xff, 0x09, 0x0f, 0x94, 0xc0, 0x48, 0x0f, 0x45, 0xc6, 0x48,
            0x85, 0xc0, 0x48, 0xf7, 0xc6, 0x01, 0x00, 0x00, 0x00, 0x31, 0xc9, 0x48, 0x6b, 0xd7, 0x05, 0x48, 0x83, 0xc2,
            0x01, 0x48, 0xff, 0xc2, 0x0f, 0x31, 0xe8, 0xbd, 0x01, 0x00, 0x00, 0xe8, 0xda, 0x01, 0x00, 0x00, 0xff, 0xd6,
            0x74, 0x02, 0xeb, 0x00, 0xc3, 0x0f, 0x0b, 0xe9, 0xcc, 0x01, 0x00, 0x00, 0xff, 0xe6,
        ];
        data[..code.len()].copy_from_slice(code);
        let jt_fn: &[u8] = &[
            0x48, 0x8d, 0x0d, 0xf9, 0x01, 0x00, 0x00, // 0x1100: lea rcx, [rip + 0x1f9] -> 0x1300
            0x48, 0x63, 0x04, 0x89, // 0x1107: movsxd rax, dword ptr [rcx + rcx*4]
            0xff, 0xe0, // 0x110b: jmp rax
            0x48, 0x8b, 0x06, // 0x110d: mov rax, [rsi]
            0xb9, 0x01, 0x00, 0x00, 0x00, // 0x1110: mov ecx, 1
            0x48, 0x8d, 0x35, 0x04, 0x02, 0x00, 0x00, // 0x1115: lea rsi, [rip + 0x204] -> 0x1320 ("hello txt")
            0xba, 0x05, 0x00, 0x00, 0x00, // 0x111c: mov edx, 5
            0x49, 0x83, 0xc6, 0xff, // 0x1121: add r14, -1
            0xff, 0x15, 0xdf, 0x01, 0x00, 0x00, // 0x1125: call [rip + 0x1df] -> 0x130a (Import "puts")
            0xff, 0x15, 0xe1, 0x01, 0x00, 0x00, // 0x112b: call [rip + 0x1e1] -> 0x1312 (Pointer 0x1220)
            0x0f, 0x57, 0xc0, // 0x1131: xorps xmm0, xmm0
            0xf3, 0x48, 0x0f, 0xbc, 0xc7, // 0x1134: tzcnt rax, rdi
            0xc3, // 0x1139: ret
        ];
        data[0x100..0x100 + jt_fn.len()].copy_from_slice(jt_fn);
        let end1 = 0x1000 + code.len() as u64;
        let image = Image {
            data,
            segments: vec![Segment { va: 0x1000, offset: 0, size: 0x400 }],
            functions: vec![0x1000..end1, 0x1100..0x1100 + jt_fn.len() as u64, 0x1200..0x1206, 0x1220..0x1224],
            pointers: vec![(0x1312, 0x1220)],
            imports: vec![(0x1306, "puts".to_owned()), (0x130a, "puts".to_owned())],
            symbols: Vec::new(),
        };
        let mut out = Vec::new();
        assert!(c(&image, 0x1000, None, None, &mut out).is_ok());
        let text = String::from_utf8_lossy(&out);
        assert!(text.contains("r14 = rdi;") && text.contains("puts(") && text.contains("fn_1220("), "{text}");
        assert!(text.contains("unreachable();") && text.contains("return rsi(") && text.contains("rdtsc"), "{text}");
        let mut out2 = Vec::new();
        assert!(c(&image, 0x1100, None, None, &mut out2).is_ok());
        let text2 = String::from_utf8_lossy(&out2);
        assert!(text2.contains("switch (") && text2.contains("case 0 (0x0):"), "{text2}");
        assert!(
            text2.contains("rax = *(u64 *)(rsi);")
                && text2.contains("puts(\"hello\", 5, 1)")
                && text2.contains("r14 = (r14 - 1);")
                && text2.contains("zmm0 = 0;")
                && text2.contains("return __builtin_ctzll(rdi);"),
            "{text2}"
        );
        assert!(c(&image, 0x1000, Some(0x1000), Some(0x1010), &mut Vec::new()).is_ok());
        assert!(c(&image, 0x9999, None, None, &mut Vec::new()).is_err());
    }
}
