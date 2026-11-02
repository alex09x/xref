/*
 * xref — Ultra blazing fast cross-references of an x86-64 ELF binary
 * Copyright (c) 2026 Alexander Panasenko
 *
 * Contact: alex@prod.codes
 * Author: https://prod.codes/about/
 * SPDX-License-Identifier: MIT OR Apache-2.0
 */

//! Interprocedural function signatures: CFG-aware parameter liveness (`rdi`..`r9`), stack frame
//! caller arguments (`arg7`..), standard import arities and two-register `(rax, rdx)` returns.

use std::collections::BTreeSet;
use std::ops::Range;

use iced_x86::{FlowControl, Instruction, InstructionInfoFactory, Mnemonic, OpAccess, OpKind, Register};

use crate::expr::{ABI_ARGS, CALLEE_SAVED};
use crate::graph::call_target;
use crate::image::Image;
use crate::listing::is_call;
use crate::scan::{branch_target, decode, immediates};
use crate::tables::tables;

const ALL_ABI: u8 = 0b0011_1111;

pub struct FnSig {
    pub regs: Vec<Register>,
    pub stack_args: Vec<usize>,
    pub arg_base_rsp: Option<i64>,
    pub uses_fp: bool,
    pub exact: bool,
}

pub fn has_frame_pointer(bytes: &[u8], start: u64) -> bool {
    prologue_frame(bytes, start).0
}

fn prologue_frame(bytes: &[u8], start: u64) -> (bool, Option<i64>) {
    let (mut pushes, mut sub_rsp, mut uses_fp, mut in_pro) = (0i64, 0i64, false, true);
    decode(bytes, start, |ins| {
        if !in_pro {
            return;
        }
        let (m, dst) = (ins.mnemonic(), ins.op0_register().full_register());
        if matches!(m, Mnemonic::Endbr64 | Mnemonic::Nop) {
        } else if m == Mnemonic::Push
            && ins.op0_kind() == OpKind::Register
            && (CALLEE_SAVED.contains(&dst) || dst == Register::RAX)
        {
            pushes += 1;
        } else if m == Mnemonic::Mov && dst == Register::RBP && ins.op1_register().full_register() == Register::RSP {
            uses_fp = true;
        } else if m == Mnemonic::Sub
            && dst == Register::RSP
            && sub_rsp == 0
            && let Some(imm) = immediates(ins).next()
        {
            sub_rsp = imm.cast_signed();
            in_pro = false;
        } else {
            in_pro = false;
        }
    });
    let base = (!uses_fp && (pushes > 0 || sub_rsp > 0)).then_some(pushes * 8 + sub_rsp + 8);
    (uses_fp, base)
}

fn abi_bit(reg: Register) -> Option<u8> {
    ABI_ARGS.iter().position(|&r| r == reg).map(|idx| 1u8 << idx)
}

pub fn zero_idiom_reg(ins: &Instruction) -> Option<Register> {
    (matches!(ins.mnemonic(), Mnemonic::Xor | Mnemonic::Sub)
        && ins.op0_kind() == OpKind::Register
        && ins.op1_kind() == OpKind::Register
        && ins.op0_register() == ins.op1_register())
    .then(|| ins.op0_register().full_register())
}

fn caller_stack_slot(ins: &Instruction, uses_fp: bool, arg_base_rsp: Option<i64>) -> Option<usize> {
    if ins.is_ip_rel_memory_operand() || ins.memory_index() != Register::None {
        return None;
    }
    let (disp, base) = (ins.memory_displacement64().cast_signed(), ins.memory_base().full_register());
    let idx = if uses_fp && base == Register::RBP && disp >= 0x10 && (disp - 0x10) % 8 == 0 {
        (disp - 0x10) / 8
    } else if let Some(ab) = arg_base_rsp
        && base == Register::RSP
        && disp >= ab
        && (disp - ab) % 8 == 0
    {
        (disp - ab) / 8
    } else {
        return None;
    };
    usize::try_from(idx).ok().filter(|&k| k < 8)
}

fn propagate_live_mask(gen_read: &[u8], kill_write: &[u8], succs: &[Vec<usize>]) -> u8 {
    let n = gen_read.len();
    let (mut in_written, mut reachable) = (vec![ALL_ABI; n], vec![false; n]);
    if n > 0 {
        (in_written[0], reachable[0]) = (0, true);
    }
    let mut changed = true;
    while changed {
        changed = false;
        for b in 0..n {
            if !reachable[b] {
                continue;
            }
            let out_w = in_written[b] | kill_write[b];
            for &s in &succs[b] {
                let next_in = if reachable[s] { in_written[s] & out_w } else { out_w };
                if !reachable[s] || next_in != in_written[s] {
                    (reachable[s], in_written[s], changed) = (true, next_in, true);
                }
            }
        }
    }
    (0..n).filter(|&b| reachable[b]).fold(0u8, |acc, b| acc | (gen_read[b] & !in_written[b]))
}

fn step_abi_rw(factory: &mut InstructionInfoFactory, ins: &Instruction, w: &mut u8, r: &mut u8) {
    if let Some(bit) = zero_idiom_reg(ins).and_then(abi_bit) {
        *w |= bit;
        return;
    }
    let (mut ir, mut iw) = (0u8, 0u8);
    for u in factory.info(ins).used_registers() {
        if let Some(bit) = abi_bit(u.register().full_register()) {
            if matches!(u.access(), OpAccess::Read | OpAccess::CondRead | OpAccess::ReadWrite | OpAccess::ReadCondWrite)
            {
                ir |= bit;
            }
            if matches!(
                u.access(),
                OpAccess::Write | OpAccess::CondWrite | OpAccess::ReadWrite | OpAccess::ReadCondWrite
            ) {
                iw |= bit;
            }
        }
    }
    *r |= ir & !*w;
    *w |= iw;
}

fn callee_abi_mask(image: &Image, self_start: u64, ct: u64, depth: usize) -> (u8, bool) {
    if ct == self_start {
        return (0, true);
    }
    if let Some(tf) = image.function_at(ct).filter(|tf| tf.start == ct) {
        let sub = fn_sig_depth(image, &tf, depth + 1);
        let mask = sub.regs.into_iter().filter_map(abi_bit).fold(0u8, |a, b| a | b);
        return (mask, sub.exact);
    }
    crate::runtime::plt_import(image, ct).and_then(import_arity).map_or((0, false), |arity| ((1u8 << arity) - 1, true))
}

pub fn fn_sig(image: &Image, function: &Range<u64>) -> FnSig {
    fn_sig_depth(image, function, 0)
}

fn fn_sig_depth(image: &Image, function: &Range<u64>, depth: usize) -> FnSig {
    let Some(bytes) = image.code(function) else {
        return FnSig { regs: Vec::new(), stack_args: Vec::new(), arg_base_rsp: None, uses_fp: false, exact: false };
    };
    let (uses_fp, arg_base_rsp) = prologue_frame(bytes, function.start);
    let jt = tables(image, function);
    let mut leaders: BTreeSet<u64> = jt.iter().flat_map(|t| t.arms.iter().copied()).collect();
    leaders.insert(function.start);
    let mut insns = Vec::new();
    decode(bytes, function.start, |ins| {
        if let Some(t) = branch_target(ins).filter(|t| function.contains(t)) {
            leaders.insert(t);
        }
        if !matches!(ins.flow_control(), FlowControl::Next | FlowControl::Call | FlowControl::IndirectCall) {
            let nx = ins.next_ip();
            if function.contains(&nx) {
                leaders.insert(nx);
            }
        }
        insns.push(*ins);
    });

    let starts: Vec<u64> = leaders.into_iter().collect();
    let idx_of = |addr: u64| starts.binary_search(&addr).ok();
    let n = starts.len();
    let mut factory = InstructionInfoFactory::new();
    let (mut gen_read, mut kill_write) = (vec![0u8; n], vec![0u8; n]);
    let mut succs: Vec<Vec<usize>> = vec![Vec::new(); n];
    let mut calls: Vec<(usize, Option<u64>, u8)> = Vec::new();
    let mut exact = true;
    let (mut stack_written, mut stack_args) = (BTreeSet::new(), BTreeSet::new());

    for (b, &b_start) in starts.iter().enumerate() {
        let b_end = starts.get(b + 1).copied().unwrap_or(function.end);
        let (mut w, mut r) = (0u8, 0u8);
        for ins in insns.iter().filter(|i| i.ip() >= b_start && i.ip() < b_end) {
            if let Some(k) = caller_stack_slot(ins, uses_fp, arg_base_rsp) {
                if ins.op0_kind() == OpKind::Memory && ins.mnemonic() != Mnemonic::Cmp {
                    stack_written.insert(k);
                } else if !stack_written.contains(&k) && ins.mnemonic() != Mnemonic::Lea {
                    stack_args.insert(k);
                }
            }
            step_abi_rw(&mut factory, ins, &mut w, &mut r);
            match ins.flow_control() {
                FlowControl::Call | FlowControl::IndirectCall => {
                    if w != ALL_ABI {
                        calls.push((b, call_target(image, ins), w));
                    }
                    w = ALL_ABI;
                }
                FlowControl::ConditionalBranch => {
                    succs[b].extend(branch_target(ins).and_then(idx_of));
                    succs[b].extend((b + 1 < n).then_some(b + 1));
                }
                FlowControl::UnconditionalBranch | FlowControl::IndirectBranch => {
                    if let Some(tbl) = jt.iter().find(|t| t.dispatch <= ins.ip() && ins.ip() - t.dispatch <= 32) {
                        succs[b].extend(tbl.arms.iter().filter_map(|&arm| idx_of(arm)));
                    } else if is_call(ins, function) || ins.flow_control() == FlowControl::IndirectBranch {
                        if w != ALL_ABI {
                            calls.push((b, call_target(image, ins), w));
                        }
                    } else {
                        succs[b].extend(branch_target(ins).and_then(idx_of));
                    }
                }
                _ => {}
            }
        }
        if b + 1 < n
            && insns.iter().rev().find(|i| i.ip() >= b_start && i.ip() < b_end).is_some_and(|l| {
                matches!(l.flow_control(), FlowControl::Next | FlowControl::Call | FlowControl::IndirectCall)
            })
        {
            succs[b].push(b + 1);
        }
        (gen_read[b], kill_write[b]) = (r, w);
    }

    for &(b, ct, w_mask) in &calls {
        if let Some(ct) = ct {
            if depth < 2 {
                let (sub_mask, sub_exact) = callee_abi_mask(image, function.start, ct, depth);
                gen_read[b] |= sub_mask & !w_mask;
                exact &= sub_exact;
            }
        } else {
            exact = false;
        }
    }
    let mut live_mask = propagate_live_mask(&gen_read, &kill_write, &succs);
    if let Some(max_k) = (0..6).rfind(|&k| (live_mask & (1 << k)) != 0).filter(|&k| k > 0) {
        let prefix_mask = (1u8 << max_k) - 1;
        for &(b, ct, w_mask) in &calls {
            if ct.is_none() {
                gen_read[b] |= prefix_mask & !w_mask;
            }
        }
        live_mask = propagate_live_mask(&gen_read, &kill_write, &succs);
    }
    let regs = ABI_ARGS.into_iter().filter(|&r| abi_bit(r).is_some_and(|b| (live_mask & b) != 0)).collect();
    FnSig { regs, stack_args: stack_args.into_iter().collect(), arg_base_rsp, uses_fp, exact }
}

pub fn import_arity(raw_name: &str) -> Option<usize> {
    let name = raw_name.split('@').next().unwrap_or(raw_name);
    match name {
        "abort" | "__errno_location" | "sched_yield" | "getpid" | "gettid" => Some(0),
        "strlen" | "free" | "malloc" | "close" | "_Unwind_Resume" => Some(1),
        "calloc" | "realloc" | "strcmp" | "strstr" | "stat" | "fstat" | "clock_gettime" | "munmap" => Some(2),
        "memcpy" | "memmove" | "memset" | "memcmp" | "bcmp" | "strncmp" | "read" | "write" | "mprotect" => Some(3),
        _ => None,
    }
}

fn slice_reads_reg(bytes: &[u8], start_ip: u64, limit: usize, reg: Register) -> (bool, Option<u64>) {
    let mut factory = InstructionInfoFactory::new();
    let (mut count, mut stopped, mut found_read, mut first_cond) = (0usize, false, false, None);
    decode(bytes, start_ip, |ins| {
        if stopped || count >= limit {
            stopped = true;
            return;
        }
        count += 1;
        if zero_idiom_reg(ins) == Some(reg) {
            stopped = true;
            return;
        }
        for u in factory.info(ins).used_registers() {
            if u.register().full_register() == reg {
                let acc = u.access();
                found_read =
                    matches!(acc, OpAccess::Read | OpAccess::CondRead | OpAccess::ReadWrite | OpAccess::ReadCondWrite);
                stopped = true;
                return;
            }
        }
        match ins.flow_control() {
            FlowControl::ConditionalBranch if first_cond.is_none() => first_cond = branch_target(ins),
            FlowControl::Next | FlowControl::ConditionalBranch => {}
            _ => stopped = true,
        }
    });
    (found_read, first_cond)
}

/// Whether code immediately following `after_ip` inside `function` reads `reg` before overwriting it.
pub fn call_reads_reg(image: &Image, function: &Range<u64>, after_ip: u64, reg: Register) -> bool {
    let Some(bytes) = (after_ip < function.end)
        .then(|| image.read(after_ip, usize::try_from(function.end - after_ip).unwrap_or(0)))
        .flatten()
    else {
        return false;
    };
    let (read_fall, cond_target) = slice_reads_reg(bytes, after_ip, 12, reg);
    read_fall
        || cond_target
            .filter(|t| function.contains(t))
            .and_then(|t| Some((t, image.read(t, usize::try_from(function.end - t).unwrap_or(0))?)))
            .is_some_and(|(t, tbytes)| slice_reads_reg(tbytes, t, 8, reg).0)
}

pub fn call_reads_rdx(image: &Image, function: &Range<u64>, after_ip: u64) -> bool {
    call_reads_reg(image, function, after_ip, Register::RDX)
}

#[cfg(test)]
mod tests {
    use super::{call_reads_rdx, fn_sig, has_frame_pointer, import_arity};
    use crate::image::{Image, Segment};
    use iced_x86::Register;

    #[test]
    fn recovers_branched_params_stack_args_thunks_imports_and_rdx_returns() {
        let mut data = vec![0u8; 0x500];
        let f1: &[u8] = &[
            0xf3, 0x0f, 0x1e, 0xfa, 0x53, 0x48, 0x83, 0xec, 0x10, 0x31, 0xc0, 0x83, 0xff, 0x01, 0x74, 0x09, 0x48, 0x8b,
            0x44, 0x24, 0x20, 0x48, 0x01, 0xf0, 0xc3, 0x48, 0x89, 0xd0, 0xe9, 0xdf, 0x00, 0x00, 0x00,
        ];
        data[..f1.len()].copy_from_slice(f1);
        let f2: &[u8] =
            &[0x55, 0x48, 0x89, 0xe5, 0x48, 0x8b, 0x45, 0x10, 0x48, 0x01, 0xc8, 0x5d, 0xe9, 0xef, 0x01, 0x00, 0x00];
        data[0x100..0x100 + f2.len()].copy_from_slice(f2);
        let f3: &[u8] = &[0xa8, 0x01, 0x75, 0x04, 0x48, 0x89, 0xfa, 0xc3, 0x48, 0x39, 0xf2, 0xc3];
        data[0x200..0x200 + f3.len()].copy_from_slice(f3);
        data[0x240..0x243].copy_from_slice(&[0x31, 0xd2, 0xc3]);
        data[0x300..0x306].copy_from_slice(&[0xff, 0x25, 0xfa, 0x00, 0x00, 0x00]);
        data[0x320..0x322].copy_from_slice(&[0xff, 0xe0]);
        data[0x340..0x342].copy_from_slice(&[0xeb, 0x3e]);
        // 0x1360: push rbp; mov rbp, rsp; call 0x1300 (plt memcpy, 3 args); ud2 -> noreturn wrapper!
        let f_wrap: &[u8] = &[0x55, 0x48, 0x89, 0xe5, 0xe8, 0x97, 0xff, 0xff, 0xff, 0x0f, 0x0b];
        data[0x360..0x360 + f_wrap.len()].copy_from_slice(f_wrap);

        let r1 = 0x1000..0x1000 + f1.len() as u64;
        let r2 = 0x1100..0x1100 + f2.len() as u64;
        let r3 = 0x1200..0x1200 + f3.len() as u64;
        let rw = 0x1360..0x1360 + f_wrap.len() as u64;
        let image = Image {
            data,
            segments: vec![Segment { va: 0x1000, offset: 0, size: 0x500 }],
            functions: vec![
                r1.clone(),
                r2.clone(),
                r3.clone(),
                0x1240..0x1243,
                0x1320..0x1322,
                0x1340..0x1342,
                rw.clone(),
            ],
            pointers: Vec::new(),
            imports: vec![(0x1400, "memcpy".to_owned())],
            symbols: Vec::new(),
        };
        let (s1, s2, sw) = (fn_sig(&image, &r1), fn_sig(&image, &r2), fn_sig(&image, &rw));
        let four = vec![Register::RDI, Register::RSI, Register::RDX, Register::RCX];
        assert_eq!((&s1.regs, &s1.stack_args, s1.arg_base_rsp), (&four, &vec![0], Some(0x20)));
        assert!(s1.exact && !s1.uses_fp && s2.uses_fp && has_frame_pointer(f2, 0x1100));
        assert_eq!((&s2.regs, &s2.stack_args), (&four, &vec![0]));
        assert_eq!((sw.regs, sw.exact), (vec![Register::RDI, Register::RSI, Register::RDX], true));
        assert!(!fn_sig(&image, &(0x1320..0x1322)).exact);
        assert!(!fn_sig(&image, &(0x1340..0x1342)).exact);
        assert!(!fn_sig(&image, &(0x9000..0x9010)).exact);
        assert_eq!(import_arity("memcpy@GLIBC_2.14"), Some(3));
        assert_eq!((import_arity("free"), import_arity("calloc")), (Some(1), Some(2)));
        assert_eq!((import_arity("abort"), import_arity("custom_sym")), (Some(0), None));
        assert!(call_reads_rdx(&image, &r3, 0x1208) && call_reads_rdx(&image, &r3, 0x1200));
        assert!(!call_reads_rdx(&image, &r3, 0x1204) && !call_reads_rdx(&image, &(0x1240..0x1243), 0x1240));
        assert!(!call_reads_rdx(&image, &(0x1240..0x1243), 0x1243));
    }
}
