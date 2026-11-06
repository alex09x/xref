/*
 * xref — Ultra blazing fast cross-references of an x86-64 ELF binary
 * Copyright (c) 2026 Alexander Panasenko
 *
 * Contact: alex@prod.codes
 * Author: https://prod.codes/about/
 * SPDX-License-Identifier: MIT OR Apache-2.0
 */

//! Interprocedural function signatures: CFG-aware parameter liveness (`rdi`..`r9`, `xmm0`..`xmm7`),
//! stack frame caller arguments (`arg7`..), standard import arities, two-register `(rax, rdx)`
//! returns and scalar floating-point returns in `xmm0`.

use std::collections::{BTreeSet, HashMap};
use std::ops::Range;

use iced_x86::{FlowControl, Instruction, InstructionInfoFactory, Mnemonic, OpAccess, OpKind, Register};

use crate::expr::{ABI_ARGS, CALLEE_SAVED};
use crate::graph::call_target;
use crate::image::Image;
use crate::listing::is_call;
use crate::scan::{branch_target, decode, immediates};
use crate::tables::tables;

mod float_ret;
mod reads;
pub mod xmm;
pub use reads::call_reads_rdx;
#[cfg(test)]
pub use reads::call_reads_reg;
pub use xmm::{FloatParam, FloatRet};

const ALL_ABI: u8 = 0b0011_1111;
const ALL_XMM: u8 = 0xff;

pub struct FnSig {
    pub regs: Vec<Register>,
    pub stack_args: Vec<usize>,
    pub arg_base_rsp: Option<i64>,
    pub uses_fp: bool,
    pub exact: bool,
    /// `xmm0`..`xmm7` read before written, in register order.
    pub float_params: Vec<FloatParam>,
    /// Scalar floating-point value in `xmm0` on every return path.
    pub float_ret: Option<FloatRet>,
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

/// Per reachable block, the registers of `gen_read` not written on every path from the entry.
fn exposed_reads(gen_read: &[u8], kill_write: &[u8], succs: &[Vec<usize>], all: u8) -> Vec<u8> {
    let n = gen_read.len();
    let (mut in_written, mut reachable) = (vec![all; n], vec![false; n]);
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
    (0..n).map(|b| if reachable[b] { gen_read[b] & !in_written[b] } else { 0 }).collect()
}

fn propagate_live_mask(gen_read: &[u8], kill_write: &[u8], succs: &[Vec<usize>]) -> u8 {
    exposed_reads(gen_read, kill_write, succs, ALL_ABI).into_iter().fold(0u8, |acc, e| acc | e)
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

struct Callee {
    mask: u8,
    exact: bool,
    floats: Vec<FloatParam>,
    float_ret: Option<&'static str>,
}

fn import_floats(image: &Image, ct: u64) -> (Vec<FloatParam>, Option<&'static str>) {
    crate::runtime::plt_import(image, ct).and_then(xmm::import_float_sig).map_or_else(
        || (Vec::new(), None),
        |(n, ty)| ((0..n).map(|index| FloatParam { index, ty }).collect(), Some(ty)),
    )
}

fn callee_info(image: &Image, self_start: u64, ct: u64, depth: usize) -> Callee {
    if ct == self_start {
        return Callee { mask: 0, exact: true, floats: Vec::new(), float_ret: None };
    }
    let (floats, float_ret) = import_floats(image, ct);
    if let Some(tf) = image.function_at(ct).filter(|tf| tf.start == ct) {
        let sub = fn_sig_depth(image, &tf, depth + 1);
        let mask = sub.regs.into_iter().filter_map(abi_bit).fold(0u8, |a, b| a | b);
        if floats.is_empty() {
            let float_ret = sub.float_ret.filter(|r| !r.rax_written).map(|r| r.ty);
            return Callee { mask, exact: sub.exact, floats: sub.float_params, float_ret };
        }
        return Callee { mask, exact: sub.exact, floats, float_ret };
    }
    let (mask, exact) = crate::runtime::plt_import(image, ct)
        .and_then(import_arity)
        .map_or((0, false), |arity| ((1u8 << arity) - 1, true));
    Callee { mask, exact, floats, float_ret }
}

/// Float parameters and float return type of a direct call target, as its own signature shows them.
pub fn callee_float_abi(image: &Image, target: u64) -> (Vec<FloatParam>, Option<&'static str>) {
    let imported = import_floats(image, target);
    if !imported.0.is_empty() {
        return imported;
    }
    if let Some(f) = image.function_at(target).filter(|f| f.start == target) {
        let sig = fn_sig(image, &f);
        return (sig.float_params, sig.float_ret.filter(|r| !r.rax_written).map(|r| r.ty));
    }
    imported
}

pub fn fn_sig(image: &Image, function: &Range<u64>) -> FnSig {
    fn_sig_depth(image, function, 0)
}

#[allow(clippy::too_many_lines)] // One CFG walk feeds both the integer and the SSE liveness.
fn fn_sig_depth(image: &Image, function: &Range<u64>, depth: usize) -> FnSig {
    let Some(bytes) = image.code(function) else {
        return FnSig {
            regs: Vec::new(),
            stack_args: Vec::new(),
            arg_base_rsp: None,
            uses_fp: false,
            exact: false,
            float_params: Vec::new(),
            float_ret: None,
        };
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
    let mut xblocks = vec![xmm::XmmBlock::default(); n];
    let mut succs: Vec<Vec<usize>> = vec![Vec::new(); n];
    // (block, target, written ABI GPRs, written xmm0..7, call ip)
    let mut calls: Vec<(usize, Option<u64>, u8, u8, u64)> = Vec::new();
    let (mut exact, mut has_tail) = (true, false);
    let (mut stack_written, mut stack_args) = (BTreeSet::new(), BTreeSet::new());

    for (b, &b_start) in starts.iter().enumerate() {
        let b_end = starts.get(b + 1).copied().unwrap_or(function.end);
        let (mut w, mut r) = (0u8, 0u8);
        let xb = &mut xblocks[b];
        for ins in insns.iter().filter(|i| i.ip() >= b_start && i.ip() < b_end) {
            if let Some(k) = caller_stack_slot(ins, uses_fp, arg_base_rsp) {
                if ins.op0_kind() == OpKind::Memory && ins.mnemonic() != Mnemonic::Cmp {
                    stack_written.insert(k);
                } else if !stack_written.contains(&k) && ins.mnemonic() != Mnemonic::Lea {
                    stack_args.insert(k);
                }
            }
            step_abi_rw(&mut factory, ins, &mut w, &mut r);
            xb.step(&mut factory, ins);
            match ins.flow_control() {
                FlowControl::Call | FlowControl::IndirectCall => {
                    calls.push((b, call_target(image, ins), w, xb.written, ins.ip()));
                    (w, xb.written) = (ALL_ABI, ALL_XMM);
                }
                FlowControl::ConditionalBranch => {
                    succs[b].extend(branch_target(ins).and_then(idx_of));
                    succs[b].extend((b + 1 < n).then_some(b + 1));
                }
                FlowControl::UnconditionalBranch | FlowControl::IndirectBranch => {
                    if let Some(tbl) = jt.iter().find(|t| t.dispatch <= ins.ip() && ins.ip() - t.dispatch <= 32) {
                        succs[b].extend(tbl.arms.iter().filter_map(|&arm| idx_of(arm)));
                    } else if is_call(ins, function) || ins.flow_control() == FlowControl::IndirectBranch {
                        calls.push((b, call_target(image, ins), w, xb.written, ins.ip()));
                        has_tail = true;
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

    let mut call_rets: HashMap<u64, &'static str> = HashMap::new();
    for &(b, ct, w_mask, x_mask, ip) in &calls {
        if let Some(ct) = ct {
            if depth < 2 {
                let callee = callee_info(image, function.start, ct, depth);
                if w_mask != ALL_ABI {
                    gen_read[b] |= callee.mask & !w_mask;
                    exact &= callee.exact;
                }
                let fmask = callee.floats.iter().fold(0u8, |m, p| m | (1 << p.index));
                let ty_of = |i: u8| callee.floats.iter().find(|p| p.index == i).map_or(xmm::F64, |p| p.ty);
                xblocks[b].use_regs(fmask, x_mask, ip, ty_of);
                if let Some(ty) = callee.float_ret {
                    call_rets.insert(ip, ty);
                }
            }
        } else if w_mask != ALL_ABI {
            exact = false;
        }
    }
    let mut live_mask = propagate_live_mask(&gen_read, &kill_write, &succs);
    if let Some(max_k) = (0..6).rfind(|&k| (live_mask & (1 << k)) != 0).filter(|&k| k > 0) {
        let prefix_mask = (1u8 << max_k) - 1;
        for &(b, ct, w_mask, _, _) in &calls {
            if ct.is_none() {
                gen_read[b] |= prefix_mask & !w_mask;
            }
        }
        live_mask = propagate_live_mask(&gen_read, &kill_write, &succs);
    }
    let regs = ABI_ARGS.into_iter().filter(|&r| abi_bit(r).is_some_and(|b| (live_mask & b) != 0)).collect();

    let xgen: Vec<u8> = xblocks.iter().map(|x| x.read).collect();
    let xkill: Vec<u8> = xblocks.iter().map(|x| x.written).collect();
    let xexposed = exposed_reads(&xgen, &xkill, &succs, ALL_XMM);
    let float_params = xmm::float_params(&xblocks, &xexposed, xexposed.iter().fold(0u8, |a, e| a | e));
    let float_ret = float_ret::RetScan {
        insns: &insns,
        function,
        starts: &starts,
        succs: &succs,
        params: &float_params,
        call_ret: &|ip| call_rets.get(&ip).copied(),
        has_tail,
    }
    .run();
    FnSig { regs, stack_args: stack_args.into_iter().collect(), arg_base_rsp, uses_fp, exact, float_params, float_ret }
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

#[cfg(test)]
mod tests;
#[cfg(test)]
mod xmm_tests;
