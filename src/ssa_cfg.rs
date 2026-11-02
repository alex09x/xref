/*
 * xref — Ultra blazing fast cross-references of an x86-64 ELF binary
 * Copyright (c) 2026 Alexander Panasenko
 *
 * Contact: alex@prod.codes
 * Author: https://prod.codes/about/
 * Project: https://github.com/alex09x/xref
 * SPDX-License-Identifier: MIT OR Apache-2.0
 */

//! Machine-level CFG & GPR liveness foundation (`SsaGraph`) for intra-procedural Def-Use Webs.

use std::collections::BTreeSet;
use std::ops::Range;

use iced_x86::{ConditionCode, FlowControl, Instruction, InstructionInfoFactory, Mnemonic, OpAccess, OpKind, Register};

use crate::caller_ret::CallerRetStats;
use crate::expr::{ABI_ARGS, CALLEE_SAVED, IGNORED};
use crate::graph::call_target;
use crate::image::{Image, Slot};
use crate::listing::is_call;
use crate::runtime::{RuntimeFn, RuntimeMap};
use crate::scan::{branch_target, decode};
use crate::sig::{FnSig, call_reads_rdx, fn_sig, import_arity, zero_idiom_reg};
use crate::tables::Table;

pub const GPRS: [Register; 15] = [
    Register::RAX,
    Register::RCX,
    Register::RDX,
    Register::RBX,
    Register::RBP,
    Register::RSI,
    Register::RDI,
    Register::R8,
    Register::R9,
    Register::R10,
    Register::R11,
    Register::R12,
    Register::R13,
    Register::R14,
    Register::R15,
];

pub const SCRATCH_MASK: u16 =
    (1 << 0) | (1 << 1) | (1 << 2) | (1 << 5) | (1 << 6) | (1 << 7) | (1 << 8) | (1 << 9) | (1 << 10);

pub fn gpr_idx(reg: Register) -> Option<usize> {
    let full = reg.full_register();
    GPRS.iter().position(|&r| r == full)
}

#[derive(Clone, Copy, Default)]
pub struct RawRw {
    pub reads: u16,
    pub writes: u16,
    pub clobbers: u16,
    pub read_bytes: [u8; 15],
    pub write_bytes: u8,
    pub is_zero: bool,
    pub mem_rw: (bool, bool),
    pub flag_rw: (bool, bool),
    pub is_frame_skip: bool,
}

pub struct SsaGraph {
    pub insns: Vec<Instruction>,
    pub rws: Vec<RawRw>,
    pub block_of: Vec<usize>,
    pub block_ranges: Vec<Range<usize>>,
    pub succs: Vec<Vec<usize>>,
    pub live_out: Vec<u16>,
    pub call_arg_regs: Vec<Vec<Register>>,
    pub call_rdx_used: Vec<bool>,
    pub rdx_returned: bool,
}

fn resolve_call_regs(
    image: &Image,
    runtime: &RuntimeMap,
    sig: &FnSig,
    ins: &Instruction,
    (active_abi, killed_abi, unreferenced_abi): (u8, u8, u8),
) -> Vec<Register> {
    let ct = call_target(image, ins);
    let rt_arity = ct.and_then(|t| runtime.get(t)).and_then(RuntimeFn::arity);
    let imp_name = ct.and_then(|t| runtime.label(image, t)).or_else(|| {
        ins.is_ip_rel_memory_operand()
            .then(|| match image.slot(ins.ip_rel_memory_address()) {
                Some(Slot::Import(n)) => Some(n),
                _ => None,
            })
            .flatten()
    });
    if let Some(arity) = rt_arity.or_else(|| imp_name.and_then(import_arity)) {
        return ABI_ARGS[..arity].to_vec();
    }
    if let Some(cf) = ct.and_then(|t| image.function_at(t).filter(|f| f.start == t)) {
        let csig = fn_sig(image, &cf);
        if csig.exact {
            return csig.regs;
        }
        return ABI_ARGS
            .into_iter()
            .enumerate()
            .filter(|&(i, r)| (active_abi & (1 << i)) != 0 || csig.regs.contains(&r))
            .map(|(_, r)| r)
            .collect();
    }
    let callee_reg = (ins.op0_kind() == OpKind::Register).then(|| ins.op0_register().full_register());
    let target_reg =
        callee_reg.or_else(|| (ins.op0_kind() == OpKind::Memory).then(|| ins.memory_base().full_register()));
    let target_abi_idx =
        target_reg.and_then(|tr| ABI_ARGS.iter().position(|&r| r == tr)).filter(|&k| (killed_abi & (1 << k)) == 0);
    ABI_ARGS
        .into_iter()
        .enumerate()
        .filter(|&(i, r)| {
            Some(r) != callee_reg
                && ((active_abi & (1 << i)) != 0
                    || (sig.regs.contains(&r)
                        && (killed_abi & (1 << i)) == 0
                        && Some(r) != target_reg
                        && (target_abi_idx.is_some_and(|tk| i < tk) || (unreferenced_abi & (1 << i)) != 0)))
        })
        .map(|(_, r)| r)
        .collect()
}

fn classify_rw(factory: &mut InstructionInfoFactory, ins: &Instruction, in_pro: &mut bool, uses_fp: bool) -> RawRw {
    let (m, dst) = (ins.mnemonic(), ins.op0_register().full_register());
    let is_pro_push = m == Mnemonic::Push
        && *in_pro
        && ins.op0_kind() == OpKind::Register
        && (CALLEE_SAVED.contains(&dst) || dst == Register::RAX);
    let is_sp_adj = m == Mnemonic::Pop || (matches!(m, Mnemonic::Add | Mnemonic::Sub) && dst == Register::RSP);
    if IGNORED.contains(&m)
        || (m == Mnemonic::Mov && dst == Register::RBP && ins.op1_register().full_register() == Register::RSP)
        || is_pro_push
        || is_sp_adj
    {
        *in_pro &= !is_sp_adj;
        return RawRw { is_frame_skip: true, ..RawRw::default() };
    }
    *in_pro = false;
    if let Some(zr) = zero_idiom_reg(ins)
        && let Some(g) = gpr_idx(zr)
    {
        return RawRw { writes: 1 << g, write_bytes: 8, is_zero: true, flag_rw: (false, true), ..RawRw::default() };
    }
    let reads_cf = ins.condition_code() != ConditionCode::None || matches!(m, Mnemonic::Sbb | Mnemonic::Adc);
    let keeps_flags = crate::expr::MOVES.contains(&m)
        || [Mnemonic::Push, Mnemonic::Cqo, Mnemonic::Cdq, Mnemonic::Cdqe, Mnemonic::Cwde, Mnemonic::Cbw, Mnemonic::Cwd]
            .contains(&m);
    let mut out =
        RawRw { flag_rw: (reads_cf, !keeps_flags && ins.condition_code() == ConditionCode::None), ..RawRw::default() };
    for u in factory.info(ins).used_registers() {
        let r = u.register();
        if uses_fp && r.full_register() == Register::RBP {
            continue;
        }
        let Some(g) = gpr_idx(r) else { continue };
        let sz = u8::try_from(r.size()).unwrap_or(8);
        let acc = u.access();
        if matches!(
            acc,
            OpAccess::Read | OpAccess::CondRead | OpAccess::ReadWrite | OpAccess::ReadCondWrite | OpAccess::CondWrite
        ) {
            out.reads |= 1 << g;
            out.read_bytes[g] = out.read_bytes[g].max(sz);
        }
        if matches!(acc, OpAccess::Write | OpAccess::CondWrite | OpAccess::ReadWrite | OpAccess::ReadCondWrite) {
            out.writes |= 1 << g;
            out.write_bytes = out.write_bytes.max(sz);
        }
    }
    if m == Mnemonic::Cbw
        || (matches!(m, Mnemonic::Div | Mnemonic::Idiv) && ins.op_count() == 1 && out.write_bytes == 1)
    {
        (out.reads, out.read_bytes[0], out.writes, out.write_bytes) =
            (out.reads | 1, out.read_bytes[0].max(1), out.writes | 1, 2);
    }
    out.is_zero =
        m == Mnemonic::Mov && ins.op0_kind() == OpKind::Register && crate::scan::immediates(ins).next() == Some(0);
    let has_mem = (0..ins.op_count()).any(|k| ins.op_kind(k) == OpKind::Memory);
    let writes_mem = ins.op0_kind() == OpKind::Memory && !matches!(m, Mnemonic::Cmp | Mnemonic::Test | Mnemonic::Lea);
    let reads_mem =
        has_mem && m != Mnemonic::Lea && (!writes_mem || (ins.op_count() > 1 && ins.op1_kind() == OpKind::Memory));
    out.mem_rw = (reads_mem, writes_mem);
    out
}

impl SsaGraph {
    pub fn build(
        image: &Image,
        runtime: &RuntimeMap,
        function: &Range<u64>,
        sig: &FnSig,
        jt: &[Table],
        caller_st: CallerRetStats,
        rax_unused: bool,
    ) -> Option<Self> {
        let bytes = image.code(function)?;
        let mut leaders: BTreeSet<u64> = jt.iter().flat_map(|t| t.arms.iter().copied()).collect();
        leaders.insert(function.start);
        let mut insns = Vec::new();
        decode(bytes, function.start, |ins| {
            if let Some(t) = branch_target(ins).filter(|t| function.contains(t)) {
                leaders.insert(t);
            }
            let nr_call = matches!(ins.flow_control(), FlowControl::Call | FlowControl::IndirectCall)
                && call_target(image, ins).is_some_and(|ct| crate::callee_meta::is_target_noreturn(image, runtime, ct));
            if nr_call
                || !matches!(ins.flow_control(), FlowControl::Next | FlowControl::Call | FlowControl::IndirectCall)
            {
                let nx = ins.next_ip();
                if function.contains(&nx) {
                    leaders.insert(nx);
                }
            }
            insns.push(*ins);
        });
        let starts: Vec<u64> = leaders.into_iter().collect();
        let b_cnt = starts.len();
        let mut block_of = vec![0usize; insns.len()];
        let mut block_ranges: Vec<Range<usize>> = vec![0..0; b_cnt];
        let mut rws = Vec::with_capacity(insns.len());
        let (mut factory, mut in_pro) = (InstructionInfoFactory::new(), true);
        for (i, ins) in insns.iter().enumerate() {
            let b = starts.partition_point(|&s| s <= ins.ip()).saturating_sub(1);
            block_of[i] = b;
            if block_ranges[b].is_empty() && (i == 0 || block_of[i - 1] != b) {
                block_ranges[b] = i..i + 1;
            } else {
                block_ranges[b].end = i + 1;
            }
            rws.push(classify_rw(&mut factory, ins, &mut in_pro, sig.uses_fp));
        }
        let rdx_returned = if caller_st.direct_callers > 0 {
            caller_st.rdx_readers > 0
        } else {
            block_ranges.iter().any(|rng| {
                insns.get(rng.end.saturating_sub(1)).is_some_and(|l| l.flow_control() == FlowControl::Return)
                    && rng.clone().any(|i| {
                        (rws[i].writes & (1 << 2)) != 0
                            && !rws[i].is_zero
                            && !matches!(insns[i].flow_control(), FlowControl::Call | FlowControl::IndirectCall)
                            && (i + 1..rng.end).all(|k| {
                                (rws[k].reads & (1 << 2)) == 0
                                    && (rws[k].writes & (1 << 2)) == 0
                                    && !matches!(insns[k].flow_control(), FlowControl::Call | FlowControl::IndirectCall)
                            })
                    })
            })
        };
        let n_ins = insns.len();
        let mut graph = Self {
            insns,
            rws,
            block_of,
            block_ranges,
            succs: vec![Vec::new(); b_cnt],
            live_out: Vec::new(),
            call_arg_regs: vec![Vec::new(); n_ins],
            call_rdx_used: vec![false; n_ins],
            rdx_returned,
        };
        let ret_info = (rax_unused, caller_st.ret_rax_bytes());
        graph.wire_calls_and_succs((image, runtime), function, sig, jt, &starts, ret_info);
        graph.live_out = compute_liveness(&graph.rws, &graph.block_ranges, &graph.succs);
        Some(graph)
    }

    fn wire_calls_and_succs(
        &mut self,
        (image, runtime): (&Image, &RuntimeMap),
        function: &Range<u64>,
        sig: &FnSig,
        jt: &[Table],
        starts: &[u64],
        (rax_unused, ret_rax_bytes): (bool, u8),
    ) {
        let b_cnt = starts.len();
        let idx_of = |addr: u64| starts.binary_search(&addr).ok();
        let unreferenced_abi = ABI_ARGS.iter().enumerate().fold(0u8, |acc, (ak, &areg)| {
            acc | u8::from(gpr_idx(areg).is_some_and(|g| self.rws.iter().all(|rw| (rw.reads & (1 << g)) == 0))) << ak
        });
        let (mut in_active, mut in_killed) = (vec![0u8; b_cnt], vec![0u8; b_cnt]);
        let (mut first_pass, mut changed) = (true, true);
        while changed {
            changed = false;
            for (b, rng) in self.block_ranges.iter().enumerate() {
                let (mut active_abi, mut killed_abi) = (in_active[b], in_killed[b]);
                for i in rng.clone() {
                    if !matches!(self.insns[i].flow_control(), FlowControl::Call | FlowControl::IndirectCall) {
                        for (ak, &areg) in ABI_ARGS.iter().enumerate() {
                            if gpr_idx(areg).is_some_and(|g| (self.rws[i].writes & (1 << g)) != 0) {
                                (active_abi, killed_abi) = (active_abi | (1 << ak), killed_abi | (1 << ak));
                            }
                        }
                    }
                    let (ins, fc) = (&self.insns[i], self.insns[i].flow_control());
                    let is_tail = matches!(fc, FlowControl::UnconditionalBranch | FlowControl::IndirectBranch)
                        && !jt.iter().any(|t| t.dispatch <= ins.ip() && ins.ip() - t.dispatch <= 32)
                        && (is_call(ins, function) || fc == FlowControl::IndirectBranch);
                    if matches!(fc, FlowControl::Call | FlowControl::IndirectCall) || is_tail {
                        let cregs =
                            resolve_call_regs(image, runtime, sig, ins, (active_abi, killed_abi, unreferenced_abi));
                        for &cr in &cregs {
                            if let Some(g) = gpr_idx(cr) {
                                (self.rws[i].reads, self.rws[i].read_bytes[g]) = (self.rws[i].reads | (1 << g), 8);
                            }
                        }
                        self.call_arg_regs[i] = cregs;
                        if !is_tail {
                            let is_nr = call_target(image, ins)
                                .is_some_and(|ct| crate::callee_meta::is_target_noreturn(image, runtime, ct));
                            let rdx_used = !is_nr && call_reads_rdx(image, function, ins.next_ip());
                            let ret_writes = if is_nr { 0 } else { 1u16 | if rdx_used { 1u16 << 2 } else { 0 } };
                            (self.rws[i].writes, self.rws[i].clobbers, self.rws[i].write_bytes) =
                                (ret_writes, SCRATCH_MASK, 8);
                            self.call_rdx_used[i] = rdx_used;
                            (active_abi, killed_abi) = (0, 0x3f);
                        }
                    }
                    match fc {
                        FlowControl::Return if first_pass => {
                            if !rax_unused || self.rdx_returned {
                                (self.rws[i].reads, self.rws[i].read_bytes[0]) = (self.rws[i].reads | 1, ret_rax_bytes);
                            }
                            if self.rdx_returned {
                                (self.rws[i].reads, self.rws[i].read_bytes[2]) = (self.rws[i].reads | (1 << 2), 8);
                            }
                        }
                        FlowControl::ConditionalBranch if first_pass => {
                            self.succs[b].extend(branch_target(ins).and_then(idx_of));
                            self.succs[b].extend((b + 1 < b_cnt).then_some(b + 1));
                        }
                        FlowControl::UnconditionalBranch | FlowControl::IndirectBranch if first_pass => {
                            if let Some(tbl) = jt.iter().find(|t| t.dispatch <= ins.ip() && ins.ip() - t.dispatch <= 32)
                            {
                                self.succs[b].extend(tbl.arms.iter().filter_map(|&a| idx_of(a)));
                            } else if !is_tail {
                                self.succs[b].extend(branch_target(ins).and_then(idx_of));
                            }
                        }
                        _ => {}
                    }
                }
                if first_pass
                    && b + 1 < b_cnt
                    && rng.clone().last().is_some_and(|l| {
                        let fc = self.insns[l].flow_control();
                        fc == FlowControl::Next
                            || (matches!(fc, FlowControl::Call | FlowControl::IndirectCall)
                                && !call_target(image, &self.insns[l])
                                    .is_some_and(|ct| crate::callee_meta::is_target_noreturn(image, runtime, ct)))
                    })
                {
                    self.succs[b].push(b + 1);
                }
                for &s in &self.succs[b] {
                    if (in_active[s] | active_abi) != in_active[s] || (in_killed[s] | killed_abi) != in_killed[s] {
                        in_active[s] |= active_abi;
                        in_killed[s] |= killed_abi;
                        changed = true;
                    }
                }
            }
            first_pass = false;
        }
    }
}

fn compute_liveness(rws: &[RawRw], block_ranges: &[Range<usize>], succs: &[Vec<usize>]) -> Vec<u16> {
    let b_cnt = block_ranges.len();
    let (mut use_b, mut def_b) = (vec![0u16; b_cnt], vec![0u16; b_cnt]);
    for (b, rng) in block_ranges.iter().enumerate() {
        for i in rng.clone() {
            use_b[b] |= rws[i].reads & !def_b[b];
            def_b[b] |= rws[i].writes | rws[i].clobbers;
        }
    }
    let (mut live_in, mut live_out, mut changed) = (vec![0u16; b_cnt], vec![0u16; b_cnt], true);
    while changed {
        changed = false;
        for b in (0..b_cnt).rev() {
            let out = succs[b].iter().fold(0u16, |acc, &s| acc | live_in[s]);
            let inp = use_b[b] | (out & !def_b[b]);
            if out != live_out[b] || inp != live_in[b] {
                (live_out[b], live_in[b], changed) = (out, inp, true);
            }
        }
    }
    live_out
}
