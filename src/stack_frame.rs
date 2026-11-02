/*
 * xref — Ultra blazing fast cross-references of an x86-64 ELF binary
 * Copyright (c) 2026 Alexander Panasenko
 *
 * Contact: alex@prod.codes
 * Author: https://prod.codes/about/
 * Project: https://github.com/alex09x/xref
 * SPDX-License-Identifier: MIT OR Apache-2.0
 */

//! Stack-frame layout & alias safety: tracks `rsp` deltas across the CFG, normalizes local stack
//! displacements (`slot_<hex>`), detects `mov reg, rsp` / `lea reg, [rsp+off]` address-taking and
//! byte-interval overlaps, and proves immutable 8-byte ABI parameter spills.

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::ops::Range;

use iced_x86::{FlowControl, Instruction, Mnemonic, OpKind, Register};

use crate::expr::{ABI_ARGS, CALLEE_SAVED};
use crate::image::Image;
use crate::scan::{branch_target, decode, immediates};
use crate::sig::FnSig;
use crate::tables::Table;

#[derive(Clone, Debug, Default)]
pub struct StackSlot {
    pub offset: i64,
    pub max_width: u8,
    pub widths_mask: u8,
    pub reads: usize,
    pub writes: usize,
    pub addr_taken: bool,
    pub overlapping: bool,
    pub entry_arg_write: Option<(usize, usize)>,
    first_read_ord: Option<usize>,
}

#[derive(Default)]
pub struct StackFrame {
    pub slots: BTreeMap<i64, StackSlot>,
    pub norm_by_ip: HashMap<u64, i64>,
    pub rsp_copy_by_ip: HashMap<u64, i64>,
    pub spill_to_arg: HashMap<i64, String>,
    pub split_zero_128: BTreeSet<i64>,
    pub sp_exact: bool,
}

const fn width_bit(bytes: usize) -> u8 {
    match bytes {
        1 => 1,
        2 => 2,
        4 => 4,
        8 => 8,
        16 => 16,
        _ => 32,
    }
}

fn step_sp(ins: &Instruction, cur: Option<i64>, uses_fp: bool, rbp_sp: Option<i64>) -> (Option<i64>, bool) {
    let m = ins.mnemonic();
    let dst = (ins.op0_kind() == OpKind::Register).then(|| ins.op0_register().full_register());
    match m {
        Mnemonic::Push => (cur.map(|v| v - 8), true),
        Mnemonic::Pop => (cur.map(|v| v + 8), true),
        Mnemonic::Sub if dst == Some(Register::RSP) => {
            immediates(ins).next().map_or((None, false), |imm| (cur.map(|v| v - imm.cast_signed()), true))
        }
        Mnemonic::Add if dst == Some(Register::RSP) => {
            immediates(ins).next().map_or((None, false), |imm| (cur.map(|v| v + imm.cast_signed()), true))
        }
        Mnemonic::Mov
            if uses_fp && dst == Some(Register::RSP) && ins.op1_register().full_register() == Register::RBP =>
        {
            (rbp_sp, rbp_sp.is_some())
        }
        Mnemonic::Leave if uses_fp => (rbp_sp.map(|v| v + 8), rbp_sp.is_some()),
        _ if dst == Some(Register::RSP) => (None, false),
        _ => (cur, true),
    }
}

fn find_frame_sp(insns: &[Instruction], uses_fp: bool) -> (i64, Option<i64>) {
    let (mut cur, mut rbp_sp) = (0i64, None);
    for ins in insns {
        let (m, dst) = (ins.mnemonic(), ins.op0_register().full_register());
        if matches!(m, Mnemonic::Endbr64 | Mnemonic::Nop) {
            continue;
        }
        if m == Mnemonic::Push
            && ins.op0_kind() == OpKind::Register
            && (CALLEE_SAVED.contains(&dst) || dst == Register::RAX)
        {
            cur -= 8;
        } else if m == Mnemonic::Mov && dst == Register::RBP && ins.op1_register().full_register() == Register::RSP {
            rbp_sp = Some(cur);
        } else if m == Mnemonic::Sub
            && dst == Register::RSP
            && let Some(imm) = immediates(ins).next()
        {
            cur -= imm.cast_signed();
            break;
        } else {
            break;
        }
    }
    (cur, if uses_fp { rbp_sp } else { None })
}

fn is_caller_arg(sig: &FnSig, base: Register, norm_disp: i64, raw_disp: i64) -> bool {
    if sig.uses_fp && base == Register::RBP && raw_disp >= 0x10 {
        return true;
    }
    sig.arg_base_rsp.is_some_and(|ab| base == Register::RSP && norm_disp >= ab)
}

fn propagate_sp_deltas(
    insns: &[Instruction],
    starts: &[u64],
    fn_end: u64,
    sig: &FnSig,
    rbp_sp: Option<i64>,
    jt: &[Table],
) -> (Vec<Option<i64>>, bool) {
    let b_cnt = starts.len();
    let idx_of = |addr: u64| starts.binary_search(&addr).ok();
    let (mut block_in, mut visited) = (vec![None; b_cnt], vec![false; b_cnt]);
    (block_in[0], visited[0]) = (Some(0), true);
    let (mut sp_exact, mut queue) = (true, vec![0usize]);
    while let Some(b) = queue.pop() {
        let (b_start, b_end) = (starts[b], starts.get(b + 1).copied().unwrap_or(fn_end));
        let (mut cur, mut last_fc, mut succs) = (block_in[b], FlowControl::Next, Vec::new());
        for ins in insns.iter().filter(|i| i.ip() >= b_start && i.ip() < b_end) {
            let (next_sp, ok) = step_sp(ins, cur, sig.uses_fp, rbp_sp);
            (sp_exact, cur, last_fc) = (sp_exact & ok, next_sp, ins.flow_control());
            match last_fc {
                FlowControl::ConditionalBranch => {
                    succs.extend(branch_target(ins).and_then(idx_of));
                    succs.extend((b + 1 < b_cnt).then_some(b + 1));
                }
                FlowControl::UnconditionalBranch | FlowControl::IndirectBranch => {
                    if let Some(tbl) = jt.iter().find(|t| t.dispatch <= ins.ip() && ins.ip() - t.dispatch <= 32) {
                        succs.extend(tbl.arms.iter().filter_map(|&a| idx_of(a)));
                    } else {
                        succs.extend(branch_target(ins).and_then(idx_of));
                    }
                }
                _ => {}
            }
        }
        if b + 1 < b_cnt && matches!(last_fc, FlowControl::Next | FlowControl::Call | FlowControl::IndirectCall) {
            succs.push(b + 1);
        }
        for s in succs {
            if !visited[s] {
                (visited[s], block_in[s]) = (true, cur);
                queue.push(s);
            } else if block_in[s] != cur && block_in[s].is_some() {
                (block_in[s], sp_exact) = (None, false);
                queue.push(s);
            }
        }
    }
    (block_in, sp_exact)
}

struct ScanEnv<'a> {
    sig: &'a FnSig,
    frame_sp: i64,
    rbp_sp: Option<i64>,
    any_indexed: bool,
    raw_128_stores: Vec<i64>,
}

impl StackFrame {
    pub fn analyze(image: &Image, function: &Range<u64>, sig: &FnSig, jt: &[Table]) -> Self {
        let Some(bytes) = image.code(function) else { return Self::default() };
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
        if insns.is_empty() {
            return Self::default();
        }
        let (frame_sp, rbp_sp) = find_frame_sp(&insns, sig.uses_fp);
        let starts: Vec<u64> = leaders.into_iter().collect();
        let (block_in, sp_exact) = propagate_sp_deltas(&insns, &starts, function.end, sig, rbp_sp, jt);
        let mut out = Self { sp_exact, ..Self::default() };
        let mut env = ScanEnv { sig, frame_sp, rbp_sp, any_indexed: false, raw_128_stores: Vec::new() };
        let (mut abi_unmodified, mut in_entry) = (0b0011_1111u8, true);

        for (ord, ins) in insns.iter().enumerate() {
            let b = starts.partition_point(|&s| s <= ins.ip()).saturating_sub(1);
            in_entry &= b == 0;
            let mut cur_sp = block_in[b];
            for prev in insns.iter().filter(|p| p.ip() >= starts[b] && p.ip() < ins.ip()) {
                cur_sp = step_sp(prev, cur_sp, sig.uses_fp, rbp_sp).0;
            }
            out.record_insn(ins, ord, cur_sp, in_entry, abi_unmodified, &mut env);
            if ins.op0_kind() == OpKind::Register
                && let Some(ak) = ABI_ARGS.iter().position(|&r| r == ins.op0_register().full_register())
            {
                abi_unmodified &= !(1u8 << ak);
            }
            in_entry &= ins.flow_control() == FlowControl::Next;
        }
        out.finalize_overlaps_and_spills(env.any_indexed, &env.raw_128_stores);
        out
    }

    fn record_insn(
        &mut self,
        ins: &Instruction,
        ord: usize,
        cur_sp: Option<i64>,
        in_entry: bool,
        abi_unmodified: u8,
        env: &mut ScanEnv<'_>,
    ) {
        let (m, dst_k) = (ins.mnemonic(), ins.op0_kind());
        if m == Mnemonic::Mov
            && dst_k == OpKind::Register
            && ins.op1_kind() == OpKind::Register
            && ins.op1_register().full_register() == Register::RSP
            && !(env.sig.uses_fp && ins.op0_register().full_register() == Register::RBP)
        {
            let norm = cur_sp.map_or(0, |c| c - env.frame_sp);
            self.rsp_copy_by_ip.insert(ins.ip(), norm);
            self.slots.entry(norm).or_insert_with(|| StackSlot { offset: norm, ..StackSlot::default() }).addr_taken =
                true;
        }
        let has_mem = (0..ins.op_count()).any(|k| ins.op_kind(k) == OpKind::Memory);
        if !has_mem || ins.is_ip_rel_memory_operand() || matches!(m, Mnemonic::Push | Mnemonic::Pop) {
            return;
        }
        let (base, raw_disp) = (ins.memory_base().full_register(), ins.memory_displacement64().cast_signed());
        let stk_off = if base == Register::RSP {
            Some(raw_disp + cur_sp.map_or(0, |c| c - env.frame_sp))
        } else if env.sig.uses_fp && base == Register::RBP && raw_disp < 0 {
            env.rbp_sp.map(|r_sp| raw_disp + (r_sp - env.frame_sp))
        } else {
            None
        };
        let Some(norm) = stk_off.filter(|&n| !is_caller_arg(env.sig, base, n, raw_disp)) else { return };
        if ins.memory_index() != Register::None {
            env.any_indexed = true;
            return;
        }
        self.norm_by_ip.insert(ins.ip(), norm);
        let sz = ins.memory_size().size();
        let is_w = dst_k == OpKind::Memory && !matches!(m, Mnemonic::Cmp | Mnemonic::Test);
        if is_w && sz == 16 {
            env.raw_128_stores.push(norm);
        }
        let sl = self.slots.entry(norm).or_insert_with(|| StackSlot { offset: norm, ..StackSlot::default() });
        if m == Mnemonic::Lea {
            sl.addr_taken = true;
            return;
        }
        sl.max_width = sl.max_width.max(u8::try_from(sz).unwrap_or(16));
        sl.widths_mask |= width_bit(sz);
        if is_w {
            sl.writes += 1;
            if in_entry
                && sl.writes == 1
                && sz == 8
                && ins.op1_kind() == OpKind::Register
                && let Some(ak) = ABI_ARGS.iter().position(|&r| r == ins.op1_register().full_register())
                && (abi_unmodified & (1u8 << ak)) != 0
            {
                sl.entry_arg_write = Some((ord, ak));
            }
        } else {
            sl.reads += 1;
            sl.first_read_ord.get_or_insert(ord);
        }
    }

    fn finalize_overlaps_and_spills(&mut self, any_indexed: bool, raw_128_stores: &[i64]) {
        for &d in raw_128_stores {
            let has_hi = self.slots.get(&(d + 8)).is_some_and(|s| s.widths_mask == 0x08);
            let lo_only_8_16 = self.slots.get(&d).is_some_and(|s| (s.widths_mask & !0x18) == 0);
            if has_hi && lo_only_8_16 {
                self.split_zero_128.insert(d);
                if let Some(lo) = self.slots.get_mut(&d) {
                    lo.widths_mask = (lo.widths_mask & !0x10) | 0x08;
                    lo.max_width = 8;
                }
                if let Some(hi) = self.slots.get_mut(&(d + 8)) {
                    hi.writes += 1;
                }
            }
        }
        let keys: Vec<(i64, i64)> = self.slots.values().map(|s| (s.offset, i64::from(s.max_width.max(1)))).collect();
        for &(oa, wa) in &keys {
            for &(ob, wb) in &keys {
                if oa != ob
                    && oa < ob + wb
                    && ob < oa + wa
                    && let Some(sl) = self.slots.get_mut(&oa)
                {
                    sl.overlapping = true;
                }
            }
        }
        let min_addr_taken = self.slots.values().filter(|s| s.addr_taken).map(|s| s.offset).min();
        if !self.sp_exact || any_indexed {
            return;
        }
        for sl in self.slots.values() {
            if !sl.overlapping
                && !sl.addr_taken
                && min_addr_taken.is_none_or(|base| sl.offset < base)
                && sl.widths_mask == 8
                && sl.writes == 1
                && sl.reads >= 1
                && let Some((w_ord, ak)) = sl.entry_arg_write
                && sl.first_read_ord.is_some_and(|r_ord| r_ord > w_ord)
            {
                self.spill_to_arg.insert(sl.offset, format!("arg_{ak}"));
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::StackFrame;
    use crate::image::{Image, Segment};
    use crate::sig::fn_sig;

    #[test]
    fn distinguishes_immutable_param_spill_from_address_taken_rsp_slot() {
        let mut data = vec![0u8; 0x100];
        let f1: &[u8] = &[
            0x48, 0x83, 0xec, 0x18, 0x48, 0x89, 0x7c, 0x24, 0x08, 0x48, 0x8b, 0x44, 0x24, 0x08, 0x48, 0x83, 0xc4, 0x18,
            0xc3,
        ];
        data[..f1.len()].copy_from_slice(f1);
        let f2: &[u8] = &[
            0x48, 0x83, 0xec, 0x18, 0x48, 0x89, 0x7c, 0x24, 0x08, 0x48, 0x89, 0xe7, 0x48, 0x8b, 0x44, 0x24, 0x08, 0x48,
            0x83, 0xc4, 0x18, 0xc3,
        ];
        data[0x40..0x40 + f2.len()].copy_from_slice(f2);
        let img = Image {
            data,
            segments: vec![Segment { va: 0x1000, offset: 0, size: 0x100 }],
            functions: vec![0x1000..0x1000 + f1.len() as u64, 0x1040..0x1040 + f2.len() as u64],
            pointers: Vec::new(),
            imports: Vec::new(),
            symbols: Vec::new(),
        };
        let r1 = 0x1000..0x1000 + f1.len() as u64;
        let sf1 = StackFrame::analyze(&img, &r1, &fn_sig(&img, &r1), &[]);
        assert_eq!(sf1.spill_to_arg.get(&8).map(String::as_str), Some("arg_0"));

        let r2 = 0x1040..0x1040 + f2.len() as u64;
        let sf2 = StackFrame::analyze(&img, &r2, &fn_sig(&img, &r2), &[]);
        assert!(sf2.rsp_copy_by_ip.contains_key(&0x1049) && !sf2.spill_to_arg.contains_key(&8));
    }
}
