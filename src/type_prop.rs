/*
 * xref — Ultra blazing fast cross-references of an x86-64 ELF binary
 * Copyright (c) 2026 Alexander Panasenko
 *
 * Contact: alex@prod.codes
 * Author: https://prod.codes/about/
 * Project: https://github.com/alex09x/xref
 * SPDX-License-Identifier: MIT OR Apache-2.0
 */

//! Intra-procedural type evidence extraction, fixed-point web/stack-slot type propagation, and
//! scope-dominated inline local variable declarations for `xref c`.

use std::collections::HashMap;

use iced_x86::{ConditionCode, FlowControl, Instruction, MemorySize, Mnemonic, OpKind, Register};

use crate::callee_meta::{import_sig, is_target_noreturn};
use crate::graph::call_target;
use crate::image::Image;
use crate::locations::Location;
use crate::runtime::RuntimeMap;
use crate::source::location_at;
use crate::ssa_webs::{InsnMeta, SsaCfg};

const EV_CODE_PTR: u16 = 1 << 0;
const EV_STACK_REF: u16 = 1 << 1;
const EV_NON_1B_MEM: u16 = 1 << 2;
const EV_SCALE8_MEM: u16 = 1 << 3;
const EV_NON_8B_MEM: u16 = 1 << 4;
const EV_IS_INDEX: u16 = 1 << 5;
const EV_SIGNED: u16 = 1 << 6;
const EV_UNSIGNED: u16 = 1 << 7;
const EV_BIT_OPS: u16 = 1 << 8;
const EV_MOVZX_1B: u16 = 1 << 9;
const EV_MOVZX_2B: u16 = 1 << 10;
const EV_ALL_32B: u16 = 1 << 11;
const EV_ALL_CALL: u16 = 1 << 12;

#[derive(Clone, Default)]
pub struct WebEv {
    pub flags: u16,
    pub loads: usize,
    pub stores: usize,
    pub scale_factor: Option<u64>,
    pub max_read_bytes: u8,
    pub plt_ty: Option<(&'static str, String)>,
}

impl WebEv {
    const fn has(&self, mask: u16) -> bool {
        (self.flags & mask) != 0
    }
}

pub struct LocalTypes {
    pub web_ty: Vec<&'static str>,
    pub web_ev: Vec<WebEv>,
    pub slot_ty: HashMap<i64, &'static str>,
}

fn is_movzx_sz(ins: &Instruction, msz: MemorySize, rsz: usize) -> bool {
    ins.mnemonic() == Mnemonic::Movzx
        && ((ins.op1_kind() == OpKind::Memory && ins.memory_size() == msz)
            || (ins.op1_kind() == OpKind::Register && ins.op1_register().size() == rsz))
}

fn collect_evidence(image: &Image, locs: &[Location], runtime: &RuntimeMap, ssa: &SsaCfg) -> Vec<WebEv> {
    let mut ev = vec![WebEv::default(); ssa.webs.len()];
    for (wid, w) in ssa.webs.iter().enumerate() {
        if !w.defs.is_empty() {
            let m1 = w.defs.iter().all(|&di| is_movzx_sz(&ssa.insns[di], MemorySize::UInt8, 1));
            let m2 = w.defs.iter().all(|&di| is_movzx_sz(&ssa.insns[di], MemorySize::UInt16, 2));
            let ac = w
                .defs
                .iter()
                .all(|&di| matches!(ssa.insns[di].flow_control(), FlowControl::Call | FlowControl::IndirectCall));
            let a32 = !m1
                && !m2
                && !ac
                && w.defs.iter().all(|&di| {
                    ssa.insns[di].op0_kind() == OpKind::Register && ssa.insns[di].op0_register().size() == 4
                });
            ev[wid].flags |= (u16::from(m1) * EV_MOVZX_1B)
                | (u16::from(m2) * EV_MOVZX_2B)
                | (u16::from(ac) * EV_ALL_CALL)
                | (u16::from(a32) * EV_ALL_32B);
        }
    }
    let (mut cur_block, mut cmp_webs, mut test_self) = (usize::MAX, Vec::new(), false);
    for (i, ins) in ssa.insns.iter().enumerate() {
        let meta = &ssa.metas[i];
        if meta.block != cur_block {
            (cur_block, test_self) = (meta.block, false);
            cmp_webs.clear();
        }
        let m = ins.mnemonic();
        for k in 0..ins.op_count() {
            if ins.op_kind(k) == OpKind::Register
                && let Some(rw) = meta.web_of_read(ins.op_register(k))
            {
                let rsz = u8::try_from(ins.op_register(k).size()).unwrap_or(8);
                ev[rw].max_read_bytes = ev[rw].max_read_bytes.max(rsz);
                if m == Mnemonic::Imul && ins.op_count() >= 2 {
                    let last = ins.op_count() - 1;
                    if matches!(
                        ins.op_kind(last),
                        OpKind::Immediate8 | OpKind::Immediate32 | OpKind::Immediate8to64 | OpKind::Immediate32to64
                    ) {
                        ev[rw].flags |= EV_IS_INDEX;
                        ev[rw].scale_factor = Some(ins.immediate(last));
                    }
                }
            }
        }
        if matches!(m, Mnemonic::Cmp | Mnemonic::Test) {
            cmp_webs.clear();
            for k in 0..usize::from(meta.read_cnt) {
                if (0..ins.op_count()).any(|op| {
                    ins.op_kind(op) == OpKind::Register && ins.op_register(op).full_register() == meta.read_webs[k].0
                }) {
                    cmp_webs.push(meta.read_webs[k].1);
                }
            }
            test_self = m == Mnemonic::Test
                && ins.op0_kind() == OpKind::Register
                && ins.op1_kind() == OpKind::Register
                && ins.op0_register() == ins.op1_register();
        }
        step_alu_and_cc(ins, meta, &cmp_webs, test_self, &mut ev);
        step_mem_and_calls(image, locs, runtime, ssa, i, ins, &mut ev);
    }
    ev
}

fn step_alu_and_cc(ins: &Instruction, meta: &InsnMeta, cmp_webs: &[usize], test_self: bool, ev: &mut [WebEv]) {
    let cc_flag = match ins.condition_code() {
        ConditionCode::l | ConditionCode::le | ConditionCode::g | ConditionCode::ge => EV_SIGNED,
        ConditionCode::s | ConditionCode::ns if test_self => EV_SIGNED,
        ConditionCode::b | ConditionCode::be | ConditionCode::a | ConditionCode::ae => EV_UNSIGNED,
        _ => 0,
    };
    if cc_flag != 0 {
        for &w in cmp_webs {
            ev[w].flags |= cc_flag;
        }
    }
    let m = ins.mnemonic();
    let alu_flag = if matches!(m, Mnemonic::Sar | Mnemonic::Idiv | Mnemonic::Movsx | Mnemonic::Movsxd | Mnemonic::Neg) {
        EV_SIGNED
    } else if matches!(m, Mnemonic::Shr | Mnemonic::Div | Mnemonic::Mul) {
        EV_UNSIGNED
    } else {
        0
    };
    if alu_flag != 0 {
        for k in 0..usize::from(meta.read_cnt) {
            ev[meta.read_webs[k].1].flags |= alu_flag;
        }
        if let Some(dw) = meta.def_web {
            ev[dw].flags |= alu_flag;
        }
    } else if matches!(m, Mnemonic::Shl | Mnemonic::And | Mnemonic::Or | Mnemonic::Xor)
        && let Some(dw) = meta.def_web
    {
        ev[dw].flags |= EV_BIT_OPS;
    }
}

fn step_mem_and_calls(
    image: &Image,
    locs: &[Location],
    runtime: &RuntimeMap,
    ssa: &SsaCfg,
    i: usize,
    ins: &Instruction,
    ev: &mut [WebEv],
) {
    let (meta, m) = (&ssa.metas[i], ins.mnemonic());
    if (0..ins.op_count()).any(|k| ins.op_kind(k) == OpKind::Memory) && !ins.is_ip_rel_memory_operand() {
        let breg = ins.memory_base().full_register();
        if m == Mnemonic::Lea && matches!(breg, Register::RSP | Register::RBP) {
            if let Some(dw) = meta.def_web {
                ev[dw].flags |= EV_STACK_REF;
            }
        } else if m != Mnemonic::Lea
            && let Some(bw) = meta.web_of_read(breg)
        {
            let msz = ins.memory_size().size();
            if ins.op0_kind() == OpKind::Memory && !matches!(m, Mnemonic::Cmp | Mnemonic::Test) {
                ev[bw].stores += 1;
            } else {
                ev[bw].loads += 1;
            }
            if msz != 1 {
                ev[bw].flags |= EV_NON_1B_MEM;
            }
            ev[bw].flags |= if msz == 8 && ins.memory_index_scale() == 8 { EV_SCALE8_MEM } else { EV_NON_8B_MEM };
        }
        let ireg = ins.memory_index().full_register();
        if ireg != Register::None
            && let Some(iw) = meta.web_of_read(ireg)
        {
            if m != Mnemonic::Lea || ins.memory_index_scale() > 1 {
                ev[iw].flags |= EV_IS_INDEX;
            }
            if ins.memory_index_scale() > 1 {
                let extra = u64::from(m == Mnemonic::Lea && breg == ireg);
                ev[iw].scale_factor = Some(u64::from(ins.memory_index_scale()) + extra);
            }
        }
    }
    if matches!(ins.flow_control(), FlowControl::IndirectCall | FlowControl::IndirectBranch)
        && call_target(image, ins).is_none()
        && ins.op0_kind() == OpKind::Register
        && let Some(cw) = meta.web_of_read(ins.op0_register())
    {
        ev[cw].flags |= EV_CODE_PTR;
    }
    if matches!(ins.flow_control(), FlowControl::Call | FlowControl::IndirectCall)
        && let Some(ct) = call_target(image, ins)
    {
        if let Some(imp) = runtime.label(image, ct)
            && let Some(isig) = import_sig(imp)
        {
            for (pos, &cr) in meta.call_arg_regs.iter().enumerate() {
                if let (Some(w), Some(&(pty, role))) = (meta.web_of_read(cr), isig.params.get(pos)) {
                    ev[w].plt_ty = Some((pty, format!("via {imp} param `{role}`")));
                }
            }
        } else if is_target_noreturn(image, runtime, ct) && meta.call_arg_regs.len() == 3 {
            let has_loc = (i.saturating_sub(4)..=i).any(|k| {
                ssa.insns[k].is_ip_rel_memory_operand()
                    && location_at(locs, ssa.insns[k].ip_rel_memory_address()).is_some()
            });
            if has_loc {
                for &cr in meta.call_arg_regs.iter().take(2) {
                    if let Some(w) = meta.web_of_read(cr) {
                        ev[w].flags |= EV_IS_INDEX;
                    }
                }
            }
        }
    }
}

fn initial_web_type(ssa: &SsaCfg, wid: usize, ev: &WebEv) -> &'static str {
    let w = &ssa.webs[wid];
    if ev.has(EV_CODE_PTR) {
        return "code_ptr";
    }
    if ev.has(EV_STACK_REF) {
        return "void *";
    }
    if ev.loads > 0 || ev.stores > 0 || w.deref_base || w.deref_store {
        if !ev.has(EV_NON_1B_MEM) && (ev.loads + ev.stores) > 0 {
            return if ev.stores > 0 { "u8 *" } else { "const u8 *" };
        }
        if ev.has(EV_SCALE8_MEM) && !ev.has(EV_NON_8B_MEM) {
            return if ev.stores > 0 { "u64 *" } else { "const u64 *" };
        }
        return if ev.stores > 0 || w.deref_store { "void *" } else { "const void *" };
    }
    if let Some((pty, _)) = ev.plt_ty {
        return pty;
    }
    if (w.only_setcc && !w.defs.is_empty())
        || ev.has(EV_MOVZX_1B)
        || w.max_write_bytes == 1
        || (ev.has(EV_ALL_CALL) && ev.max_read_bytes == 1)
        || (w.is_param.is_some() && ev.max_read_bytes == 1)
    {
        return "u8";
    }
    if ev.has(EV_MOVZX_2B) || w.max_write_bytes == 2 || (w.is_param.is_some() && ev.max_read_bytes == 2) {
        return "u16";
    }
    if ev.has(EV_IS_INDEX) {
        return "usize";
    }
    let is_32 = (ev.has(EV_ALL_32B) && ev.max_read_bytes <= 4) || (w.is_param.is_some() && ev.max_read_bytes == 4);
    if ev.has(EV_SIGNED) && !ev.has(EV_UNSIGNED) {
        return if is_32 { "i32" } else { "i64" };
    }
    if (ev.has(EV_UNSIGNED) || ev.has(EV_BIT_OPS)) && !ev.has(EV_SIGNED) {
        return if is_32 { "u32" } else { "u64" };
    }
    if is_32 {
        return "u32";
    }
    "unk64"
}

fn sync_slot(slot_ty: &mut HashMap<i64, &'static str>, norm: i64, wty: &mut &'static str) {
    let cur = slot_ty.get(&norm).copied().unwrap_or("unk64");
    if cur == "unk64" && *wty != "unk64" {
        slot_ty.insert(norm, *wty);
    } else if *wty == "unk64" && cur != "unk64" {
        *wty = cur;
    }
}

fn unify_webs(web_ty: &mut [&'static str], a: usize, b: usize) {
    if web_ty[a] == "unk64" && web_ty[b] != "unk64" {
        web_ty[a] = web_ty[b];
    } else if web_ty[b] == "unk64" && web_ty[a] != "unk64" {
        web_ty[b] = web_ty[a];
    }
}

impl LocalTypes {
    pub fn analyze(image: &Image, locs: &[Location], runtime: &RuntimeMap, ssa: &SsaCfg) -> Self {
        let web_ev = collect_evidence(image, locs, runtime, ssa);
        let mut web_ty: Vec<&'static str> = (0..ssa.webs.len()).map(|w| initial_web_type(ssa, w, &web_ev[w])).collect();
        let mut slot_ty: HashMap<i64, &'static str> = ssa
            .stack
            .slots
            .values()
            .map(|sl| {
                let ty = match sl.max_width {
                    1 => "u8",
                    2 => "u16",
                    4 => "u32",
                    16 => "u128",
                    _ => "unk64",
                };
                (sl.offset, ty)
            })
            .collect();

        for _ in 0..4 {
            for (i, ins) in ssa.insns.iter().enumerate() {
                let (meta, m) = (&ssa.metas[i], ins.mnemonic());
                if let Some(&norm) = ssa.stack.norm_by_ip.get(&ins.ip()) {
                    if m == Mnemonic::Mov {
                        let w = (ins.op0_kind() == OpKind::Memory && ins.op1_kind() == OpKind::Register)
                            .then(|| meta.web_of_read(ins.op1_register()))
                            .flatten()
                            .or(meta.def_web);
                        if let Some(w) = w {
                            sync_slot(&mut slot_ty, norm, &mut web_ty[w]);
                        }
                    } else if m == Mnemonic::Cmp {
                        for k in 0..usize::from(meta.read_cnt) {
                            sync_slot(&mut slot_ty, norm, &mut web_ty[meta.read_webs[k].1]);
                        }
                    }
                }
                if let Some(dw) = meta.def_web {
                    if m == Mnemonic::Mov
                        && ins.op1_kind() == OpKind::Register
                        && let Some(sw) = meta.web_of_read(ins.op1_register())
                    {
                        unify_webs(&mut web_ty, dw, sw);
                    } else if m == Mnemonic::Lea
                        && !ins.is_ip_rel_memory_operand()
                        && web_ty[dw] == "unk64"
                        && let Some(bw) = meta.web_of_read(ins.memory_base())
                        && web_ty[bw].ends_with('*')
                    {
                        web_ty[dw] = web_ty[bw];
                    } else if matches!(m, Mnemonic::Add | Mnemonic::Sub) {
                        let any_ptr = (0..usize::from(meta.read_cnt)).find_map(|k| {
                            web_ty[meta.read_webs[k].1].ends_with('*').then_some(web_ty[meta.read_webs[k].1])
                        });
                        let any_usize = (0..usize::from(meta.read_cnt)).any(|k| web_ty[meta.read_webs[k].1] == "usize");
                        if web_ty[dw] == "unk64" {
                            if m == Mnemonic::Add
                                && let Some(pty) = any_ptr
                            {
                                web_ty[dw] = pty;
                            } else if any_usize && any_ptr.is_none() {
                                web_ty[dw] = "usize";
                            }
                        } else if web_ty[dw] == "usize" && any_ptr.is_none() {
                            for k in 0..usize::from(meta.read_cnt) {
                                let rw = meta.read_webs[k].1;
                                if web_ty[rw] == "unk64" {
                                    web_ty[rw] = "usize";
                                }
                            }
                        }
                    }
                }
                if m == Mnemonic::Cmp
                    && ins.op0_kind() == OpKind::Register
                    && ins.op1_kind() == OpKind::Register
                    && let (Some(w0), Some(w1)) =
                        (meta.web_of_read(ins.op0_register()), meta.web_of_read(ins.op1_register()))
                {
                    unify_webs(&mut web_ty, w0, w1);
                }
            }
        }
        Self { web_ty, web_ev, slot_ty }
    }
}
