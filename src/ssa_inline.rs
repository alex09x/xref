/*
 * xref — Ultra blazing fast cross-references of an x86-64 ELF binary
 * Copyright (c) 2026 Alexander Panasenko
 *
 * Contact: alex@prod.codes
 * Author: https://prod.codes/about/
 * Project: https://github.com/alex09x/xref
 * SPDX-License-Identifier: MIT OR Apache-2.0
 */

//! Web naming, single-def parameter copy folding, and flag-safe expression inlining for `SsaCfg`.

use std::collections::HashMap;
use std::ops::Range;

use iced_x86::{ConditionCode, FlowControl, Mnemonic, OpKind, Register};

use crate::expr::{ABI_ARGS, reg_name};
use crate::sig::FnSig;
use crate::ssa_cfg::{GPRS, RawRw};
use crate::ssa_webs::{DefNode, InsnMeta, SsaCfg, UnionFind, WebInfo};

fn last_flag_user(rws: &[RawRw], block_end: usize, u: usize) -> usize {
    if !rws[u].flag_rw.1 {
        return u;
    }
    let mut end = u;
    for (k, rw) in rws.iter().enumerate().take(block_end).skip(u + 1) {
        if rw.flag_rw.0 {
            end = k;
        }
        if rw.flag_rw.1 {
            break;
        }
    }
    end
}

#[allow(clippy::too_many_arguments)]
pub fn finalize_webs_and_inlining(
    ssa: &mut SsaCfg,
    uf: &mut UnionFind,
    defs: &[DefNode],
    ins_defs: &[Vec<(usize, usize)>],
    read_sites: &[(usize, usize, usize)],
    rws: &[RawRw],
    block_ranges: &[Range<usize>],
    live_out: &[u16],
    sig: &FnSig,
    metas: &mut [InsnMeta],
) {
    let mut root_to_web: HashMap<usize, usize> = HashMap::new();
    for (did, dn) in defs.iter().enumerate() {
        let wid = *root_to_web.entry(uf.find(did)).or_insert_with(|| {
            let id = ssa.webs.len();
            ssa.webs.push(WebInfo {
                reg: GPRS[dn.gpr],
                name: String::new(),
                is_param: None,
                init_from_arg: None,
                defs: Vec::new(),
                total_reads: 0,
                only_setcc: true,
                deref_base: false,
                deref_store: false,
                max_write_bytes: 0,
            });
            id
        });
        if let Some(ins_i) = dn.ins_idx {
            ssa.webs[wid].defs.push(ins_i);
            let ins = &ssa.insns[ins_i];
            ssa.webs[wid].only_setcc &= ins.condition_code() != ConditionCode::None && ins.op_count() == 1;
            ssa.webs[wid].max_write_bytes = ssa.webs[wid].max_write_bytes.max(rws[ins_i].write_bytes);
        } else {
            ssa.webs[wid].only_setcc = false;
        }
        ssa.webs[wid].total_reads += dn.uses;
    }
    for &(ins_i, g, first_d) in read_sites {
        let wid = root_to_web[&uf.find(first_d)];
        metas[ins_i].add_read_web(GPRS[g], wid);
        let ins = &ssa.insns[ins_i];
        if !ins.is_ip_rel_memory_operand()
            && ins.mnemonic() != Mnemonic::Lea
            && (0..ins.op_count()).any(|k| ins.op_kind(k) == OpKind::Memory)
            && ins.memory_base().full_register() == GPRS[g]
        {
            ssa.webs[wid].deref_base = true;
            ssa.webs[wid].deref_store |=
                ins.op0_kind() == OpKind::Memory && !matches!(ins.mnemonic(), Mnemonic::Cmp | Mnemonic::Test);
        }
    }
    for (i, dlist) in ins_defs.iter().enumerate() {
        if matches!(ssa.insns[i].flow_control(), FlowControl::Call | FlowControl::IndirectCall) {
            for &(g, did) in dlist {
                let wid = root_to_web[&uf.find(did)];
                if g == 0 {
                    (metas[i].def_web, metas[i].call_ret_used.0) = (Some(wid), defs[did].uses > 0);
                } else if g == 2 {
                    metas[i].rdx_def_web = Some(wid);
                }
            }
        } else if let Some(&(_, did)) = dlist.first() {
            metas[i].def_web = Some(root_to_web[&uf.find(did)]);
        }
    }
    assign_param_webs(ssa, uf, &root_to_web, sig, metas);
    mark_inlinable(ssa, defs, ins_defs, rws, block_ranges, live_out, metas);
    assign_local_names(ssa, metas);
}

fn assign_param_webs(
    ssa: &mut SsaCfg,
    uf: &mut UnionFind,
    root_to_web: &HashMap<usize, usize>,
    sig: &FnSig,
    metas: &mut [InsnMeta],
) {
    for (g, &reg) in GPRS.iter().enumerate() {
        let wid = root_to_web[&uf.find(g)];
        let clob_wid = root_to_web[&uf.find(15 + g)];
        if ssa.webs[clob_wid].defs.is_empty() && clob_wid != wid {
            ssa.webs[clob_wid].name = reg_name(reg);
        }
        if let Some(ak) = ABI_ARGS.iter().position(|&r| r == reg).filter(|_| sig.regs.contains(&reg)) {
            if ssa.webs[wid].defs.is_empty() && wid != clob_wid {
                (ssa.webs[wid].is_param, ssa.webs[wid].name) = (Some(ak), format!("arg_{ak}"));
            } else {
                ssa.webs[wid].init_from_arg = Some(ak);
            }
        } else if ssa.webs[wid].defs.is_empty() {
            ssa.webs[wid].name = reg_name(reg);
        }
    }
    for wid in 0..ssa.webs.len() {
        if !ssa.webs[wid].name.is_empty() || ssa.webs[wid].defs.len() != 1 {
            continue;
        }
        let di = ssa.webs[wid].defs[0];
        let ins = &ssa.insns[di];
        if metas[di].block == 0
            && ins.mnemonic() == Mnemonic::Mov
            && ins.op0_kind() == OpKind::Register
            && ins.op1_kind() == OpKind::Register
            && ins.op0_register().size() == 8
            && let Some(src_w) = metas[di].web_of_read(ins.op1_register())
            && let Some(ak) = ssa.webs[src_w].is_param
        {
            (ssa.webs[wid].is_param, ssa.webs[wid].name, metas[di].elide_def) = (Some(ak), format!("arg_{ak}"), true);
        }
    }
}

fn assign_local_names(ssa: &mut SsaCfg, metas: &[InsnMeta]) {
    let mut seq = 1usize;
    for pass in 0..3 {
        for w in &mut ssa.webs {
            if !w.name.is_empty() {
                continue;
            }
            let inlined = w.defs.len() == 1 && metas[w.defs[0]].can_inline;
            let bucket = if w.total_reads == 0 { 2 } else { usize::from(inlined) };
            if bucket != pass {
                continue;
            }
            let pfx = if w.only_setcc && !w.defs.is_empty() {
                "flag"
            } else if w.deref_base {
                "ptr"
            } else {
                "v"
            };
            w.name = format!("{pfx}_{seq}");
            seq += 1;
        }
    }
}

fn mark_inlinable(
    ssa: &SsaCfg,
    defs: &[DefNode],
    ins_defs: &[Vec<(usize, usize)>],
    rws: &[RawRw],
    block_ranges: &[Range<usize>],
    live_out: &[u16],
    metas: &mut [InsnMeta],
) {
    let mut dep_reads: Vec<u16> = rws.iter().map(|r| r.reads).collect();
    let mut dep_mem: Vec<bool> = rws.iter().map(|r| r.mem_rw.0).collect();
    for i in 0..ssa.insns.len() {
        if metas[i].elide_def || metas[i].partial_merge.is_some() {
            continue;
        }
        let (Some(&(g, did)), Some(wid)) = (ins_defs[i].first(), metas[i].def_web) else { continue };
        let b = metas[i].block;
        let killed_after_i = (i + 1..block_ranges[b].end).any(|k| {
            ((rws[k].writes & (1 << g)) != 0 && metas[k].partial_merge.is_none())
                || matches!(ssa.insns[k].flow_control(), FlowControl::Call | FlowControl::IndirectCall)
        });
        if ssa.webs[wid].defs.len() != 1
            || ssa.webs[wid].total_reads != 1
            || ssa.webs[wid].init_from_arg.is_some()
            || (!killed_after_i && (live_out[b] & (1 << g)) != 0)
        {
            continue;
        }
        let Some(u) = defs[did].single_user.filter(|&u| u > i && metas[u].block == b) else { continue };
        let span_end = if matches!(ssa.insns[u].mnemonic(), Mnemonic::Cmp | Mnemonic::Test) {
            last_flag_user(rws, block_ranges[b].end, u)
        } else {
            u
        };
        if matches!(ssa.insns[i].flow_control(), FlowControl::Call | FlowControl::IndirectCall) {
            if !metas[i].call_ret_used.1 && (i + 1..u).all(|k| rws[k].is_frame_skip) {
                (metas[i].can_inline, dep_reads[u], dep_mem[u]) = (true, dep_reads[u] | dep_reads[i], true);
            }
            continue;
        }
        let safe = (i + 1..=span_end).all(|k| {
            k == u
                || (!matches!(ssa.insns[k].flow_control(), FlowControl::Call | FlowControl::IndirectCall)
                    && (rws[k].writes & dep_reads[i]) == 0
                    && (!dep_mem[i] || !rws[k].mem_rw.1))
        });
        if safe {
            metas[i].can_inline = true;
            dep_reads[u] |= dep_reads[i];
            dep_mem[u] |= dep_mem[i];
        }
    }
}

impl SsaCfg {
    /// Path-sensitive SSA field summary `(offset -> (width, reads, writes), any_load, any_store)`
    /// for parameter `ak`, considering only exact `arg_k` webs, unshifted `mov` copies, and
    /// single-store non-escaped entry stack spills (cursor-mutated copies contribute only load/store flags).
    pub fn param_fields(&self, ak: usize) -> (std::collections::BTreeMap<u64, (usize, usize, usize)>, bool, bool) {
        let is_arg_slot = |ip: u64| -> bool {
            self.stack.norm_by_ip.get(&ip).and_then(|n| self.stack.slots.get(n)).is_some_and(|sl| {
                !sl.addr_taken && !sl.overlapping && sl.writes == 1 && sl.entry_arg_write.is_some_and(|(_, k)| k == ak)
            })
        };
        let is_exact_copy_def = |di: usize| -> bool {
            let ins = &self.insns[di];
            ins.mnemonic() == Mnemonic::Mov
                && ins.op0_kind() == OpKind::Register
                && ins.op0_register().size() == 8
                && ((ins.op1_kind() == OpKind::Register
                    && self.metas[di]
                        .web_of_read(ins.op1_register())
                        .is_some_and(|w| self.webs[w].is_param == Some(ak)))
                    || (ins.op1_kind() == OpKind::Memory && !ins.is_ip_rel_memory_operand() && is_arg_slot(ins.ip())))
        };

        let (mut exact_webs, mut any_load, mut any_store) = (vec![false; self.webs.len()], false, false);
        for (wid, w) in self.webs.iter().enumerate() {
            if w.is_param == Some(ak) || (!w.defs.is_empty() && w.defs.iter().all(|&di| is_exact_copy_def(di))) {
                exact_webs[wid] = true;
                any_load |= w.deref_base;
                any_store |= w.deref_store;
            } else if w.init_from_arg == Some(ak) || w.defs.iter().any(|&di| is_exact_copy_def(di)) {
                any_load |= w.deref_base;
                any_store |= w.deref_store;
            }
        }

        let mut fields = std::collections::BTreeMap::new();
        for (i, ins) in self.insns.iter().enumerate() {
            let m = ins.mnemonic();
            if ins.is_ip_rel_memory_operand()
                || m == Mnemonic::Lea
                || !(0..ins.op_count()).any(|k| ins.op_kind(k) == OpKind::Memory)
            {
                continue;
            }
            let Some(bw) = self.metas[i].web_of_read(ins.memory_base()).filter(|&w| exact_webs[w]) else { continue };
            let _ = bw;
            any_load = true;
            let is_w = ins.op0_kind() == OpKind::Memory && !matches!(m, Mnemonic::Cmp | Mnemonic::Test);
            any_store |= is_w;
            if ins.memory_index() == Register::None
                && let Ok(off) = u64::try_from(ins.memory_displacement64().cast_signed())
            {
                let sz = ins.memory_size().size().max(1);
                let entry = fields.entry(off).or_insert((sz, 0usize, 0usize));
                entry.0 = entry.0.max(sz);
                if is_w {
                    entry.2 += 1;
                } else {
                    entry.1 += 1;
                }
            }
        }
        (fields, any_load, any_store)
    }
}

#[cfg(test)]
mod tests {
    use crate::c::c_one;
    use crate::image::{Image, Segment};
    use crate::runtime::RuntimeMap;
    use crate::sig::fn_sig;
    use crate::ssa_webs::SsaCfg;

    #[test]
    fn splits_reused_register_live_ranges_and_handles_zero_setcc() {
        let code: &[u8] =
            &[0x48, 0x8b, 0x07, 0x48, 0x89, 0x06, 0x31, 0xd2, 0x83, 0xff, 0x05, 0x0f, 0x94, 0xc2, 0x89, 0xd0, 0xc3];
        let mut data = vec![0u8; 0x80];
        data[..code.len()].copy_from_slice(code);
        let f = 0x1000..0x1000 + code.len() as u64;
        let img = Image {
            data,
            segments: vec![Segment { va: 0x1000, offset: 0, size: 0x80 }],
            functions: vec![f.clone()],
            pointers: Vec::new(),
            imports: Vec::new(),
            symbols: Vec::new(),
        };
        let ssa = SsaCfg::analyze(&img, &RuntimeMap::default(), &f, &fn_sig(&img, &f), &[]);
        assert_ne!(ssa.metas[0].def_web, ssa.metas[5].def_web);
        assert_eq!(ssa.metas[4].partial_merge, None);
    }

    #[test]
    fn renders_typed_c_unary_precedence_void_caller_and_stack_addr() {
        // fn 0x1000: xor eax,eax; cmp rdi,43; sete al; neg rax; ret -> (-(arg_0 == 43))
        let f1: &[u8] = &[0x31, 0xc0, 0x48, 0x83, 0xff, 0x2b, 0x0f, 0x94, 0xc0, 0x48, 0xf7, 0xd8, 0xc3];
        // fn 0x1020: mov [rdi], rsi; mov eax, 99; ret (caller at 0x1040 kills rax -> void!)
        let f2: &[u8] = &[0x48, 0x89, 0x37, 0xb8, 0x63, 0x00, 0x00, 0x00, 0xc3];
        // fn 0x1040: sub rsp, 0x18; mov qword [rsp], 7; mov rdi, rsp; mov esi, 3; call 0x1020 (-0x39); xor eax, eax; add rsp, 0x18; ret
        let f3: &[u8] = &[
            0x48, 0x83, 0xec, 0x18, 0x48, 0xc7, 0x04, 0x24, 0x07, 0x00, 0x00, 0x00, 0x48, 0x89, 0xe7, 0xbe, 0x03, 0x00,
            0x00, 0x00, 0xe8, 0xc7, 0xff, 0xff, 0xff, 0x31, 0xc0, 0x48, 0x83, 0xc4, 0x18, 0xc3,
        ];
        let mut data = vec![0xccu8; 0x100];
        data[..f1.len()].copy_from_slice(f1);
        data[0x20..0x20 + f2.len()].copy_from_slice(f2);
        data[0x40..0x40 + f3.len()].copy_from_slice(f3);
        let img = Image {
            data,
            segments: vec![Segment { va: 0x1000, offset: 0, size: 0x100 }],
            functions: vec![
                0x1000..0x1000 + f1.len() as u64,
                0x1020..0x1020 + f2.len() as u64,
                0x1040..0x1040 + f3.len() as u64,
            ],
            pointers: Vec::new(),
            imports: Vec::new(),
            symbols: Vec::new(),
        };
        let rt = RuntimeMap::detect(&img);
        let (_, c1) = c_one(&img, &[], &rt, 0x1000, None, None).unwrap_or_default();
        assert!(c1.contains("(-(arg_0 == 43))"), "{c1}");

        let (_, c2) = c_one(&img, &[], &rt, 0x1020, None, None).unwrap_or_default();
        assert!(c2.contains("void fn_1020(void *arg_0, unk64 arg_1)"), "{c2}");
        assert!(!c2.contains("return 99;"), "{c2}");

        let (_, c3) = c_one(&img, &[], &rt, 0x1040, None, None).unwrap_or_default();
        assert!(c3.contains("fn_1020(&slot_0, 3);"), "{c3}");
    }
}
