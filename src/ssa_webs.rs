/*
 * xref — Ultra blazing fast cross-references of an x86-64 ELF binary
 * Copyright (c) 2026 Alexander Panasenko
 *
 * Contact: alex@prod.codes
 * Author: https://prod.codes/about/
 * Project: https://github.com/alex09x/xref
 * SPDX-License-Identifier: MIT OR Apache-2.0
 */

//! Intra-procedural SSA Def-Use Webs (`SsaCfg`): Reaching Definitions and Union-Find live-range
//! splitting across basic blocks, branches, loops, and partial 8/16-bit register writes.

use std::collections::HashMap;
use std::ops::Range;

use iced_x86::{Instruction, Register};

use crate::image::Image;
use crate::runtime::RuntimeMap;
use crate::sig::FnSig;
use crate::ssa_cfg::{GPRS, RawRw, SsaGraph};
use crate::stack_frame::StackFrame;
use crate::tables::Table;

#[derive(Clone, Debug)]
pub struct WebInfo {
    pub reg: Register,
    pub name: String,
    pub is_param: Option<usize>,
    pub init_from_arg: Option<usize>,
    pub defs: Vec<usize>,
    pub total_reads: usize,
    pub only_setcc: bool,
    pub deref_base: bool,
    pub deref_store: bool,
    pub max_write_bytes: u8,
    pub max_read_bytes: u8,
}

#[derive(Clone, Debug, Default)]
pub struct InsnMeta {
    pub block: usize,
    pub read_webs: [(Register, usize); 8],
    pub read_cnt: u8,
    pub def_web: Option<usize>,
    pub rdx_def_web: Option<usize>,
    pub elide_def: bool,
    pub partial_merge: Option<u8>,
    pub rdx_partial_merge: Option<u8>,
    pub can_inline: bool,
    pub call_arg_regs: Vec<Register>,
    pub call_ret_used: (bool, bool),
}

impl InsnMeta {
    pub fn web_of_read(&self, reg: Register) -> Option<usize> {
        let full = reg.full_register();
        self.read_webs[..usize::from(self.read_cnt)].iter().find_map(|&(r, w)| (r == full).then_some(w))
    }

    pub fn add_read_web(&mut self, reg: Register, web: usize) {
        let full = reg.full_register();
        if self.web_of_read(full).is_none() && usize::from(self.read_cnt) < self.read_webs.len() {
            self.read_webs[usize::from(self.read_cnt)] = (full, web);
            self.read_cnt += 1;
        }
    }
}

#[derive(Default)]
pub struct SsaCfg {
    pub insns: Vec<Instruction>,
    pub metas: Vec<InsnMeta>,
    pub ip_to_idx: HashMap<u64, usize>,
    pub webs: Vec<WebInfo>,
    pub stack: StackFrame,
    pub caller_stats: crate::caller_ret::CallerRetStats,
    pub rax_proven_unused: bool,
    pub rdx_returned: bool,
}

pub struct UnionFind {
    parent: Vec<usize>,
}

impl UnionFind {
    pub fn new(n: usize) -> Self {
        Self { parent: (0..n).collect() }
    }
    pub fn find(&mut self, mut x: usize) -> usize {
        while self.parent[x] != x {
            self.parent[x] = self.parent[self.parent[x]];
            x = self.parent[x];
        }
        x
    }
    pub fn union(&mut self, a: usize, b: usize) {
        let (ra, rb) = (self.find(a), self.find(b));
        if ra != rb {
            self.parent[rb.max(ra)] = ra.min(rb);
        }
    }
}

#[derive(Clone)]
pub struct DefNode {
    pub gpr: usize,
    pub ins_idx: Option<usize>,
    pub is_zero: bool,
    pub uses: usize,
    pub max_read_bytes: u8,
    pub single_user: Option<usize>,
}

const fn bit_set(words: &mut [u64], idx: usize) {
    words[idx / 64] |= 1u64 << (idx % 64);
}
const fn bit_test(words: &[u64], idx: usize) -> bool {
    (words[idx / 64] & (1u64 << (idx % 64))) != 0
}

fn has_prior_nonzero(defs: &[DefNode], cur: &[u64], g: usize, sig: &FnSig) -> bool {
    (0..defs.len()).any(|d| {
        defs[d].gpr == g
            && bit_test(cur, d)
            && ((defs[d].ins_idx.is_some() && !defs[d].is_zero) || (d < 15 && sig.regs.contains(&GPRS[g])))
    })
}

fn apply_clobbers(cur: &mut [u64], gpr_kill: &[Vec<u64>], words: usize, clobber_only: u16) {
    if clobber_only == 0 {
        return;
    }
    for (g, kill) in gpr_kill.iter().enumerate().take(15) {
        if (clobber_only & (1 << g)) != 0 {
            for w in 0..words {
                cur[w] &= !kill[w];
            }
            bit_set(cur, 15 + g);
        }
    }
}

fn reach_fixed_point(
    defs: &[DefNode],
    ins_defs: &[Vec<(usize, usize)>],
    rws: &[RawRw],
    block_ranges: &[Range<usize>],
    succs: &[Vec<usize>],
    sig: &FnSig,
) -> (Vec<Vec<u64>>, Vec<Vec<u64>>, usize) {
    let words = defs.len().div_ceil(64).max(1);
    let mut gpr_kill: Vec<Vec<u64>> = vec![vec![0u64; words]; 15];
    for (did, d) in defs.iter().enumerate() {
        bit_set(&mut gpr_kill[d.gpr], did);
    }
    let b_cnt = block_ranges.len();
    let (mut reach_in, mut reach_out) = (vec![vec![0u64; words]; b_cnt], vec![vec![0u64; words]; b_cnt]);
    for g in 0..15 {
        bit_set(&mut reach_in[0], g);
    }
    let mut changed = true;
    while changed {
        changed = false;
        for (b, rng) in block_ranges.iter().enumerate() {
            let mut cur = reach_in[b].clone();
            for i in rng.clone() {
                let is_subword = rws[i].write_bytes > 0 && rws[i].write_bytes < 4 && !rws[i].is_zero;
                for &(g, did) in &ins_defs[i] {
                    if !(is_subword && has_prior_nonzero(defs, &cur, g, sig)) {
                        for w in 0..words {
                            cur[w] &= !gpr_kill[g][w];
                        }
                    }
                    bit_set(&mut cur, did);
                }
                apply_clobbers(&mut cur, &gpr_kill, words, rws[i].clobbers & !rws[i].writes);
            }
            if cur != reach_out[b] {
                reach_out[b].clone_from(&cur);
                changed = true;
            }
            for &s in &succs[b] {
                for w in 0..words {
                    let merged = reach_in[s][w] | cur[w];
                    if merged != reach_in[s][w] {
                        (reach_in[s][w], changed) = (merged, true);
                    }
                }
            }
        }
    }
    (reach_in, gpr_kill, words)
}

struct ReachData {
    defs: Vec<DefNode>,
    ins_defs: Vec<Vec<(usize, usize)>>,
    reach_in: Vec<Vec<u64>>,
    gpr_kill: Vec<Vec<u64>>,
    words: usize,
}

impl ReachData {
    fn compute(
        insns_len: usize,
        rws: &[RawRw],
        block_ranges: &[Range<usize>],
        succs: &[Vec<usize>],
        sig: &FnSig,
    ) -> Self {
        let mut defs: Vec<DefNode> = (0..30)
            .map(|k| DefNode {
                gpr: k % 15,
                ins_idx: None,
                is_zero: false,
                uses: 0,
                max_read_bytes: 0,
                single_user: None,
            })
            .collect();
        let mut ins_defs: Vec<Vec<(usize, usize)>> = vec![Vec::new(); insns_len];
        for (i, rw) in rws.iter().enumerate() {
            if rw.is_frame_skip || rw.writes == 0 {
                continue;
            }
            for g in 0..15 {
                if (rw.writes & (1 << g)) != 0 {
                    let did = defs.len();
                    defs.push(DefNode {
                        gpr: g,
                        ins_idx: Some(i),
                        is_zero: rw.is_zero,
                        uses: 0,
                        max_read_bytes: 0,
                        single_user: None,
                    });
                    ins_defs[i].push((g, did));
                }
            }
        }
        let (reach_in, gpr_kill, words) = reach_fixed_point(&defs, &ins_defs, rws, block_ranges, succs, sig);
        for (b, rng) in block_ranges.iter().enumerate() {
            let mut cur = reach_in[b].clone();
            for i in rng.clone() {
                for g in 0..15 {
                    if (rws[i].reads & (1 << g)) != 0 {
                        for (d, dn) in defs.iter_mut().enumerate() {
                            if dn.gpr == g && bit_test(&cur, d) {
                                dn.max_read_bytes = dn.max_read_bytes.max(rws[i].read_bytes[g]);
                            }
                        }
                    }
                }
                let is_subword = rws[i].write_bytes > 0 && rws[i].write_bytes < 4 && !rws[i].is_zero;
                for &(g, did) in &ins_defs[i] {
                    if !(is_subword && has_prior_nonzero(&defs, &cur, g, sig)) {
                        for w in 0..words {
                            cur[w] &= !gpr_kill[g][w];
                        }
                    }
                    bit_set(&mut cur, did);
                }
                apply_clobbers(&mut cur, &gpr_kill, words, rws[i].clobbers & !rws[i].writes);
            }
        }
        Self { defs, ins_defs, reach_in, gpr_kill, words }
    }
}

impl SsaCfg {
    pub fn analyze(image: &Image, runtime: &RuntimeMap, function: &Range<u64>, sig: &FnSig, jt: &[Table]) -> Self {
        let caller_stats = runtime.caller_stats(image, function.start);
        let rax_proven_unused = caller_stats.rax_proven_unused();
        let stack = StackFrame::analyze(image, function, sig, jt);
        let Some(graph) = SsaGraph::build(image, runtime, function, sig, jt, caller_stats, rax_proven_unused) else {
            return Self { stack, caller_stats, rax_proven_unused, ..Self::default() };
        };
        let ip_to_idx: HashMap<u64, usize> = graph.insns.iter().enumerate().map(|(i, ins)| (ins.ip(), i)).collect();
        let mut metas: Vec<InsnMeta> = (0..graph.insns.len())
            .map(|i| InsnMeta {
                block: graph.block_of[i],
                call_arg_regs: graph.call_arg_regs[i].clone(),
                call_ret_used: (false, graph.call_rdx_used[i]),
                ..InsnMeta::default()
            })
            .collect();
        let mut out = Self {
            insns: graph.insns,
            metas: Vec::new(),
            ip_to_idx,
            webs: Vec::new(),
            stack,
            caller_stats,
            rax_proven_unused,
            rdx_returned: graph.rdx_returned,
        };
        out.solve_webs(&graph.rws, &graph.block_ranges, &graph.succs, &graph.live_out, sig, &mut metas);
        out.metas = metas;
        out
    }

    fn solve_webs(
        &mut self,
        rws: &[RawRw],
        block_ranges: &[Range<usize>],
        succs: &[Vec<usize>],
        live_out: &[u16],
        sig: &FnSig,
        metas: &mut [InsnMeta],
    ) {
        let mut rd = ReachData::compute(self.insns.len(), rws, block_ranges, succs, sig);
        let mut uf = UnionFind::new(rd.defs.len());
        let mut read_sites: Vec<(usize, usize, usize)> = Vec::new();
        for (b, rng) in block_ranges.iter().enumerate() {
            let mut cur = rd.reach_in[b].clone();
            for i in rng.clone() {
                let mut reads_mask = rws[i].reads;
                let is_subword = rws[i].write_bytes > 0 && rws[i].write_bytes < 4 && !rws[i].is_zero;
                if is_subword {
                    for &(g, did) in &rd.ins_defs[i] {
                        if has_prior_nonzero(&rd.defs, &cur, g, sig) && rd.defs[did].max_read_bytes > rws[i].write_bytes
                        {
                            reads_mask |= 1 << g;
                            if g == 2 && rd.ins_defs[i].len() > 1 {
                                metas[i].rdx_partial_merge = Some(rws[i].write_bytes * 8);
                            } else {
                                metas[i].partial_merge = Some(rws[i].write_bytes * 8);
                            }
                        }
                    }
                }
                for g in 0..15 {
                    if (reads_mask & (1 << g)) == 0 {
                        continue;
                    }
                    let rdefs: Vec<usize> =
                        (0..rd.defs.len()).filter(|&d| rd.defs[d].gpr == g && bit_test(&cur, d)).collect();
                    if let Some(&first) = rdefs.first() {
                        for &d in &rdefs {
                            uf.union(first, d);
                            rd.defs[d].uses += 1;
                            rd.defs[d].single_user = if rd.defs[d].uses == 1 { Some(i) } else { None };
                        }
                        read_sites.push((i, g, first));
                    }
                }
                for &(g, did) in &rd.ins_defs[i] {
                    let is_pm = if g == 2 && rd.ins_defs[i].len() > 1 {
                        metas[i].rdx_partial_merge.is_some()
                    } else {
                        metas[i].partial_merge.is_some()
                    };
                    if is_pm {
                        for (d, dn) in rd.defs.iter().enumerate() {
                            if dn.gpr == g && bit_test(&cur, d) {
                                uf.union(did, d);
                            }
                        }
                    }
                    for (cw, &kw) in cur.iter_mut().zip(&rd.gpr_kill[g]) {
                        *cw &= !kw;
                    }
                    bit_set(&mut cur, did);
                }
                apply_clobbers(&mut cur, &rd.gpr_kill, rd.words, rws[i].clobbers & !rws[i].writes);
            }
        }
        crate::ssa_inline::finalize_webs_and_inlining(
            self,
            &mut uf,
            &rd.defs,
            &rd.ins_defs,
            &read_sites,
            rws,
            block_ranges,
            live_out,
            sig,
            metas,
        );
    }
}
