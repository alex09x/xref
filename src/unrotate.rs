/*
 * xref — Ultra blazing fast cross-references of an x86-64 ELF binary
 * Copyright (c) 2026 Alexander Panasenko
 *
 * Contact: alex@prod.codes
 * Author: https://prod.codes/about/
 * Project: https://github.com/alex09x/xref
 * SPDX-License-Identifier: MIT OR Apache-2.0
 */

//! Detection and structuring of compiler loop-rotated regions (`goto L_entry; L_latch: ... L_entry:`).

use std::collections::{BTreeMap, BTreeSet};

use crate::cfg::{Block, Term, structure};
use crate::loops::{rewrite_continues, stmt_gotos};
use crate::reduce::{rewrite_breaks, trim_parens};

#[derive(Clone, Copy, Debug)]
pub struct RotatedLoop {
    pub p_idx: usize,
    pub h: usize,
    pub m: usize,
    pub l: usize,
}

fn is_valid_rotated(blocks: &[Block], targets: &[Vec<u64>], p_idx: usize, m: usize, l: usize) -> bool {
    let h = p_idx + 1;
    let entry_addr = blocks[m].start;
    if blocks[h..=l].iter().any(|b| matches!(b.term, Term::Switch { .. })) {
        return false;
    }
    if matches!(blocks[l].term, Term::Fall | Term::Cond { .. }) && l + 1 >= blocks.len() {
        return false;
    }
    let latch_reaches_entry = matches!(blocks[m - 1].term, Term::Fall | Term::Cond { .. })
        || targets[h..m].iter().any(|bt| bt.contains(&entry_addr));
    if !latch_reaches_entry {
        return false;
    }
    let region: BTreeSet<u64> = blocks[h..=l].iter().map(|b| b.start).collect();
    if stmt_gotos(&blocks[p_idx].stmts).iter().any(|t| region.contains(t)) {
        return false;
    }
    for (idx, bt) in targets.iter().enumerate() {
        if !(p_idx..=l).contains(&idx) && bt.iter().any(|t| region.contains(t)) {
            return false;
        }
    }
    let latch_lo = blocks[h].start;
    let body_tail = (m < l).then(|| (blocks[m + 1].start, blocks[l].start));
    for (k, bt) in targets.iter().enumerate().take(m).skip(h) {
        let latch_hi = blocks[k].start;
        for &t in bt {
            if !region.contains(&t) {
                continue;
            }
            if (latch_lo..=latch_hi).contains(&t) || body_tail.is_some_and(|(blo, bhi)| (blo..=bhi).contains(&t)) {
                return false;
            }
        }
    }
    true
}

pub fn find_best_rotated(blocks: &[Block], targets: &[Vec<u64>]) -> Option<RotatedLoop> {
    let mut best: Option<RotatedLoop> = None;
    for p_idx in 0..blocks.len().saturating_sub(2) {
        let Term::Jump(entry_addr) = blocks[p_idx].term else { continue };
        let h = p_idx + 1;
        let max_m = (h + 8).min(blocks.len() - 1);
        let Some(m) = (h + 1..=max_m).find(|&idx| blocks[idx].start == entry_addr) else { continue };
        let latch_addrs: BTreeSet<u64> = blocks[h..m].iter().map(|b| b.start).collect();
        let max_l = blocks.len().min(h + 96);
        let Some(mut l) = (m..max_l).rev().find(|&idx| match blocks[idx].term {
            Term::Jump(t) | Term::Cond { target: t, .. } => latch_addrs.contains(&t),
            _ => false,
        }) else {
            continue;
        };
        let init_hi = blocks[l].start;
        let latch_exits: BTreeSet<u64> = targets[h..m].iter().flatten().copied().filter(|&t| t > init_hi).collect();
        let ext_limit =
            blocks[l + 1..max_l].iter().position(|b| latch_exits.contains(&b.start)).map_or(max_l, |off| l + 1 + off);
        while let Some(q) = (l + 1..ext_limit).rev().find(|&idx| {
            let (lo, hi) = (blocks[h].start, blocks[l].start);
            targets[idx].iter().any(|&t| (lo..=hi).contains(&t))
        }) {
            l = q;
        }
        if is_valid_rotated(blocks, targets, p_idx, m, l) && best.as_ref().is_none_or(|b| l - h < b.l - b.h) {
            best = Some(RotatedLoop { p_idx, h, m, l });
        }
    }
    best
}

fn choose_rotated_exit(blocks: &[Block], targets: &[Vec<u64>], h: usize, l: usize) -> Option<u64> {
    let region: BTreeSet<u64> = blocks[h..=l].iter().map(|b| b.start).collect();
    let mut counts: BTreeMap<u64, usize> = BTreeMap::new();
    for bt in &targets[h..=l] {
        for &t in bt {
            if !region.contains(&t) {
                *counts.entry(t).or_default() += 1;
            }
        }
    }
    let next_start = blocks.get(l + 1).map(|b| b.start);
    if matches!(blocks[l].term, Term::Fall | Term::Cond { .. })
        && let Some(nx) = next_start
    {
        *counts.entry(nx).or_default() += 1;
    }
    if let Some(nx) = next_start
        && counts.contains_key(&nx)
    {
        return Some(nx);
    }
    counts.into_iter().max_by_key(|&(_, c)| c).map(|(addr, _)| addr)
}

fn exit_stmt(target: u64, exit_opt: Option<u64>) -> String {
    if Some(target) == exit_opt { "break;".to_owned() } else { format!("goto L_{target:x};") }
}

fn remap_latch_gotos(lines: &mut [String], latch_map: &[(u64, u64)]) {
    for &(orig, synth) in latch_map {
        let needle = format!("goto L_{orig:x};");
        let repl = format!("goto L_{synth:x};");
        for line in &mut *lines {
            if line.ends_with(&needle) {
                let keep = line.len() - needle.len();
                line.replace_range(keep.., &repl);
            }
        }
    }
}

fn unmap_synth_labels(lines: &mut [String], latch_map: &[(u64, u64)]) {
    for line in &mut *lines {
        if line.starts_with("L_") {
            line.insert_str(0, "  ");
        }
        for &(orig, synth) in latch_map {
            let synth_lbl = format!("L_{synth:x}:");
            let synth_gt = format!("goto L_{synth:x};");
            let synth_skip = format!("skip_{synth:x}");
            if line.trim_start() == synth_lbl {
                let pad = line.len() - line.trim_start().len();
                line.replace_range(pad.., &format!("L_{orig:x}:"));
            } else if line.ends_with(&synth_gt) {
                let keep = line.len() - synth_gt.len();
                line.replace_range(keep.., &format!("goto L_{orig:x};"));
            } else if line.contains(&synth_skip) {
                *line = line.replace(&synth_skip, &format!("skip_{orig:x}"));
            }
        }
    }
}

struct LowerCtx<'a> {
    m: usize,
    l: usize,
    entry_addr: u64,
    after_l: u64,
    exit_opt: Option<u64>,
    has_do_while: bool,
    region: &'a BTreeSet<u64>,
    latch_map: &'a [(u64, u64)],
}

impl LowerCtx<'_> {
    fn remap(&self, addr: u64) -> u64 {
        self.latch_map.iter().find_map(|&(orig, synth)| (orig == addr).then_some(synth)).unwrap_or(addr)
    }

    fn lower_term(&self, idx: usize, term: &Term, stmts: &mut Vec<String>) -> Term {
        if idx == self.l {
            return match term {
                Term::Fall => Term::Return(exit_stmt(self.after_l, self.exit_opt)),
                Term::Return(ret) => Term::Return(ret.clone()),
                Term::Jump(t) if *t == self.entry_addr => Term::Return("continue;".to_owned()),
                Term::Jump(t) if self.region.contains(t) => Term::Jump(self.remap(*t)),
                Term::Jump(t) => Term::Return(exit_stmt(*t, self.exit_opt)),
                Term::Cond { cond, neg, target } => {
                    if self.region.contains(target) {
                        stmts.push(format!("if ({}) {}", trim_parens(neg), exit_stmt(self.after_l, self.exit_opt)));
                        Term::Jump(self.remap(*target))
                    } else {
                        stmts.push(format!("if ({}) {}", trim_parens(cond), exit_stmt(*target, self.exit_opt)));
                        Term::Return(exit_stmt(self.after_l, self.exit_opt))
                    }
                }
                Term::Switch { .. } => Term::Fall,
            };
        }
        if idx == self.m - 1 {
            return match term {
                Term::Fall | Term::Switch { .. } => Term::Fall,
                Term::Return(ret) => Term::Return(ret.clone()),
                Term::Jump(t) if *t == self.entry_addr => Term::Fall,
                Term::Jump(t) => Term::Return(exit_stmt(*t, self.exit_opt)),
                Term::Cond { cond, target, .. } => {
                    if !self.has_do_while && *target != self.entry_addr {
                        stmts.push(format!("if ({}) {}", trim_parens(cond), exit_stmt(*target, self.exit_opt)));
                    }
                    Term::Fall
                }
            };
        }
        match term {
            Term::Fall | Term::Switch { .. } => Term::Fall,
            Term::Return(ret) => Term::Return(ret.clone()),
            Term::Jump(t) if *t == self.entry_addr => Term::Return("continue;".to_owned()),
            Term::Jump(t) if self.region.contains(t) => Term::Jump(self.remap(*t)),
            Term::Jump(t) => Term::Return(exit_stmt(*t, self.exit_opt)),
            Term::Cond { cond, neg, target } => {
                if *target == self.entry_addr {
                    stmts.push(format!("if ({}) continue;", trim_parens(cond)));
                    Term::Fall
                } else if self.region.contains(target) {
                    Term::Cond { cond: cond.clone(), neg: neg.clone(), target: self.remap(*target) }
                } else {
                    stmts.push(format!("if ({}) {}", trim_parens(cond), exit_stmt(*target, self.exit_opt)));
                    Term::Fall
                }
            }
        }
    }
}

pub fn reduce_rotated(blocks: &mut Vec<Block>, targets: &[Vec<u64>], rot: RotatedLoop) {
    let RotatedLoop { p_idx, h, m, l } = rot;
    let entry_addr = blocks[m].start;
    let exit_opt = choose_rotated_exit(blocks, targets, h, l);
    let do_while_neg = if let Term::Cond { ref neg, target, .. } = blocks[m - 1].term
        && Some(target) == exit_opt
        && !targets[h..=l].iter().any(|bt| bt.contains(&entry_addr))
    {
        Some(neg.clone())
    } else {
        None
    };

    let region: BTreeSet<u64> = blocks[h..=l].iter().map(|b| b.start).collect();
    let synth_base = (blocks.last().map_or(0, |b| b.start) + 0x10_0000) | 0x100_0000;
    let latch_map: Vec<(u64, u64)> =
        (h..m).map(|k| (blocks[k].start, synth_base + u64::try_from(k - h).unwrap_or(0) * 0x10)).collect();
    let ctx = LowerCtx {
        m,
        l,
        entry_addr,
        after_l: blocks.get(l + 1).map_or(0, |b| b.start),
        exit_opt,
        has_do_while: do_while_neg.is_some(),
        region: &region,
        latch_map: &latch_map,
    };

    let mut sub_blocks = Vec::with_capacity(l - h + 1);
    for idx in (m..=l).chain(h..m) {
        let start = ctx.remap(blocks[idx].start);
        let mut stmts = blocks[idx].stmts.clone();
        rewrite_continues(&mut stmts, entry_addr);
        if let Some(exit) = exit_opt {
            rewrite_breaks(&mut stmts, exit);
        }
        remap_latch_gotos(&mut stmts, &latch_map);
        let term = ctx.lower_term(idx, &blocks[idx].term, &mut stmts);
        sub_blocks.push(Block { start, stmts, term });
    }

    let mut body = structure(sub_blocks);
    unmap_synth_labels(&mut body, &latch_map);
    crate::goto_elim::strip_trailing_continue_label(&mut body);
    if let Some(neg) = do_while_neg {
        blocks[p_idx].stmts.push("do {".to_owned());
        blocks[p_idx].stmts.extend(body);
        blocks[p_idx].stmts.push(format!("}} while ({});", trim_parens(&neg)));
    } else {
        blocks[p_idx].stmts.push("while (1) {".to_owned());
        blocks[p_idx].stmts.extend(body);
        blocks[p_idx].stmts.push("}".to_owned());
    }
    blocks[p_idx].term = exit_opt.map_or(Term::Return(String::new()), Term::Jump);
    blocks.drain(h..=l);
}

#[cfg(test)]
mod tests {
    use crate::cfg::{Block, Term, structure};

    fn blk(start: u64, stmts: &[&str], term: Term) -> Block {
        Block { start, stmts: stmts.iter().map(|s| (*s).to_owned()).collect(), term }
    }

    #[test]
    fn structures_three_store_vec_epilogue_early_guards_without_goto() {
        let blocks = vec![
            blk(
                0x10,
                &["sp_90 = rdi;", "sp_20 = 0;"],
                Term::Cond { cond: "len == 0".to_owned(), neg: "len != 0".to_owned(), target: 0x90 },
            ),
            blk(
                0x20,
                &["r9 = rcx - 1;"],
                Term::Cond { cond: "r9 >= 0".to_owned(), neg: "r9 < 0".to_owned(), target: 0x40 },
            ),
            blk(0x30, &["sp_20 = 0;"], Term::Jump(0x90)),
            blk(0x40, &["sp_20 = work(r9);"], Term::Jump(0x90)),
            blk(
                0x90,
                &["*(u64 *)(sp_90 + 16) = sp_20;", "*(u64 *)(sp_90) = 0;", "*(u64 *)(sp_90 + 8) = 8;"],
                Term::Return("return sp_90;".to_owned()),
            ),
        ];
        let joined = structure(blocks).join("\n");
        assert!(!joined.contains("goto "), "{joined}");
        assert!(joined.contains("if (len == 0) {") && joined.contains("if (r9 < 0) {"), "{joined}");
    }

    #[test]
    fn structures_rotated_latch_before_entry_without_goto() {
        let blocks = vec![
            blk(0x10, &["p = start;"], Term::Jump(0x30)),
            blk(
                0x20,
                &["p += 24;"],
                Term::Cond { cond: "p == end".to_owned(), neg: "p != end".to_owned(), target: 0x50 },
            ),
            blk(
                0x30,
                &["tag = *p;"],
                Term::Cond { cond: "tag == 0".to_owned(), neg: "tag != 0".to_owned(), target: 0x20 },
            ),
            blk(0x40, &["push(p);"], Term::Jump(0x20)),
            blk(0x50, &["*out = p;"], Term::Return("return out;".to_owned())),
        ];
        let joined = structure(blocks).join("\n");
        assert!(!joined.contains("goto "), "{joined}");
        assert!(joined.contains("do {") && joined.contains("} while (p != end);"), "{joined}");
        assert!(joined.contains("if (tag != 0) {"), "{joined}");
    }

    #[test]
    fn ignores_cold_return_island_placed_before_target() {
        let blocks = vec![
            blk(0x10, &["x = init();"], Term::Jump(0x30)),
            blk(0x20, &["panic_cold();"], Term::Return("return 0;".to_owned())),
            blk(
                0x30,
                &["y = check(x);"],
                Term::Cond { cond: "y == 0".to_owned(), neg: "y != 0".to_owned(), target: 0x20 },
            ),
            blk(0x40, &[], Term::Return("return y;".to_owned())),
        ];
        let joined = structure(blocks).join("\n");
        assert!(!joined.contains("do {") && !joined.contains("while ("), "{joined}");
    }

    #[test]
    fn structures_multiblock_latch_and_out_of_line_body_tail() {
        let blocks = vec![
            blk(0x10, &["p = s;"], Term::Jump(0x40)),
            blk(0x20, &["push(v);"], Term::Fall),
            blk(0x30, &["p += 8;"], Term::Cond { cond: "p == e".to_owned(), neg: "p != e".to_owned(), target: 0x80 }),
            blk(0x40, &["v = *p;"], Term::Cond { cond: "v == 0".to_owned(), neg: "v != 0".to_owned(), target: 0x30 }),
            blk(0x50, &[], Term::Cond { cond: "cap == 0".to_owned(), neg: "cap != 0".to_owned(), target: 0x70 }),
            blk(0x60, &["store(v);"], Term::Jump(0x20)),
            blk(0x70, &["reserve();"], Term::Jump(0x60)),
            blk(0x80, &["done = 1;"], Term::Return("return done;".to_owned())),
        ];
        let joined = structure(blocks).join("\n");
        assert!(!joined.contains("goto L_40;") && joined.matches("L_20:").count() <= 1, "{joined}");
        assert!(joined.contains("do {") && joined.contains("} while (p != e);"), "{joined}");
    }
}
