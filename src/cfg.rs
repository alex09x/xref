/*
 * xref — Ultra blazing fast cross-references of an x86-64 ELF binary
 * Copyright (c) 2026 Alexander Panasenko
 *
 * Contact: alex@prod.codes
 * Author: https://prod.codes/about/
 * SPDX-License-Identifier: MIT OR Apache-2.0
 */

//! Control-flow structuring: T1/T2 region reduction of basic blocks into structured `if`,
//! `if`/`else`, `while`, `do`/`while` and `switch` statements with dead-label elimination.

use std::collections::{BTreeMap, BTreeSet};

use crate::reduce::{coalesce_switches, effective_jump, is_stub, prune_unreachable, step_loops_and_jumps, trim_parens};

#[derive(Clone, PartialEq, Eq)]
pub enum Term {
    Fall,
    Jump(u64),
    Cond { cond: String, neg: String, target: u64 },
    Switch { idx: String, base: u64, arms: Vec<u64> },
    Return(String),
}

pub struct Block {
    pub start: u64,
    pub stmts: Vec<String>,
    pub term: Term,
}

pub fn indent(lines: &[String]) -> Vec<String> {
    lines.iter().map(|line| format!("  {line}")).collect()
}

fn wrap_if(cond: &str, then_body: &[String], else_body: Option<&[String]>) -> Vec<String> {
    let mut out = vec![format!("if ({}) {{", trim_parens(cond))];
    out.extend(indent(then_body));
    if let Some(els) = else_body {
        out.push("} else {".to_owned());
        out.extend(indent(els));
    }
    out.push("}".to_owned());
    out
}

fn preds(blocks: &[Block]) -> Vec<usize> {
    let mut counts = vec![0; blocks.len()];
    let mut add = |target: u64| {
        if let Ok(idx) = blocks.binary_search_by_key(&target, |b| b.start) {
            counts[idx] += 1;
        }
    };
    let mut stmt_targets = BTreeSet::new();
    for block in blocks {
        stmt_targets.extend(crate::loops::stmt_gotos(&block.stmts));
        match &block.term {
            Term::Jump(t) | Term::Cond { target: t, .. } => add(*t),
            Term::Switch { arms, .. } => {
                let unique: BTreeSet<u64> = arms.iter().copied().collect();
                for arm in unique {
                    add(arm);
                }
            }
            Term::Fall | Term::Return(_) => {}
        }
    }
    for addr in stmt_targets {
        add(addr);
    }
    counts
}

pub const fn can_fall(blocks: &[Block], idx: usize) -> bool {
    idx > 0 && matches!(blocks[idx - 1].term, Term::Fall | Term::Cond { .. })
}

fn lower_switch(blocks: &mut Vec<Block>, i: usize, p: &[usize]) {
    let Term::Switch { idx, base, arms } = blocks[i].term.clone() else { return };
    let mut groups: Vec<(u64, Vec<usize>)> = Vec::new();
    for (case_idx, &arm) in arms.iter().enumerate() {
        if let Some((_, list)) = groups.iter_mut().find(|(a, _)| *a == arm) {
            list.push(case_idx);
        } else {
            groups.push((arm, vec![case_idx]));
        }
    }
    let arm_cand = |arm: u64| {
        blocks.binary_search_by_key(&arm, |b| b.start).ok().filter(|&t| t != i && !can_fall(blocks, t) && p[t] == 1)
    };
    let inlined: BTreeSet<u64> = groups
        .iter()
        .filter_map(|&(arm, _)| {
            let t = arm_cand(arm)?;
            (matches!(blocks[t].term, Term::Return(_)) || effective_jump(blocks, t).is_some()).then_some(arm)
        })
        .collect();
    let next_start = blocks[i + 1..].iter().find(|b| !inlined.contains(&b.start)).map(|b| b.start);
    let mut join_counts: BTreeMap<u64, usize> = BTreeMap::new();
    for &(arm, ref cases) in &groups {
        if let Some(jmp) = arm_cand(arm).and_then(|t| effective_jump(blocks, t)) {
            *join_counts.entry(jmp).or_insert(0) += cases.len();
        }
    }
    let break_target = join_counts
        .into_iter()
        .max_by_key(|&(jmp, cnt)| (cnt, Some(jmp) == next_start))
        .map(|(jmp, _)| jmp)
        .or(next_start);
    let mut lines = vec![format!("switch ({}) {{ // table {base:#x}", trim_parens(&idx))];
    let mut removed = Vec::new();
    let mut has_break = false;
    for (arm, cases) in groups {
        let header: String = cases.iter().map(|c| format!("case {c} ({c:#x}):")).collect::<Vec<_>>().join(" ");
        let cand = arm_cand(arm);
        if let Some(t) = cand
            && let Term::Return(ref ret) = blocks[t].term
        {
            lines.push(format!("  {header}"));
            lines.extend(indent(&indent(&blocks[t].stmts)));
            if !ret.is_empty() {
                lines.push(format!("    {ret}"));
            }
            removed.push(arm);
            continue;
        }
        if let Some(t) = cand
            && let Some(jmp) = effective_jump(blocks, t)
        {
            lines.push(format!("  {header}"));
            lines.extend(indent(&indent(&blocks[t].stmts)));
            if Some(jmp) == break_target {
                lines.push("    break;".to_owned());
                has_break = true;
            } else {
                lines.push(format!("    goto L_{jmp:x};"));
            }
            removed.push(arm);
            continue;
        }
        lines.push(format!("  {header} goto L_{arm:x};"));
    }
    lines.push("}".to_owned());
    blocks[i].stmts.extend(lines);
    blocks[i].term =
        if has_break && let Some(bt) = break_target { Term::Jump(bt) } else { Term::Return(String::new()) };
    blocks.retain(|b| !removed.contains(&b.start));
}

fn step_diamonds(blocks: &mut Vec<Block>, p: &[usize]) -> bool {
    for i in 0..blocks.len() {
        let Term::Cond { ref cond, ref neg, target } = blocks[i].term else { continue };
        let excl = |t: usize, join: u64| {
            t > 0 && p[t] == 1 && ((t == i + 2 && blocks[i + 1].term == Term::Jump(join)) || !can_fall(blocks, t))
        };
        if i + 1 < blocks.len()
            && p[i + 1] == 0
            && let Some(join) = effective_jump(blocks, i + 1)
            && join != blocks[i].start
            && join != target
            && let Ok(t) = blocks.binary_search_by_key(&target, |b| b.start)
            && t != i
            && t != i + 1
            && effective_jump(blocks, t) == Some(join)
            && (excl(t, join) || (join > blocks[i].start && is_stub(&blocks[t], false)))
        {
            let neg = neg.clone();
            let (then_s, els_s, idx) = if excl(t, join) {
                let (b_hi, b_lo) = (blocks.remove(t.max(i + 1)), blocks.remove(t.min(i + 1)));
                let (then, els) = if t > i + 1 { (b_lo, b_hi) } else { (b_hi, b_lo) };
                (then.stmts, els.stmts, i - usize::from(t < i))
            } else {
                let els_stmts = blocks[t].stmts.clone();
                (blocks.remove(i + 1).stmts, els_stmts, i)
            };
            blocks[idx].stmts.extend(wrap_if(&neg, &then_s, Some(&els_s)));
            blocks[idx].term = Term::Jump(join);
            return true;
        }
        if i + 1 < blocks.len()
            && p[i + 1] > 0
            && is_stub(&blocks[i + 1], false)
            && let Some(join) = effective_jump(blocks, i + 1)
            && join > blocks[i].start
            && join != target
            && let Ok(t) = blocks.binary_search_by_key(&target, |b| b.start)
            && t != i
            && t != i + 1
            && effective_jump(blocks, t) == Some(join)
            && ((t > 0 && !can_fall(blocks, t) && p[t] == 1) || is_stub(&blocks[t], false))
        {
            let (cond, fall_stmts) = (cond.clone(), blocks[i + 1].stmts.clone());
            let (target_stmts, idx) = if t > 0 && !can_fall(blocks, t) && p[t] == 1 {
                (blocks.remove(t).stmts, i - usize::from(t < i))
            } else {
                (blocks[t].stmts.clone(), i)
            };
            blocks[idx].stmts.extend(wrap_if(&cond, &target_stmts, Some(&fall_stmts)));
            blocks[idx].term = Term::Jump(join);
            return true;
        }
    }
    false
}

fn step_ifs(blocks: &mut Vec<Block>, p: &[usize]) -> bool {
    for i in 0..blocks.len() {
        let Term::Cond { ref cond, ref neg, target } = blocks[i].term else { continue };
        if i + 1 < blocks.len() && p[i + 1] == 0 && effective_jump(blocks, i + 1) == Some(target) {
            let neg = neg.clone();
            let then = blocks.remove(i + 1);
            blocks[i].stmts.extend(wrap_if(&neg, &then.stmts, None));
            blocks[i].term = Term::Jump(target);
            return true;
        }
        if i + 2 < blocks.len()
            && blocks[i + 2].start == target
            && p[i + 1] == 0
            && matches!(blocks[i + 1].term, Term::Return(_))
        {
            let neg = neg.clone();
            let mut then = blocks.remove(i + 1);
            if let Term::Return(ret) = then.term
                && !ret.is_empty()
            {
                then.stmts.push(ret);
            }
            blocks[i].stmts.extend(wrap_if(&neg, &then.stmts, None));
            blocks[i].term = Term::Fall;
            return true;
        }
        let Some(t) = blocks.binary_search_by_key(&target, |b| b.start).ok().filter(|&t| t != i) else { continue };
        let scan_end = blocks.len().min(i + 96);
        let post_loop_cont = matches!(&blocks[t].term, Term::Return(r) if r.is_empty() || r != "unreachable();")
            && blocks[i + 1..scan_end].iter().any(|b| match b.term {
                Term::Jump(back) | Term::Cond { target: back, .. } => {
                    back <= blocks[i].start && blocks[t].start > b.start
                }
                _ => false,
            });
        if !post_loop_cont
            && t > 0
            && !can_fall(blocks, t)
            && p[t] == 1
            && (matches!(&blocks[t].term, Term::Return(r) if !r.is_empty())
                || (i + 1 < blocks.len() && effective_jump(blocks, t) == Some(blocks[i + 1].start)))
        {
            let cond = cond.clone();
            let mut blk = blocks.remove(t);
            if let Term::Return(ret) = blk.term {
                blk.stmts.push(ret);
            }
            let idx = usize::from(t < i);
            blocks[i - idx].stmts.extend(wrap_if(&cond, &blk.stmts, None));
            blocks[i - idx].term = Term::Fall;
            return true;
        }
        if !post_loop_cont
            && let Term::Return(ref ret) = blocks[t].term
            && !ret.is_empty()
            && is_stub(&blocks[t], true)
        {
            let cond = cond.clone();
            let mut stmts = blocks[t].stmts.clone();
            stmts.push(ret.clone());
            blocks[i].stmts.extend(wrap_if(&cond, &stmts, None));
            blocks[i].term = Term::Fall;
            return true;
        }
    }
    false
}

fn step_structured(blocks: &mut Vec<Block>) -> bool {
    prune_unreachable(blocks) || {
        let p = preds(blocks);
        step_loops_and_jumps(blocks, &p) || step_diamonds(blocks, &p) || step_ifs(blocks, &p)
    }
}

fn step_fallback(blocks: &mut Vec<Block>) -> bool {
    if crate::loops::step_region_loop(blocks) {
        return true;
    }
    let p = preds(blocks);
    for i in (0..blocks.len().saturating_sub(1)).rev() {
        if let Term::Cond { ref cond, target, .. } = blocks[i].term
            && target > blocks[i].start
            && p[i + 1] == 0
        {
            let line = format!("if ({}) goto L_{target:x};", trim_parens(cond));
            let next = blocks.remove(i + 1);
            blocks[i].stmts.push(line);
            blocks[i].stmts.extend(next.stmts);
            blocks[i].term = next.term;
            return true;
        }
    }
    if let Some(i) = blocks.iter().position(|b| matches!(b.term, Term::Switch { .. })) {
        lower_switch(blocks, i, &p);
        return true;
    }
    false
}

pub fn structure(mut blocks: Vec<Block>) -> Vec<String> {
    prune_unreachable(&mut blocks);
    coalesce_switches(&mut blocks);
    while step_structured(&mut blocks) || step_fallback(&mut blocks) {}
    for block in &mut blocks {
        match &block.term {
            Term::Return(ret) if !ret.is_empty() => block.stmts.push(ret.clone()),
            Term::Jump(t) => block.stmts.push(format!("goto L_{t:x};")),
            Term::Cond { cond, target, .. } => {
                block.stmts.push(format!("if ({}) goto L_{target:x};", trim_parens(cond)));
            }
            _ => {}
        }
    }
    let gotos: BTreeSet<u64> = blocks.iter().flat_map(|b| crate::loops::stmt_gotos(&b.stmts)).collect();
    let mut out = Vec::new();
    for (idx, block) in blocks.into_iter().enumerate() {
        if idx > 0 && gotos.contains(&block.start) {
            out.push(format!("L_{:x}:", block.start));
        }
        out.extend(indent(&block.stmts));
    }
    out
}

#[cfg(test)]
mod tests {
    use super::{Block, Term, structure, trim_parens};

    fn blk(start: u64, stmt: &str, term: Term) -> Block {
        Block { start, stmts: if stmt.is_empty() { Vec::new() } else { vec![stmt.to_owned()] }, term }
    }

    fn cnd(start: u64, stmt: &str, cond: &str, neg: &str, target: u64) -> Block {
        blk(start, stmt, Term::Cond { cond: cond.to_owned(), neg: neg.to_owned(), target })
    }

    #[test]
    fn structures_diamonds_loops_cold_returns_and_switches() {
        assert_eq!(trim_parens("(a == 0) || (b == 0)"), "(a == 0) || (b == 0)");
        let sw = Term::Switch { idx: "k".to_owned(), base: 0x2000, arms: vec![0x78, 0x78, 0x7c, 0x84, 0x94, 0x98] };
        let blocks = vec![
            cnd(0x10, "a = 1;", "x == 0", "x != 0", 0x30),
            blk(0x20, "b = 2;", Term::Jump(0x34)),
            blk(0x30, "b = 3;", Term::Fall),
            cnd(0x34, "chk();", "ok != 0", "ok == 0", 0x40),
            blk(0x38, "fail();", Term::Return("return 0;".to_owned())),
            cnd(0x40, "i += 1;", "i > 9", "i <= 9", 0x90),
            cnd(0x50, "s += i;", "i < 5", "i >= 5", 0x40),
            cnd(0x60, "c = 4;", "err != 0", "err == 0", 0x80),
            cnd(0x68, "c2 = 4;", "cold != 0", "cold == 0", 0x88),
            blk(0x70, "d = 5;", sw),
            blk(0x78, "e = 6;", Term::Jump(0x90)),
            blk(0x7c, "e2 = 7;", Term::Jump(0x98)),
            blk(0x80, "cleanup();", Term::Return("unreachable();".to_owned())),
            blk(0x84, "done();", Term::Return("return 3;".to_owned())),
            blk(0x88, "log_cold();", Term::Jump(0x70)),
            blk(0x90, "f = 7;", Term::Fall),
            cnd(0x94, "g = 8;", "g > 0", "g <= 0", 0x90),
            blk(0x98, "g2 = 8;", Term::Jump(0x90)),
        ];
        let text = structure(blocks).join("\n");
        assert!(text.contains("if (x != 0) {\n    b = 2;\n  } else {\n    b = 3;\n  }"));
        assert!(text.contains("do {\n    i += 1;\n    if (i > 9) goto L_90;\n    s += i;\n  } while (i < 5);"));
        assert!(text.contains("cleanup();\n    unreachable();") && text.contains("if (g > 0) goto L_90;"));
        assert!(text.contains("case 0 (0x0): case 1 (0x1):\n      e = 6;\n      break;"));
        let text2 = structure(vec![
            cnd(0x10, "a = 0;", "p == 0", "p != 0", 0x50),
            cnd(0x18, "b = 1;", "q != 0", "q == 0", 0x40),
            cnd(0x20, "c = 2;", "r == 0", "r != 0", 0x50),
            blk(0x28, "d = 3;", Term::Fall),
            blk(0x30, "r8 = 1;", Term::Jump(0x52)),
            cnd(0x40, "work();", "ok == 0", "ok != 0", 0x30),
            blk(0x50, "r8 = 0;", Term::Fall),
            cnd(0x52, "mid();", "n == 0", "n != 0", 0x5c),
            cnd(0x56, "chk2();", "m != 0", "m == 0", 0x88),
            blk(0x5c, "r9 = 0;", Term::Fall),
            cnd(0x60, "use(r8);", "z == 0", "z != 0", 0x80),
            cnd(0x61, "g0();", "v == 0", "v != 0", 0x64),
            blk(0x62, "g1();", Term::Fall),
            cnd(0x64, "chk3();", "u == 0", "u != 0", 0x99),
            cnd(0x66, "chk4();", "u2 == 0", "u2 != 0", 0x80),
            cnd(0x68, "more();", "w != 0", "w == 0", 0x78),
            blk(0x70, "fin();", Term::Jump(0x80)),
            blk(0x78, "alt();", Term::Jump(0x80)),
            blk(0x80, "", Term::Return("return rax;".to_owned())),
            blk(0x88, "only();", Term::Jump(0x60)),
        ])
        .join("\n");
        assert!(text2.contains("r8 = 1;") && text2.contains("g1();") && text2.contains("only();"), "{text2}");
    }
}
