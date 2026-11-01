/*
 * xref — Ultra blazing fast cross-references of an x86-64 ELF binary
 * Copyright (c) 2026 Alexander Panasenko
 *
 * Contact: alex@prod.codes
 * Author: https://prod.codes/about/
 * SPDX-License-Identifier: MIT OR Apache-2.0
 */

//! Control-flow graph reachability pruning, switch coalescing, short-circuit condition merging
//! and loop/jump region reductions.

use std::collections::{BTreeSet, VecDeque};

use crate::cfg::{Block, Term, can_fall, indent};

pub fn trim_parens(s: &str) -> &str {
    let bytes = s.as_bytes();
    if bytes.len() < 2 || bytes[0] != b'(' || bytes[bytes.len() - 1] != b')' {
        return s;
    }
    let mut depth = 0i32;
    for &b in &bytes[1..bytes.len() - 1] {
        depth += i32::from(b == b'(') - i32::from(b == b')');
        if depth < 0 {
            return s;
        }
    }
    if depth == 0 { &s[1..s.len() - 1] } else { s }
}

pub fn has_call(stmt: &str) -> bool {
    let bytes = stmt.as_bytes();
    bytes.windows(2).any(|w| (w[0].is_ascii_alphanumeric() || w[0] == b'_') && w[1] == b'(')
}

pub fn is_stub(block: &Block, allow_empty: bool) -> bool {
    (allow_empty || !block.stmts.is_empty())
        && block.stmts.len() <= 4
        && block.stmts.iter().all(|s| !s.contains('{') && !s.contains("goto ") && !has_call(s))
}

pub const fn effective_jump(blocks: &[Block], idx: usize) -> Option<u64> {
    match blocks[idx].term {
        Term::Jump(t) => Some(t),
        Term::Fall if idx + 1 < blocks.len() => Some(blocks[idx + 1].start),
        _ => None,
    }
}

pub fn rewrite_breaks(stmts: &mut [String], exit: u64) -> bool {
    let needle = format!("goto L_{exit:x};");
    let mut scopes: Vec<bool> = Vec::new();
    let mut changed = false;
    for line in stmts {
        let trimmed = line.trim_start();
        if trimmed.starts_with('}') {
            scopes.pop();
        }
        let breakable =
            trimmed.starts_with("do {") || trimmed.starts_with("while (") || trimmed.starts_with("switch (");
        if trimmed.ends_with('{') || trimmed.starts_with("switch (") {
            scopes.push(breakable);
        }
        if !scopes.iter().any(|&b| b) && line.ends_with(&needle) {
            let keep = line.len() - needle.len();
            line.truncate(keep);
            line.push_str("break;");
            changed = true;
        }
    }
    changed
}

pub fn prune_unreachable(blocks: &mut Vec<Block>) -> bool {
    if blocks.len() <= 1 {
        return false;
    }
    let before = blocks.len();
    let mut seen = vec![false; before];
    let mut queue = VecDeque::from([0usize]);
    seen[0] = true;
    let visit = |target: u64, seen: &mut [bool], queue: &mut VecDeque<usize>| {
        if let Ok(idx) = blocks.binary_search_by_key(&target, |b| b.start)
            && !seen[idx]
        {
            seen[idx] = true;
            queue.push_back(idx);
        }
    };
    while let Some(idx) = queue.pop_front() {
        for addr in crate::loops::stmt_gotos(&blocks[idx].stmts) {
            visit(addr, &mut seen, &mut queue);
        }
        match &blocks[idx].term {
            Term::Fall => {
                if idx + 1 < before && !seen[idx + 1] {
                    seen[idx + 1] = true;
                    queue.push_back(idx + 1);
                }
            }
            Term::Jump(t) => visit(*t, &mut seen, &mut queue),
            Term::Cond { target, .. } => {
                if idx + 1 < before && !seen[idx + 1] {
                    seen[idx + 1] = true;
                    queue.push_back(idx + 1);
                }
                visit(*target, &mut seen, &mut queue);
            }
            Term::Switch { arms, .. } => {
                let unique: BTreeSet<u64> = arms.iter().copied().collect();
                for arm in unique {
                    visit(arm, &mut seen, &mut queue);
                }
            }
            Term::Return(_) => {}
        }
    }
    let mut keep = seen.into_iter();
    blocks.retain(|_| keep.next().unwrap_or(false));
    blocks.len() < before
}

pub fn coalesce_switches(blocks: &mut Vec<Block>) {
    loop {
        let mut group: Option<(u64, Vec<u64>, Vec<usize>)> = None;
        for block in blocks.iter() {
            if let Term::Switch { base, ref arms, .. } = block.term {
                let members: Vec<usize> = blocks
                    .iter()
                    .enumerate()
                    .filter_map(|(j, b)| match &b.term {
                        Term::Switch { base: b2, arms: a2, .. } if *b2 == base && a2 == arms => Some(j),
                        _ => None,
                    })
                    .collect();
                if members.len() > 1 {
                    group = Some((base, arms.clone(), members));
                    break;
                }
            }
        }
        let Some((base, arms, members)) = group else { break };
        let last = *members.last().unwrap_or(&0);
        let exprs: Vec<String> = members
            .iter()
            .map(|&m| if let Term::Switch { ref idx, .. } = blocks[m].term { idx.clone() } else { String::new() })
            .collect();
        let same_idx = exprs.windows(2).all(|w| w[0] == w[1]);
        let mut sw_addr = blocks[last].start.saturating_add(1);
        while blocks.iter().any(|b| b.start == sw_addr) {
            sw_addr += 1;
        }
        let sw_idx = if same_idx { exprs[0].clone() } else { "sw_idx".to_owned() };
        for (&m, expr) in members.iter().zip(exprs) {
            if !same_idx {
                blocks[m].stmts.push(format!("sw_idx = {expr};"));
            }
            blocks[m].term = Term::Jump(sw_addr);
        }
        let pos = blocks.partition_point(|b| b.start < sw_addr);
        blocks.insert(pos, Block { start: sw_addr, stmts: Vec::new(), term: Term::Switch { idx: sw_idx, base, arms } });
    }
}

fn wrap_while(cond: &str, body: &[String]) -> Vec<String> {
    let mut out = vec![format!("while ({}) {{", trim_parens(cond))];
    out.extend(indent(body));
    out.push("}".to_owned());
    out
}

fn step_jumps_and_conds(blocks: &mut Vec<Block>, p: &[usize]) -> bool {
    for i in 0..blocks.len() {
        if let Term::Jump(target) = blocks[i].term
            && let Ok(t) = blocks.binary_search_by_key(&target, |b| b.start)
            && t != i
            && let Term::Return(ref ret) = blocks[t].term
            && is_stub(&blocks[t], true)
        {
            let (stmts, ret) = (blocks[t].stmts.clone(), ret.clone());
            blocks[i].stmts.extend(stmts);
            blocks[i].term = Term::Return(ret);
            return true;
        }
        if i + 1 < blocks.len() && blocks[i].term == Term::Jump(blocks[i + 1].start) {
            blocks[i].term = Term::Fall;
            return true;
        }
        if i + 1 < blocks.len() && blocks[i].term == Term::Fall && p[i + 1] == 0 {
            let next = blocks.remove(i + 1);
            blocks[i].stmts.extend(next.stmts);
            blocks[i].term = next.term;
            return true;
        }
        if let Term::Jump(target) = blocks[i].term
            && let Ok(t) = blocks.binary_search_by_key(&target, |b| b.start)
            && t != i
            && t > 0
            && !can_fall(blocks, t)
            && p[t] == 1
            && !matches!(blocks[t].term, Term::Cond { .. })
        {
            let fall_next = (blocks[t].term == Term::Fall).then(|| blocks.get(t + 1).map(|b| b.start)).flatten();
            let blk = blocks.remove(t);
            let idx = i - usize::from(t < i);
            blocks[idx].stmts.extend(blk.stmts);
            blocks[idx].term = match blk.term {
                Term::Fall => fall_next.map_or(Term::Fall, Term::Jump),
                other => other,
            };
            return true;
        }
        if i + 2 < blocks.len()
            && let Term::Cond { ref cond, ref neg, target } = blocks[i].term
            && target == blocks[i + 2].start
            && p[i + 1] == 0
            && blocks[i + 1].stmts.is_empty()
            && let Term::Jump(t2) = blocks[i + 1].term
            && t2 != target
        {
            let (new_c, new_n) = (neg.clone(), cond.clone());
            blocks.remove(i + 1);
            blocks[i].term = Term::Cond { cond: new_c, neg: new_n, target: t2 };
            return true;
        }
        if i + 1 < blocks.len()
            && p[i + 1] == 0
            && blocks[i + 1].stmts.is_empty()
            && let Term::Cond { ref cond, ref neg, target } = blocks[i].term
            && let Term::Cond { cond: ref c2, neg: ref n2, target: t2 } = blocks[i + 1].term
        {
            if target == t2 {
                let (mc, mn) = (format!("({cond} || {c2})"), format!("({neg} && {n2})"));
                blocks.remove(i + 1);
                blocks[i].term = Term::Cond { cond: mc, neg: mn, target };
                return true;
            }
            if i + 2 < blocks.len() && target == blocks[i + 2].start {
                let (mc, mn) = (format!("({neg} && {c2})"), format!("({cond} || {n2})"));
                blocks.remove(i + 1);
                blocks[i].term = Term::Cond { cond: mc, neg: mn, target: t2 };
                return true;
            }
        }
    }
    false
}

pub fn step_loops_and_jumps(blocks: &mut Vec<Block>, p: &[usize]) -> bool {
    if step_jumps_and_conds(blocks, p) {
        return true;
    }
    for i in 0..blocks.len() {
        if let Term::Cond { ref cond, target, .. } = blocks[i].term
            && target == blocks[i].start
        {
            let cond = cond.clone();
            if let Some(nx) = blocks.get(i + 1).map(|b| b.start) {
                rewrite_breaks(&mut blocks[i].stmts, nx);
            }
            let mut body = vec!["do {".to_owned()];
            body.extend(indent(&blocks[i].stmts));
            body.push(format!("}} while ({});", trim_parens(&cond)));
            blocks[i].stmts = body;
            blocks[i].term = Term::Fall;
            return true;
        }
        if i + 1 < blocks.len()
            && blocks[i].stmts.is_empty()
            && let Term::Cond { ref neg, target: exit, .. } = blocks[i].term
            && exit != blocks[i].start
            && exit != blocks[i + 1].start
            && p[i + 1] == 0
            && blocks[i + 1].term == Term::Jump(blocks[i].start)
        {
            let neg = neg.clone();
            let mut body = blocks.remove(i + 1);
            rewrite_breaks(&mut body.stmts, exit);
            blocks[i].stmts = wrap_while(&neg, &body.stmts);
            blocks[i].term = Term::Jump(exit);
            return true;
        }
        if blocks[i].term == Term::Jump(blocks[i].start) {
            if let Some(nx) = blocks.get(i + 1).map(|b| b.start)
                && rewrite_breaks(&mut blocks[i].stmts, nx)
            {
                blocks[i].stmts = wrap_while("1", &blocks[i].stmts);
                blocks[i].term = Term::Fall;
                return true;
            }
            let (head, tail) = blocks.split_at_mut(i + 1);
            let stmts = &mut head[i].stmts;
            if let Some(exit) = tail.iter().map(|b| b.start).find(|&e| rewrite_breaks(stmts, e)) {
                blocks[i].stmts = wrap_while("1", &blocks[i].stmts);
                blocks[i].term = Term::Jump(exit);
                return true;
            }
            blocks[i].stmts = wrap_while("1", &blocks[i].stmts);
            blocks[i].term = Term::Return(String::new());
            return true;
        }
    }
    false
}

#[cfg(test)]
mod tests {
    use super::{coalesce_switches, has_call, is_stub, prune_unreachable, rewrite_breaks};
    use crate::cfg::{Block, Term, structure};

    fn blk(start: u64, stmts: &[&str], term: Term) -> Block {
        Block { start, stmts: stmts.iter().map(|s| (*s).to_owned()).collect(), term }
    }

    #[test]
    fn helpers_switches_loops_and_compounds_reduce_cleanly() {
        assert!(has_call("rax = fn_1000(rdi);") && !has_call("*(u64 *)(rdi + 8) = (rsi + 1);"));
        assert!(is_stub(&blk(0x10, &[], Term::Return("return rax;".to_owned())), true));
        assert!(!is_stub(&blk(0x10, &[], Term::Jump(0x20)), false));
        let mut nested = vec![
            "if (a != 0) {".to_owned(),
            "  do {".to_owned(),
            "    if (b == 0) goto L_90;".to_owned(),
            "  } while (c != 0);".to_owned(),
            "  if (d == 0) goto L_90;".to_owned(),
            "}".to_owned(),
        ];
        assert!(rewrite_breaks(&mut nested, 0x90));
        assert!(nested[2].contains("goto L_90;") && nested[4].ends_with("break;"));

        let mut single = vec![blk(0x10, &["a = 1;"], Term::Return("return 0;".to_owned()))];
        assert!(!prune_unreachable(&mut single));

        // Coalesce duplicate switches with distinct index expressions and prune dead landing pad 0xf0
        let mut sw = vec![
            blk(0x10, &[], Term::Cond { cond: "p == 0".to_owned(), neg: "p != 0".to_owned(), target: 0x20 }),
            blk(0x14, &["x = 1;"], Term::Switch { idx: "i1".to_owned(), base: 0x500, arms: vec![0x30, 0x34] }),
            blk(0x20, &["x = 2;"], Term::Switch { idx: "i2".to_owned(), base: 0x500, arms: vec![0x30, 0x34] }),
            blk(0x21, &["pad = 0;"], Term::Return("return 9;".to_owned())),
            blk(0x30, &["y = 3;"], Term::Jump(0x40)),
            blk(0x34, &["y = 4;"], Term::Jump(0x40)),
            blk(0x40, &[], Term::Return("return y;".to_owned())),
            blk(0xf0, &["rax = _Unwind_Resume(rbx);"], Term::Return("unreachable();".to_owned())),
        ];
        coalesce_switches(&mut sw);
        let sw_text = structure(sw).join("\n");
        assert!(sw_text.contains("sw_idx = i1;") && sw_text.contains("sw_idx = i2;"), "{sw_text}");
        assert!(!sw_text.contains("goto ") && !sw_text.contains("_Unwind_Resume"), "{sw_text}");

        // Header-tested while, && / || merging, condition flip, out-of-line Jump, and while(1) modes
        let loop_text = structure(vec![
            blk(0x10, &[], Term::Cond { cond: "a == 0".to_owned(), neg: "a != 0".to_owned(), target: 0x40 }),
            blk(0x14, &[], Term::Cond { cond: "b == 0".to_owned(), neg: "b != 0".to_owned(), target: 0x40 }),
            blk(0x18, &[], Term::Cond { cond: "c == 0".to_owned(), neg: "c != 0".to_owned(), target: 0x24 }),
            blk(0x1c, &[], Term::Jump(0x40)),
            blk(0x24, &[], Term::Cond { cond: "d == 0".to_owned(), neg: "d != 0".to_owned(), target: 0x30 }),
            blk(0x28, &[], Term::Cond { cond: "e != 0".to_owned(), neg: "e == 0".to_owned(), target: 0x40 }),
            blk(0x30, &["ok = 1;"], Term::Jump(0x38)),
            blk(0x34, &["s1();", "s2();", "s3();"], Term::Return("return 9;".to_owned())),
            blk(0x38, &["ok += 1;"], Term::Cond { cond: "z != 0".to_owned(), neg: "z == 0".to_owned(), target: 0x34 }),
            blk(0x40, &[], Term::Cond { cond: "i >= n".to_owned(), neg: "i < n".to_owned(), target: 0x48 }),
            blk(0x44, &["i += 1;"], Term::Jump(0x40)),
            blk(0x48, &[], Term::Cond { cond: "skip != 0".to_owned(), neg: "skip == 0".to_owned(), target: 0x58 }),
            blk(0x50, &["k += 1;"], Term::Cond { cond: "k == 9".to_owned(), neg: "k != 9".to_owned(), target: 0x60 }),
            blk(0x54, &["step();"], Term::Jump(0x50)),
            blk(0x58, &["mid1();", "mid2();", "mid3();"], Term::Jump(0x60)),
            blk(0x60, &["m += 1;"], Term::Cond { cond: "m == 3".to_owned(), neg: "m != 3".to_owned(), target: 0x68 }),
            blk(0x62, &["mid_loop();"], Term::Fall),
            blk(0x64, &["tick();"], Term::Jump(0x60)),
            blk(
                0x68,
                &["done1();", "done2();", "done3();"],
                Term::Cond { cond: "q == 0".to_owned(), neg: "q != 0".to_owned(), target: 0x74 },
            ),
            blk(0x70, &["spin();"], Term::Jump(0x70)),
            blk(0x74, &[], Term::Return("return k;".to_owned())),
        ])
        .join("\n");
        assert!(loop_text.contains("while (i < n) {") && loop_text.contains("while (1) {"), "{loop_text}");
        assert!(loop_text.contains("if (k == 9) break;") && loop_text.contains("if (m == 3) break;"), "{loop_text}");
    }
}
