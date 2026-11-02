/*
 * xref — Ultra blazing fast cross-references of an x86-64 ELF binary
 * Copyright (c) 2026 Alexander Panasenko
 *
 * Contact: alex@prod.codes
 * Author: https://prod.codes/about/
 * SPDX-License-Identifier: MIT OR Apache-2.0
 */

//! Multi-block natural loop region detection and structuring (`while` and `do`/`while` with
//! scope-aware `break;` and `continue;` rewriting).

use std::collections::{BTreeMap, BTreeSet};

use crate::cfg::{Block, Term, can_fall, indent};
use crate::reduce::{effective_jump, has_call, rewrite_breaks, trim_parens};

pub fn rewrite_continues(stmts: &mut [String], head: u64) -> bool {
    let needle = format!("goto L_{head:x};");
    let mut loop_scopes: Vec<bool> = Vec::new();
    let mut changed = false;
    for line in stmts {
        let trimmed = line.trim_start();
        if trimmed.starts_with('}') {
            loop_scopes.pop();
        }
        let is_loop = trimmed.starts_with("do {") || trimmed.starts_with("while (");
        if trimmed.ends_with('{') || trimmed.starts_with("switch (") {
            loop_scopes.push(is_loop);
        }
        if !loop_scopes.iter().any(|&b| b) && line.ends_with(&needle) {
            let keep = line.len() - needle.len();
            line.truncate(keep);
            line.push_str("continue;");
            changed = true;
        }
    }
    changed
}

pub fn stmt_gotos(stmts: &[String]) -> Vec<u64> {
    let mut out = Vec::new();
    for line in stmts {
        if let Some(pos) = line.find("goto L_")
            && let Some(hex) = line[pos + 7..].strip_suffix(';')
            && let Ok(addr) = u64::from_str_radix(hex, 16)
        {
            out.push(addr);
        }
    }
    out
}

fn block_targets(block: &Block) -> Vec<u64> {
    let mut out = match &block.term {
        Term::Jump(t) | Term::Cond { target: t, .. } => vec![*t],
        Term::Switch { arms, .. } => arms.clone(),
        Term::Fall | Term::Return(_) => Vec::new(),
    };
    out.extend(stmt_gotos(&block.stmts));
    out
}

fn is_valid_loop_region(blocks: &[Block], targets: &[Vec<u64>], h: usize, l: usize) -> bool {
    if blocks[h..=l].iter().any(|b| matches!(b.term, Term::Switch { .. })) {
        return false;
    }
    let (lo, hi) = (blocks[h + 1].start, blocks[l].start);
    let interior: BTreeSet<u64> = blocks[h + 1..=l].iter().map(|b| b.start).collect();
    for (idx, bt) in targets.iter().enumerate() {
        if !(h..=l).contains(&idx) && bt.iter().any(|&t| t >= lo && t <= hi && interior.contains(&t)) {
            return false;
        }
    }
    for m in h..=l {
        let m_hi = blocks[m].start;
        if targets[m].iter().any(|&t| t >= lo && t <= m_hi && interior.contains(&t)) {
            return false;
        }
    }
    true
}

fn choose_exit(blocks: &[Block], targets: &[Vec<u64>], h: usize, l: usize) -> Option<u64> {
    let region: BTreeSet<u64> = blocks[h..=l].iter().map(|b| b.start).collect();
    if blocks[h].stmts.is_empty()
        && let Term::Cond { target, .. } = blocks[h].term
        && !region.contains(&target)
        && !targets[h + 1..=l].iter().any(|bt| bt.contains(&blocks[h + 1].start))
    {
        return Some(target);
    }
    let mut counts: BTreeMap<u64, usize> = BTreeMap::new();
    for bt in &targets[h..=l] {
        for &t in bt {
            if !region.contains(&t) {
                *counts.entry(t).or_default() += 1;
            }
        }
    }
    let next_start = blocks.get(l + 1).map(|b| b.start);
    if let Some(nx) = next_start
        && counts.contains_key(&nx)
    {
        return Some(nx);
    }
    counts.into_iter().max_by_key(|&(_, c)| c).map(|(addr, _)| addr)
}

fn find_best_natural(blocks: &[Block], targets: &[Vec<u64>]) -> Option<(usize, usize)> {
    let mut best: Option<(usize, usize)> = None;
    for h in 0..blocks.len() {
        let head = blocks[h].start;
        let max_l = blocks.len().min(h + 96);
        let Some(l) = (h + 1..max_l).rev().find(|&idx| match blocks[idx].term {
            Term::Jump(t) | Term::Cond { target: t, .. } => t == head,
            _ => false,
        }) else {
            continue;
        };
        if is_valid_loop_region(blocks, targets, h, l) && best.is_none_or(|(bh, bl)| l - h < bl - bh) {
            best = Some((h, l));
        }
    }
    best
}

pub fn step_region_loop(blocks: &mut Vec<Block>) -> bool {
    let targets: Vec<Vec<u64>> = blocks.iter().map(block_targets).collect();
    let best = find_best_natural(blocks, &targets);
    if let Some(rot) = crate::unrotate::find_best_rotated(blocks, &targets)
        && best.is_none_or(|(bh, bl)| rot.l - rot.h <= bl - bh)
    {
        crate::unrotate::reduce_rotated(blocks, &targets, rot);
        return true;
    }
    let Some((h, l)) = best else { return false };
    let head = blocks[h].start;
    let do_cond = match &blocks[l].term {
        Term::Cond { cond, target, .. } if *target == head => Some(cond.clone()),
        _ => None,
    };
    let exit_opt =
        if do_cond.is_some() { blocks.get(l + 1).map(|b| b.start) } else { choose_exit(blocks, &targets, h, l) };
    let pure_while_neg = if do_cond.is_none()
        && blocks[h].stmts.is_empty()
        && let Term::Cond { ref neg, target, .. } = blocks[h].term
        && Some(target) == exit_opt
        && !targets[h + 1..=l].iter().any(|bt| bt.contains(&blocks[h + 1].start))
    {
        Some(neg.clone())
    } else {
        None
    };

    let start_idx = h + usize::from(pure_while_neg.is_some());
    let mut chunks: Vec<(u64, Vec<String>)> = Vec::with_capacity(l - start_idx + 1);
    for idx in start_idx..=l {
        let mut lines = blocks[idx].stmts.clone();
        rewrite_continues(&mut lines, head);
        if let Some(exit) = exit_opt {
            rewrite_breaks(&mut lines, exit);
        }
        let next_in_region = (idx < l).then(|| blocks[idx + 1].start);
        match &blocks[idx].term {
            Term::Fall | Term::Switch { .. } => {}
            Term::Return(ret) => {
                if !ret.is_empty() {
                    lines.push(ret.clone());
                }
            }
            Term::Jump(t) => {
                if idx == l && *t == head || next_in_region == Some(*t) {
                } else if *t == head {
                    lines.push("continue;".to_owned());
                } else if Some(*t) == exit_opt {
                    lines.push("break;".to_owned());
                } else {
                    lines.push(format!("goto L_{t:x};"));
                }
            }
            Term::Cond { cond, target, .. } => {
                if (idx == l && *target == head) || next_in_region == Some(*target) {
                } else if *target == head {
                    lines.push(format!("if ({}) continue;", trim_parens(cond)));
                } else if Some(*target) == exit_opt {
                    lines.push(format!("if ({}) break;", trim_parens(cond)));
                } else {
                    lines.push(format!("if ({}) goto L_{target:x};", trim_parens(cond)));
                }
            }
        }
        chunks.push((blocks[idx].start, lines));
    }

    let joined: String = chunks.iter().flat_map(|(_, ls)| ls.iter().cloned()).collect::<Vec<_>>().join("\n");
    let mut body = Vec::new();
    for (pos, (addr, lines)) in chunks.into_iter().enumerate() {
        if pos > 0 && joined.contains(&format!("goto L_{addr:x};")) {
            body.push(format!("L_{addr:x}:"));
        }
        body.extend(lines);
    }

    if let Some(cond) = do_cond {
        let mut out = vec!["do {".to_owned()];
        out.extend(indent(&body));
        out.push(format!("}} while ({});", trim_parens(&cond)));
        blocks[h].stmts = out;
        blocks[h].term = Term::Fall;
    } else {
        let header = pure_while_neg.as_deref().map_or("1", trim_parens);
        let mut out = vec![format!("while ({header}) {{")];
        out.extend(indent(&body));
        out.push("}".to_owned());
        blocks[h].stmts = out;
        blocks[h].term = exit_opt.map_or(Term::Return(String::new()), Term::Jump);
    }
    blocks.drain(h + 1..=l);
    true
}

pub fn step_cond_prep(blocks: &mut Vec<Block>, p: &[usize]) -> bool {
    for i in 0..blocks.len().saturating_sub(1) {
        if p[i + 1] == 0 && blocks[i + 1].stmts.is_empty() && blocks[i + 1].term == Term::Fall {
            blocks.remove(i + 1);
            return true;
        }
        if let Term::Cond { ref neg, target, .. } = blocks[i].term
            && p[i + 1] == 0
            && blocks[i + 1].stmts.is_empty()
            && let Term::Return(ref ret) = blocks[i + 1].term
            && !ret.is_empty()
        {
            let body = if ret.contains("; ") { format!("{{ {ret} }}") } else { ret.clone() };
            let line = format!("if ({}) {body}", trim_parens(neg));
            blocks.remove(i + 1);
            blocks[i].stmts.push(line);
            blocks[i].term = Term::Jump(target);
            return true;
        }
        if let Term::Cond { ref cond, ref neg, target } = blocks[i].term
            && p[i + 1] == 0
            && let Ok(t) = blocks.binary_search_by_key(&target, |b| b.start)
            && t != i
            && t != i + 1
            && t > 0
            && !can_fall(blocks, t)
            && p[t] == 1
            && blocks[t].stmts.len() == 1
            && blocks[i + 1].stmts.first() == blocks[t].stmts.first()
            && let Some(join) = effective_jump(blocks, t)
            && let Some((lhs, _)) = blocks[t].stmts[0].split_once(" = ")
            && lhs.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_')
            && !has_call(&blocks[t].stmts[0])
            && !has_call(cond)
            && !cond.contains(['*', '['])
            && !cond.contains(lhs)
            && !neg.contains(lhs)
        {
            let (cond, neg) = (cond.clone(), neg.clone());
            let s0 = blocks[i + 1].stmts.remove(0);
            blocks.remove(t);
            let idx = i - usize::from(t < i);
            blocks[idx].stmts.push(s0);
            blocks[idx].term = Term::Cond { cond, neg, target: join };
            return true;
        }
    }
    false
}

pub fn step_cond_fallback(blocks: &mut Vec<Block>, p: &[usize]) -> bool {
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
    false
}

#[cfg(test)]
mod tests {
    use super::{rewrite_continues, step_region_loop};
    use crate::cfg::{Block, Term, structure};

    fn blk(start: u64, stmts: &[&str], term: Term) -> Block {
        Block { start, stmts: stmts.iter().map(|s| (*s).to_owned()).collect(), term }
    }

    #[test]
    fn structures_multiblock_while_dowhile_and_nested_continues() {
        let mut lines = vec![
            "switch (x) {".to_owned(),
            "  case 0: goto L_10;".to_owned(),
            "}".to_owned(),
            "while (y) {".to_owned(),
            "  if (z) goto L_10;".to_owned(),
            "}".to_owned(),
        ];
        assert!(rewrite_continues(&mut lines, 0x10));
        assert!(lines[1].ends_with("continue;") && lines[4].contains("goto L_10;"));

        // Rejects region with external jump into interior block 0x20
        let mut non_single_entry = vec![
            blk(0x00, &[], Term::Cond { cond: "ext".to_owned(), neg: "!ext".to_owned(), target: 0x20 }),
            blk(0x10, &["a = 1;"], Term::Fall),
            blk(0x20, &["b = 2;"], Term::Jump(0x10)),
        ];
        assert!(!step_region_loop(&mut non_single_entry));

        // Multi-block header-tested while with continue, early return, internal label, and exit break
        let blocks = vec![
            blk(0x10, &[], Term::Cond { cond: "i >= n".to_owned(), neg: "i < n".to_owned(), target: 0x60 }),
            blk(
                0x20,
                &["if (skip) goto L_10;"],
                Term::Cond { cond: "fast".to_owned(), neg: "!fast".to_owned(), target: 0x40 },
            ),
            blk(
                0x30,
                &["if (err) goto L_70;", "x = 1;"],
                Term::Cond { cond: "retry".to_owned(), neg: "!retry".to_owned(), target: 0x10 },
            ),
            blk(0x40, &["step();"], Term::Cond { cond: "stop".to_owned(), neg: "!stop".to_owned(), target: 0x60 }),
            blk(0x50, &["i = i + 1;"], Term::Jump(0x10)),
            blk(0x60, &["after();"], Term::Cond { cond: "ok".to_owned(), neg: "!ok".to_owned(), target: 0x80 }),
            blk(0x70, &[], Term::Return("return -1;".to_owned())),
            blk(0x80, &[], Term::Return("return i;".to_owned())),
        ];
        let text = structure(blocks).join("\n");
        assert!(text.contains("while (i < n) {") && text.contains("continue;") && text.contains("break;"), "{text}");

        let mut inf = vec![
            blk(0x10, &["tick();"], Term::Cond { cond: "done".to_owned(), neg: "!done".to_owned(), target: 0x50 }),
            blk(0x18, &["f();"], Term::Fall),
            blk(0x20, &["t1();"], Term::Jump(0x10)),
            blk(0x28, &[], Term::Return("return 9;".to_owned())),
            blk(0x30, &["t2();"], Term::Jump(0x50)),
            blk(0x38, &["t3();"], Term::Jump(0x60)),
            blk(0x40, &["t4();"], Term::Jump(0x10)),
            blk(0x50, &[], Term::Return("return 1;".to_owned())),
            blk(0x60, &[], Term::Return("return 2;".to_owned())),
        ];
        assert!(step_region_loop(&mut inf));
        assert!(inf[0].stmts.join("\n").contains("while (1) {"));
        let mut sw_in_loop = vec![
            blk(0x10, &[], Term::Switch { idx: "k".to_owned(), base: 0, arms: vec![0x20] }),
            blk(0x20, &[], Term::Jump(0x10)),
        ];
        assert!(!step_region_loop(&mut sw_in_loop));
        let mut inner_back = vec![
            blk(0x10, &[], Term::Cond { cond: "e".to_owned(), neg: "!e".to_owned(), target: 0x30 }),
            blk(0x20, &[], Term::Fall),
            blk(0x30, &[], Term::Cond { cond: "c".to_owned(), neg: "!c".to_owned(), target: 0x20 }),
            blk(0x40, &[], Term::Jump(0x10)),
        ];
        assert!(!step_region_loop(&mut inner_back));

        // Multi-block do-while latch
        let dw = vec![
            blk(0x10, &["a();"], Term::Cond { cond: "skip".to_owned(), neg: "!skip".to_owned(), target: 0x30 }),
            blk(0x20, &["if (bad) goto L_40;", "b();"], Term::Jump(0x30)),
            blk(0x30, &["c();"], Term::Cond { cond: "more".to_owned(), neg: "!more".to_owned(), target: 0x10 }),
            blk(0x40, &[], Term::Return("return 0;".to_owned())),
        ];
        let dw_text = structure(dw).join("\n");
        assert!(dw_text.contains("do {") && dw_text.contains("} while (more);"), "{dw_text}");

        // Common-prefix hoist + empty-Return cond inversion + header-exit preference
        let hoisted = structure(vec![
            blk(0x10, &[], Term::Cond { cond: "n != 1".to_owned(), neg: "n == 1".to_owned(), target: 0x30 }),
            blk(0x18, &["c = *p;"], Term::Cond { cond: "c == 43".to_owned(), neg: "c != 43".to_owned(), target: 0x60 }),
            blk(0x20, &[], Term::Fall),
            blk(0x28, &[], Term::Jump(0x40)),
            blk(0x30, &["c = *p;"], Term::Fall),
            blk(0x40, &["use(c);"], Term::Return("return 1;".to_owned())),
            blk(0x60, &[], Term::Return("return 0;".to_owned())),
        ])
        .join("\n");
        assert!(hoisted.contains("c = *p;\n  if (n != 1 || c != 43) {\n    use(c);"), "{hoisted}");
    }
}
