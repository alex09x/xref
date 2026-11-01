/*
 * xref — Ultra blazing fast cross-references of an x86-64 ELF binary
 * Copyright (c) 2026 Alexander Panasenko
 *
 * Contact: alex@prod.codes
 * Author: https://prod.codes/about/
 * SPDX-License-Identifier: MIT OR Apache-2.0
 */

//! Control-flow structuring: T1/T2 region reduction of basic blocks into structured `if`,
//! `if`/`else`, `do`/`while` and `switch` statements with dead-label elimination.

use std::collections::BTreeSet;

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

fn indent(lines: &[String]) -> Vec<String> {
    lines.iter().map(|line| format!("  {line}")).collect()
}

fn wrap_if(cond: &str, then_body: &[String], else_body: Option<&[String]>) -> Vec<String> {
    let mut out = vec![format!("if ({cond}) {{")];
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
        if let Some(idx) = blocks.iter().position(|b| b.start == target) {
            counts[idx] += 1;
        }
    };
    for block in blocks {
        let label = format!("goto L_{:x};", block.start);
        if blocks.iter().any(|b| b.stmts.iter().any(|s| s.contains(&label))) {
            add(block.start);
        }
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
    counts
}

const fn can_fall(blocks: &[Block], idx: usize) -> bool {
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
    let mut lines = vec![format!("switch ({idx}) {{ // table {base:#x}")];
    let mut removed = Vec::new();
    let mut all_return = true;
    for (arm, cases) in groups {
        let header: String = cases.iter().map(|c| format!("case {c} ({c:#x}):")).collect::<Vec<_>>().join(" ");
        let cand = blocks.iter().position(|b| b.start == arm).filter(|&t| t != i && !can_fall(blocks, t) && p[t] == 1);
        if let Some(t) = cand
            && let Term::Return(ref ret) = blocks[t].term
        {
            lines.push(format!("  {header}"));
            for s in indent(&indent(&blocks[t].stmts)) {
                lines.push(s);
            }
            lines.push(format!("    {ret}"));
            removed.push(arm);
            continue;
        }
        if let Some(t) = cand
            && matches!(blocks[t].term, Term::Fall | Term::Jump(_))
        {
            lines.push(format!("  {header}"));
            for s in indent(&indent(&blocks[t].stmts)) {
                lines.push(s);
            }
            lines.push("    break;".to_owned());
            removed.push(arm);
            all_return = false;
            continue;
        }
        lines.push(format!("  {header} goto L_{arm:x};"));
        all_return = false;
    }
    lines.push("}".to_owned());
    blocks[i].stmts.extend(lines);
    blocks[i].term = if all_return { Term::Return(String::new()) } else { Term::Fall };
    blocks.retain(|b| !removed.contains(&b.start));
}

fn step_structured(blocks: &mut Vec<Block>) -> bool {
    let p = preds(blocks);
    for i in 0..blocks.len() {
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
        if let Term::Cond { ref cond, target, .. } = blocks[i].term
            && target == blocks[i].start
        {
            let cond = cond.clone();
            let mut body = vec!["do {".to_owned()];
            body.extend(indent(&blocks[i].stmts));
            body.push(format!("}} while ({cond});"));
            blocks[i].stmts = body;
            blocks[i].term = Term::Fall;
            return true;
        }
        if i + 2 < blocks.len()
            && let Term::Cond { ref neg, target, .. } = blocks[i].term
            && blocks[i + 2].start == target
            && p[i + 1] == 0
            && p[i + 2] == 1
            && let Term::Jump(join) = blocks[i + 1].term
            && (blocks[i + 2].term == Term::Jump(join)
                || (blocks[i + 2].term == Term::Fall && i + 3 < blocks.len() && blocks[i + 3].start == join))
        {
            let neg = neg.clone();
            let els = blocks.remove(i + 2);
            let then = blocks.remove(i + 1);
            blocks[i].stmts.extend(wrap_if(&neg, &then.stmts, Some(&els.stmts)));
            blocks[i].term = Term::Jump(join);
            return true;
        }
        if i + 2 < blocks.len()
            && let Term::Cond { ref neg, target, .. } = blocks[i].term
            && blocks[i + 2].start == target
            && p[i + 1] == 0
            && matches!(blocks[i + 1].term, Term::Fall | Term::Return(_))
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
        if let Term::Cond { ref cond, target, .. } = blocks[i].term
            && let Some(t) = blocks.iter().position(|b| b.start == target)
            && t != i
            && !can_fall(blocks, t)
            && p[t] == 1
            && (matches!(blocks[t].term, Term::Return(_))
                || (i + 1 < blocks.len() && blocks[t].term == Term::Jump(blocks[i + 1].start)))
        {
            let cond = cond.clone();
            let mut blk = blocks.remove(t);
            if let Term::Return(ret) = blk.term
                && !ret.is_empty()
            {
                blk.stmts.push(ret);
            }
            let idx = usize::from(t < i);
            blocks[i - idx].stmts.extend(wrap_if(&cond, &blk.stmts, None));
            blocks[i - idx].term = Term::Fall;
            return true;
        }
    }
    false
}

fn step_fallback(blocks: &mut Vec<Block>) -> bool {
    let p = preds(blocks);
    for i in (0..blocks.len().saturating_sub(1)).rev() {
        if let Term::Cond { ref cond, target, .. } = blocks[i].term
            && target > blocks[i].start
            && p[i + 1] == 0
        {
            let line = format!("if ({cond}) goto L_{target:x};");
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
    while step_structured(&mut blocks) || step_fallback(&mut blocks) {}
    for block in &mut blocks {
        match &block.term {
            Term::Return(ret) if !ret.is_empty() => block.stmts.push(ret.clone()),
            Term::Jump(t) => block.stmts.push(format!("goto L_{t:x};")),
            Term::Cond { cond, target, .. } => block.stmts.push(format!("if ({cond}) goto L_{target:x};")),
            _ => {}
        }
    }
    let all_text: String = blocks.iter().flat_map(|b| b.stmts.iter()).cloned().collect::<Vec<_>>().join("\n");
    let mut out = Vec::new();
    for (idx, block) in blocks.into_iter().enumerate() {
        if idx > 0 && all_text.contains(&format!("goto L_{:x};", block.start)) {
            out.push(format!("L_{:x}:", block.start));
        }
        out.extend(indent(&block.stmts));
    }
    out
}

#[cfg(test)]
mod tests {
    use super::{Block, Term, structure};

    fn blk(start: u64, stmt: &str, term: Term) -> Block {
        Block { start, stmts: vec![stmt.to_owned()], term }
    }

    #[test]
    fn structures_diamonds_loops_cold_returns_and_switches() {
        let blocks = vec![
            // 0x10: if/else diamond (0x20 vs 0x30 -> join 0x34) + inline early-return if (0x34 -> 0x38 -> 0x40)
            blk(0x10, "a = 1;", Term::Cond { cond: "x == 0".to_owned(), neg: "x != 0".to_owned(), target: 0x30 }),
            blk(0x20, "b = 2;", Term::Jump(0x34)),
            blk(0x30, "b = 3;", Term::Fall),
            blk(0x34, "chk();", Term::Cond { cond: "ok != 0".to_owned(), neg: "ok == 0".to_owned(), target: 0x40 }),
            blk(0x38, "fail();", Term::Return("return 0;".to_owned())),
            // 0x40: loop header with internal exit (unstructured Cond fallthrough merge -> self-loop do/while)
            blk(0x40, "i += 1;", Term::Cond { cond: "i > 9".to_owned(), neg: "i <= 9".to_owned(), target: 0x90 }),
            blk(0x50, "s += i;", Term::Cond { cond: "i < 5".to_owned(), neg: "i >= 5".to_owned(), target: 0x40 }),
            // 0x60: out-of-line cold return at 0x80, and 0x68: out-of-line cold block at 0x88 jumping back to 0x70
            blk(0x60, "c = 4;", Term::Cond { cond: "err != 0".to_owned(), neg: "err == 0".to_owned(), target: 0x80 }),
            blk(
                0x68,
                "c2 = 4;",
                Term::Cond { cond: "cold != 0".to_owned(), neg: "cold == 0".to_owned(), target: 0x88 },
            ),
            // 0x70: switch with duplicate case (0, 1 -> 0x78) and un-inlined arms (2 -> 0x94, 3 -> 0x98)
            blk(0x70, "d = 5;", Term::Switch { idx: "k".to_owned(), base: 0x2000, arms: vec![0x78, 0x78, 0x94, 0x98] }),
            blk(0x78, "e = 6;", Term::Jump(0x90)),
            blk(0x80, "cleanup();", Term::Return("unreachable();".to_owned())),
            blk(0x88, "log_cold();", Term::Jump(0x70)),
            // 0x90..0x98: multi-predecessor targets keeping top-level Cond and Jump terminators
            blk(0x90, "f = 7;", Term::Fall),
            blk(0x94, "g = 8;", Term::Cond { cond: "g > 0".to_owned(), neg: "g <= 0".to_owned(), target: 0x90 }),
            blk(0x98, "g2 = 8;", Term::Jump(0x90)),
            blk(0xa0, "h = 9;", Term::Return("return rax;".to_owned())),
        ];
        let text = structure(blocks).join("\n");
        assert!(text.contains("if (x != 0) {\n    b = 2;\n  } else {\n    b = 3;\n  }"), "{text}");
        assert!(
            text.contains("do {\n    i += 1;\n    if (i > 9) goto L_90;\n    s += i;\n  } while (i < 5);"),
            "{text}"
        );
        assert!(text.contains("if (err != 0) {\n    cleanup();\n    unreachable();\n  }"), "{text}");
        assert!(text.contains("if (cold != 0) {\n    log_cold();\n  }"), "{text}");
        assert!(text.contains("case 0 (0x0): case 1 (0x1):\n      e = 6;\n      break;"), "{text}");
        assert!(
            text.contains("case 2 (0x2): goto L_94;") && text.contains("L_90:") && text.contains("L_98:"),
            "{text}"
        );
        assert!(text.contains("if (g > 0) goto L_90;") && text.contains("goto L_90;"), "{text}");
    }
}
