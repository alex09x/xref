/*
 * XRef — Basic-block pruning for reachability paths before pseudo-C lifting
 * Copyright (c) 2026 Alexander Panasenko
 * Contact: alex@prod.codes
 * Author: https://prod.codes/about/
 * Project: https://github.com/alex09x/xref
 * SPDX-License-Identifier: MIT OR Apache-2.0
 */

use std::collections::{HashMap, VecDeque};
use std::ops::Range;

use crate::cfg::{Block, Term, wrap_if};

pub const ELIDED_COMMENT: &str = "/* ... */";

/// Validate that `target` falls on an instruction boundary inside `f`.
pub fn validate_target(target: u64, f: &Range<u64>, ip_to_idx: &HashMap<u64, usize>) -> Result<(), String> {
    if target < f.start || target >= f.end {
        return Err(format!("address {target:#x} is outside function {:#x}..{:#x}", f.start, f.end));
    }
    if !ip_to_idx.contains_key(&target) {
        return Err(format!("address {target:#x} is outside function instructions in {:#x}..{:#x}", f.start, f.end));
    }
    Ok(())
}

fn build_cfg(blocks: &[Block]) -> (Vec<Vec<usize>>, Vec<Vec<usize>>) {
    let n = blocks.len();
    let mut succs: Vec<Vec<usize>> = vec![Vec::new(); n];
    let mut preds: Vec<Vec<usize>> = vec![Vec::new(); n];

    let add_edge = |from: usize, to_addr: u64, s: &mut [Vec<usize>], p: &mut [Vec<usize>]| {
        if let Ok(v) = blocks.binary_search_by_key(&to_addr, |b| b.start)
            && !s[from].contains(&v)
        {
            s[from].push(v);
            p[v].push(from);
        }
    };

    for (u, block) in blocks.iter().enumerate() {
        match &block.term {
            Term::Fall => {
                if u + 1 < n {
                    succs[u].push(u + 1);
                    preds[u + 1].push(u);
                }
            }
            Term::Jump(target) => {
                add_edge(u, *target, &mut succs, &mut preds);
            }
            Term::Cond { target, .. } => {
                if u + 1 < n {
                    succs[u].push(u + 1);
                    preds[u + 1].push(u);
                }
                add_edge(u, *target, &mut succs, &mut preds);
            }
            Term::Switch { arms, .. } => {
                for &arm in arms {
                    add_edge(u, arm, &mut succs, &mut preds);
                }
            }
            Term::Return(_) => {}
        }
        for target in crate::loops::stmt_gotos(&block.stmts) {
            add_edge(u, target, &mut succs, &mut preds);
        }
    }

    (succs, preds)
}

fn compute_reachability(
    n: usize,
    f: &Range<u64>,
    target_blk_idx: usize,
    target_addr: u64,
    succs: &[Vec<usize>],
    preds: &[Vec<usize>],
) -> Result<Vec<bool>, String> {
    let mut from_entry = vec![false; n];
    let mut q = VecDeque::new();
    from_entry[0] = true;
    q.push_back(0);
    while let Some(u) = q.pop_front() {
        for &v in &succs[u] {
            if !from_entry[v] {
                from_entry[v] = true;
                q.push_back(v);
            }
        }
    }

    if !from_entry[target_blk_idx] {
        return Err(format!("address {target_addr:#x} is unreachable in function {:#x}..{:#x}", f.start, f.end));
    }

    let mut to_target = vec![false; n];
    to_target[target_blk_idx] = true;
    q.clear();
    q.push_back(target_blk_idx);
    while let Some(v) = q.pop_front() {
        for &u in &preds[v] {
            if !to_target[u] {
                to_target[u] = true;
                q.push_back(u);
            }
        }
    }

    if !to_target[0] {
        return Err(format!("address {target_addr:#x} is unreachable in function {:#x}..{:#x}", f.start, f.end));
    }

    Ok((0..n)
        .map(|i| from_entry.get(i).copied().unwrap_or(false) && to_target.get(i).copied().unwrap_or(false))
        .collect())
}

fn transform_target_block(mut block: Block, blocks: &[Block], can_reach: &[bool], u: usize) -> Block {
    let reach_check = |idx: usize| can_reach.get(idx).copied().unwrap_or(false);
    let has_reaching_succ = match &block.term {
        Term::Fall => reach_check(u + 1),
        Term::Jump(target) => blocks.binary_search_by_key(target, |b| b.start).is_ok_and(reach_check),
        Term::Cond { target, .. } => {
            reach_check(u + 1) || blocks.binary_search_by_key(target, |b| b.start).is_ok_and(reach_check)
        }
        Term::Switch { arms, .. } => {
            arms.iter().any(|arm| blocks.binary_search_by_key(arm, |b| b.start).is_ok_and(reach_check))
        }
        Term::Return(_) => false,
    };

    if !has_reaching_succ && !matches!(block.term, Term::Return(_)) {
        block.stmts.push(ELIDED_COMMENT.to_string());
        block.term = Term::Return(String::new());
    }
    block
}

fn transform_cond_block(
    mut block: Block,
    blocks: &[Block],
    can_reach: &[bool],
    u: usize,
    cond: String,
    neg: String,
    target: u64,
) -> Block {
    let reach_check = |idx: usize| can_reach.get(idx).copied().unwrap_or(false);
    let target_can = blocks.binary_search_by_key(&target, |b| b.start).is_ok_and(reach_check);
    let fall_can = reach_check(u + 1);
    let elided_comment = [ELIDED_COMMENT.to_string()];

    if target_can && fall_can {
        block.term = Term::Cond { cond, neg, target };
    } else if target_can && !fall_can {
        block.stmts.extend(wrap_if(&neg, &elided_comment, None));
        // Fallthrough is decided by the final pass over the emitted order, which includes stubs.
        block.term = Term::Jump(target);
    } else if !target_can && fall_can {
        block.stmts.extend(wrap_if(&cond, &elided_comment, None));
        block.term = Term::Fall;
    } else {
        block.stmts.push(ELIDED_COMMENT.to_string());
        block.term = Term::Return(String::new());
    }
    block
}

/// Prune basic blocks to only those that can reach `target_addr` from function entry.
///
/// Unrelated branches and trailing regions that cannot reach `target_addr` are elided and
/// replaced by a one-line comment (`/* ... */`), preserving consistent labels and gotos.
pub fn prune_to_only_paths(mut blocks: Vec<Block>, f: &Range<u64>, target_addr: u64) -> Result<Vec<Block>, String> {
    if target_addr < f.start || target_addr >= f.end {
        return Err(format!("address {target_addr:#x} is outside function {:#x}..{:#x}", f.start, f.end));
    }
    if blocks.is_empty() || target_addr < blocks[0].start {
        return Err(format!("address {target_addr:#x} is outside function {:#x}..{:#x}", f.start, f.end));
    }

    let target_blk_idx = blocks.partition_point(|b| b.start <= target_addr).saturating_sub(1);
    let (succs, preds) = build_cfg(&blocks);
    let can_reach = compute_reachability(blocks.len(), f, target_blk_idx, target_addr, &succs, &preds)?;
    let reach_check = |idx: usize| can_reach.get(idx).copied().unwrap_or(false);
    // Switch arms and statement-level gotos of kept blocks may name pruned blocks; those keep a
    // stub block at the same address so every emitted label stays defined.
    let mut stub_needed = vec![false; blocks.len()];
    for (u, block) in blocks.iter().enumerate().filter(|(u, _)| reach_check(*u)) {
        let mut referenced = crate::loops::stmt_gotos(&block.stmts);
        if let Term::Switch { arms, .. } = &block.term {
            referenced.extend(arms.iter().copied());
        }
        for addr in referenced {
            if let Ok(v) = blocks.binary_search_by_key(&addr, |b| b.start)
                && !reach_check(v)
                && v != u
            {
                stub_needed[v] = true;
            }
        }
    }

    let mut new_blocks = Vec::new();
    for u in 0..blocks.len() {
        if !reach_check(u) {
            if stub_needed[u] {
                let start = blocks[u].start;
                new_blocks.push(Block {
                    start,
                    stmts: vec![ELIDED_COMMENT.to_string()],
                    term: Term::Return(String::new()),
                });
            }
            continue;
        }
        // Keep `start` so later binary searches over `blocks` still see a sorted sequence.
        let start = blocks[u].start;
        let block = std::mem::replace(&mut blocks[u], Block { start, stmts: Vec::new(), term: Term::Fall });
        let block = if u == target_blk_idx {
            transform_target_block(block, &blocks, &can_reach, u)
        } else {
            let mut b = block;
            let term = std::mem::replace(&mut b.term, Term::Fall);
            match term {
                Term::Cond { cond, neg, target } => transform_cond_block(b, &blocks, &can_reach, u, cond, neg, target),
                Term::Jump(target) => {
                    if blocks.binary_search_by_key(&target, |bl| bl.start).is_ok_and(reach_check) {
                        // Fallthrough is decided by the final pass over the emitted order.
                        b.term = Term::Jump(target);
                    } else {
                        b.stmts.push(ELIDED_COMMENT.to_string());
                        b.term = Term::Return(String::new());
                    }
                    b
                }
                Term::Fall => {
                    if !reach_check(u + 1) {
                        b.stmts.push(ELIDED_COMMENT.to_string());
                        b.term = Term::Return(String::new());
                    }
                    b
                }
                Term::Switch { .. } | Term::Return(_) => {
                    b.term = term;
                    b
                }
            }
        };
        new_blocks.push(block);
    }

    for k in 0..new_blocks.len().saturating_sub(1) {
        if let Term::Jump(target) = new_blocks[k].term
            && target == new_blocks[k + 1].start
        {
            new_blocks[k].term = Term::Fall;
        }
    }

    Ok(new_blocks)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cfg::Term;

    fn blk(start: u64, stmts: &[&str], term: Term) -> Block {
        Block { start, stmts: stmts.iter().map(|&s| s.to_owned()).collect(), term }
    }

    #[test]
    fn only_paths_prunes_unrelated_branch_and_marks_elided() {
        let blocks = vec![
            blk(
                0x1000,
                &["v_1 = arg_0;"],
                Term::Cond { cond: "v_1 == 0".into(), neg: "v_1 != 0".into(), target: 0x1050 },
            ),
            blk(0x1010, &["unrelated_work();", "unrelated_2();"], Term::Return("return 0;".into())),
            blk(0x1050, &["target_store = 42;"], Term::Return("return target_store;".into())),
        ];
        let f = 0x1000..0x1060;
        let Ok(pruned) = prune_to_only_paths(blocks, &f, 0x1050) else {
            panic!("expected ok");
        };
        assert_eq!(pruned.len(), 2);
        assert_eq!(pruned[0].start, 0x1000);
        assert_eq!(pruned[1].start, 0x1050);
        assert!(pruned[0].stmts.iter().any(|s| s.contains("/* ... */")));
        assert!(pruned[1].stmts.iter().any(|s| s.contains("target_store = 42;")));
        assert!(!pruned.iter().any(|b| b.stmts.iter().any(|s| s.contains("unrelated_work"))));
    }

    #[test]
    fn only_paths_errors_on_address_outside_function() {
        let f = 0x1000..0x1020;
        let make_b = || vec![blk(0x1000, &["v = 1;"], Term::Return("return v;".into()))];
        assert!(prune_to_only_paths(make_b(), &f, 0x999).is_err());
        assert!(prune_to_only_paths(make_b(), &f, 0x1030).is_err());
    }

    #[test]
    fn only_paths_errors_on_unreachable_address() {
        let blocks = vec![
            blk(0x1000, &["return 0;"], Term::Return("return 0;".into())),
            blk(0x1010, &["dead_code = 1;"], Term::Return("return dead_code;".into())),
        ];
        let f = 0x1000..0x1020;
        let Err(err) = prune_to_only_paths(blocks, &f, 0x1010) else {
            panic!("expected error");
        };
        assert!(err.contains("unreachable"), "{err}");
    }

    #[test]
    fn only_paths_keeps_switch_arm_labels_defined_with_elided_stubs() {
        let switch = Term::Switch { idx: "arg_0".into(), base: 0x2000, arms: vec![0x1010, 0x1020, 0x1030] };
        let blocks = vec![
            blk(0x1000, &["v = arg_0;"], switch),
            blk(0x1010, &["unrelated_a();"], Term::Return("return 0;".into())),
            blk(0x1020, &["target_store = 1;"], Term::Return("return 1;".into())),
            blk(0x1030, &["unrelated_b();"], Term::Return("return 2;".into())),
        ];
        let Ok(pruned) = prune_to_only_paths(blocks, &(0x1000..0x1040), 0x1020) else {
            panic!("expected ok");
        };
        let starts: Vec<u64> = pruned.iter().map(|b| b.start).collect();
        assert_eq!(starts, [0x1000, 0x1010, 0x1020, 0x1030], "every switch arm keeps a block");
        for stub in [&pruned[1], &pruned[3]] {
            assert_eq!(stub.stmts, [ELIDED_COMMENT], "pruned arm is an elided stub");
        }
        assert!(pruned[2].stmts.iter().any(|s| s.contains("target_store")));
        assert!(!pruned.iter().any(|b| b.stmts.iter().any(|s| s.contains("unrelated"))));
    }

    #[test]
    fn only_paths_keeps_explicit_jump_over_an_intervening_stub() {
        let cond = Term::Cond { cond: "v == 0".into(), neg: "v != 0".into(), target: 0x1030 };
        let blocks = vec![
            blk(0x1000, &["if (w) goto L_1010;"], cond),
            blk(0x1010, &["unrelated();"], Term::Return("return 0;".into())),
            blk(0x1030, &["target_store = 1;"], Term::Return("return 1;".into())),
        ];
        let Ok(pruned) = prune_to_only_paths(blocks, &(0x1000..0x1040), 0x1030) else {
            panic!("expected ok");
        };
        let starts: Vec<u64> = pruned.iter().map(|b| b.start).collect();
        assert_eq!(starts, [0x1000, 0x1010, 0x1030]);
        assert!(matches!(pruned[0].term, Term::Jump(0x1030)), "must jump over the stub, not fall into it");
        assert_eq!(pruned[1].stmts, [ELIDED_COMMENT]);
    }

    #[test]
    fn only_paths_marks_trailing_code_after_target() {
        let blocks = vec![
            blk(0x1000, &["target_call();"], Term::Fall),
            blk(0x1020, &["subsequent_cleanup();"], Term::Return("return;".into())),
        ];
        let f = 0x1000..0x1030;
        let Ok(pruned) = prune_to_only_paths(blocks, &f, 0x1000) else {
            panic!("expected ok");
        };
        assert_eq!(pruned.len(), 1);
        assert_eq!(pruned[0].start, 0x1000);
        assert!(pruned[0].stmts.iter().any(|s| s.contains("target_call();")));
        assert!(pruned[0].stmts.iter().any(|s| s.contains("/* ... */")));
        assert!(!pruned[0].stmts.iter().any(|s| s.contains("subsequent_cleanup")));
    }
}
