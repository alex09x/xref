/*
 * xref — Ultra blazing fast cross-references of an x86-64 ELF binary
 * Copyright (c) 2026 Alexander Panasenko
 *
 * Contact: alex@prod.codes
 * Author: https://prod.codes/about/
 * Project: https://github.com/alex09x/xref
 * SPDX-License-Identifier: MIT OR Apache-2.0
 */

//! Unit tests for CFG structuring (`unrotate`, `goto_elim`, `loops`, `reduce`, `ssa_cfg`).

use std::ops::Range;

use crate::caller_ret::CallerRetStats;
use crate::cfg::{Block, Term};
use crate::goto_elim::eliminate_forward_gotos;
use crate::image::{Image, Segment};
use crate::loops::{block_targets, step_cond_fallback};
use crate::reduce::step_loops_and_jumps;
use crate::runtime::RuntimeMap;
use crate::sig::fn_sig;
use crate::ssa_cfg::SsaGraph;
use crate::unrotate::{RotatedLoop, find_best_rotated, reduce_rotated};

fn blk(start: u64, stmts: &[&str], term: Term) -> Block {
    Block { start, stmts: stmts.iter().map(|s| (*s).to_owned()).collect(), term }
}

#[test]
fn unrotate_find_best_and_validity_filters() {
    let b_switch = vec![
        blk(0x10, &[], Term::Jump(0x30)),
        blk(0x20, &[], Term::Fall),
        blk(0x30, &[], Term::Switch { idx: "s".to_owned(), base: 0, arms: vec![] }),
        blk(0x40, &[], Term::Jump(0x20)),
        blk(0x50, &[], Term::Return("ret".to_owned())),
    ];
    let t_switch: Vec<Vec<u64>> = b_switch.iter().map(block_targets).collect();
    assert!(find_best_rotated(&b_switch, &t_switch).is_none());

    let b_cond_end = vec![
        blk(0x10, &[], Term::Jump(0x30)),
        blk(0x20, &[], Term::Fall),
        blk(0x30, &[], Term::Fall),
        blk(0x40, &[], Term::Cond { cond: "c".to_owned(), neg: "!c".to_owned(), target: 0x20 }),
    ];
    let t_cond_end: Vec<Vec<u64>> = b_cond_end.iter().map(block_targets).collect();
    assert!(find_best_rotated(&b_cond_end, &t_cond_end).is_none());

    let b_no_reach = vec![
        blk(0x10, &[], Term::Jump(0x30)),
        blk(0x20, &[], Term::Jump(0x999)),
        blk(0x30, &[], Term::Fall),
        blk(0x40, &[], Term::Jump(0x20)),
        blk(0x50, &[], Term::Return("ret".to_owned())),
    ];
    let t_no_reach: Vec<Vec<u64>> = b_no_reach.iter().map(block_targets).collect();
    assert!(find_best_rotated(&b_no_reach, &t_no_reach).is_none());

    let b_reach = vec![
        blk(0x10, &[], Term::Jump(0x40)),
        blk(0x20, &["goto L_40;"], Term::Fall),
        blk(0x30, &[], Term::Jump(0x999)),
        blk(0x40, &[], Term::Fall),
        blk(0x50, &[], Term::Jump(0x20)),
        blk(0x60, &[], Term::Return("ret".to_owned())),
    ];
    let t_reach: Vec<Vec<u64>> = b_reach.iter().map(block_targets).collect();
    let _ = find_best_rotated(&b_reach, &t_reach);

    let b_p_goto = vec![
        blk(0x10, &["goto L_20;"], Term::Jump(0x30)),
        blk(0x20, &[], Term::Fall),
        blk(0x30, &[], Term::Fall),
        blk(0x40, &[], Term::Jump(0x20)),
        blk(0x50, &[], Term::Return("ret".to_owned())),
    ];
    let t_p_goto: Vec<Vec<u64>> = b_p_goto.iter().map(block_targets).collect();
    assert!(find_best_rotated(&b_p_goto, &t_p_goto).is_none());

    let b_latch_target = vec![
        blk(0x10, &[], Term::Jump(0x40)),
        blk(0x20, &["goto L_999;"], Term::Fall),
        blk(0x30, &["goto L_20;"], Term::Fall),
        blk(0x40, &[], Term::Fall),
        blk(0x50, &[], Term::Jump(0x20)),
        blk(0x60, &[], Term::Return("ret".to_owned())),
    ];
    let t_latch_target: Vec<Vec<u64>> = b_latch_target.iter().map(block_targets).collect();
    assert!(find_best_rotated(&b_latch_target, &t_latch_target).is_none());

    let b_ext = vec![
        blk(0x10, &[], Term::Jump(0x30)),
        blk(0x20, &[], Term::Fall),
        blk(0x30, &[], Term::Fall),
        blk(0x40, &[], Term::Jump(0x20)),
        blk(0x50, &[], Term::Jump(0x20)),
        blk(0x60, &[], Term::Return("ret".to_owned())),
    ];
    let t_ext: Vec<Vec<u64>> = b_ext.iter().map(block_targets).collect();
    assert!(find_best_rotated(&b_ext, &t_ext).is_some());
}

#[test]
fn unrotate_reduce_rotated_and_lowering() {
    let mut blocks = vec![
        blk(0x10, &[], Term::Jump(0x30)),
        blk(0x20, &["goto L_20;"], Term::Fall),
        blk(0x30, &["L_1100060:", "goto L_1100060;", "skip_1100060 = 1;"], Term::Fall),
        blk(0x40, &[], Term::Fall),
        blk(0x50, &[], Term::Fall),
        blk(0x60, &[], Term::Return("ret".to_owned())),
    ];
    let targets: Vec<Vec<u64>> = blocks.iter().map(block_targets).collect();
    reduce_rotated(&mut blocks, &targets, RotatedLoop { p_idx: 0, h: 1, m: 2, l: 3 });
    assert!(blocks[0].stmts.iter().any(|s| s.contains("while (1)")));

    for term_l in [
        Term::Jump(0x999),
        Term::Cond { cond: "c".to_owned(), neg: "!c".to_owned(), target: 0x20 },
        Term::Cond { cond: "c".to_owned(), neg: "!c".to_owned(), target: 0x999 },
        Term::Switch { idx: "s".to_owned(), base: 0, arms: vec![] },
    ] {
        let mut b = vec![
            blk(0x10, &[], Term::Jump(0x30)),
            blk(0x20, &[], Term::Fall),
            blk(0x30, &[], Term::Fall),
            blk(0x40, &[], term_l),
            blk(0x50, &[], Term::Return("ret".to_owned())),
        ];
        let tgts: Vec<Vec<u64>> = b.iter().map(block_targets).collect();
        reduce_rotated(&mut b, &tgts, RotatedLoop { p_idx: 0, h: 1, m: 2, l: 3 });
    }

    for term_m_prev in [
        Term::Return("ret".to_owned()),
        Term::Jump(0x30),
        Term::Jump(0x999),
        Term::Cond { cond: "c".to_owned(), neg: "!c".to_owned(), target: 0x999 },
    ] {
        let mut b = vec![
            blk(0x10, &[], Term::Jump(0x30)),
            blk(0x20, &[], term_m_prev),
            blk(0x30, &[], Term::Fall),
            blk(0x40, &[], Term::Fall),
            blk(0x50, &[], Term::Return("ret".to_owned())),
        ];
        let tgts: Vec<Vec<u64>> = b.iter().map(block_targets).collect();
        reduce_rotated(&mut b, &tgts, RotatedLoop { p_idx: 0, h: 1, m: 2, l: 3 });
    }

    for term_mid in [
        Term::Return("ret".to_owned()),
        Term::Jump(0x40),
        Term::Jump(0x20),
        Term::Jump(0x999),
        Term::Cond { cond: "c".to_owned(), neg: "!c".to_owned(), target: 0x40 },
        Term::Cond { cond: "c".to_owned(), neg: "!c".to_owned(), target: 0x45 },
        Term::Cond { cond: "c".to_owned(), neg: "!c".to_owned(), target: 0x999 },
    ] {
        let mut b = vec![
            blk(0x10, &[], Term::Jump(0x40)),
            blk(0x20, &[], Term::Fall),
            blk(0x30, &[], Term::Fall),
            blk(0x40, &[], Term::Fall),
            blk(0x45, &[], term_mid),
            blk(0x50, &[], Term::Fall),
            blk(0x60, &[], Term::Return("ret".to_owned())),
        ];
        let tgts: Vec<Vec<u64>> = b.iter().map(block_targets).collect();
        reduce_rotated(&mut b, &tgts, RotatedLoop { p_idx: 0, h: 1, m: 3, l: 5 });
    }
}

#[test]
fn goto_elim_forward_and_sinking() {
    let mut lines1: Vec<String> = vec!["L_50:".to_owned(), "L_10:".to_owned(), "return;".to_owned()];
    eliminate_forward_gotos(&mut lines1);
    assert!(!lines1.iter().any(|s| s.contains("L_")));

    let mut lines2: Vec<String> = vec![
        "goto L_10;".to_owned(),
        "return;".to_owned(),
        "L_10:".to_owned(),
        "x = 1;".to_owned(),
        "L_20:".to_owned(),
        "goto L_20;".to_owned(),
        "return;".to_owned(),
    ];
    eliminate_forward_gotos(&mut lines2);

    let mut lines3: Vec<String> = vec![
        "return;".to_owned(),
        "L_10:".to_owned(),
        "x = 1;".to_owned(),
        "return;".to_owned(),
        "goto L_10;".to_owned(),
        "return;".to_owned(),
    ];
    eliminate_forward_gotos(&mut lines3);

    let mut lines4: Vec<String> = vec![
        "if (c) {".to_owned(),
        "  goto L_20;".to_owned(),
        "}".to_owned(),
        "L_20:".to_owned(),
        "return;".to_owned(),
    ];
    eliminate_forward_gotos(&mut lines4);

    let mut lines5: Vec<String> = vec![
        "do {".to_owned(),
        "  if (c) goto L_30;".to_owned(),
        "  x += 1;".to_owned(),
        "L_30:".to_owned(),
        "} while (x < 10);".to_owned(),
        "return;".to_owned(),
    ];
    eliminate_forward_gotos(&mut lines5);

    let mut lines6: Vec<String> = vec![
        "if (c) {".to_owned(),
        "  while (1) {".to_owned(),
        "    goto L_80;".to_owned(),
        "  }".to_owned(),
        "  x = 1;".to_owned(),
        "}".to_owned(),
        "L_80:".to_owned(),
        "return;".to_owned(),
    ];
    eliminate_forward_gotos(&mut lines6);

    let mut lines7: Vec<String> = vec![
        "while (1) {".to_owned(),
        "  while (c) {".to_owned(),
        "    if (d) {".to_owned(),
        "    }".to_owned(),
        "    goto L_90;".to_owned(),
        "  }".to_owned(),
        "}".to_owned(),
        "switch (x) {".to_owned(),
        "  case 1: goto L_90;".to_owned(),
        "}".to_owned(),
        "L_90:".to_owned(),
        "return;".to_owned(),
    ];
    eliminate_forward_gotos(&mut lines7);
}

#[test]
fn loops_and_reduce_structuring() {
    let mut b_loops = vec![
        blk(0x10, &[], Term::Cond { cond: "a == 0".to_owned(), neg: "a != 0".to_owned(), target: 0x30 }),
        blk(0x20, &[], Term::Cond { cond: "b == 1".to_owned(), neg: "b != 1".to_owned(), target: 0x40 }),
        blk(0x30, &[], Term::Return("return 0;".to_owned())),
    ];
    let p_loops = [0, 0, 1];
    assert!(step_cond_fallback(&mut b_loops, &p_loops));
    assert!(b_loops[1].term == Term::Fall);

    let mut b_red1 =
        vec![blk(0x10, &["goto L_20;"], Term::Jump(0x10)), blk(0x20, &[], Term::Return("return 0;".to_owned()))];
    let p_red = [0, 1, 1];
    assert!(step_loops_and_jumps(&mut b_red1, &p_red));
    assert!(b_red1[0].term == Term::Fall);

    let mut b_red2 = vec![
        blk(0x10, &["goto L_30;"], Term::Jump(0x10)),
        blk(0x20, &[], Term::Jump(0x999)),
        blk(0x30, &[], Term::Return("return 0;".to_owned())),
    ];
    assert!(step_loops_and_jumps(&mut b_red2, &p_red));
    assert!(b_red2[0].term == Term::Jump(0x30));
}

#[test]
fn ssa_cfg_uses_fp_skips_rbp() {
    let code: &[u8] = &[0x55, 0x48, 0x89, 0xe5, 0x48, 0x83, 0xec, 0x10, 0x89, 0x7d, 0xfc, 0x8b, 0x45, 0xfc, 0xc3];
    let mut data = vec![0u8; 0x80];
    data[..code.len()].copy_from_slice(code);
    let len = u64::try_from(code.len()).unwrap_or(0);
    let f: Range<u64> = 0x1000..0x1000 + len;
    let img = Image {
        data,
        segments: vec![Segment { va: 0x1000, offset: 0, size: 0x80 }],
        functions: vec![f.clone()],
        pointers: Vec::new(),
        imports: Vec::new(),
        symbols: Vec::new(),
    };
    let sig = fn_sig(&img, &f);
    assert!(sig.uses_fp);
    let graph = SsaGraph::build(&img, &RuntimeMap::default(), &f, &sig, &[], CallerRetStats::default(), false);
    assert!(graph.is_some());
}
