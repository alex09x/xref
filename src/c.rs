/*
 * xref — Ultra blazing fast cross-references of an x86-64 ELF binary
 * Copyright (c) 2026 Alexander Panasenko
 *
 * Contact: alex@prod.codes
 * Author: https://prod.codes/about/
 * Project: https://github.com/alex09x/xref
 * SPDX-License-Identifier: MIT OR Apache-2.0
 */

//! Pseudo-C decompiler: SSA Def-Use Web locals, frame-normalized stack slots, evidence-backed
//! function signatures, incoming-edge flag propagation, and structured control-flow lifting.

use std::collections::{BTreeSet, HashMap, HashSet};
use std::ops::Range;

use iced_x86::FlowControl;

use crate::c_step::{FnCtx, flush_block_end, step};
use crate::calls::leaders_and_stack;
use crate::cfg::{Block, Term};
use crate::expr::{Flags, State};
use crate::image::Image;
use crate::listing::is_call;
use crate::locations::Location;
use crate::runtime::RuntimeMap;
use crate::scan::{branch_target, decode};
use crate::sig::fn_sig;
use crate::ssa_webs::SsaCfg;
use crate::tables::{Table, tables};
use crate::type_facts::TypeFacts;

pub const fn find_comment_outside_str(line: &str) -> Option<usize> {
    let bytes = line.as_bytes();
    let (mut in_str, mut escaped, mut i) = (false, false, 0);
    while i < bytes.len() {
        let b = bytes[i];
        if in_str {
            if escaped {
                escaped = false;
            } else if b == b'\\' {
                escaped = true;
            } else if b == b'"' {
                in_str = false;
            }
        } else if b == b'"' {
            in_str = true;
        } else if b == b'/' && i + 1 < bytes.len() && (bytes[i + 1] == b'*' || bytes[i + 1] == b'/') {
            return Some(i);
        }
        i += 1;
    }
    None
}

pub fn line_idents(line: &str) -> HashSet<String> {
    let mut set = HashSet::new();
    let trim = line.trim_start();
    if trim.starts_with("/*") || trim.starts_with("* ") || trim == "*/" {
        return set;
    }
    let code = find_comment_outside_str(line).map_or(line, |idx| &line[..idx]);
    let mut cur = String::new();
    let (mut in_str, mut escaped) = (false, false);
    for ch in code.chars() {
        if in_str {
            if escaped {
                escaped = false;
            } else if ch == '\\' {
                escaped = true;
            } else if ch == '"' {
                in_str = false;
            }
            continue;
        }
        if ch == '"' {
            if !cur.is_empty() {
                set.insert(std::mem::take(&mut cur));
            }
            in_str = true;
        } else if ch.is_ascii_alphanumeric() || ch == '_' {
            cur.push(ch);
        } else if !cur.is_empty() {
            set.insert(std::mem::take(&mut cur));
        }
    }
    if !cur.is_empty() {
        set.insert(cur);
    }
    set
}

fn count_cfg_preds(code: &[u8], f: &Range<u64>, leaders: &BTreeSet<u64>, jt: &[Table]) -> HashMap<u64, usize> {
    let mut preds: HashMap<u64, usize> = HashMap::new();
    decode(code, f.start, |ins| {
        let fc = ins.flow_control();
        let nx = ins.next_ip();
        if matches!(
            fc,
            FlowControl::Next | FlowControl::Call | FlowControl::IndirectCall | FlowControl::ConditionalBranch
        ) && leaders.contains(&nx)
        {
            *preds.entry(nx).or_insert(0) += 1;
        }
        if fc == FlowControl::ConditionalBranch
            && let Some(bt) = branch_target(ins).filter(|t| f.contains(t))
        {
            *preds.entry(bt).or_insert(0) += 1;
        } else if matches!(fc, FlowControl::UnconditionalBranch | FlowControl::IndirectBranch) {
            if let Some(tbl) = jt.iter().find(|t| t.dispatch <= ins.ip() && ins.ip() - t.dispatch <= 32) {
                for &arm in &tbl.arms {
                    *preds.entry(arm).or_insert(0) += 1;
                }
            } else if !is_call(ins, f)
                && fc != FlowControl::IndirectBranch
                && let Some(bt) = branch_target(ins).filter(|t| f.contains(t))
            {
                *preds.entry(bt).or_insert(0) += 1;
            }
        }
    });
    preds
}

fn push_in_flags(map: &mut HashMap<u64, (usize, Option<Flags>)>, dst: u64, flags: Option<Flags>) {
    map.entry(dst)
        .and_modify(|(cnt, cur)| {
            *cnt += 1;
            if *cur != flags {
                *cur = None;
            }
        })
        .or_insert((1, flags));
}

type CRes = Result<(u64, String), String>;

#[derive(Clone, Default)]
pub struct COptions {
    pub from: Option<u64>,
    pub to: Option<u64>,
    pub mark_ip: Option<u64>,
    pub mark_targets: Option<HashMap<u64, crate::slice_parse::MarkKind>>,
    pub keep_gotos: bool,
    pub only_paths_to: Option<u64>,
}

pub fn c_one(img: &Image, locs: &[Location], rt: &RuntimeMap, addr: u64, from: Option<u64>, to: Option<u64>) -> CRes {
    c_one_marked(img, locs, rt, addr, from, to, None)
}

pub fn c_one_marked(
    img: &Image,
    locs: &[Location],
    rt: &RuntimeMap,
    addr: u64,
    from: Option<u64>,
    to: Option<u64>,
    mark_ip: Option<u64>,
) -> CRes {
    c_one_options(img, locs, rt, addr, COptions { from, to, mark_ip, ..Default::default() })
}

#[allow(clippy::too_many_lines)] // Lifting loop plus the optional only-paths pruning pass; split separately.
pub fn c_one_options(img: &Image, locs: &[Location], rt: &RuntimeMap, addr: u64, options: COptions) -> CRes {
    let COptions { from, to, mark_ip, mark_targets, keep_gotos, only_paths_to } = options;
    // Blocks are pruned whole, so the target's own block may continue past ADDR; mark ADDR's
    // statement so the reader sees where the requested instruction is.
    let mark_ip = mark_ip.or(only_paths_to);
    let (f, code) = img
        .function_or_span(addr, to)
        .and_then(|f| Some((f.clone(), img.code(&f)?)))
        .ok_or_else(|| format!("no function contains {addr:#x}"))?;
    let (shown, sig, found_tables) = (from.unwrap_or(f.start)..to.unwrap_or(f.end), fn_sig(img, &f), tables(img, &f));
    let ssa = SsaCfg::analyze(img, rt, &f, &sig, &found_tables);
    if let Some(target) = only_paths_to {
        crate::only_paths::validate_target(target, &f, &ssa.ip_to_idx)?;
    }
    let tf = TypeFacts::build(img, locs, rt, &f, &sig, &ssa);
    let (leaders, targets, _) = leaders_and_stack(code, &f, &found_tables);
    let pred_counts = count_cfg_preds(code, &f, &leaders, &found_tables);
    let mut in_flags: HashMap<u64, (usize, Option<Flags>)> = HashMap::new();
    let partial_slice = from.is_some() || to.is_some();
    let float_abi = !sig.float_params.is_empty() || matches!(tf.ret_kind, crate::type_facts::ReturnKind::Float(_));
    let ret_reads = u16::from(matches!(tf.ret_kind, crate::type_facts::ReturnKind::Float(_)) || tf.xmm0_note.is_some());
    let xmm_live =
        float_abi.then(|| crate::xmm_live::XmmLive::build(img, &f, code, &found_tables, ret_reads, &sig.float_params));
    let ctx = FnCtx {
        image: img,
        locations: locs,
        runtime: rt,
        tables: &found_tables,
        function: &f,
        ssa: &ssa,
        ret_kind: tf.ret_kind,
        partial_slice,
        mark_ip,
        mark_targets: mark_targets.as_ref(),
        xmm0_note: tf.xmm0_note,
        xmm_live: xmm_live.as_ref(),
    };
    // A float parameter register reads as its `arg_fN` variable: unwritten at the entry, and every
    // block end of a float-ABI function assigns live xmm values back to it (`XmmLive::flush`).
    let homes: Vec<_> = sig.float_params.iter().map(|p| (p.reg(), p.name())).collect();
    let mut state = State {
        in_prologue: from.is_none(),
        arg_base_rsp: sig.arg_base_rsp,
        uses_fp: sig.uses_fp,
        stack: ssa.stack.spill_to_arg.clone(),
        homes: homes.clone(),
        ..State::default()
    };
    let mut blocks: Vec<Block> = Vec::new();
    let mut cur = Block { start: shown.start, stmts: Vec::new(), term: Term::Fall };
    let mut prev_ip = None;
    decode(code, f.start, |instruction| {
        let ip = instruction.ip();
        if leaders.contains(&ip) {
            let keep_fall = !targets.contains(&ip) && matches!(cur.term, Term::Cond { .. });
            if shown.contains(&ip) {
                // Before the flags flow on: carrying xmm values may rename what they read.
                flush_block_end(&ctx, &mut state, prev_ip, &mut cur.stmts);
            }
            if (!cur.stmts.is_empty() || cur.term != Term::Fall) && matches!(cur.term, Term::Fall | Term::Cond { .. }) {
                push_in_flags(&mut in_flags, ip, state.flags.clone());
            }
            if shown.contains(&ip) {
                let prev = std::mem::replace(&mut cur, Block { start: ip, stmts: Vec::new(), term: Term::Fall });
                if !prev.stmts.is_empty() || prev.term != Term::Fall || !blocks.is_empty() {
                    blocks.push(prev);
                }
            }
            let mut old = std::mem::take(&mut state);
            let merged_flags = in_flags
                .get(&ip)
                .filter(|(seen, _)| pred_counts.get(&ip).is_some_and(|&tot| *seen == tot))
                .and_then(|(_, fl)| fl.clone());
            let base = State {
                const_saved: std::mem::take(&mut old.const_saved),
                fn_saved: std::mem::take(&mut old.fn_saved),
                stack: ssa.stack.spill_to_arg.clone(),
                arg_base_rsp: sig.arg_base_rsp,
                uses_fp: sig.uses_fp,
                flags: merged_flags,
                homes: homes.clone(),
                ..State::default()
            };
            state = if keep_fall { State { flags: old.flags, rodata_ptrs: old.rodata_ptrs, ..base } } else { base };
        } else if instruction.flow_control() != FlowControl::Exception
            && let Term::Return(s) = std::mem::replace(&mut cur.term, Term::Fall)
            && !s.is_empty()
        {
            cur.stmts.push(s);
        }
        if shown.contains(&ip)
            && let Some(&ins_idx) = ssa.ip_to_idx.get(&ip)
        {
            let prev_len = cur.stmts.len();
            step(&ctx, &mut state, instruction, ins_idx, &mut cur);
            if let Some(live) = ctx.xmm_live {
                live.bind_unlifted_writes(&mut state, ip);
            }
            if let Some(kind) = ctx.mark_kind(instruction) {
                let suffix = match kind {
                    crate::slice_parse::MarkKind::Exact => " /* @xref_slice_target */",
                    crate::slice_parse::MarkKind::MayAlias => " /* @xref_slice_target */ /* may-alias */",
                };
                if cur.stmts.len() > prev_len {
                    if let Some(last) = cur.stmts.last_mut() {
                        last.push_str(suffix);
                    }
                } else if let Term::Return(ref mut s) = cur.term
                    && !s.is_empty()
                {
                    s.push_str(suffix);
                } else if only_paths_to == Some(instruction.ip()) {
                    // The target produced no pseudo-C of its own (e.g. `nop`, a compare): emit the
                    // marker as its own line so --only-paths-to always shows where ADDR is.
                    cur.stmts.push(format!("/* @xref_slice_target {:#x} */", instruction.ip()));
                }
            }
            if let Term::Cond { target, .. } | Term::Jump(target) = cur.term {
                push_in_flags(&mut in_flags, target, state.flags.clone());
            }
        }
        prev_ip = Some(ip);
    });
    flush_block_end(&ctx, &mut state, prev_ip, &mut cur.stmts);
    blocks.push(cur);
    let blocks = if let Some(target) = only_paths_to {
        crate::only_paths::prune_to_only_paths(blocks, &f, target)?
    } else {
        blocks
    };
    let fold_floats = float_abi && !partial_slice && only_paths_to.is_none();
    Ok((f.start, body::finish_c_body(&ssa, &tf, (&f, &shown), blocks, keep_gotos, (&homes, fold_floats))))
}

mod body;
#[cfg(test)]
mod tests;
