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

use crate::c_step::{FnCtx, flush_non_gpr_dirty, step};
use crate::calls::leaders_and_stack;
use crate::cfg::{Block, Term, structure};
use crate::expr::{Flags, State, reg_name, stack_name};
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

fn inline_scoped_decls(ssa: &SsaCfg, tf: &TypeFacts, body_lines: &mut [String]) -> (HashSet<String>, HashSet<String>) {
    let mut scope_stack = vec![0usize];
    let mut next_scope = 1usize;
    let mut scopes = Vec::with_capacity(body_lines.len());
    let mut idents_per_line = Vec::with_capacity(body_lines.len());
    let mut all_used = HashSet::new();
    for line in body_lines.iter() {
        let trim = line.trim();
        if trim.starts_with('}') && scope_stack.len() > 1 {
            scope_stack.pop();
        }
        scopes.push(scope_stack.clone());
        let ids = line_idents(line);
        all_used.extend(ids.iter().cloned());
        idents_per_line.push(ids);
        if trim.ends_with('{') {
            scope_stack.push(next_scope);
            next_scope += 1;
        }
    }
    let mut inlined = HashSet::new();
    for (wid, w) in ssa.webs.iter().enumerate() {
        if w.is_param.is_some() || w.init_from_arg.is_some() || w.defs.is_empty() || !all_used.contains(&w.name) {
            continue;
        }
        let uses: Vec<usize> = (0..body_lines.len()).filter(|&l| idents_per_line[l].contains(&w.name)).collect();
        let Some(&u0) = uses.first() else { continue };
        if u0 > 0 && body_lines[u0 - 1].trim().ends_with(':') {
            continue;
        }
        if !uses.iter().all(|&u| scopes[u].starts_with(&scopes[u0])) {
            continue;
        }
        let line = &body_lines[u0];
        let indent = &line[..line.len() - line.trim_start().len()];
        let (code_part, comment_part) =
            find_comment_outside_str(line).map_or((line.as_str(), ""), |idx| (&line[..idx], &line[idx..]));
        let prefix = format!("{indent}{} = ", w.name);
        if let Some(rhs_semi) = code_part.strip_prefix(&prefix)
            && rhs_semi.trim_end().ends_with(';')
            && !line_idents(rhs_semi).contains(&w.name)
        {
            let ty = tf.local_types.web_ty[wid];
            let sep = if ty.ends_with('*') { "" } else { " " };
            body_lines[u0] = format!("{indent}{ty}{sep}{} = {rhs_semi}{comment_part}", w.name);
            inlined.insert(w.name.clone());
        }
    }
    (all_used, inlined)
}

fn format_local_decls(ssa: &SsaCfg, tf: &TypeFacts, body_lines: &mut [String]) -> Vec<String> {
    let (used, inlined) = inline_scoped_decls(ssa, tf, body_lines);
    let mut decls = Vec::new();
    for (wid, w) in ssa.webs.iter().enumerate() {
        if w.is_param.is_some() || w.defs.is_empty() || !used.contains(&w.name) || inlined.contains(&w.name) {
            continue;
        }
        let ty = tf.local_types.web_ty[wid];
        let sep = if ty.ends_with('*') { "" } else { " " };
        if let Some(ak) = w.init_from_arg {
            decls.push(format!("  {ty}{sep}{} = arg_{ak}; /* {} */", w.name, reg_name(w.reg)));
        } else {
            decls.push(format!("  {ty}{sep}{}; /* {} */", w.name, reg_name(w.reg)));
        }
    }
    for sl in ssa.stack.slots.values() {
        if ssa.stack.spill_to_arg.contains_key(&sl.offset) {
            continue;
        }
        let sname = stack_name(sl.offset);
        if !used.contains(&sname) {
            continue;
        }
        let ty = tf.local_types.slot_ty.get(&sl.offset).copied().unwrap_or("unk64");
        let sep = if ty.ends_with('*') { "" } else { " " };
        let note = if sl.addr_taken { ", addr-taken" } else { "" };
        let sp_lbl = if sl.offset >= 0 {
            format!("[rsp+{:#x}]", sl.offset)
        } else {
            format!("[rsp-{:#x}]", sl.offset.unsigned_abs())
        };
        decls.push(format!("  {ty}{sep}{sname}; /* {sp_lbl}{note} */"));
    }
    decls
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

#[derive(Clone, Copy, Default)]
pub struct COptions {
    pub from: Option<u64>,
    pub to: Option<u64>,
    pub mark_ip: Option<u64>,
    pub keep_gotos: bool,
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
    c_one_options(img, locs, rt, addr, COptions { from, to, mark_ip, keep_gotos: false })
}

pub fn c_one_options(img: &Image, locs: &[Location], rt: &RuntimeMap, addr: u64, options: COptions) -> CRes {
    let COptions { from, to, mark_ip, keep_gotos } = options;
    let (f, code) = img
        .function_or_span(addr, to)
        .and_then(|f| Some((f.clone(), img.code(&f)?)))
        .ok_or_else(|| format!("no function contains {addr:#x}"))?;
    let (shown, sig, found_tables) = (from.unwrap_or(f.start)..to.unwrap_or(f.end), fn_sig(img, &f), tables(img, &f));
    let ssa = SsaCfg::analyze(img, rt, &f, &sig, &found_tables);
    let tf = TypeFacts::build(img, locs, rt, &f, &sig, &ssa);
    let (leaders, targets, _) = leaders_and_stack(code, &f, &found_tables);
    let pred_counts = count_cfg_preds(code, &f, &leaders, &found_tables);
    let mut in_flags: HashMap<u64, (usize, Option<Flags>)> = HashMap::new();
    let partial_slice = from.is_some() || to.is_some();
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
    };
    let mut state = State {
        in_prologue: from.is_none(),
        arg_base_rsp: sig.arg_base_rsp,
        uses_fp: sig.uses_fp,
        stack: ssa.stack.spill_to_arg.clone(),
        ..State::default()
    };
    let mut blocks: Vec<Block> = Vec::new();
    let mut cur = Block { start: shown.start, stmts: Vec::new(), term: Term::Fall };
    decode(code, f.start, |instruction| {
        let ip = instruction.ip();
        if leaders.contains(&ip) {
            let keep_fall = !targets.contains(&ip) && matches!(cur.term, Term::Cond { .. });
            if (!cur.stmts.is_empty() || cur.term != Term::Fall) && matches!(cur.term, Term::Fall | Term::Cond { .. }) {
                push_in_flags(&mut in_flags, ip, state.flags.clone());
            }
            if shown.contains(&ip) {
                flush_non_gpr_dirty(&mut state, &mut cur.stmts);
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
            if ctx.is_marked(instruction) {
                if cur.stmts.len() > prev_len {
                    if let Some(last) = cur.stmts.last_mut() {
                        last.push_str(" /* @xref_slice_target */");
                    }
                } else if let Term::Return(ref mut s) = cur.term
                    && !s.is_empty()
                {
                    s.push_str(" /* @xref_slice_target */");
                }
            }
            if let Term::Cond { target, .. } | Term::Jump(target) = cur.term {
                push_in_flags(&mut in_flags, target, state.flags.clone());
            }
        }
    });
    flush_non_gpr_dirty(&mut state, &mut cur.stmts);
    blocks.push(cur);
    Ok((f.start, finish_c_body(&ssa, &tf, &f, &shown, blocks, keep_gotos)))
}

fn finish_c_body(
    ssa: &SsaCfg,
    tf: &TypeFacts,
    f: &Range<u64>,
    shown: &Range<u64>,
    blocks: Vec<Block>,
    keep_gotos: bool,
) -> String {
    let mut lines = if keep_gotos { crate::cfg::structure_with_gotos(blocks, true) } else { structure(blocks) };
    let mut decls = format_local_decls(ssa, tf, &mut lines);
    for declaration in crate::float_alu::local_declarations(ssa) {
        let name = declaration.trim().strip_prefix("f64 ").and_then(|value| value.strip_suffix(';')).unwrap_or("");
        if !decls
            .iter()
            .any(|line| line.split_whitespace().nth(1).is_some_and(|declared| declared.trim_end_matches(';') == name))
        {
            decls.push(declaration);
        }
    }
    if !decls.is_empty() {
        decls.push(String::new());
        decls.extend(lines);
        lines = decls;
    }
    if shown.start > f.start {
        lines.insert(0, format!("  /* ... slice from {:#x} (function starts at {:#x}) ... */", shown.start, f.start));
    }
    if shown.end < f.end {
        lines.push(format!("  /* ... truncated at {:#x} (function ends at {:#x}) ... */", shown.end, f.end));
    }
    format!("{}\n{}\n{}\n}}\n", tf.header_block, tf.sig_line, lines.join("\n"))
}

#[cfg(test)]
mod tests;
