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

fn line_idents(line: &str) -> HashSet<String> {
    let mut set = HashSet::new();
    let trim = line.trim_start();
    if trim.starts_with("/*") || trim.starts_with("* ") || trim == "*/" {
        return set;
    }
    let code = line.find("/*").map_or(line, |idx| &line[..idx]);
    let mut cur = String::new();
    for ch in code.chars() {
        if ch.is_ascii_alphanumeric() || ch == '_' {
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
        let (code_part, comment_part) = line.find("/*").map_or((line.as_str(), ""), |idx| (&line[..idx], &line[idx..]));
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

pub fn c_one(
    image: &Image,
    all_locations: &[Location],
    runtime: &RuntimeMap,
    addr: u64,
    from: Option<u64>,
    to: Option<u64>,
) -> Result<(u64, String), String> {
    let (f, code) = image
        .function_or_span(addr, to)
        .and_then(|f| Some((f.clone(), image.code(&f)?)))
        .ok_or_else(|| format!("no function contains {addr:#x}"))?;
    let shown = from.unwrap_or(f.start)..to.unwrap_or(f.end);
    let sig = fn_sig(image, &f);
    let found_tables = tables(image, &f);
    let ssa = SsaCfg::analyze(image, runtime, &f, &sig, &found_tables);
    let tf = TypeFacts::build(image, all_locations, runtime, &f, &sig, &ssa);
    let (leaders, targets, _) = leaders_and_stack(code, &f, &found_tables);
    let pred_counts = count_cfg_preds(code, &f, &leaders, &found_tables);
    let mut in_flags: HashMap<u64, (usize, Option<Flags>)> = HashMap::new();
    let partial_slice = from.is_some() || to.is_some();
    let ctx = FnCtx {
        image,
        locations: all_locations,
        runtime,
        tables: &found_tables,
        function: &f,
        ssa: &ssa,
        ret_kind: tf.ret_kind,
        partial_slice,
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
        }
        if shown.contains(&ip)
            && let Some(&ins_idx) = ssa.ip_to_idx.get(&ip)
        {
            step(&ctx, &mut state, instruction, ins_idx, &mut cur);
            match cur.term {
                Term::Cond { target, .. } | Term::Jump(target) => {
                    push_in_flags(&mut in_flags, target, state.flags.clone());
                }
                _ => {}
            }
        }
    });
    flush_non_gpr_dirty(&mut state, &mut cur.stmts);
    blocks.push(cur);
    let mut lines = structure(blocks);
    let decls = format_local_decls(&ssa, &tf, &mut lines);
    if !decls.is_empty() {
        let mut with_decls = decls;
        with_decls.push(String::new());
        with_decls.extend(lines);
        lines = with_decls;
    }
    if shown.start > f.start {
        lines.insert(0, format!("  /* ... slice from {:#x} (function starts at {:#x}) ... */", shown.start, f.start));
    }
    if shown.end < f.end {
        lines.push(format!("  /* ... truncated at {:#x} (function ends at {:#x}) ... */", shown.end, f.end));
    }
    Ok((f.start, format!("{}\n{}\n{}\n}}\n", tf.header_block, tf.sig_line, lines.join("\n"))))
}

#[cfg(test)]
mod tests {
    use super::c_one;
    use crate::image::{Image, Segment};
    use crate::runtime::RuntimeMap;

    #[test]
    fn decompiles_branches_calls_tables_ops_runtime_and_tuples() {
        let mut data = vec![0u8; 0x500];
        data[0x200..0x206].copy_from_slice(&[0xff, 0x25, 0x00, 0x01, 0x00, 0x00]);
        data[0x220..0x224].copy_from_slice(&[0x48, 0x89, 0xf8, 0xc3]);
        data[0x300..0x304].copy_from_slice(&(-0x1f3i32).to_le_bytes());
        data[0x320..0x329].copy_from_slice(b"hello txt");
        data[0x340..0x361].copy_from_slice(b"\x20index out of bounds: the len is ");
        let code: &[u8] = &[
            0x55, 0x48, 0x89, 0xe5, 0x48, 0x83, 0xec, 0x10, 0x49, 0x89, 0xfe, 0x48, 0x89, 0x74, 0x24, 0x08, 0x48, 0x8d,
            0x44, 0x24, 0x08, 0x48, 0x89, 0x07, 0x48, 0x83, 0xff, 0x09, 0x0f, 0x94, 0xc0, 0x48, 0x0f, 0x45, 0xc6, 0x48,
            0x85, 0xc0, 0x48, 0xf7, 0xc6, 0x01, 0x00, 0x00, 0x00, 0x31, 0xc9, 0x48, 0x6b, 0xd7, 0x05, 0x48, 0x83, 0xc2,
            0x01, 0x48, 0xff, 0xc2, 0x0f, 0x31, 0x6a, 0x07, 0xe8, 0xbd, 0x01, 0x00, 0x00, 0x58, 0xe8, 0xd7, 0x01, 0x00,
            0x00, 0xff, 0xd6, 0x66, 0x0f, 0x2e, 0xc0, 0x70, 0x05, 0x75, 0x05, 0xeb, 0x00, 0xc3, 0x0f, 0x0b, 0x78, 0x05,
            0xe9, 0xc1, 0x01, 0x00, 0x00, 0xff, 0xe6, 0x0f, 0x0b,
        ];
        data[..code.len()].copy_from_slice(code);
        let jt_fn: &[u8] = &[
            0x48, 0x8d, 0x0d, 0xf9, 0x01, 0x00, 0x00, 0x48, 0x63, 0x04, 0x89, 0xff, 0xe0, 0x48, 0x8b, 0x06, 0xb9, 0x01,
            0x00, 0x00, 0x00, 0x48, 0x8d, 0x35, 0x04, 0x02, 0x00, 0x00, 0xba, 0x05, 0x00, 0x00, 0x00, 0x49, 0x83, 0xc6,
            0xff, 0xff, 0x15, 0xdf, 0x01, 0x00, 0x00, 0xff, 0x15, 0xe1, 0x01, 0x00, 0x00, 0x0f, 0x57, 0xc0, 0xf3, 0x48,
            0x0f, 0xbc, 0xc7, 0xc3,
        ];
        data[0x100..0x100 + jt_fn.len()].copy_from_slice(jt_fn);
        let (end1, end2) = (0x1000 + code.len() as u64, 0x1100 + jt_fn.len() as u64);
        let image = Image {
            data,
            segments: vec![Segment { va: 0x1000, offset: 0, size: 0x500 }],
            functions: vec![0x1000..end1, 0x1100..end2, 0x1200..0x1206, 0x1220..0x1224],
            pointers: vec![(0x1312, 0x1220)],
            imports: vec![(0x1306, "puts".to_owned()), (0x130a, "puts".to_owned())],
            symbols: Vec::new(),
        };
        let rt = RuntimeMap::default();
        let (_, text) = c_one(&image, &[], &rt, 0x1000, None, None).unwrap_or_default();
        assert!(text.contains("fn_1000(") && text.contains("&slot_8") && text.contains(", 7)"), "{text}");
        assert!(text.contains("fn_1220(") && text.contains("overflow(") && text.contains("return rsi("), "{text}");
        assert!(text.contains("rdtsc"), "{text}");
        let (_, t2) = c_one(&image, &[], &rt, 0x1100, None, None).unwrap_or_default();
        assert!(t2.contains("switch (") && t2.contains("case 0 (0x0):") && t2.contains("puts(\"hello\", 5, 1)"));
        assert!(t2.contains("zmm0 = 0;") && t2.contains("return __builtin_ctzll(rdi);"), "{t2}");
        assert!(c_one(&image, &[], &rt, 0x9999, None, None).is_err());
        let (_, sliced) = c_one(&image, &[], &rt, 0x1000, Some(0x1004), Some(0x1010)).unwrap_or_default();
        assert!(sliced.contains("slice from 0x1004") && sliced.contains("truncated at 0x1010"), "{sliced}");
    }
}
