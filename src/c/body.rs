/*
 * xref — Ultra blazing fast cross-references of an x86-64 ELF binary
 * Copyright (c) 2026 Alexander Panasenko
 *
 * Contact: alex@prod.codes
 * Author: https://prod.codes/about/
 * Project: https://github.com/alex09x/xref
 * SPDX-License-Identifier: MIT OR Apache-2.0
 */

//! The function body after lifting: structured statements, local declarations (SSA webs, stack
//! slots, xmm registers), folded float temporaries and the slice/truncation markers.

use std::collections::HashSet;
use std::ops::Range;

use super::{find_comment_outside_str, line_idents};
use crate::cfg::{Block, structure};
use crate::expr::{reg_name, stack_name};
use crate::ssa_webs::SsaCfg;
use crate::type_facts::TypeFacts;

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

pub(super) fn finish_c_body(
    ssa: &SsaCfg,
    tf: &TypeFacts,
    (f, shown): (&Range<u64>, &Range<u64>),
    blocks: Vec<Block>,
    keep_gotos: bool,
    (homes, fold_floats): (&[(iced_x86::Register, String)], bool),
) -> String {
    let mut lines = if keep_gotos { crate::cfg::structure_with_gotos(blocks, true) } else { structure(blocks) };
    if fold_floats {
        crate::float_inline::inline_float_temps(&mut lines);
    }
    let mut decls = format_local_decls(ssa, tf, &mut lines);
    crate::float_alu::merge_declarations(ssa, homes, &mut decls);
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
