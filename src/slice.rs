/*
 * xref — Ultra blazing fast cross-references of an x86-64 ELF binary
 * Copyright (c) 2026 Alexander Panasenko
 *
 * Contact: alex@prod.codes
 * Author: https://prod.codes/about/
 * Project: https://github.com/alex09x/xref
 * SPDX-License-Identifier: MIT OR Apache-2.0
 */

//! Backward program slice (`xref slice`): extracts the minimal set of pseudo-C statements,
//! referenced local declarations, and enclosing control conditions affecting a target.

use std::collections::HashSet;
use std::io::Write;
use std::ops::Range;

use crate::cli::hex_address;
use crate::commands::Res;
use crate::fields_c::apply_field_sugar;
use crate::graph::resolve;
use crate::image::Image;
use crate::locations::locations;
use crate::runtime::RuntimeMap;
use crate::slice_parse::{
    build_block_spans, collect_stack_ptr_vars, decl_ident, pure_decl_ident, stmt_def_use, strip_comment,
    target_hints_for_ip,
};

const SLICE_MARK: &str = "/* @xref_slice_target */";

mod control;
use control::Control;

pub mod field;

pub fn slice_fn(image: &Image, spec: &str, target: &str, use_fields: bool, out: &mut dyn Write) -> Res {
    slice_fn_with_mode(image, spec, target, use_fields, false, out)
}

pub fn slice_fn_with_mode(
    image: &Image,
    spec: &str,
    target: &str,
    use_fields: bool,
    keep_gotos: bool,
    out: &mut dyn Write,
) -> Res {
    let f = resolve(image, spec)?;
    let (locs, rt) = (locations(image), RuntimeMap::detect(image));
    let parsed_field = crate::slice_parse::FieldSliceTarget::parse(target);
    let (mark_ip, mark_targets) = if let Some(field_target) = &parsed_field {
        let targets = field::find_field_targets(image, &f, field_target)?;
        (None, Some(targets))
    } else {
        (hex_address(target).filter(|&ip| f.contains(&ip)), None)
    };
    let (_, raw_c) = crate::c::c_one_options(
        image,
        &locs,
        &rt,
        f.start,
        crate::c::COptions { mark_ip, mark_targets, keep_gotos, ..Default::default() },
    )?;
    let full_c = if use_fields { apply_field_sugar(image, &f, &raw_c) } else { raw_c };
    let q_low = target.trim().to_ascii_lowercase();
    let hints: Vec<String> = if parsed_field.is_some() {
        Vec::new()
    } else {
        mark_ip.map_or_else(
            || {
                let mut v = vec![q_low.clone()];
                if let Some(hex) = q_low.strip_prefix("0x") {
                    v.push(format!("_{hex}"));
                }
                v
            },
            |ip| target_hints_for_ip(image, &locs, &f, ip).into_iter().map(|s| s.to_ascii_lowercase()).collect(),
        )
    };
    if parsed_field.is_some() {
        // State the alias model instead of silently dropping accesses through other pointers.
        writeln!(
            out,
            "/* --to-field alias model: accesses through other pointers are kept as may-alias only at the same field offset (or with an index register); an interior pointer to the same object at a different offset is not tracked */"
        )?;
    }
    slice_rendered_c(&f, target, &hints, &full_c, out)
}

pub fn slice_rendered_c(f: &Range<u64>, target: &str, hints: &[String], full_c: &str, out: &mut dyn Write) -> Res {
    let lines: Vec<&str> = full_c.lines().collect();
    if lines.len() <= 2 {
        out.write_all(full_c.as_bytes())?;
        return Ok(());
    }
    let sig_idx = lines
        .iter()
        .position(|l| !l.starts_with(' ') && !l.starts_with("/*") && !l.starts_with('*') && l.ends_with(") {"))
        .unwrap_or(0);
    let (mut keep, mut matched_any) = (vec![false; lines.len()], false);
    (keep[sig_idx], keep[lines.len() - 1]) = (true, true);
    for (idx, &line) in lines.iter().enumerate().skip(sig_idx + 1).take(lines.len().saturating_sub(sig_idx + 2)) {
        if line.contains(SLICE_MARK) {
            (keep[idx], matched_any) = (true, true);
        }
    }
    if !matched_any {
        for (idx, &line) in lines.iter().enumerate().skip(sig_idx + 1).take(lines.len().saturating_sub(sig_idx + 2)) {
            let code = strip_comment(line);
            if !code.is_empty() && pure_decl_ident(code).is_none() {
                let low = code.to_ascii_lowercase();
                if hints.iter().any(|h| !h.is_empty() && low.contains(h)) {
                    (keep[idx], matched_any) = (true, true);
                }
            }
        }
    }
    if !matched_any {
        return Err(format!("slice target {target:?} not found in {:#x}..{:#x}", f.start, f.end).into());
    }
    let (stack_ptr_vars, spans) = (collect_stack_ptr_vars(&lines), build_block_spans(&lines, sig_idx));
    let control = Control::new(&lines);
    let selected = keep.clone();
    let _ = control.propagate(&lines, sig_idx, &selected, &mut keep);
    let top_ret = (sig_idx + 1..lines.len() - 1)
        .find(|&k| {
            (lines[k].len() - lines[k].trim_start().len()) == 2
                && (strip_comment(lines[k]).starts_with("return") || strip_comment(lines[k]) == "unreachable();")
        })
        .unwrap_or(lines.len() - 1);
    if top_ret < lines.len() - 1 && keep[top_ret + 1..lines.len() - 1].iter().any(|&k| k) {
        keep[top_ret] = true;
    }
    let last_target = keep[..top_ret].iter().rposition(|&k| k).unwrap_or(sig_idx);
    for idx in (sig_idx + 1..last_target).rev() {
        let trimmed = strip_comment(lines[idx]);
        if !keep[idx] && trimmed.starts_with("if ") {
            if !trimmed.ends_with('{') {
                if trimmed.contains("return") || trimmed.contains("unreachable()") {
                    keep[idx] = true;
                }
            } else if let Some(sp) = spans.iter().find(|s| s.open == idx && s.elses.is_empty() && s.close < last_target)
            {
                let last_t = strip_comment(lines[sp.close - 1]);
                if !last_t.starts_with('}')
                    && (last_t.starts_with("return") || last_t == "unreachable();" || last_t == "break;")
                {
                    (keep[sp.open], keep[sp.close - 1], keep[sp.close]) = (true, true, true);
                }
            }
        }
    }

    control.keep_bypasses(&lines, &spans, last_target, &mut keep);
    let (mut ever_used, mut changed): (HashSet<String>, bool) = (HashSet::new(), true);
    while changed {
        changed = control.propagate(&lines, sig_idx, &selected, &mut keep);
        let mut live: HashSet<String> = HashSet::new();
        for idx in (sig_idx + 1..lines.len() - 1).rev() {
            let trimmed = strip_comment(lines[idx]);
            if trimmed.is_empty() {
                continue;
            }
            let indent = lines[idx].len() - lines[idx].trim_start().len();
            let is_uncond = indent <= 2 && !trimmed.starts_with("if ");
            let is_label = control.is_label(idx);
            let is_ctrl = (trimmed.starts_with("if ") && trimmed.ends_with('{'))
                || trimmed.starts_with("} else")
                || trimmed.starts_with("while ")
                || trimmed.starts_with("do {")
                || trimmed.starts_with("} while")
                || trimmed.starts_with("switch ")
                || trimmed.starts_with("case ")
                || is_label;
            if keep[idx] {
                let (defs, uses) = stmt_def_use(trimmed, &stack_ptr_vars);
                for d in &defs {
                    if is_uncond && !uses.contains(d) {
                        live.remove(d);
                    }
                    ever_used.insert(d.clone());
                }
                for u in uses {
                    live.insert(u.clone());
                    ever_used.insert(u);
                }
                // Keep every comment line directly above a kept statement (callee note, object note).
                let mut above = idx;
                while above > sig_idx + 1
                    && lines[above - 1].trim_start().starts_with("/* ")
                    && lines[above - 1].trim_end().ends_with("*/")
                {
                    above -= 1;
                    if !keep[above] {
                        (keep[above], changed) = (true, true);
                    }
                }
            } else if is_label {
                if ever_used.contains(trimmed.trim_end_matches(':').trim()) {
                    (keep[idx], changed) = (true, true);
                }
            } else if !is_ctrl {
                let (defs, uses) = stmt_def_use(trimmed, &stack_ptr_vars);
                let decl_hit = decl_ident(trimmed).is_some_and(|dv| ever_used.contains(&dv));
                if decl_hit || (!defs.is_empty() && defs.iter().any(|d| live.contains(d))) {
                    (keep[idx], changed) = (true, true);
                    for d in &defs {
                        if is_uncond && !uses.contains(d) {
                            live.remove(d);
                        }
                        ever_used.insert(d.clone());
                    }
                    for u in uses {
                        live.insert(u.clone());
                        ever_used.insert(u);
                    }
                }
            }
        }
        for sp in &spans {
            let has_inner = (sp.open + 1..sp.close).any(|k| keep[k] && !sp.elses.contains(&k));
            if keep[sp.open] || keep[sp.close] || sp.elses.iter().any(|&el| keep[el]) || has_inner {
                for &b_idx in &[sp.open, sp.close] {
                    if !keep[b_idx] {
                        (keep[b_idx], changed) = (true, true);
                    }
                }
                for (i, &el) in sp.elses.iter().enumerate() {
                    let next_bound = sp.elses.get(i + 1).copied().unwrap_or(sp.close);
                    if (el + 1..next_bound).any(|k| keep[k]) && !keep[el] {
                        (keep[el], changed) = (true, true);
                    }
                }
            }
        }
    }

    let kept_cnt = keep.iter().filter(|&&k| k).count();
    writeln!(out, "/* slice of {:#x}..{:#x} -> {target} ({kept_cnt}/{} lines) */", f.start, f.end, lines.len())?;
    for (idx, &line) in lines.iter().enumerate() {
        if keep[idx] {
            let clean = line.replace(" /* @xref_slice_target */", "").replace(SLICE_MARK, "");
            let clean = control.terminate_sink(&lines, &keep, idx, clean);
            writeln!(out, "{clean}")?;
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests;
