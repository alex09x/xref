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

use crate::c::c_one_marked;
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

fn propagate_labels_and_gotos(lines: &[&str], sig_idx: usize, keep: &mut [bool]) -> bool {
    let mut changed = false;
    for idx in (sig_idx + 1..lines.len() - 1).rev() {
        if !keep[idx] {
            continue;
        }
        for prev in (sig_idx + 1..idx).rev() {
            let pt = strip_comment(lines[prev]);
            if pt.ends_with(':') && !pt.starts_with("case ") {
                let goto_pat = format!("goto {};", pt.trim_end_matches(':').trim());
                if !keep[prev] {
                    (keep[prev], changed) = (true, true);
                }
                for (g_idx, &g_line) in lines.iter().enumerate().skip(sig_idx + 1).take(lines.len() - sig_idx - 2) {
                    if !keep[g_idx] && strip_comment(g_line).contains(&goto_pat) {
                        (keep[g_idx], changed) = (true, true);
                    }
                }
                break;
            }
            if (lines[prev].len() - lines[prev].trim_start().len()) <= 2
                && (pt.starts_with("return") || pt == "unreachable();")
            {
                break;
            }
        }
    }
    changed
}

pub fn slice_fn(image: &Image, spec: &str, target: &str, use_fields: bool, out: &mut dyn Write) -> Res {
    let f = resolve(image, spec)?;
    let (locs, rt) = (locations(image), RuntimeMap::detect(image));
    let target_ip = hex_address(target).filter(|&ip| f.contains(&ip));
    let (_, raw_c) = c_one_marked(image, &locs, &rt, f.start, None, None, target_ip)?;
    let full_c = if use_fields { apply_field_sugar(image, &f, &raw_c) } else { raw_c };
    let q_low = target.trim().to_ascii_lowercase();
    let hints: Vec<String> = target_ip.map_or_else(
        || {
            let mut v = vec![q_low.clone()];
            if let Some(hex) = q_low.strip_prefix("0x") {
                v.push(format!("_{hex}"));
            }
            v
        },
        |ip| target_hints_for_ip(image, &locs, &f, ip).into_iter().map(|s| s.to_ascii_lowercase()).collect(),
    );
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
    let _ = propagate_labels_and_gotos(&lines, sig_idx, &mut keep);
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

    let (mut ever_used, mut changed): (HashSet<String>, bool) = (HashSet::new(), true);
    while changed {
        changed = propagate_labels_and_gotos(&lines, sig_idx, &mut keep);
        let mut live: HashSet<String> = HashSet::new();
        for idx in (sig_idx + 1..lines.len() - 1).rev() {
            let trimmed = strip_comment(lines[idx]);
            if trimmed.is_empty() {
                continue;
            }
            let indent = lines[idx].len() - lines[idx].trim_start().len();
            let is_uncond = indent <= 2 && !trimmed.starts_with("if ");
            let is_label = trimmed.ends_with(':') && !trimmed.starts_with("case ");
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
                if idx > sig_idx + 1
                    && lines[idx - 1].trim_start().starts_with("/* ")
                    && lines[idx - 1].trim_end().ends_with("*/")
                    && !keep[idx - 1]
                {
                    (keep[idx - 1], changed) = (true, true);
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
            writeln!(out, "{clean}")?;
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::slice_fn;
    use crate::image::{Image, Segment};

    #[test]
    fn slices_reaching_defs_skip_flags_balanced_braces_and_exact_call_ip() {
        let mut data = vec![0u8; 0x100];
        let code: &[u8] = &[
            0x48, 0x89, 0xfb, 0x48, 0xc7, 0xc1, 0x2a, 0x00, 0x00, 0x00, 0x48, 0x89, 0x0e, 0x48, 0x85, 0xdb, 0x74, 0x06,
            0x48, 0x8d, 0x43, 0x05, 0xc3, 0x31, 0xc0, 0xc3,
        ];
        data[..code.len()].copy_from_slice(code);
        data[0x40..0x43].copy_from_slice(&[0x89, 0xf8, 0xc3]);
        let f2: &[u8] = &[
            0x53, 0x48, 0x89, 0xfb, 0x48, 0x85, 0xf6, 0x74, 0x0c, 0x48, 0x83, 0xfa, 0x09, 0x74, 0x1a, 0x48, 0x83, 0xc3,
            0x01, 0xeb, 0x09, 0x48, 0x81, 0xf9, 0xa1, 0x01, 0x00, 0x00, 0x75, 0x0b, 0x48, 0x89, 0xdf, 0xe8, 0xca, 0xff,
            0xff, 0xff, 0x48, 0x01, 0xc3, 0xbf, 0x63, 0x00, 0x00, 0x00, 0xe8, 0xbd, 0xff, 0xff, 0xff, 0x48, 0x85, 0xc0,
            0x74, 0x04, 0x48, 0x83, 0xc0, 0x01, 0x48, 0x01, 0xd8, 0x5b, 0xc3,
        ];
        data[0x50..0x50 + f2.len()].copy_from_slice(f2);
        let image = Image {
            data,
            segments: vec![Segment { va: 0x1000, offset: 0, size: 0x100 }],
            functions: vec![0x1000..0x1000 + code.len() as u64, 0x1040..0x1043, 0x1050..0x1050 + f2.len() as u64],
            pointers: Vec::new(),
            imports: Vec::new(),
            symbols: Vec::new(),
        };
        let mut out = Vec::new();
        assert!(slice_fn(&image, "0x1000", "arg_0 + 5", false, &mut out).is_ok());
        let s = String::from_utf8_lossy(&out);
        assert!(s.contains("arg_0") && s.contains("if (") && !s.contains("42"), "{s}");
        assert!(slice_fn(&image, "0x1000", "nonexistent_token", false, &mut out).is_err());

        out.clear();
        assert!(slice_fn(&image, "0x1050", "0x1071", false, &mut out).is_ok());
        let s2 = String::from_utf8_lossy(&out);
        let opens = s2.chars().filter(|&c| c == '{').count();
        let closes = s2.chars().filter(|&c| c == '}').count();
        assert_eq!(opens, closes, "unbalanced braces:\n{s2}");
        assert!(s2.contains("u8 skip_1079 = 0;") && s2.contains("417") && !s2.contains("fn_1040(99)"), "{s2}");

        out.clear();
        assert!(slice_fn(&image, "0x1050", "fn_1040(99)", false, &mut out).is_ok());
        let s3 = String::from_utf8_lossy(&out);
        assert_eq!(s3.chars().filter(|&c| c == '{').count(), s3.chars().filter(|&c| c == '}').count(), "{s3}");
    }
}
