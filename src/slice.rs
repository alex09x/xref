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

use crate::c::{c_one, find_comment_outside_str};
use crate::callee_meta::sanitize_panic_path;
use crate::cli::hex_address;
use crate::commands::Res;
use crate::fields_c::apply_field_sugar;
use crate::graph::{call_target, resolve};
use crate::image::Image;
use crate::locations::{Location, locations};
use crate::runtime::RuntimeMap;
use crate::scan::{branch_target, decode};
use crate::source::location_at;

fn strip_comment(line: &str) -> &str {
    find_comment_outside_str(line).map_or(line, |idx| &line[..idx]).trim()
}

fn extract_idents(text: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut cur = String::new();
    for ch in text.chars() {
        if ch.is_ascii_alphanumeric() || ch == '_' {
            cur.push(ch);
        } else if !cur.is_empty() {
            if cur.chars().next().is_some_and(|c| c.is_ascii_alphabetic() || c == '_') {
                out.push(std::mem::take(&mut cur));
            } else {
                cur.clear();
            }
        }
    }
    if !cur.is_empty() && cur.chars().next().is_some_and(|c| c.is_ascii_alphabetic() || c == '_') {
        out.push(cur);
    }
    out
}

fn pure_decl_ident(code: &str) -> Option<String> {
    if code.contains('=') || code.contains('(') || !code.ends_with(';') {
        return None;
    }
    let body = code.strip_suffix(';')?.trim();
    if body.starts_with("return") || body == "break" || body == "continue" || body.starts_with("goto ") {
        return None;
    }
    extract_idents(body).pop()
}

struct BlockSpan {
    open: usize,
    elses: Vec<usize>,
    close: usize,
}

fn collect_stack_ptr_vars(lines: &[&str]) -> HashSet<String> {
    let mut out = HashSet::new();
    for &line in lines {
        let trimmed = strip_comment(line);
        if let Some((lhs, rhs)) = trimmed.strip_suffix(';').and_then(|s| s.split_once(" = "))
            && rhs.trim().starts_with("&slot_")
            && let Some(id) = extract_idents(lhs.trim()).pop()
        {
            out.insert(id);
        }
    }
    out
}

fn stmt_def_use(raw_trimmed: &str, stack_ptr_vars: &HashSet<String>) -> (Vec<String>, Vec<String>) {
    let trimmed = strip_comment(raw_trimmed);
    if trimmed.is_empty() {
        return (Vec::new(), Vec::new());
    }
    let mut call_defs = Vec::new();
    if trimmed.contains('(') {
        for rest in trimmed.split("&slot_").skip(1) {
            let hex_len = rest.bytes().take_while(u8::is_ascii_hexdigit).count();
            if hex_len > 0
                && let Ok(off) = u64::from_str_radix(&rest[..hex_len], 16)
            {
                call_defs.push(format!("slot_{off:x}"));
                call_defs.push(format!("slot_{:x}", off + 8));
                call_defs.push(format!("slot_{:x}", off + 16));
            }
        }
        for id in extract_idents(trimmed) {
            if stack_ptr_vars.contains(&id) {
                call_defs.push(id);
            }
        }
    }
    if let Some((lhs, rhs)) = trimmed.strip_suffix(';').and_then(|s| s.split_once(" = ")) {
        let lhs_t = lhs.trim();
        if lhs_t.starts_with('*') || lhs_t.contains("->") || lhs_t.contains('[') {
            let mut uses = extract_idents(lhs_t);
            uses.extend(extract_idents(rhs));
            return (call_defs, uses);
        }
        let mut lhs_ids = extract_idents(lhs_t);
        let mut defs: Vec<String> = if lhs_t.starts_with('(') { lhs_ids } else { lhs_ids.pop().into_iter().collect() };
        defs.extend(call_defs);
        return (defs, extract_idents(rhs));
    }
    (call_defs, extract_idents(trimmed))
}

fn build_block_spans(lines: &[&str], sig_idx: usize) -> Vec<BlockSpan> {
    let mut stack: Vec<(usize, Vec<usize>)> = Vec::new();
    let mut spans = Vec::new();
    for (idx, &line) in lines.iter().enumerate().skip(sig_idx + 1).take(lines.len().saturating_sub(sig_idx + 2)) {
        let t = strip_comment(line);
        if t.starts_with("} else") && t.ends_with('{') {
            if let Some((_, elses)) = stack.last_mut() {
                elses.push(idx);
            }
        } else if t.ends_with('{') {
            stack.push((idx, Vec::new()));
        } else if (t == "}" || t.starts_with("} while"))
            && let Some((open, elses)) = stack.pop()
        {
            spans.push(BlockSpan { open, elses, close: idx });
        }
    }
    spans
}

fn target_hints_for_ip(image: &Image, locs: &[Location], f: &std::ops::Range<u64>, target_ip: u64) -> Vec<String> {
    let mut hints = vec![format!("{target_ip:#x}"), format!("L_{target_ip:x}")];
    let Some(bytes) = image.code(f) else { return hints };
    decode(bytes, f.start, |ins| {
        if ins.ip() <= target_ip + 32 && target_ip < ins.next_ip() {
            if let Some(ct) = call_target(image, ins) {
                hints.push(format!("fn_{ct:x}"));
            }
            if let Some(bt) = branch_target(ins) {
                hints.push(format!("L_{bt:x}"));
            }
            if ins.is_ip_rel_memory_operand() {
                let place = ins.ip_rel_memory_address();
                if let Some(loc) = location_at(locs, place) {
                    hints.push(format!("{}:{}", sanitize_panic_path(&loc.file), loc.line));
                } else if let Some(prev) = image.preview(place) {
                    hints.push(prev);
                }
            }
        }
    });
    hints
}

pub fn slice_fn(image: &Image, spec: &str, target: &str, use_fields: bool, out: &mut dyn Write) -> Res {
    let f = resolve(image, spec)?;
    let locs = locations(image);
    let rt = RuntimeMap::detect(image);
    let (_, raw_c) = c_one(image, &locs, &rt, f.start, None, None)?;
    let full_c = if use_fields { apply_field_sugar(image, &f, &raw_c) } else { raw_c };
    let lines: Vec<&str> = full_c.lines().collect();
    if lines.len() <= 2 {
        out.write_all(full_c.as_bytes())?;
        return Ok(());
    }

    let q_low = target.trim().to_ascii_lowercase();
    let hints: Vec<String> = hex_address(target).filter(|&ip| f.contains(&ip)).map_or_else(
        || {
            let mut v = vec![q_low.clone()];
            if let Some(hex) = q_low.strip_prefix("0x") {
                v.push(format!("_{hex}"));
            }
            v
        },
        |ip| target_hints_for_ip(image, &locs, &f, ip).into_iter().map(|s| s.to_ascii_lowercase()).collect(),
    );

    let sig_idx = lines
        .iter()
        .position(|l| !l.starts_with(' ') && !l.starts_with("/*") && !l.starts_with('*') && l.ends_with(") {"))
        .unwrap_or(0);

    let mut keep = vec![false; lines.len()];
    (keep[sig_idx], keep[lines.len() - 1]) = (true, true);
    let mut matched_any = false;
    for (idx, &line) in lines.iter().enumerate().skip(sig_idx + 1).take(lines.len().saturating_sub(sig_idx + 2)) {
        let code = strip_comment(line);
        if !code.is_empty() && pure_decl_ident(code).is_none() {
            let low = code.to_ascii_lowercase();
            if hints.iter().any(|h| !h.is_empty() && low.contains(h)) {
                (keep[idx], matched_any) = (true, true);
            }
        }
    }
    if !matched_any {
        return Err(format!("slice target {target:?} not found in {:#x}..{:#x}", f.start, f.end).into());
    }
    let stack_ptr_vars = collect_stack_ptr_vars(&lines);
    let spans = build_block_spans(&lines, sig_idx);
    for idx in (sig_idx + 1..lines.len() - 1).rev() {
        if !keep[idx] {
            continue;
        }
        for prev in (sig_idx + 1..idx).rev() {
            let pt = strip_comment(lines[prev]);
            if pt.ends_with(':') && !pt.starts_with("case ") {
                let lbl = pt.trim_end_matches(':').trim();
                let goto_pat = format!("goto {lbl};");
                keep[prev] = true;
                for (g_idx, &g_line) in lines.iter().enumerate().skip(sig_idx + 1).take(lines.len() - sig_idx - 2) {
                    if strip_comment(g_line).contains(&goto_pat) {
                        keep[g_idx] = true;
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
                let exits = (sp.open + 1..sp.close).any(|k| {
                    let t = strip_comment(lines[k]);
                    t.starts_with("return") || t == "unreachable();" || t == "break;"
                });
                if exits {
                    (keep[sp.open], keep[sp.close - 1], keep[sp.close]) = (true, true, true);
                }
            }
        }
    }

    let mut ever_used: HashSet<String> = HashSet::new();
    let mut changed = true;
    while changed {
        changed = false;
        let mut live: HashSet<String> = HashSet::new();
        for idx in (sig_idx + 1..lines.len() - 1).rev() {
            let trimmed = strip_comment(lines[idx]);
            if trimmed.is_empty() {
                continue;
            }
            let is_label = trimmed.ends_with(':') && !trimmed.starts_with("case ");
            let is_ctrl = trimmed.starts_with("if ")
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
                    if !uses.contains(d) {
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
            } else if let Some(decl_var) = pure_decl_ident(trimmed) {
                if ever_used.contains(&decl_var) {
                    (keep[idx], changed) = (true, true);
                }
            } else if is_label {
                if ever_used.contains(trimmed.trim_end_matches(':').trim()) {
                    (keep[idx], changed) = (true, true);
                }
            } else if !is_ctrl {
                let (defs, uses) = stmt_def_use(trimmed, &stack_ptr_vars);
                if !defs.is_empty() && defs.iter().any(|d| live.contains(d)) {
                    (keep[idx], changed) = (true, true);
                    for d in &defs {
                        if !uses.contains(d) {
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
            if (sp.open + 1..sp.close).any(|k| keep[k] && !sp.elses.contains(&k)) {
                if !keep[sp.open] {
                    (keep[sp.open], changed) = (true, true);
                }
                if !keep[sp.close] {
                    (keep[sp.close], changed) = (true, true);
                }
                for &el in &sp.elses {
                    if (el + 1..sp.close).any(|k| keep[k]) && !keep[el] {
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
            writeln!(out, "{line}")?;
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::slice_fn;
    use crate::image::{Image, Segment};

    #[test]
    fn slices_only_reaching_definitions_and_enclosing_branches() {
        let mut data = vec![0u8; 0x80];
        let code: &[u8] = &[
            0x48, 0x89, 0xfb, // mov rbx, rdi
            0x48, 0xc7, 0xc1, 0x2a, 0x00, 0x00, 0x00, // mov rcx, 42 (dead for target)
            0x48, 0x89, 0x0e, // mov [rsi], rcx (dead store)
            0x48, 0x85, 0xdb, // test rbx, rbx
            0x74, 0x06, // je +6 -> ret
            0x48, 0x8d, 0x43, 0x05, // lea rax, [rbx+5]
            0xc3, // ret
            0x31, 0xc0, // xor eax, eax
            0xc3,
        ];
        data[..code.len()].copy_from_slice(code);
        let image = Image {
            data,
            segments: vec![Segment { va: 0x1000, offset: 0, size: 0x80 }],
            functions: std::iter::once(0x1000..0x1000 + code.len() as u64).collect(),
            pointers: Vec::new(),
            imports: Vec::new(),
            symbols: Vec::new(),
        };
        let mut out = Vec::new();
        assert!(slice_fn(&image, "0x1000", "arg_0 + 5", false, &mut out).is_ok());
        let s = String::from_utf8_lossy(&out);
        assert!(s.contains("arg_0") && s.contains("if (") && !s.contains("42"), "{s}");
        assert!(slice_fn(&image, "0x1000", "nonexistent_token", false, &mut out).is_err());
    }
}
