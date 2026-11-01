/*
 * xref — Ultra blazing fast cross-references of an x86-64 ELF binary
 * Copyright (c) 2026 Alexander Panasenko
 *
 * Contact: alex@prod.codes
 * Author: https://prod.codes/about/
 * Project: https://github.com/alex09x/xref
 * SPDX-License-Identifier: MIT OR Apache-2.0
 */

//! Backward program slice (`xref slice`): extracts the minimal set of pseudo-C statements and
//! enclosing control conditions affecting a target address, call, field, or panic string.

use std::collections::HashSet;
use std::io::Write;

use crate::c::c_one;
use crate::cli::hex_address;
use crate::commands::Res;
use crate::fields_c::apply_field_sugar;
use crate::graph::{call_target, resolve};
use crate::image::Image;
use crate::locations::{Location, locations};
use crate::runtime::RuntimeMap;
use crate::scan::{branch_target, decode};
use crate::source::location_at;

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

fn stmt_def_use(trimmed: &str) -> (Vec<String>, Vec<String>) {
    if let Some((lhs, rhs)) = trimmed.strip_suffix(';').and_then(|s| s.split_once(" = ")) {
        let lhs_t = lhs.trim();
        if lhs_t.starts_with('*') || lhs_t.contains("->") || lhs_t.contains('[') {
            let mut uses = extract_idents(lhs_t);
            uses.extend(extract_idents(rhs));
            return (Vec::new(), uses);
        }
        return (extract_idents(lhs_t), extract_idents(rhs));
    }
    (Vec::new(), extract_idents(trimmed))
}

fn target_hints_for_ip(image: &Image, locs: &[Location], f: &std::ops::Range<u64>, target_ip: u64) -> Vec<String> {
    let mut hints = vec![format!("{target_ip:#x}"), format!("L_{target_ip:x}")];
    let Some(bytes) = image.code(f) else { return hints };
    decode(bytes, f.start, |ins| {
        if ins.ip() <= target_ip && target_ip < ins.next_ip() {
            if let Some(ct) = call_target(image, ins) {
                hints.push(format!("fn_{ct:x}"));
            }
            if let Some(bt) = branch_target(ins) {
                hints.push(format!("L_{bt:x}"));
            }
            if ins.is_ip_rel_memory_operand() {
                let place = ins.ip_rel_memory_address();
                if let Some(loc) = location_at(locs, place) {
                    hints.push(format!("{}:{}", loc.file, loc.line));
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

    let mut keep = vec![false; lines.len()];
    keep[0] = true;
    keep[lines.len() - 1] = true;
    if lines.get(1).is_some_and(|l| l.starts_with("function ")) {
        keep[1] = true;
    }

    let mut matched_any = false;
    for (idx, &line) in lines.iter().enumerate() {
        let low = line.to_ascii_lowercase();
        if !line.starts_with("/*")
            && !line.starts_with("function ")
            && hints.iter().any(|h| !h.is_empty() && low.contains(h))
        {
            keep[idx] = true;
            matched_any = true;
        }
    }
    if !matched_any {
        return Err(format!("slice target {target:?} not found in {:#x}..{:#x}", f.start, f.end).into());
    }

    let last_target = keep[..lines.len() - 1].iter().rposition(|&k| k).unwrap_or(0);
    let mut needed: HashSet<String> = HashSet::new();
    for idx in (1..lines.len() - 1).rev() {
        let trimmed = lines[idx].trim();
        let indent = lines[idx].len() - lines[idx].trim_start().len();
        if !keep[idx] && idx < last_target && trimmed.starts_with("if ") {
            if !trimmed.ends_with('{') {
                keep[idx] = true;
            } else if let Some(end_rel) = (idx + 1..lines.len())
                .find(|&k| (lines[k].len() - lines[k].trim_start().len()) == indent && lines[k].trim() == "}")
                && end_rel < last_target
            {
                let exits = (idx + 1..end_rel).any(|k| {
                    let t = lines[k].trim();
                    t.starts_with("return ") || t == "unreachable();" || t.starts_with("goto ") || t == "break;"
                });
                if exits {
                    keep[idx] = true;
                    keep[end_rel - 1] = true;
                    keep[end_rel] = true;
                }
            }
        }
        let is_ctrl = trimmed.starts_with("if ")
            || trimmed.starts_with("} else")
            || trimmed.starts_with("while ")
            || trimmed.starts_with("do {")
            || trimmed.starts_with("} while")
            || trimmed.starts_with("switch ")
            || trimmed.starts_with("case ")
            || trimmed.ends_with(':');

        if keep[idx] {
            let (_, uses) = stmt_def_use(trimmed);
            needed.extend(uses);
            let mut open_indent = indent;
            for prev in (1..idx).rev() {
                let p_trim = lines[prev].trim();
                let p_ind = lines[prev].len() - lines[prev].trim_start().len();
                if p_ind < open_indent && (p_trim.ends_with('{') || p_trim.starts_with("case ")) {
                    keep[prev] = true;
                    let (_, c_uses) = stmt_def_use(p_trim);
                    needed.extend(c_uses);
                    open_indent = p_ind;
                    for close in (idx + 1)..lines.len() {
                        let c_ind = lines[close].len() - lines[close].trim_start().len();
                        let c_trim = lines[close].trim();
                        if c_ind == p_ind && (c_trim == "}" || c_trim.starts_with("} while")) {
                            keep[close] = true;
                            let (_, w_uses) = stmt_def_use(c_trim);
                            needed.extend(w_uses);
                            break;
                        }
                    }
                }
            }
            continue;
        }
        if is_ctrl {
            continue;
        }
        let (defs, uses) = stmt_def_use(trimmed);
        if !defs.is_empty() && defs.iter().any(|d| needed.contains(d)) {
            keep[idx] = true;
            for d in &defs {
                needed.remove(d);
            }
            needed.extend(uses);
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
        assert!(slice_fn(&image, "0x1000", "rbx + 5", false, &mut out).is_ok());
        let s = String::from_utf8_lossy(&out);
        assert!(s.contains("rbx = rdi;") && s.contains("if (") && !s.contains("42"), "{s}");
        assert!(slice_fn(&image, "0x1000", "nonexistent_token", false, &mut out).is_err());
    }
}
