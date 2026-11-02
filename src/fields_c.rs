/*
 * xref — Ultra blazing fast cross-references of an x86-64 ELF binary
 * Copyright (c) 2026 Alexander Panasenko
 *
 * Contact: alex@prod.codes
 * Author: https://prod.codes/about/
 * Project: https://github.com/alex09x/xref
 * SPDX-License-Identifier: MIT OR Apache-2.0
 */

//! Width-accurate pointer-offset field sugar (`arg_k->f_<off>`, `&arg_k->off_<off>`) lifted onto
//! immutable SSA parameter references in pseudo-C without speculative container/type claims.

use std::collections::{BTreeMap, HashMap, HashSet};
use std::ops::Range;

use crate::expr::ABI_ARGS;
use crate::image::Image;
use crate::layout::{FieldInfo, scan_fn};

fn is_ident(s: &str) -> bool {
    !s.is_empty() && s.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_')
}

fn find_arg_copy_aliases<'a>(lines: &[&'a str]) -> HashMap<usize, Vec<&'a str>> {
    let mut addr_taken_slots: HashSet<&'a str> = HashSet::new();
    let mut assigns: HashMap<&'a str, Vec<&'a str>> = HashMap::new();
    let mut tainted: HashSet<&'a str> = HashSet::new();

    for &line in lines {
        let trim = line.trim_start();
        if trim.starts_with("/*") || trim.starts_with("* ") || trim == "*/" {
            continue;
        }
        if line.contains("addr-taken")
            && let Some(semi) = trim.find(';')
            && let Some(id) = trim[..semi].split_whitespace().last().filter(|s| s.starts_with("slot_"))
        {
            addr_taken_slots.insert(id);
            continue;
        }
        let code = trim.find("/*").map_or(trim, |idx| &trim[..idx]).trim();
        if code.starts_with('(')
            && let Some((tup, _)) = code.split_once(") = ")
        {
            for part in tup.trim_start_matches('(').split(',') {
                let id = part.trim();
                if is_ident(id) {
                    tainted.insert(id);
                }
            }
            continue;
        }
        for clause in code.split(';') {
            let cl = clause.trim().trim_start_matches("for (").trim_end_matches(") {").trim();
            if let Some((lhs, rhs)) = cl.split_once(" = ") {
                let (l, r) = (lhs.trim(), rhs.trim());
                if is_ident(l) && !l.ends_with(['!', '<', '>', '=']) && !r.starts_with('=') {
                    assigns.entry(l).or_default().push(r);
                }
            }
        }
    }

    let arg_idx = |s: &str| -> Option<usize> { s.strip_prefix("arg_")?.parse::<usize>().ok().filter(|&k| k < 6) };
    let mut slot_to_arg: HashMap<&'a str, usize> = HashMap::new();
    for (&lhs, rhss) in &assigns {
        if lhs.starts_with("slot_")
            && !addr_taken_slots.contains(lhs)
            && !tainted.contains(lhs)
            && rhss.len() == 1
            && let Some(ak) = arg_idx(rhss[0])
        {
            slot_to_arg.insert(lhs, ak);
        }
    }
    let mut out: HashMap<usize, Vec<&'a str>> = HashMap::new();
    for (&lhs, rhss) in &assigns {
        if (lhs.starts_with("ptr_") || lhs.starts_with("v_")) && !tainted.contains(lhs) && !rhss.is_empty() {
            let mut resolved = rhss.iter().map(|&r| arg_idx(r).or_else(|| slot_to_arg.get(r).copied()));
            if let Some(Some(first_ak)) = resolved.next()
                && resolved.all(|x| x == Some(first_ak))
            {
                out.entry(first_ak).or_default().push(lhs);
            }
        }
    }
    out
}

fn build_field_names(fields: &BTreeMap<u64, FieldInfo>) -> BTreeMap<u64, String> {
    let mut map = BTreeMap::new();
    for (&off, info) in fields {
        let name = if info.ty.is_empty() { format!("off_{off:x}") } else { format!("f_{off:x}") };
        map.insert(off, name);
    }
    map
}

fn format_off_tokens(off: u64) -> [String; 2] {
    [format!("{off:#x}"), format!("{off}")]
}

fn rewrite_line(line: &str, rules: &[(String, String)]) -> String {
    let trimmed = line.trim_start();
    if trimmed.starts_with("/*") || trimmed.starts_with("* ") || trimmed == "*/" {
        return line.to_owned();
    }
    let (code_part, trailing_comment) = line.find("/*").map_or((line, ""), |idx| (&line[..idx], &line[idx..]));
    let mut cur = code_part.to_owned();
    for (pat, rep) in rules {
        if cur.contains(pat.as_str()) {
            cur = cur.replace(pat.as_str(), rep);
        }
    }
    if trailing_comment.is_empty() { cur } else { format!("{cur}{trailing_comment}") }
}

pub fn apply_field_sugar(image: &Image, function: &Range<u64>, pseudo_c: &str) -> String {
    let lines: Vec<&str> = pseudo_c.lines().collect();
    let mut rules: Vec<(String, String)> = Vec::new();
    let mut header_notes: Vec<String> = Vec::new();
    let mut arg_layouts: HashMap<usize, BTreeMap<u64, FieldInfo>> = HashMap::new();

    for (ak, &reg) in ABI_ARGS.iter().enumerate() {
        let mut fields = BTreeMap::new();
        let mut forwarded = Vec::new();
        scan_fn(image, function, reg, 0, None, &mut fields, &mut forwarded);
        if fields.len() >= 2 {
            arg_layouts.insert(ak, fields);
        }
    }
    if arg_layouts.is_empty() {
        return pseudo_c.to_owned();
    }

    let aliases = find_arg_copy_aliases(&lines);
    for ak in 0..ABI_ARGS.len() {
        let Some(fields) = arg_layouts.get(&ak) else { continue };
        let aname = format!("arg_{ak}");
        let fmap = build_field_names(fields);
        let summary: Vec<String> = fields
            .iter()
            .take(5)
            .map(|(off, fi)| {
                let t = if fi.ty.is_empty() { "addr" } else { fi.ty };
                format!("+{off:#x}:{t}")
            })
            .collect();
        header_notes.push(format!("{aname} [{}]", summary.join(", ")));

        let mut bases = vec![aname];
        if let Some(extra) = aliases.get(&ak) {
            bases.extend(extra.iter().map(|&s| s.to_owned()));
        }
        for bname in &bases {
            for (&off, fname) in &fmap {
                let info = &fields[&off];
                if off == 0 {
                    if !info.ty.is_empty() {
                        rules.push((format!("*({} *)({bname})", info.ty), format!("{bname}->{fname}")));
                    }
                    continue;
                }
                for tok in format_off_tokens(off) {
                    if !info.ty.is_empty() {
                        rules.push((format!("*({} *)({bname} + {tok})", info.ty), format!("{bname}->{fname}")));
                    }
                    if info.leas > 0 {
                        rules.push((format!("({bname} + {tok})"), format!("&{bname}->{fname}")));
                        rules.push((format!(" = {bname} + {tok};"), format!(" = &{bname}->{fname};")));
                    }
                }
            }
        }
    }
    rules.sort_by_key(|a| std::cmp::Reverse(a.0.len()));

    let mut out = String::with_capacity(pseudo_c.len() + 128);
    if !header_notes.is_empty() {
        out.push_str("/* field offsets: ");
        out.push_str(&header_notes.join("; "));
        out.push_str(" */\n");
    }
    for line in lines {
        out.push_str(&rewrite_line(line, &rules));
        out.push('\n');
    }
    out
}

#[cfg(test)]
mod tests {
    use super::apply_field_sugar;
    use crate::image::{Image, Segment};

    #[test]
    fn rewrites_width_matched_offsets_on_immutable_args_without_vec_claims() {
        let mut data = vec![0u8; 0x80];
        let code: &[u8] = &[
            0x49, 0x89, 0xfd, // mov r13, rdi
            0x49, 0x8b, 0x45, 0x20, // mov rax, [r13+0x20]
            0x48, 0x6b, 0xce, 0x30, // imul rcx, rsi, 0x30
            0x48, 0x8b, 0x14, 0x08, // mov rdx, [rax+rcx]
            0x49, 0x39, 0x75, 0x28, // cmp [r13+0x28], rsi
            0x49, 0x8d, 0x7d, 0x40, // lea rdi, [r13+0x40]
            0xc3,
        ];
        data[..code.len()].copy_from_slice(code);
        let f = 0x1000..0x1000 + code.len() as u64;
        let image = Image {
            data,
            segments: vec![Segment { va: 0x1000, offset: 0, size: 0x80 }],
            functions: vec![f.clone()],
            pointers: Vec::new(),
            imports: Vec::new(),
            symbols: Vec::new(),
        };
        let raw = "unk64 fn_1000(const void *arg_0, u64 arg_1) {\n  unk64 slot_20; /* [rsp+0x20] */\n  slot_20 = arg_0;\n  ptr_9 = slot_20;\n  ptr_3 = arg_0;\n  ptr_3 = (ptr_3 + 24);\n  if (arg_1 >= *(u64 *)(arg_0 + 0x28)) return 0;\n  ptr_1 = *(u64 *)(ptr_9 + 0x20);\n  v_2 = *(u64 *)(ptr_3 + 0x20);\n  v_4 = (arg_0 + 0x40);\n  *(u128 *)(arg_0 + 0x20) = 0;\n}\n";
        let sugared = apply_field_sugar(&image, &f, raw);
        assert!(sugared.contains("arg_0->f_28") && sugared.contains("ptr_9->f_20"), "{sugared}");
        assert!(sugared.contains("*(u64 *)(ptr_3 + 0x20)"), "{sugared}");
        assert!(sugared.contains("&arg_0->off_40"), "{sugared}");
        // 16-byte u128 store must NOT be falsely rewritten as an 8-byte f_20 store, and zero Vec claims!
        assert!(sugared.contains("*(u128 *)(arg_0 + 0x20) = 0;"), "{sugared}");
        assert!(!sugared.contains("vec_") && !sugared.contains("Vec"), "{sugared}");
    }
}
