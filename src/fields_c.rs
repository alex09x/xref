/*
 * xref — Ultra blazing fast cross-references of an x86-64 ELF binary
 * Copyright (c) 2026 Alexander Panasenko
 *
 * Contact: alex@prod.codes
 * Author: https://prod.codes/about/
 * Project: https://github.com/alex09x/xref
 * SPDX-License-Identifier: MIT OR Apache-2.0
 */

//! Struct field and `Vec<T>` sugar (`->f_off`, `->vec_off.ptr`, `->vec_off.len`, `->vec_off.cap`)
//! lifted from `xref layout` directly onto structured pseudo-C output.

use std::collections::{BTreeMap, HashMap};
use std::ops::Range;

use iced_x86::Register;

use crate::expr::{ABI_ARGS, CALLEE_SAVED, reg_name};
use crate::image::Image;
use crate::layout::{FieldInfo, scan_fn};

fn detect_aliases<'a>(lines: &[&'a str], root_name: &'a str) -> Vec<&'a str> {
    let mut aliases = vec![root_name];
    let saved_names: Vec<String> = CALLEE_SAVED.iter().map(|&r| reg_name(r)).collect();
    for &line in lines.iter().take(16) {
        let trimmed = line.trim();
        if let Some((lhs, rhs)) = trimmed.strip_suffix(';').and_then(|s| s.split_once(" = "))
            && rhs == root_name
            && saved_names.iter().any(|n| n == lhs)
            && !aliases.contains(&lhs)
        {
            aliases.push(lhs);
        }
    }
    aliases
}

fn build_field_names(fields: &BTreeMap<u64, FieldInfo>) -> BTreeMap<u64, String> {
    let mut map = BTreeMap::new();
    let mut vec_bases = Vec::new();
    for (&off, info) in fields {
        if info.stride.is_some() && info.width == 8 && fields.get(&(off + 8)).is_some_and(|n| n.width == 8) {
            vec_bases.push(off);
        }
    }
    for &base in &vec_bases {
        map.insert(base, format!("vec_{base:x}.ptr"));
        map.insert(base + 8, format!("vec_{base:x}.len"));
        if fields.get(&(base + 16)).is_some_and(|n| n.width == 8) {
            map.insert(base + 16, format!("vec_{base:x}.cap"));
        }
    }
    for (&off, info) in fields {
        if map.contains_key(&off) {
            continue;
        }
        let name = if info.ty.is_empty() { format!("sub_{off:x}") } else { format!("f_{off:x}") };
        map.insert(off, name);
    }
    map
}

fn format_off_tokens(off: u64) -> [String; 2] {
    [format!("{off:#x}"), format!("{off}")]
}

fn rewrite_line(line: &str, rules: &[(String, String)]) -> String {
    let mut cur = line.to_owned();
    for (pat, rep) in rules {
        if cur.contains(pat.as_str()) {
            cur = cur.replace(pat.as_str(), rep);
        }
    }
    cur
}

pub fn apply_field_sugar(image: &Image, function: &Range<u64>, pseudo_c: &str) -> String {
    let lines: Vec<&str> = pseudo_c.lines().collect();
    let mut rules: Vec<(String, String)> = Vec::new();
    let mut header_notes: Vec<String> = Vec::new();
    let mut reg_layouts: HashMap<Register, BTreeMap<u64, FieldInfo>> = HashMap::new();

    for &reg in ABI_ARGS.iter().take(3) {
        let mut fields = BTreeMap::new();
        let mut forwarded = Vec::new();
        scan_fn(image, function, reg, 0, None, &mut fields, &mut forwarded);
        if fields.len() >= 2 {
            reg_layouts.insert(reg, fields);
        }
    }
    if reg_layouts.is_empty() {
        return pseudo_c.to_owned();
    }

    for &reg in ABI_ARGS.iter().take(3) {
        let Some(fields) = reg_layouts.get(&reg) else { continue };
        let rname = reg_name(reg);
        let aliases = detect_aliases(&lines, &rname);
        let fmap = build_field_names(fields);
        let vec_cnt = fmap.values().filter(|v| v.starts_with("vec_") && v.contains(".ptr")).count();
        if vec_cnt > 0 {
            header_notes.push(format!("{rname}: {} fields ({vec_cnt} Vec)", fields.len()));
        } else {
            header_notes.push(format!("{rname}: {} fields", fields.len()));
        }

        for (&off, fname) in &fmap {
            let info = &fields[&off];
            for alias in &aliases {
                if off == 0 {
                    for ty in ["u8", "u16", "u32", "u64", "u128"] {
                        rules.push((format!("*({ty} *)({alias})"), format!("{alias}->{fname}")));
                    }
                    continue;
                }
                for tok in format_off_tokens(off) {
                    for ty in ["u8", "u16", "u32", "u64", "u128"] {
                        rules.push((format!("*({ty} *)({alias} + {tok})"), format!("{alias}->{fname}")));
                    }
                    if info.leas > 0 {
                        rules.push((format!("({alias} + {tok})"), format!("&{alias}->{fname}")));
                        rules.push((format!(" = {alias} + {tok};"), format!(" = &{alias}->{fname};")));
                    }
                }
            }
        }
    }
    rules.sort_by_key(|a| std::cmp::Reverse(a.0.len()));

    let mut out = String::with_capacity(pseudo_c.len() + 128);
    if !header_notes.is_empty() {
        out.push_str("/* struct sugar: ");
        out.push_str(&header_notes.join(", "));
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
    fn rewrites_vec_ptr_len_and_struct_fields_onto_pseudo_c() {
        let mut data = vec![0u8; 0x80];
        let code: &[u8] = &[
            0x49, 0x89, 0xfd, // mov r13, rdi
            0x49, 0x8b, 0x45, 0x20, // mov rax, [r13+0x20]
            0x48, 0x6b, 0xce, 0x30, // imul rcx, rsi, 0x30
            0x48, 0x8b, 0x14, 0x08, // mov rdx, [rax+rcx] -> stride 0x30 on +0x20
            0x49, 0x39, 0x75, 0x28, // cmp [r13+0x28], rsi -> +0x28 u64 (Vec len)
            0x49, 0x8d, 0x7d, 0x40, // lea rdi, [r13+0x40] -> sub_40
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
        let raw = "function 0x1000..0x1018 (rdi, rsi) {\n  r13 = rdi;\n  if (rsi >= *(u64 *)(r13 + 0x28)) return 0;\n  rax = *(u64 *)(r13 + 0x20);\n  rdi = r13 + 0x40;\n}\n";
        let sugared = apply_field_sugar(&image, &f, raw);
        assert!(sugared.contains("r13->vec_20.len") && sugared.contains("r13->vec_20.ptr"), "{sugared}");
        assert!(sugared.contains("&r13->sub_40") && sugared.contains("1 Vec"), "{sugared}");
    }
}
