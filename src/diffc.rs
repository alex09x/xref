/*
 * xref — Ultra blazing fast cross-references of an x86-64 ELF binary
 * Copyright (c) 2026 Alexander Panasenko
 *
 * Contact: alex@prod.codes
 * Author: https://prod.codes/about/
 * Project: https://github.com/alex09x/xref
 * SPDX-License-Identifier: MIT OR Apache-2.0
 */

//! Cross-build normalized pseudo-C diff (`xref diff-c`): matches counterpart functions across two
//! builds, normalizes volatile `fn_<hex>` / `L_<hex>` addresses, and emits a clean unified diff.

use std::collections::HashMap;
use std::fmt::Write as _;
use std::io::Write;

use crate::c::c_one;
use crate::commands::Res;
use crate::fields_c::apply_field_sugar;
use crate::graph::resolve;
use crate::image::Image;
use crate::locations::locations;
use crate::matching::best_matches;
use crate::runtime::RuntimeMap;

fn normalize_c(raw: &str) -> Vec<String> {
    let mut fn_ids: HashMap<String, usize> = HashMap::new();
    let mut lbl_ids: HashMap<String, usize> = HashMap::new();
    let mut out = Vec::new();

    for line in raw.lines() {
        if let Some((_, rest)) = line.split_once("function ")
            && let Some((_, params)) = rest.split_once('(')
        {
            out.push(format!("function ({params}"));
            continue;
        }
        let mut norm = String::with_capacity(line.len());
        let bytes = line.as_bytes();
        let mut i = 0;
        while i < bytes.len() {
            let rem = &line[i..];
            if let Some(after) = rem.strip_prefix("fn_") {
                let hex_len = after.bytes().take_while(u8::is_ascii_hexdigit).count();
                if hex_len > 0 {
                    let sym = &after[..hex_len];
                    let next_id = fn_ids.len() + 1;
                    let id = *fn_ids.entry(sym.to_owned()).or_insert(next_id);
                    let _ = write!(norm, "@fn_{id}");
                    i += 3 + hex_len;
                    continue;
                }
            }
            if let Some(after) = rem.strip_prefix("L_") {
                let hex_len = after.bytes().take_while(u8::is_ascii_hexdigit).count();
                if hex_len > 0 {
                    let sym = &after[..hex_len];
                    let next_id = lbl_ids.len() + 1;
                    let id = *lbl_ids.entry(sym.to_owned()).or_insert(next_id);
                    let _ = write!(norm, "@L_{id}");
                    i += 2 + hex_len;
                    continue;
                }
            }
            if let Some(ch) = rem.chars().next() {
                norm.push(ch);
                i += ch.len_utf8();
            } else {
                break;
            }
        }
        out.push(norm);
    }
    out
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Edit {
    Same(usize),
    Del(usize),
    Add(usize),
}

fn lcs_edits(left: &[String], right: &[String]) -> Vec<Edit> {
    let (len_a, len_b) = (left.len(), right.len());
    if len_a.saturating_mul(len_b) > 2_500_000 {
        let mut edits = Vec::with_capacity(len_a + len_b);
        edits.extend((0..len_a).map(Edit::Del));
        edits.extend((0..len_b).map(Edit::Add));
        return edits;
    }
    let cols = len_b + 1;
    let mut dp = vec![0u32; (len_a + 1) * cols];
    for row in (0..len_a).rev() {
        for col in (0..len_b).rev() {
            dp[row * cols + col] = if left[row] == right[col] {
                dp[(row + 1) * cols + (col + 1)] + 1
            } else {
                dp[(row + 1) * cols + col].max(dp[row * cols + (col + 1)])
            };
        }
    }
    let mut edits = Vec::new();
    let (mut row, mut col) = (0, 0);
    while row < len_a && col < len_b {
        if left[row] == right[col] {
            edits.push(Edit::Same(row));
            row += 1;
            col += 1;
        } else if dp[(row + 1) * cols + col] >= dp[row * cols + (col + 1)] {
            edits.push(Edit::Del(row));
            row += 1;
        } else {
            edits.push(Edit::Add(col));
            col += 1;
        }
    }
    edits.extend((row..len_a).map(Edit::Del));
    edits.extend((col..len_b).map(Edit::Add));
    edits
}

pub fn diff_c(
    image: &Image,
    other: &Image,
    specs: &[String],
    explicit_target: Option<&str>,
    use_fields: bool,
    out: &mut dyn Write,
) -> Res {
    let (locs_a, locs_b) = rayon::join(|| locations(image), || locations(other));
    let (rt_a, rt_b) = rayon::join(|| RuntimeMap::detect(image), || RuntimeMap::detect(other));

    let pairs = if let Some(tgt) = explicit_target {
        let fa = resolve(image, specs.first().map_or("", String::as_str))?;
        let fb = resolve(other, tgt)?;
        vec![(fa, Some((0, fb, "explicit --target".to_owned())))]
    } else {
        best_matches(image, other, specs)?
    };

    for (fa, matched) in pairs {
        let Some((score, fb, info)) = matched else {
            writeln!(out, "--- {:#x}..{:#x}: no counterpart found in --other", fa.start, fa.end)?;
            continue;
        };
        let (_, raw_a) = c_one(image, &locs_a, &rt_a, fa.start, None, None)?;
        let (_, raw_b) = c_one(other, &locs_b, &rt_b, fb.start, None, None)?;
        let ca = if use_fields { apply_field_sugar(image, &fa, &raw_a) } else { raw_a };
        let cb = if use_fields { apply_field_sugar(other, &fb, &raw_b) } else { raw_b };

        let (na, nb) = (normalize_c(&ca), normalize_c(&cb));
        let edits = lcs_edits(&na, &nb);
        let changed = edits.iter().filter(|e| !matches!(e, Edit::Same(_))).count();
        writeln!(
            out,
            "=== diff {:#x}..{:#x} (current) vs {:#x}..{:#x} (other, score {score}: {info}) ===",
            fa.start, fa.end, fb.start, fb.end
        )?;
        if changed == 0 {
            writeln!(out, "  identical normalized pseudo-C ({} lines)", na.len())?;
            continue;
        }
        let show: Vec<bool> = (0..edits.len())
            .map(|idx| {
                let lo = idx.saturating_sub(2);
                let hi = (idx + 3).min(edits.len());
                edits[lo..hi].iter().any(|e| !matches!(e, Edit::Same(_)))
            })
            .collect();

        let mut skipped = false;
        for (idx, edit) in edits.iter().enumerate() {
            if !show[idx] {
                if !skipped {
                    writeln!(out, "  ...")?;
                    skipped = true;
                }
                continue;
            }
            skipped = false;
            match *edit {
                Edit::Same(ia) => writeln!(out, "  {}", na[ia])?,
                Edit::Del(ia) => writeln!(out, "- {}", na[ia])?,
                Edit::Add(ib) => writeln!(out, "+ {}", nb[ib])?,
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{diff_c, normalize_c};
    use crate::image::{Image, Segment};

    #[test]
    fn normalizes_shifted_addresses_and_diffs_changed_constants() {
        let a =
            normalize_c("function 0x1000..0x1020 (rdi) {\n  rax = fn_2000(rdi);\n  if (rax == 0) goto L_1018;\n}\n");
        let b =
            normalize_c("function 0x4000..0x4020 (rdi) {\n  rax = fn_8000(rdi);\n  if (rax == 0) goto L_4018;\n}\n");
        assert_eq!(a, b);

        let mk = |imm: u8, shift: usize| -> Image {
            let mut data = vec![0xc3u8; 0x100];
            let code = [0x48, 0x83, 0xff, imm, 0x0f, 0x94, 0xc0, 0xc3];
            data[shift..shift + code.len()].copy_from_slice(&code);
            let va = 0x1000 + shift as u64;
            Image {
                data,
                segments: vec![Segment { va: 0x1000, offset: 0, size: 0x100 }],
                functions: std::iter::once(va..va + code.len() as u64).collect(),
                pointers: Vec::new(),
                imports: Vec::new(),
                symbols: Vec::new(),
            }
        };
        let (img1, img2) = (mk(9, 0), mk(12, 0x20));
        let mut out = Vec::new();
        assert!(diff_c(&img1, &img2, &["0x1000".to_owned()], Some("0x1020"), false, &mut out).is_ok());
        let s = String::from_utf8_lossy(&out);
        assert!(s.contains("-   return rdi == 9;") && s.contains("+   return rdi == 12;"), "{s}");
    }
}
