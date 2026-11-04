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

use crate::c::{c_one, find_comment_outside_str};
use crate::commands::Res;
use crate::fields_c::apply_field_sugar;
use crate::graph::resolve;
use crate::image::Image;
use crate::locations::locations;
use crate::matching::{MatchOptions, match_images_report};
use crate::runtime::RuntimeMap;

fn is_metadata_comment(inner: &str) -> bool {
    inner.starts_with("[runtime] ")
        || inner.starts_with("[PLT] ")
        || inner.starts_with("[stub] ")
        || (inner.starts_with("fn_") && inner.contains(": "))
        || inner.starts_with("... ")
}

fn strip_c_comments(raw: &str) -> String {
    let mut out = String::with_capacity(raw.len());
    let mut in_header = false;
    for line in raw.lines() {
        let trim = line.trim();
        if in_header {
            if trim.ends_with("*/") {
                in_header = false;
            }
            continue;
        }
        if !line.starts_with(' ') && trim.starts_with("/*") {
            if !trim.ends_with("*/") {
                in_header = true;
            }
            continue;
        }
        if let Some(idx) = find_comment_outside_str(line) {
            let before = line[..idx].trim_end();
            if !before.trim().is_empty() {
                out.push_str(before);
                out.push('\n');
            } else if let Some(inner) = line[idx..].trim().strip_prefix("/*").and_then(|s| s.strip_suffix("*/"))
                && !is_metadata_comment(inner.trim())
            {
                out.push_str(line);
                out.push('\n');
            }
        } else {
            out.push_str(line);
            out.push('\n');
        }
    }
    out
}

const fn is_ident_byte(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b == b'_'
}

fn intern_sym(map: &mut HashMap<String, usize>, key: &str, prefix: &str, out: &mut String) {
    let next_id = map.len() + 1;
    let id = *map.entry(key.to_owned()).or_insert(next_id);
    let _ = write!(out, "{prefix}{id}");
}

fn normalize_c(raw: &str) -> Vec<String> {
    let cleaned = strip_c_comments(raw);
    let mut fn_ids: HashMap<String, usize> = HashMap::new();
    let mut lbl_ids: HashMap<String, usize> = HashMap::new();
    let mut var_ids: HashMap<String, usize> = HashMap::new();
    let mut slot_ids: HashMap<String, usize> = HashMap::new();
    let mut out = Vec::new();

    for raw_line in cleaned.lines() {
        let line = raw_line.trim_end();
        if line.trim().is_empty() {
            continue;
        }
        if let Some((_, rest)) = line.split_once("function ")
            && let Some((_, params)) = rest.split_once('(')
        {
            out.push(format!("function ({params}"));
            continue;
        }
        if !line.starts_with(' ')
            && line.ends_with(" {")
            && let Some((before_paren, after_paren)) = line.split_once('(')
            && let Some((ret_ty, _fn_name)) = before_paren.rsplit_once(' ')
        {
            out.push(format!("{ret_ty} @fn({after_paren}"));
            continue;
        }
        let mut norm = String::with_capacity(line.len());
        let bytes = line.as_bytes();
        let mut i = 0;
        while i < bytes.len() {
            let at_word_start = i == 0 || !is_ident_byte(bytes[i - 1]);
            let rem = &line[i..];
            if at_word_start {
                let tok_len = rem.bytes().take_while(|&b| is_ident_byte(b)).count();
                if tok_len > 0 {
                    let tok = &rem[..tok_len];
                    if let Some(hex) = tok.strip_prefix("fn_")
                        && !hex.is_empty()
                        && hex.bytes().all(|b| b.is_ascii_hexdigit())
                    {
                        intern_sym(&mut fn_ids, hex, "@fn_", &mut norm);
                        i += tok_len;
                        continue;
                    }
                    if let Some((prefix, key)) = tok
                        .strip_prefix("L_")
                        .map(|h| ("@L_", h))
                        .or_else(|| tok.strip_prefix("skip_").map(|h| ("@skip_", h)))
                        .or_else(|| tok.strip_prefix("prod_").map(|h| ("@prod_", h)))
                        .or_else(|| tok.strip_prefix("div_").map(|h| ("@div_", h)))
                        .or_else(|| tok.strip_prefix("lhs_").map(|h| ("@lhs_", h)))
                        .or_else(|| tok.strip_prefix("rhs_").map(|h| ("@rhs_", h)))
                        .or_else(|| tok.strip_prefix("cf_").map(|h| ("@cf_", h)))
                        .or_else(|| tok.strip_prefix("pre_").map(|h| ("@pre_", h)))
                        && !key.is_empty()
                        && key.bytes().all(|b| b.is_ascii_hexdigit())
                    {
                        intern_sym(&mut lbl_ids, tok, prefix, &mut norm);
                        i += tok_len;
                        continue;
                    }
                    if let Some(dec) = tok
                        .strip_prefix("v_")
                        .or_else(|| tok.strip_prefix("ptr_"))
                        .or_else(|| tok.strip_prefix("flag_"))
                        && !dec.is_empty()
                        && dec.bytes().all(|b| b.is_ascii_digit())
                    {
                        intern_sym(&mut var_ids, tok, "@var_", &mut norm);
                        i += tok_len;
                        continue;
                    }
                    if let Some(rest_slot) = tok.strip_prefix("slot_") {
                        let hex = rest_slot.strip_prefix('m').unwrap_or(rest_slot);
                        if !hex.is_empty() && hex.bytes().all(|b| b.is_ascii_hexdigit()) {
                            intern_sym(&mut slot_ids, tok, "@slot_", &mut norm);
                            i += tok_len;
                            continue;
                        }
                    }
                    norm.push_str(tok);
                    i += tok_len;
                    continue;
                }
            }
            let ch = rem.chars().next().unwrap_or('\0');
            norm.push(ch);
            i += ch.len_utf8();
        }
        out.push(norm);
    }
    out
}

pub struct PseudoCContext {
    locs: Vec<crate::locations::Location>,
    runtime: RuntimeMap,
}

impl PseudoCContext {
    pub(crate) fn new(image: &Image) -> Self {
        Self { locs: locations(image), runtime: RuntimeMap::detect(image) }
    }

    pub(crate) fn normalized(&self, image: &Image, range: &std::ops::Range<u64>) -> Result<Vec<String>, String> {
        let (_, raw) = c_one(image, &self.locs, &self.runtime, range.start, None, None)?;
        Ok(normalize_c(&raw))
    }
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
        vec![(fa, Some((0, fb, "explicit --target".to_owned(), None)), false, Vec::new(), Vec::new())]
    } else {
        let reports = match_images_report(
            image,
            other,
            specs,
            MatchOptions { compare_pseudo_c: true, ..MatchOptions::default() },
        )?;
        reports
            .into_iter()
            .map(|report| {
                let matched = report.selected.map(|c| (c.score, c.range, c.info, c.pseudo_c_similarity));
                (report.query, matched, report.ambiguous, report.candidates, report.warnings)
            })
            .collect::<Vec<_>>()
    };

    for (fa, matched, ambiguous, candidates, warnings) in pairs {
        if ambiguous {
            writeln!(out, "--- {:#x}..{:#x}: ambiguous counterpart; specify an explicit --target", fa.start, fa.end)?;
            for candidate in candidates.iter().take(8) {
                let similarity = candidate
                    .pseudo_c_similarity
                    .map(|v| format!(", pseudo-C similarity {v:.3} (heuristic)"))
                    .unwrap_or_default();
                writeln!(
                    out,
                    "  candidate {:#x}..{:#x}, score {}{}",
                    candidate.range.start, candidate.range.end, candidate.score, similarity
                )?;
            }
            for warning in warnings {
                writeln!(out, "  warning: {warning}")?;
            }
            continue;
        }
        let Some((score, fb, mut info, similarity)) = matched else {
            writeln!(out, "--- {:#x}..{:#x}: no counterpart found in --other", fa.start, fa.end)?;
            continue;
        };
        if let Some(similarity) = similarity {
            let _ = write!(info, "; pseudo-C similarity {similarity:.3} (heuristic)");
        }
        for warning in warnings {
            writeln!(out, "  warning: {warning}")?;
        }
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
    use super::{diff_c, lcs_edits, normalize_c};
    use crate::image::{Image, Segment};

    #[test]
    fn normalizes_shifted_addresses_and_diffs_changed_constants() {
        let fn_kw = normalize_c("function foo(int a)\n  slot_xyz = 1;\n");
        assert_eq!(fn_kw, vec!["function (int a)", "  slot_xyz = 1;"]);
        let big_a: Vec<String> = (0..1600).map(|k| format!("a_{k}")).collect();
        let big_b: Vec<String> = (0..1600).map(|k| format!("b_{k}")).collect();
        assert_eq!(lcs_edits(&big_a, &big_b).len(), 3200);
        let a = normalize_c(
            "/*\n * fn_1000\n */\nunk64 fn_1000(unk64 arg_0) {\n  unk64 v_1; /* rax */\n  /* fn_2000: source src/lib.rs:1 */\n  v_1 = fn_2000(arg_0);\n  if (v_1 == 0) goto L_1018;\n}\n",
        );
        let b = normalize_c(
            "/*\n * fn_4000\n */\nunk64 fn_4000(unk64 arg_0) {\n  unk64 v_7; /* rcx */\n  v_7 = fn_8000(arg_0);\n  if (v_7 == 0) goto L_4018;\n}\n",
        );
        assert_eq!(a, b);
        assert_ne!(
            normalize_c("unk64 fn_1(void) {\n  return \"/*aaaa*/\";\n}\n"),
            normalize_c("unk64 fn_1(void) {\n  return \"/*bbbb*/\";\n}\n")
        );
        assert_ne!(
            normalize_c("unk64 fn_1(void) {\n  /* mfence */\n  return rax;\n}\n"),
            normalize_c("unk64 fn_1(void) {\n  return rax;\n}\n")
        );

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
                metadata: crate::image_format::Metadata::default(),
            }
        };
        let (img1, img2) = (mk(9, 0), mk(12, 0x20));
        let mut out = Vec::new();
        assert!(diff_c(&img1, &img2, &["0x1000".to_owned()], Some("0x1020"), false, &mut out).is_ok());
        let s = String::from_utf8_lossy(&out);
        assert!(s.contains("-   return arg_0 == 9;") && s.contains("+   return arg_0 == 12;"), "{s}");
    }
}
