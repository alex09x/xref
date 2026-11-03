/*
 * xref — Ultra blazing fast cross-references of an x86-64 ELF binary
 * Copyright (c) 2026 Alexander Panasenko
 *
 * Contact: alex@prod.codes
 * Author: https://prod.codes/about/
 * SPDX-License-Identifier: MIT OR Apache-2.0
 */

//! Algebraic linear-combination simplification (`lea` chains and constant folding), Rust/LLVM
//! saturating/comparison idioms, and exact `&str` / `fmt::Arguments` string slice recovery.

use std::fmt::Write as _;

use crate::image::Image;
use crate::reduce::trim_parens;

#[derive(Clone)]
struct Lin {
    terms: Vec<(String, i128)>,
    constant: u64,
    ops: usize,
}

fn parse_const(s: &str) -> Option<u64> {
    let t = s.trim();
    if let Some(hex) = t.strip_prefix("-0x") {
        return u64::from_str_radix(hex, 16).ok().map(u64::wrapping_neg);
    }
    if let Some(hex) = t.strip_prefix("0x") {
        return u64::from_str_radix(hex, 16).ok();
    }
    t.parse::<i64>().ok().map(i64::cast_unsigned)
}

fn format_const(val: u64) -> String {
    let s = val.cast_signed();
    if (-64..=1024).contains(&s) {
        format!("{s}")
    } else if (-0x10000..0).contains(&s) {
        format!("-{:#x}", s.unsigned_abs())
    } else {
        format!("{val:#x}")
    }
}

const fn step_quote_depth(bytes: &[u8], i: &mut usize, depth: &mut i32, in_str: &mut bool) -> bool {
    let b = bytes[*i];
    if *in_str {
        if b == b'\\' {
            *i += 1;
        } else if b == b'"' {
            *in_str = false;
        }
        *i += 1;
        return true;
    }
    match b {
        b'"' => *in_str = true,
        b'(' | b'[' => *depth += 1,
        b')' | b']' => *depth -= 1,
        _ => return false,
    }
    *i += 1;
    true
}

fn has_non_linear_top(s: &str) -> bool {
    let bytes = s.as_bytes();
    let (mut depth, mut in_str, mut i) = (0i32, false, 0usize);
    while i < bytes.len() {
        if step_quote_depth(bytes, &mut i, &mut depth, &mut in_str) {
            continue;
        }
        let b = bytes[i];
        if depth == 0
            && (matches!(b, b'?' | b':' | b'=' | b'!' | b'&' | b'|' | b'^' | b'/' | b'%' | b'>')
                || (b == b'<' && bytes.get(i + 1) != Some(&b'<') && (i == 0 || bytes[i - 1] != b'<')))
        {
            return true;
        }
        i += 1;
    }
    false
}

fn split_addends(s: &str) -> Vec<(i128, &str)> {
    let bytes = s.as_bytes();
    let mut out = Vec::new();
    let (mut depth, mut in_str, mut start, mut sign, mut i) = (0i32, false, 0usize, 1i128, 0usize);
    while i < bytes.len() {
        if step_quote_depth(bytes, &mut i, &mut depth, &mut in_str) {
            continue;
        }
        let b = bytes[i];
        if matches!(b, b'+' | b'-') && depth == 0 && i > start {
            let prev = s[..i].trim_end().as_bytes().last().copied();
            if prev.is_some_and(|p| !matches!(p, b'+' | b'-' | b'*' | b'<')) {
                let piece = s[start..i].trim();
                if !piece.is_empty() {
                    out.push((sign, piece));
                }
                sign = if b == b'+' { 1 } else { -1 };
                start = i + 1;
            }
        }
        i += 1;
    }
    let tail = s[start..].trim();
    if !tail.is_empty() {
        out.push((sign, tail));
    }
    out
}

fn find_top_op<'a>(s: &'a str, op: &str) -> Option<(&'a str, &'a str)> {
    let (bytes, opb) = (s.as_bytes(), op.as_bytes());
    let (mut depth, mut in_str, mut i) = (0i32, false, 0usize);
    while i + opb.len() <= bytes.len() {
        if step_quote_depth(bytes, &mut i, &mut depth, &mut in_str) {
            continue;
        }
        if depth == 0 && &bytes[i..i + opb.len()] == opb {
            let (lhs, rhs) = (s[..i].trim(), s[i + opb.len()..].trim());
            if !lhs.is_empty() && !rhs.is_empty() {
                return Some((lhs, rhs));
            }
        }
        i += 1;
    }
    None
}

fn eval_linear(raw: &str, allow_shift: bool) -> Lin {
    let s = trim_parens(raw.trim());
    if let Some(c) = parse_const(s) {
        return Lin { terms: Vec::new(), constant: c, ops: 0 };
    }
    if has_non_linear_top(s) {
        return Lin { terms: vec![(s.to_owned(), 1)], constant: 0, ops: 0 };
    }
    let addends = split_addends(s);
    if addends.len() > 1 {
        let mut acc = Lin { terms: Vec::new(), constant: 0, ops: addends.len() - 1 };
        for (sign, part) in addends {
            let sub = eval_linear(part, true);
            acc.ops += sub.ops;
            acc.constant = if sign > 0 {
                acc.constant.wrapping_add(sub.constant)
            } else {
                acc.constant.wrapping_sub(sub.constant)
            };
            for (sym, coef) in sub.terms {
                let delta = sign * coef;
                if let Some((_, existing)) = acc.terms.iter_mut().find(|(k, _)| *k == sym) {
                    *existing += delta;
                } else {
                    acc.terms.push((sym, delta));
                }
            }
        }
        acc.terms.retain(|(_, c)| *c != 0);
        return acc;
    }
    if let Some((lhs, rhs)) = find_top_op(s, "*") {
        let (a, b) = (eval_linear(lhs, true), eval_linear(rhs, true));
        if b.terms.is_empty() {
            let k = i128::from(b.constant.cast_signed());
            let mut terms = a.terms;
            for (_, c) in &mut terms {
                *c *= k;
            }
            terms.retain(|(_, c)| *c != 0);
            return Lin { terms, constant: a.constant.wrapping_mul(b.constant), ops: a.ops + b.ops + 1 };
        }
        if a.terms.is_empty() {
            let k = i128::from(a.constant.cast_signed());
            let mut terms = b.terms;
            for (_, c) in &mut terms {
                *c *= k;
            }
            terms.retain(|(_, c)| *c != 0);
            return Lin { terms, constant: a.constant.wrapping_mul(b.constant), ops: a.ops + b.ops + 1 };
        }
    }
    if allow_shift
        && let Some((lhs, rhs)) = find_top_op(s, "<<")
        && let Some(sh) = parse_const(rhs).filter(|&sh| sh <= 16)
    {
        let mut a = eval_linear(lhs, true);
        let factor = 1i128 << sh;
        for (_, c) in &mut a.terms {
            *c *= factor;
        }
        return Lin { terms: a.terms, constant: a.constant << sh, ops: a.ops + 1 };
    }
    let atom = if has_top_space(s) { format!("({s})") } else { s.to_owned() };
    Lin { terms: vec![(atom, 1)], constant: 0, ops: 0 }
}

fn has_top_space(s: &str) -> bool {
    let mut depth = 0i32;
    for b in s.bytes() {
        match b {
            b'(' | b'[' => depth += 1,
            b')' | b']' => depth -= 1,
            b' ' if depth == 0 => return true,
            _ => {}
        }
    }
    false
}

fn render_linear(lin: &Lin) -> String {
    if lin.terms.is_empty() {
        return format_const(lin.constant);
    }
    let mut out = String::new();
    for (idx, (sym, coef)) in lin.terms.iter().enumerate() {
        let abs = coef.unsigned_abs();
        let piece = if abs == 1 { sym.clone() } else { format!("{sym} * {abs}") };
        if idx == 0 {
            if *coef < 0 {
                out.push('-');
            }
        } else if *coef < 0 {
            out.push_str(" - ");
        } else {
            out.push_str(" + ");
        }
        out.push_str(&piece);
    }
    if lin.constant != 0 {
        let signed = lin.constant.cast_signed();
        if signed < 0 && signed > -0x10000 {
            let _ = write!(out, " - {}", format_const(signed.unsigned_abs()));
        } else {
            let _ = write!(out, " + {}", format_const(lin.constant));
        }
    }
    out
}

pub fn simplify_linear(expr: &str) -> String {
    let lin = eval_linear(expr, false);
    let final_ops = lin.terms.len().saturating_sub(1)
        + lin.terms.iter().filter(|(_, c)| c.unsigned_abs() != 1).count()
        + usize::from(!lin.terms.is_empty() && lin.constant != 0);
    if lin.ops == 0 || final_ops >= lin.ops {
        return expr.to_owned();
    }
    let rendered = render_linear(&lin);
    if expr.starts_with('(') && expr.ends_with(')') && trim_parens(expr) != expr && rendered.contains(' ') {
        format!("({rendered})")
    } else {
        rendered
    }
}

pub fn simplify_ternary(cond: &str, src: &str, prev: &str) -> String {
    let carry_sum = cond
        .strip_suffix(" == 0")
        .or_else(|| cond.strip_suffix(" < 0"))
        .or_else(|| cond.split_once(" < ").map(|(s, _)| s))
        .or_else(|| cond.strip_prefix("overflow(").and_then(|s| s.strip_suffix(')')));
    if (src == "-1" || src == "0xffffffffffffffff")
        && let Some(sum) = carry_sum
        && trim_parens(sum) == trim_parens(prev)
        && let Some((lhs, rhs)) = find_top_op(trim_parens(prev), "+")
    {
        return format!("saturating_add({}, {})", trim_parens(lhs), trim_parens(rhs));
    }
    format!("({cond} ? {src} : {prev})")
}

pub fn simplify_cmp_eq_one(lhs: &str) -> Option<String> {
    let inner = trim_parens(lhs);
    let (gt_part, _lt_part) = find_top_op(inner, "-")?;
    let gt = trim_parens(gt_part);
    (gt.contains(" > ") || gt.contains(" < ")).then(|| gt.to_owned())
}

pub fn resolve_str_slice(image: &Image, place: u64, raw_len: usize, is_fmt_tagged: bool) -> Option<String> {
    let len = if is_fmt_tagged { if raw_len & 1 == 1 { raw_len >> 1 } else { return None } } else { raw_len };
    if !(1..=256).contains(&len) {
        return None;
    }
    let bytes = image.read(place, len)?;
    let text = std::str::from_utf8(bytes).ok()?;
    text.chars().all(|c| c >= ' ' || c == '\n' || c == '\t').then(|| format!("{text:?}"))
}

#[cfg(test)]
mod tests {
    use super::{resolve_str_slice, simplify_cmp_eq_one, simplify_linear, simplify_ternary};
    use crate::image::{Image, Segment};

    #[test]
    fn simplifies_lea_chains_constants_saturating_add_and_string_slices() {
        assert_eq!(
            simplify_linear("*(u16 *)(rcx + 0x8ce) * 4 + *(u16 *)(rcx + 0x8ce) * 4 * 4"),
            "*(u16 *)(rcx + 0x8ce) * 20"
        );
        assert_eq!(simplify_linear("(rax << 3) + (rax << 3) * 8"), "rax * 72");
        assert_eq!(simplify_linear("(r9 + r9 * 2) * 8"), "r9 * 24");
        assert_eq!(simplify_linear("2 * (r9 + r9 * 2)"), "r9 * 6");
        assert_eq!(simplify_linear("(rdi - rdi * 3) + 8"), "-rdi * 2 + 8");
        assert_eq!(simplify_linear("rdi + rsi - rsi - 0x200"), "rdi - 512");
        assert_eq!(simplify_linear("0xffffffffffffef58 + 840"), "-0xd60");
        assert_eq!(simplify_linear("-0x100 + 16"), "-0xf0");
        assert_eq!(simplify_linear("0x8000000000000000 + 1"), "0x8000000000000001");
        assert_eq!(simplify_linear("(r14 - 1)"), "(r14 - 1)");
        assert_eq!(simplify_linear("(rsi << 3)"), "(rsi << 3)");
        assert_eq!(simplify_linear("((rax << 3) + (rax << 3) * 8)"), "(rax * 72)");
        assert_eq!(simplify_linear("rdi + 0x10000 + 0x10000"), "rdi + 0x20000");
        assert_eq!(simplify_linear("\"a\\\"b\" + 4 - 4"), "\"a\\\"b\"");
        assert_eq!(simplify_linear("(a ? b : c) + 1"), "(a ? b : c) + 1");

        assert_eq!(
            simplify_ternary("(*(u64 *)(r14 + 48) + 1) == 0", "-1", "(*(u64 *)(r14 + 48) + 1)"),
            "saturating_add(*(u64 *)(r14 + 48), 1)"
        );
        assert_eq!(simplify_ternary("a == 0", "1", "2"), "(a == 0 ? 1 : 2)");
        assert_eq!(simplify_cmp_eq_one("((i64)rax > 0 - rcx)"), Some("(i64)rax > 0".to_owned()));
        assert_eq!(simplify_cmp_eq_one("(rax - rcx)"), None);

        let mut data = vec![0u8; 128];
        data[..64].copy_from_slice(b"JoinHandle polled after completioninternal error: entered unreac");
        let image = Image {
            data,
            segments: vec![Segment { va: 0x2000, offset: 0, size: 128 }],
            functions: Vec::new(),
            pointers: Vec::new(),
            imports: Vec::new(),
            symbols: Vec::new(),
            metadata: crate::image_format::Metadata::default(),
        };
        assert_eq!(
            resolve_str_slice(&image, 0x2000, 69, true),
            Some("\"JoinHandle polled after completion\"".to_owned())
        );
        assert_eq!(resolve_str_slice(&image, 0x2000, 68, true), None);
        assert_eq!(resolve_str_slice(&image, 0x2000, 10, false), Some("\"JoinHandle\"".to_owned()));
        assert_eq!(resolve_str_slice(&image, 0x2000, 0, false), None);
        assert_eq!(simplify_linear("rax - rsi - rsi - rsi"), "rax - rsi * 3");
        assert_eq!(simplify_linear("3 * (2 * rax)"), "rax * 6");
    }
}
