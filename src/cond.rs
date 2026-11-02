/*
 * xref — Ultra blazing fast cross-references of an x86-64 ELF binary
 * Copyright (c) 2026 Alexander Panasenko
 *
 * Contact: alex@prod.codes
 * Author: https://prod.codes/about/
 * Project: https://github.com/alex09x/xref
 * SPDX-License-Identifier: MIT OR Apache-2.0
 */

//! Condition-code and signed arithmetic overflow lifting (`add_overflow`, `sub_overflow`,
//! `mul_overflow`, `neg_overflow`) from x86-64 flag-producing instructions.

use iced_x86::{ConditionCode, Mnemonic};

use crate::carry_cond::{arith_cond_expr, carry_cond_expr, i_term};
use crate::simplify::simplify_cmp_eq_one;

const CC_OPS: &[(ConditionCode, &str, bool)] = &[
    (ConditionCode::e, "==", false),
    (ConditionCode::ne, "!=", false),
    (ConditionCode::b, "<", false),
    (ConditionCode::ae, ">=", false),
    (ConditionCode::be, "<=", false),
    (ConditionCode::a, ">", false),
    (ConditionCode::l, "<", true),
    (ConditionCode::ge, ">=", true),
    (ConditionCode::le, "<=", true),
    (ConditionCode::g, ">", true),
    (ConditionCode::s, "<", true),
    (ConditionCode::ns, ">=", true),
];

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum FlagOp {
    #[default]
    Other,
    Add(u8),
    Sub(u8),
    Mul,
    UMul,
    Neg,
    Adc(u8),
    Sbb(u8),
}

impl FlagOp {
    pub const fn from_bin_width(mnemonic: Mnemonic, bits: u8) -> Self {
        match mnemonic {
            Mnemonic::Add => Self::Add(bits),
            Mnemonic::Sub => Self::Sub(bits),
            Mnemonic::Imul => Self::Mul,
            _ => Self::Other,
        }
    }

    pub const fn bits(self, fallback: u8) -> u8 {
        match self {
            Self::Add(b) | Self::Sub(b) | Self::Adc(b) | Self::Sbb(b) => b,
            _ => fallback,
        }
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Flags {
    pub lhs: String,
    pub rhs: String,
    pub op: FlagOp,
    pub bits: u8,
    pub ovf: Option<(String, String)>,
    pub carry: Option<String>,
}

impl Flags {
    pub fn cmp_width(lhs: String, rhs: String, bits: u8) -> Self {
        Self { ovf: Some((lhs.clone(), rhs.clone())), lhs, rhs, op: FlagOp::Sub(bits), bits, carry: None }
    }

    #[cfg(test)]
    pub fn cmp(lhs: String, rhs: String) -> Self {
        Self::cmp_width(lhs, rhs, 64)
    }

    pub fn from_cmp_width(mnemonic: Mnemonic, lhs: String, rhs: String, bits: u8) -> Self {
        if mnemonic == Mnemonic::Cmp { Self::cmp_width(lhs, rhs, bits) } else { Self::other(lhs, rhs) }
    }

    pub const fn other(lhs: String, rhs: String) -> Self {
        Self { lhs, rhs, op: FlagOp::Other, bits: 64, ovf: None, carry: None }
    }

    pub fn test_width(tested: String, bits: u8) -> Self {
        Self { lhs: tested, rhs: "0".to_owned(), op: FlagOp::Other, bits, ovf: None, carry: None }
    }

    pub fn test(tested: String) -> Self {
        Self::test_width(tested, 64)
    }

    pub fn arith_width(op: FlagOp, bits: u8, flag_lhs: String, a: String, b: String) -> Self {
        let ovf = (!matches!(op, FlagOp::Other)).then_some((a, b));
        Self { lhs: flag_lhs, rhs: "0".to_owned(), op, bits: op.bits(bits), ovf, carry: None }
    }

    pub fn arith(op: FlagOp, flag_lhs: String, a: String, b: String) -> Self {
        Self::arith_width(op, 64, flag_lhs, a, b)
    }

    pub const fn carry_op(op: FlagOp, flag_lhs: String, a: String, b: String, cf_in: String) -> Self {
        Self { lhs: flag_lhs, rhs: String::new(), op, bits: op.bits(64), ovf: Some((a, b)), carry: Some(cf_in) }
    }

    pub fn inc_dec_width(mnemonic: Mnemonic, bits: u8, expr: String, raw_val: String, prev_cf: String) -> Self {
        let op = if mnemonic == Mnemonic::Inc { FlagOp::Add(bits) } else { FlagOp::Sub(bits) };
        Self { lhs: expr, rhs: "0".to_owned(), op, bits, ovf: Some((raw_val, "1".to_owned())), carry: Some(prev_cf) }
    }

    pub fn unary_width(mnemonic: Mnemonic, bits: u8, expr: String, raw_val: String) -> Self {
        let (op, ovf) = match mnemonic {
            Mnemonic::Inc => (FlagOp::Add(bits), Some((raw_val, "1".to_owned()))),
            Mnemonic::Dec => (FlagOp::Sub(bits), Some((raw_val, "1".to_owned()))),
            Mnemonic::Neg => (FlagOp::Neg, Some((raw_val, String::new()))),
            _ => (FlagOp::Other, None),
        };
        Self { lhs: expr, rhs: "0".to_owned(), op, bits, ovf, carry: None }
    }
}

pub fn wrap_term(s: &str) -> String {
    if s.contains(' ') && trim_parens(s) == s && !(s.starts_with("((") && s.ends_with(']')) {
        format!("({s})")
    } else {
        s.to_owned()
    }
}

pub fn signed_arg(expr: &str) -> String {
    if expr.parse::<i64>().is_ok() || expr.starts_with("(i64)") { expr.to_owned() } else { format!("(i64){expr}") }
}

fn overflow_expr(negated: bool, flags: &Flags) -> String {
    let bang = if negated { "!" } else { "" };
    if let Some((a, b)) = &flags.ovf {
        match flags.op {
            FlagOp::Add(bits) => return format!("{bang}add_overflow({}, {})", i_term(a, bits), i_term(b, bits)),
            FlagOp::Sub(bits) => return format!("{bang}sub_overflow({}, {})", i_term(a, bits), i_term(b, bits)),
            FlagOp::Mul => return format!("{bang}mul_overflow({}, {})", i_term(a, flags.bits), i_term(b, flags.bits)),
            FlagOp::UMul => return format!("{bang}umul_overflow({a}, {b})"),
            FlagOp::Neg => return format!("{bang}neg_overflow({})", i_term(a, flags.bits)),
            FlagOp::Other | FlagOp::Adc(_) | FlagOp::Sbb(_) => {}
        }
    }
    if flags.rhs == "0" {
        format!("{bang}overflow({})", flags.lhs)
    } else {
        format!("{bang}overflow({}, {})", flags.lhs, flags.rhs)
    }
}

pub fn cond_expr(cc: ConditionCode, flags: Option<&Flags>) -> String {
    let Some(f) = flags else {
        return format!("cc_{cc:?}").to_ascii_lowercase();
    };
    if let FlagOp::Adc(bits) | FlagOp::Sbb(bits) = f.op
        && let Some(s) = carry_cond_expr(cc, f, matches!(f.op, FlagOp::Adc(_)), bits)
    {
        return s;
    }
    if let Some(cf) = f.carry.as_deref() {
        match cc {
            ConditionCode::b => return cf.to_owned(),
            ConditionCode::ae => return format!("!({})", wrap_term(cf)),
            ConditionCode::be => return format!("({} || {} == 0)", wrap_term(cf), wrap_term(&f.lhs)),
            ConditionCode::a => return format!("(!{} && {} != 0)", wrap_term(cf), wrap_term(&f.lhs)),
            _ => {}
        }
    }
    if let FlagOp::Add(bits) | FlagOp::Sub(bits) = f.op
        && let Some(s) = arith_cond_expr(cc, f, matches!(f.op, FlagOp::Add(_)), bits)
    {
        return s;
    }
    if f.rhs == "1"
        && matches!(cc, ConditionCode::e | ConditionCode::ne)
        && let Some(gt) = simplify_cmp_eq_one(&f.lhs)
    {
        return if cc == ConditionCode::e { gt } else { format!("!({gt})") };
    }
    match cc {
        ConditionCode::o => return overflow_expr(false, f),
        ConditionCode::no => return overflow_expr(true, f),
        ConditionCode::b if matches!(f.op, FlagOp::Mul | FlagOp::UMul) => return overflow_expr(false, f),
        ConditionCode::ae if matches!(f.op, FlagOp::Mul | FlagOp::UMul) => return overflow_expr(true, f),
        ConditionCode::b if f.op == FlagOp::Neg => {
            if let Some((a, _)) = &f.ovf {
                return format!("{} != 0", wrap_term(a));
            }
        }
        ConditionCode::ae if f.op == FlagOp::Neg => {
            if let Some((a, _)) = &f.ovf {
                return format!("{} == 0", wrap_term(a));
            }
        }
        ConditionCode::p => {
            return if f.rhs == "0" { format!("isnan({})", f.lhs) } else { format!("isnan({}, {})", f.lhs, f.rhs) };
        }
        ConditionCode::np => {
            return if f.rhs == "0" { format!("!isnan({})", f.lhs) } else { format!("!isnan({}, {})", f.lhs, f.rhs) };
        }
        _ => {}
    }
    let op_entry = CC_OPS.iter().find(|(c, _, _)| *c == cc);
    let (_, op, signed) = op_entry.unwrap_or(&(ConditionCode::ne, "!=", false));
    if *signed {
        format!("{} {op} {}", i_term(&f.lhs, f.bits), i_term(&f.rhs, f.bits))
    } else {
        format!("{} {op} {}", f.lhs, f.rhs)
    }
}

pub fn neg_cond_expr(cc: ConditionCode, flags: Option<&Flags>) -> String {
    let inv = match cc {
        ConditionCode::o => ConditionCode::no,
        ConditionCode::no => ConditionCode::o,
        ConditionCode::p => ConditionCode::np,
        ConditionCode::np => ConditionCode::p,
        _ => CC_OPS.iter().position(|(c, _, _)| *c == cc).map_or(cc, |i| CC_OPS[i ^ 1].0),
    };
    cond_expr(inv, flags)
}

pub fn trim_parens(s: &str) -> &str {
    let bytes = s.as_bytes();
    if bytes.len() < 2 || bytes[0] != b'(' || bytes[bytes.len() - 1] != b')' {
        return s;
    }
    let mut depth = 0i32;
    for &b in &bytes[1..bytes.len() - 1] {
        depth += i32::from(b == b'(') - i32::from(b == b')');
        if depth < 0 {
            return s;
        }
    }
    if depth == 0 { &s[1..s.len() - 1] } else { s }
}

pub fn has_call(stmt: &str) -> bool {
    let trimmed = stmt.trim_start();
    if trimmed.starts_with("/*") {
        return false;
    }
    let bytes = trimmed.as_bytes();
    let (mut in_str, mut esc, mut i) = (false, false, 0);
    while i < bytes.len() {
        let b = bytes[i];
        if in_str {
            if esc {
                esc = false;
            } else if b == b'\\' {
                esc = true;
            } else if b == b'"' {
                in_str = false;
            }
        } else if b == b'"' {
            in_str = true;
        } else if i + 1 < bytes.len() && (b.is_ascii_alphanumeric() || b == b'_') && bytes[i + 1] == b'(' {
            return true;
        }
        i += 1;
    }
    false
}

pub fn invert_cond(cond: &str) -> String {
    let c = trim_parens(cond.trim());
    if let Some(rest) = c.strip_prefix('!')
        && trim_parens(rest) != rest
    {
        return trim_parens(rest).to_owned();
    }
    if !c.contains("&&") && !c.contains("||") {
        for (op, inv) in
            [(" == ", " != "), (" != ", " == "), (" < ", " >= "), (" >= ", " < "), (" > ", " <= "), (" <= ", " > ")]
        {
            if let Some((l, r)) = c.split_once(op)
                && !r.contains(op.trim())
            {
                return format!("{l}{inv}{r}");
            }
        }
    }
    format!("!({c})")
}

pub fn parse_label(line: &str) -> Option<u64> {
    u64::from_str_radix(line.trim().strip_prefix("L_")?.strip_suffix(':')?, 16).ok()
}

pub fn strip_trailing_continue_label(body: &mut Vec<String>) {
    while let Some(addr) = body.last().and_then(|s| parse_label(s)) {
        crate::loops::rewrite_continues(body, addr);
        if crate::loops::stmt_gotos(body).contains(&addr) {
            break;
        }
        body.pop();
    }
}

pub fn split_top_stmts(seq: &[String]) -> Option<Vec<(usize, usize)>> {
    let (mut out, mut i) = (Vec::new(), 0);
    while i < seq.len() {
        let pad = &seq[i][..seq[i].len() - seq[i].trim_start().len()];
        let trim = seq[i].trim();
        if trim.ends_with('{') {
            let j = (i + 1..seq.len()).find(|&j| {
                &seq[j][..seq[j].len() - seq[j].trim_start().len()] == pad
                    && seq[j].trim().starts_with('}')
                    && !seq[j].trim().ends_with('{')
            })?;
            out.push((i, j + 1));
            i = j + 1;
        } else {
            if trim.starts_with('}') {
                return None;
            }
            out.push((i, i + 1));
            i += 1;
        }
    }
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::{FlagOp, Flags, cond_expr, neg_cond_expr};
    use iced_x86::{ConditionCode, Mnemonic};

    #[test]
    fn disambiguates_signed_overflow_and_conditions() {
        let cmp_zero = Flags::cmp("0".to_owned(), "*(u64 *)(r13 + 0xa18)".to_owned());
        assert_eq!(neg_cond_expr(ConditionCode::o, Some(&cmp_zero)), "!sub_overflow(0, (i64)*(u64 *)(r13 + 0xa18))");
        assert_eq!(cond_expr(ConditionCode::o, Some(&cmp_zero)), "sub_overflow(0, (i64)*(u64 *)(r13 + 0xa18))");

        let add_f = Flags::arith(
            FlagOp::from_bin_width(Mnemonic::Add, 64),
            "rax".to_owned(),
            "rax".to_owned(),
            "rbx".to_owned(),
        );
        assert_eq!(cond_expr(ConditionCode::o, Some(&add_f)), "add_overflow((i64)rax, (i64)rbx)");

        let mul_f = Flags::arith(
            FlagOp::from_bin_width(Mnemonic::Imul, 64),
            "rdx".to_owned(),
            "rdi".to_owned(),
            "5".to_owned(),
        );
        assert_eq!(cond_expr(ConditionCode::o, Some(&mul_f)), "mul_overflow((i64)rdi, 5)");

        let neg_f = Flags::unary_width(Mnemonic::Neg, 64, "(-x)".to_owned(), "x".to_owned());
        assert_eq!(cond_expr(ConditionCode::o, Some(&neg_f)), "neg_overflow((i64)x)");

        let inc_f = Flags::unary_width(Mnemonic::Inc, 64, "(x + 1)".to_owned(), "x".to_owned());
        assert_eq!(cond_expr(ConditionCode::o, Some(&inc_f)), "add_overflow((i64)x, 1)");

        let dec_f = Flags::unary_width(Mnemonic::Dec, 64, "(x - 1)".to_owned(), "x".to_owned());
        assert_eq!(cond_expr(ConditionCode::o, Some(&dec_f)), "sub_overflow((i64)x, 1)");

        let other = Flags::other("xmm0".to_owned(), "xmm1".to_owned());
        assert_eq!(neg_cond_expr(ConditionCode::o, Some(&other)), "!overflow(xmm0, xmm1)");
        assert_eq!(cond_expr(ConditionCode::np, Some(&other)), "!isnan(xmm0, xmm1)");
    }
}
