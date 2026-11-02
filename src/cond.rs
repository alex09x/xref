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
    Add,
    Sub,
    Mul,
    UMul,
    Neg,
    Adc(u8),
    Sbb(u8),
}

impl FlagOp {
    pub const fn from_bin(mnemonic: Mnemonic) -> Self {
        match mnemonic {
            Mnemonic::Add => Self::Add,
            Mnemonic::Sub => Self::Sub,
            Mnemonic::Imul => Self::Mul,
            _ => Self::Other,
        }
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Flags {
    pub lhs: String,
    pub rhs: String,
    pub op: FlagOp,
    pub ovf: Option<(String, String)>,
    pub carry: Option<String>,
}

impl Flags {
    pub fn cmp(lhs: String, rhs: String) -> Self {
        Self { ovf: Some((lhs.clone(), rhs.clone())), lhs, rhs, op: FlagOp::Sub, carry: None }
    }

    pub fn from_cmp(mnemonic: Mnemonic, lhs: String, rhs: String) -> Self {
        if mnemonic == Mnemonic::Cmp { Self::cmp(lhs, rhs) } else { Self::other(lhs, rhs) }
    }

    pub const fn other(lhs: String, rhs: String) -> Self {
        Self { lhs, rhs, op: FlagOp::Other, ovf: None, carry: None }
    }

    pub fn test(tested: String) -> Self {
        Self { lhs: tested, rhs: "0".to_owned(), op: FlagOp::Other, ovf: None, carry: None }
    }

    pub fn arith(op: FlagOp, flag_lhs: String, a: String, b: String) -> Self {
        let ovf = (!matches!(op, FlagOp::Other)).then_some((a, b));
        Self { lhs: flag_lhs, rhs: "0".to_owned(), op, ovf, carry: None }
    }

    pub const fn carry_op(op: FlagOp, flag_lhs: String, a: String, b: String, cf_in: String) -> Self {
        Self { lhs: flag_lhs, rhs: String::new(), op, ovf: Some((a, b)), carry: Some(cf_in) }
    }

    pub fn unary(mnemonic: Mnemonic, expr: String, raw_val: String) -> Self {
        let (op, ovf) = match mnemonic {
            Mnemonic::Inc => (FlagOp::Add, Some((raw_val, "1".to_owned()))),
            Mnemonic::Dec => (FlagOp::Sub, Some((raw_val, "1".to_owned()))),
            Mnemonic::Neg => (FlagOp::Neg, Some((raw_val, String::new()))),
            _ => (FlagOp::Other, None),
        };
        Self { lhs: expr, rhs: "0".to_owned(), op, ovf, carry: None }
    }
}

fn wrap_term(s: &str) -> String {
    if s.contains(' ') && trim_parens(s) == s { format!("({s})") } else { s.to_owned() }
}

fn carry_cond_expr(cc: ConditionCode, f: &Flags, is_adc: bool, bits: u8) -> Option<String> {
    let ((a, b), cf_in) = (f.ovf.as_ref()?, f.carry.as_deref()?);
    let (u_ty, i_ty, wu, wi, ones) = match bits {
        8 => ("u8", "i8", "u16", "i16", "0xff"),
        16 => ("u16", "i16", "u32", "i32", "0xffff"),
        32 => ("u32", "i32", "u64", "i64", "0xffffffff"),
        _ => ("u64", "i64", "u128", "i128", "0xffffffffffffffff"),
    };
    let (ap, bp, cp, rp) = (wrap_term(a), wrap_term(b), wrap_term(cf_in), wrap_term(&f.lhs));
    let all1 = |s: &str| s == "-1" || s.eq_ignore_ascii_case(ones);
    let cf_out = if is_adc {
        if (all1(a) && b == "0") || (all1(b) && a == "0") {
            cf_in.to_owned()
        } else if a == "0" && b == "0" {
            "0".to_owned()
        } else {
            format!("((({wu})({u_ty}){ap} + ({wu})({u_ty}){bp} + ({wu}){cp}) >> {bits}) != 0")
        }
    } else if a == b {
        cf_in.to_owned()
    } else if b == "0" {
        format!("(({wu})({u_ty}){ap} < ({wu}){cp})")
    } else {
        format!("(({wu})({u_ty}){ap} < ({wu})({u_ty}){bp} + ({wu}){cp})")
    };
    let sw = if is_adc {
        format!("(({wi})({i_ty})({u_ty}){ap} + ({wi})({i_ty})({u_ty}){bp} + ({wi}){cp})")
    } else {
        format!("(({wi})({i_ty})({u_ty}){ap} - ({wi})({i_ty})({u_ty}){bp} - ({wi}){cp})")
    };
    Some(match cc {
        ConditionCode::b => cf_out,
        ConditionCode::ae => format!("!({})", wrap_term(&cf_out)),
        ConditionCode::e => format!("({u_ty}){rp} == 0"),
        ConditionCode::ne => format!("({u_ty}){rp} != 0"),
        ConditionCode::s => format!("({i_ty})({u_ty}){rp} < 0"),
        ConditionCode::ns => format!("({i_ty})({u_ty}){rp} >= 0"),
        ConditionCode::be if !is_adc => format!("(({wu})({u_ty}){ap} <= ({wu})({u_ty}){bp} + ({wu}){cp})"),
        ConditionCode::a if !is_adc => format!("(({wu})({u_ty}){ap} > ({wu})({u_ty}){bp} + ({wu}){cp})"),
        ConditionCode::be => format!("({} || ({u_ty}){rp} == 0)", wrap_term(&cf_out)),
        ConditionCode::a => format!("(!{} && ({u_ty}){rp} != 0)", wrap_term(&cf_out)),
        ConditionCode::o => format!("({wi})({i_ty})({u_ty}){rp} != {sw}"),
        ConditionCode::no => format!("({wi})({i_ty})({u_ty}){rp} == {sw}"),
        ConditionCode::l => format!("{sw} < 0"),
        ConditionCode::ge => format!("{sw} >= 0"),
        ConditionCode::le => format!("{sw} <= 0"),
        ConditionCode::g => format!("{sw} > 0"),
        _ => return None,
    })
}

fn signed_arg(expr: &str) -> String {
    if expr.parse::<i64>().is_ok() || expr.starts_with("(i64)") { expr.to_owned() } else { format!("(i64){expr}") }
}

fn overflow_expr(negated: bool, flags: &Flags) -> String {
    let bang = if negated { "!" } else { "" };
    if let Some((a, b)) = &flags.ovf {
        match flags.op {
            FlagOp::Add => return format!("{bang}add_overflow({}, {})", signed_arg(a), signed_arg(b)),
            FlagOp::Sub => return format!("{bang}sub_overflow({}, {})", signed_arg(a), signed_arg(b)),
            FlagOp::Mul => return format!("{bang}mul_overflow({}, {})", signed_arg(a), signed_arg(b)),
            FlagOp::UMul => return format!("{bang}umul_overflow({a}, {b})"),
            FlagOp::Neg => return format!("{bang}neg_overflow({})", signed_arg(a)),
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
        let r = signed_arg(&f.rhs);
        format!("{} {op} {r}", signed_arg(&f.lhs))
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
    if let Some(inner) = c.strip_prefix("!(").and_then(|s| s.strip_suffix(')'))
        && trim_parens(c) != c
    {
        return inner.to_owned();
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

        let add_f = Flags::arith(FlagOp::from_bin(Mnemonic::Add), "rax".to_owned(), "rax".to_owned(), "rbx".to_owned());
        assert_eq!(cond_expr(ConditionCode::o, Some(&add_f)), "add_overflow((i64)rax, (i64)rbx)");

        let mul_f = Flags::arith(FlagOp::from_bin(Mnemonic::Imul), "rdx".to_owned(), "rdi".to_owned(), "5".to_owned());
        assert_eq!(cond_expr(ConditionCode::o, Some(&mul_f)), "mul_overflow((i64)rdi, 5)");

        let neg_f = Flags::unary(Mnemonic::Neg, "(-x)".to_owned(), "x".to_owned());
        assert_eq!(cond_expr(ConditionCode::o, Some(&neg_f)), "neg_overflow((i64)x)");

        let inc_f = Flags::unary(Mnemonic::Inc, "(x + 1)".to_owned(), "x".to_owned());
        assert_eq!(cond_expr(ConditionCode::o, Some(&inc_f)), "add_overflow((i64)x, 1)");

        let dec_f = Flags::unary(Mnemonic::Dec, "(x - 1)".to_owned(), "x".to_owned());
        assert_eq!(cond_expr(ConditionCode::o, Some(&dec_f)), "sub_overflow((i64)x, 1)");

        let other = Flags::other("xmm0".to_owned(), "xmm1".to_owned());
        assert_eq!(neg_cond_expr(ConditionCode::o, Some(&other)), "!overflow(xmm0, xmm1)");
        assert_eq!(cond_expr(ConditionCode::np, Some(&other)), "!isnan(xmm0, xmm1)");
    }

    #[test]
    fn preserves_carry_borrow_flags_and_checks_idiv_signext_origin() {
        use crate::c::c_one;
        use crate::image::{Image, Segment};
        use crate::runtime::RuntimeMap;

        // f1 (0x1000): cmp rdi, rsi; mov rax, -1; adc rax, 0; setc dl; movzx eax, dl; ret
        let f1: &[u8] = &[
            0x48, 0x39, 0xf7, 0x48, 0xc7, 0xc0, 0xff, 0xff, 0xff, 0xff, 0x48, 0x83, 0xd0, 0x00, 0x0f, 0x92, 0xc2, 0x0f,
            0xb6, 0xc2, 0xc3,
        ];
        // f2 (0x1020): mov rdx, rdi; sar rdx, 63; mov rax, rsi; idiv rcx; ret (rdx is sign-ext of rdi, NOT rax!)
        let f2: &[u8] = &[0x48, 0x89, 0xfa, 0x48, 0xc1, 0xfa, 0x3f, 0x48, 0x89, 0xf0, 0x48, 0xf7, 0xf9, 0xc3];
        // f3 (0x1040): mov eax, 0x12340007; mov cl, 3; div cl; ret -> preserves upper 16 bits & writes AX (AL|AH<<8)
        let f3: &[u8] = &[0xb8, 0x07, 0x00, 0x34, 0x12, 0xb1, 0x03, 0xf6, 0xf1, 0xc3];
        let (mut data, mut functions) = (vec![0xccu8; 0x60], Vec::new());
        for (off, b) in [(0, f1), (0x20, f2), (0x40, f3)] {
            data[off..off + b.len()].copy_from_slice(b);
            functions.push(0x1000 + off as u64..0x1000 + (off + b.len()) as u64);
        }
        let img = Image {
            data,
            segments: vec![Segment { va: 0x1000, offset: 0, size: 0x60 }],
            functions,
            pointers: Vec::new(),
            imports: Vec::new(),
            symbols: Vec::new(),
        };
        let rt = RuntimeMap::detect(&img);
        let (_, c1) = c_one(&img, &[], &rt, 0x1000, None, None).unwrap_or_default();
        assert!(c1.contains("return arg_0 < arg_1;") && !c1.contains("< 0"), "{c1}");
        let (_, c2) = c_one(&img, &[], &rt, 0x1020, None, None).unwrap_or_default();
        assert!(c2.contains("<< 64") && c2.contains("(i128)"), "{c2}");
        let (_, c3) = c_one(&img, &[], &rt, 0x1040, None, None).unwrap_or_default();
        assert!(c3.contains("& ~0xffff") && c3.contains("<< 8"), "{c3}");
    }
}
