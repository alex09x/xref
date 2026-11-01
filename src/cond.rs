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
    Neg,
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

#[derive(Clone, Debug, Default)]
pub struct Flags {
    pub lhs: String,
    pub rhs: String,
    pub op: FlagOp,
    pub ovf: Option<(String, String)>,
}

impl Flags {
    pub fn cmp(lhs: String, rhs: String) -> Self {
        Self { ovf: Some((lhs.clone(), rhs.clone())), lhs, rhs, op: FlagOp::Sub }
    }

    pub fn from_cmp(mnemonic: Mnemonic, lhs: String, rhs: String) -> Self {
        if mnemonic == Mnemonic::Cmp { Self::cmp(lhs, rhs) } else { Self::other(lhs, rhs) }
    }

    pub const fn other(lhs: String, rhs: String) -> Self {
        Self { lhs, rhs, op: FlagOp::Other, ovf: None }
    }

    pub fn test(tested: String) -> Self {
        Self { lhs: tested, rhs: "0".to_owned(), op: FlagOp::Other, ovf: None }
    }

    pub fn arith(op: FlagOp, flag_lhs: String, a: String, b: String) -> Self {
        let ovf = (!matches!(op, FlagOp::Other)).then_some((a, b));
        Self { lhs: flag_lhs, rhs: "0".to_owned(), op, ovf }
    }

    pub fn unary(mnemonic: Mnemonic, expr: String, raw_val: String) -> Self {
        let (op, ovf) = match mnemonic {
            Mnemonic::Inc => (FlagOp::Add, Some((raw_val, "1".to_owned()))),
            Mnemonic::Dec => (FlagOp::Sub, Some((raw_val, "1".to_owned()))),
            Mnemonic::Neg => (FlagOp::Neg, Some((raw_val, String::new()))),
            _ => (FlagOp::Other, None),
        };
        Self { lhs: expr, rhs: "0".to_owned(), op, ovf }
    }
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
            FlagOp::Neg => return format!("{bang}neg_overflow({})", signed_arg(a)),
            FlagOp::Other => {}
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
    if f.rhs == "1"
        && matches!(cc, ConditionCode::e | ConditionCode::ne)
        && let Some(gt) = simplify_cmp_eq_one(&f.lhs)
    {
        return if cc == ConditionCode::e { gt } else { format!("!({gt})") };
    }
    match cc {
        ConditionCode::o => return overflow_expr(false, f),
        ConditionCode::no => return overflow_expr(true, f),
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
}
