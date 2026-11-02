/*
 * xref — Ultra blazing fast cross-references of an x86-64 ELF binary
 * Copyright (c) 2026 Alexander Panasenko
 *
 * Contact: alex@prod.codes
 * Author: https://prod.codes/about/
 * Project: https://github.com/alex09x/xref
 * SPDX-License-Identifier: MIT OR Apache-2.0
 */

//! Width-aware unsigned carry/borrow, sub-64-bit signed comparisons, and `adc`/`sbb` conditions.

use iced_x86::ConditionCode;

use crate::cond::{Flags, signed_arg, wrap_term};

const fn bit_mask(bits: u8) -> u64 {
    match bits {
        8 => 0xff,
        16 => 0xffff,
        32 => 0xffff_ffff,
        _ => u64::MAX,
    }
}

fn parse_const_u64(s: &str, bits: u8) -> Option<u64> {
    let mask = bit_mask(bits);
    s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")).map_or_else(
        || s.parse::<u64>().ok().or_else(|| s.parse::<i64>().ok().map(i64::cast_unsigned)).map(|v| v & mask),
        |h| u64::from_str_radix(h, 16).ok().map(|v| v & mask),
    )
}

pub fn u_term(expr: &str, bits: u8) -> String {
    if let Some(v) = parse_const_u64(expr, bits) {
        return if v <= 1024 { format!("{v}") } else { format!("{v:#x}") };
    }
    if bits >= 64 {
        wrap_term(expr)
    } else {
        let pfx = format!("(u{bits})");
        let mem_idx = format!("((u{bits} *)");
        let mem_ptr = format!("*(u{bits} *)");
        if expr.starts_with(&pfx) || expr.starts_with(&mem_idx) || expr.starts_with(&mem_ptr) {
            wrap_term(expr)
        } else {
            format!("{pfx}{}", wrap_term(expr))
        }
    }
}

pub fn i_term(expr: &str, bits: u8) -> String {
    let eff = if bits == 0 { 64 } else { bits };
    if eff >= 64 {
        if let Some(v) = parse_const_u64(expr, 64) {
            let s = v.cast_signed();
            if (-1024..=1024).contains(&s) {
                return format!("{s}");
            }
        }
        return signed_arg(expr);
    }
    if let Some(v) = parse_const_u64(expr, eff) {
        let sext = match eff {
            8 => i64::from(u8::try_from(v & 0xff).unwrap_or(0).cast_signed()),
            16 => i64::from(u16::try_from(v & 0xffff).unwrap_or(0).cast_signed()),
            _ => i64::from(u32::try_from(v & 0xffff_ffff).unwrap_or(0).cast_signed()),
        };
        return format!("{sext}");
    }
    let ipfx = format!("(i{eff})");
    if expr.starts_with(&ipfx) {
        return expr.to_owned();
    }
    let upfx = format!("(u{eff})");
    let mem_idx = format!("((u{eff} *)");
    let mem_ptr = format!("*(u{eff} *)");
    if expr.starts_with(&upfx) || expr.starts_with(&mem_idx) || expr.starts_with(&mem_ptr) {
        format!("{ipfx}{}", wrap_term(expr))
    } else {
        format!("{ipfx}{upfx}{}", wrap_term(expr))
    }
}

pub fn arith_cond_expr(cc: ConditionCode, f: &Flags, is_add: bool, bits: u8) -> Option<String> {
    let (a, b) = f.ovf.as_ref()?;
    if is_add {
        if !matches!(cc, ConditionCode::b | ConditionCode::ae | ConditionCode::be | ConditionCode::a) {
            return None;
        }
        let dst = u_term(&f.lhs, bits);
        if parse_const_u64(a, bits) == Some(0) || parse_const_u64(b, bits) == Some(0) {
            return Some(match cc {
                ConditionCode::b => "0".to_owned(),
                ConditionCode::ae => "1".to_owned(),
                ConditionCode::be => format!("{dst} == 0"),
                _ => format!("{dst} != 0"),
            });
        }
        let lhs_u = u_term(a, bits);
        let b_nonzero_const = parse_const_u64(b, bits).is_some_and(|v| v != 0);
        return Some(match cc {
            ConditionCode::b => format!("{dst} < {lhs_u}"),
            ConditionCode::ae => format!("{dst} >= {lhs_u}"),
            ConditionCode::be if b_nonzero_const => format!("{dst} < {lhs_u}"),
            ConditionCode::a if b_nonzero_const => format!("{dst} >= {lhs_u}"),
            ConditionCode::be => format!("({dst} < {lhs_u} || {dst} == 0)"),
            _ => format!("({dst} >= {lhs_u} && {dst} != 0)"),
        });
    }
    if f.rhs != "0" {
        return None;
    }
    Some(match cc {
        ConditionCode::b => format!("{} < {}", u_term(a, bits), u_term(b, bits)),
        ConditionCode::ae => format!("{} >= {}", u_term(a, bits), u_term(b, bits)),
        ConditionCode::be => format!("{} <= {}", u_term(a, bits), u_term(b, bits)),
        ConditionCode::a => format!("{} > {}", u_term(a, bits), u_term(b, bits)),
        ConditionCode::l => format!("{} < {}", i_term(a, bits), i_term(b, bits)),
        ConditionCode::ge => format!("{} >= {}", i_term(a, bits), i_term(b, bits)),
        ConditionCode::le => format!("{} <= {}", i_term(a, bits), i_term(b, bits)),
        ConditionCode::g => format!("{} > {}", i_term(a, bits), i_term(b, bits)),
        _ => return None,
    })
}

pub fn carry_cond_expr(cc: ConditionCode, f: &Flags, is_adc: bool, bits: u8) -> Option<String> {
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
