/*
 * XRef — Scalar FMA3 and SSE4.1 rounding, as emitted for x86-64-v3
 * Copyright (c) 2026 Alexander Panasenko
 * Contact: alex@prod.codes
 * Author: https://prod.codes/about/
 * Project: https://github.com/alex09x/xref
 * SPDX-License-Identifier: MIT OR Apache-2.0
 */

use iced_x86::{Instruction, Mnemonic};

use crate::sig::xmm::{F32, F64};

/// A scalar fused multiply-add, `vf[n]m{add,sub}{132,213,231}{sd,ss}`: `±(a * b) ± c` with one
/// rounding, where the three digits name the operands that are `a`, `b` and `c`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Fma {
    /// Operand indices of `a`, `b` and `c`.
    pub order: [u32; 3],
    /// `-(a * b)`: the `vfnm*` forms.
    pub negate: bool,
    /// `- c`: the `*msub*` forms.
    pub subtract: bool,
    pub ty: &'static str,
}

pub fn fma(mnemonic: Mnemonic) -> Option<Fma> {
    let name = format!("{mnemonic:?}").to_ascii_lowercase();
    let rest = name.strip_prefix("vf")?;
    let (negate, rest) = rest.strip_prefix('n').map_or((false, rest), |r| (true, r));
    let (subtract, rest) =
        if let Some(r) = rest.strip_prefix("madd") { (false, r) } else { (true, rest.strip_prefix("msub")?) };
    let ty = match rest.get(3..)? {
        "sd" => F64,
        "ss" => F32,
        _ => return None,
    };
    let digits = rest.get(..3)?.as_bytes();
    let mut order = [0; 3];
    for (slot, digit) in order.iter_mut().zip(digits) {
        *slot = u32::from(digit.checked_sub(b'1').filter(|d| *d < 3)?);
    }
    Some(Fma { order, negate, subtract, ty })
}

impl Fma {
    /// `fma(a, b, c)` (`fmaf` for single precision) with the signs of the form folded in.
    pub fn expression(self, operands: [&str; 3]) -> String {
        let [a, b, c] = operands;
        let a = if self.negate { format!("-{a}") } else { a.to_owned() };
        let c = if self.subtract { format!("-{c}") } else { c.to_owned() };
        let function = if self.ty == F32 { "fmaf" } else { "fma" };
        format!("{function}({a}, {b}, {c})")
    }
}

/// `roundsd`/`roundss` (and the VEX forms): the C function its immediate selects.
pub fn rounding(ins: &Instruction, single: bool, source: &str) -> String {
    let immediate = ins.immediate(ins.op_count() - 1);
    // Bit 2 rounds with the current MXCSR mode; bits 1:0 otherwise pick the mode.
    let function = if immediate & 4 != 0 {
        "nearbyint"
    } else {
        match immediate & 3 {
            0 => "roundeven",
            1 => "floor",
            2 => "ceil",
            _ => "trunc",
        }
    };
    format!("{function}{}({source})", if single { "f" } else { "" })
}
