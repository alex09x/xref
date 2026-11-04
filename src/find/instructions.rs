/*
 * xref — cross-reference and binary analysis tools
 * Copyright (c) 2026 Alexander Panasenko
 *
 * Contact: alex@prod.codes
 * Author: https://prod.codes/about/
 * Project: https://github.com/alex09x/xref
 * SPDX-License-Identifier: MIT OR Apache-2.0
 */

use std::error::Error;
use std::io::Write;

use iced_x86::{Formatter, Instruction, IntelFormatter, Mnemonic};

use super::{FindSpec, find_impl};
use crate::commands::Res;
use crate::image::Image;

pub(super) const MAX_SITES: usize = 8;
const MAX_FILTERS: usize = 32;
const MAX_PATTERN_LEN: usize = 32;

#[derive(Clone, Debug)]
pub(super) struct InstructionPredicate {
    pub(super) label: String,
    mnemonic: Option<Mnemonic>,
    operands: Option<String>,
}

impl InstructionPredicate {
    pub(super) fn matches(&self, instruction: &Instruction) -> bool {
        if let Some(expected) = self.mnemonic {
            if instruction.mnemonic() != expected {
                return false;
            }
        } else if !is_float_mnemonic(&format!("{:?}", instruction.mnemonic()).to_ascii_lowercase()) {
            return false;
        }
        let Some(pattern) = &self.operands else {
            return true;
        };
        let mut formatter = IntelFormatter::new();
        let mut text = String::new();
        formatter.format(instruction, &mut text);
        let Some((_, operands)) = text.split_once(' ') else {
            return false;
        };
        glob_matches(pattern.as_bytes(), compact(operands).as_bytes())
    }
}

/// Find functions by the existing predicates plus exact instruction mnemonics,
/// optional operand globs, and the `float` instruction class.
pub fn find_with_instructions(
    image: &Image,
    spec: &FindSpec,
    patterns: &[String],
    classes: &[String],
    out: &mut dyn Write,
) -> Res {
    if patterns.len() + classes.len() > MAX_FILTERS {
        return Err(format!("at most {MAX_FILTERS} instruction filters are allowed").into());
    }
    let mut predicates = Vec::with_capacity(patterns.len() + classes.len());
    for pattern in patterns {
        predicates.push(parse_pattern(pattern)?);
    }
    for class in classes {
        if class.is_empty() || class.len() > MAX_PATTERN_LEN {
            return Err("instruction class must be non-empty and at most 32 bytes".into());
        }
        if !class.eq_ignore_ascii_case("float") {
            return Err(format!("unknown instruction class: {class}").into());
        }
        predicates.push(InstructionPredicate { label: "class:float".into(), mnemonic: None, operands: None });
    }
    if spec.calls.is_empty()
        && spec.refs.is_empty()
        && spec.imm.is_empty()
        && spec.disp.is_empty()
        && spec.src.is_empty()
        && spec.size.is_none()
        && predicates.is_empty()
    {
        return Err("at least one predicate is required".into());
    }
    find_impl(image, spec, &predicates, out)
}

fn parse_pattern(pattern: &str) -> Result<InstructionPredicate, Box<dyn Error>> {
    if pattern.is_empty() || pattern.len() > MAX_PATTERN_LEN {
        return Err("instruction pattern must be non-empty and at most 32 bytes".into());
    }
    let (mnemonic_text, operand_text) =
        pattern.split_once(char::is_whitespace).map_or((pattern, None), |(m, o)| (m, Some(o.trim())));
    if mnemonic_text.is_empty() {
        return Err("instruction mnemonic must be non-empty".into());
    }
    let normalized_mnemonic = mnemonic_text.to_ascii_lowercase();
    let mnemonic = Mnemonic::values()
        .find(|candidate| {
            *candidate != Mnemonic::INVALID && format!("{candidate:?}").eq_ignore_ascii_case(&normalized_mnemonic)
        })
        .ok_or_else(|| format!("unknown instruction mnemonic: {mnemonic_text}"))?;
    let operands = operand_text.map(compact).filter(|s| !s.is_empty());
    if operand_text.is_some() && operands.is_none() {
        return Err("operand glob must be non-empty".into());
    }
    Ok(InstructionPredicate {
        label: format!(
            "insn:{}{}",
            mnemonic_text.to_ascii_lowercase(),
            operands.as_ref().map_or(String::new(), |o| format!(" {o}"))
        ),
        mnemonic: Some(mnemonic),
        operands,
    })
}

fn compact(text: &str) -> String {
    text.chars().filter(|c| !c.is_ascii_whitespace()).flat_map(char::to_lowercase).collect()
}

fn glob_matches(pattern: &[u8], text: &[u8]) -> bool {
    let mut row = vec![false; text.len() + 1];
    row[0] = true;
    for &byte in pattern {
        let mut next = vec![false; text.len() + 1];
        if byte == b'*' {
            next[0] = row[0];
            for index in 1..=text.len() {
                next[index] = row[index] || next[index - 1];
            }
        } else {
            for index in 1..=text.len() {
                next[index] = row[index - 1] && (byte == b'?' || byte == text[index - 1]);
            }
        }
        row = next;
    }
    row[text.len()]
}

const FLOAT: &[&str] = &[
    "addss",
    "addsd",
    "addps",
    "addpd",
    "subss",
    "subsd",
    "subps",
    "subpd",
    "mulss",
    "mulsd",
    "mulps",
    "mulpd",
    "divss",
    "divsd",
    "divps",
    "divpd",
    "sqrtss",
    "sqrtsd",
    "sqrtps",
    "sqrtpd",
    "minss",
    "minsd",
    "minps",
    "minpd",
    "maxss",
    "maxsd",
    "maxps",
    "maxpd",
    "rcpss",
    "rcpps",
    "rsqrtss",
    "rsqrtps",
    "cvtsi2ss",
    "cvtsi2sd",
    "cvttss2si",
    "cvttsd2si",
    "cvtss2si",
    "cvtsd2si",
    "cvtsd2ss",
    "cvtss2sd",
    "cvtps2pd",
    "cvtpd2ps",
    "cvtdq2ps",
    "cvtps2dq",
    "cvttps2dq",
    "cvtdq2pd",
    "cvtpd2dq",
    "cvttpd2dq",
    "vaddss",
    "vaddsd",
    "vaddps",
    "vaddpd",
    "vsubss",
    "vsubsd",
    "vsubps",
    "vsubpd",
    "vmulss",
    "vmulsd",
    "vmulps",
    "vmulpd",
    "vdivss",
    "vdivsd",
    "vdivps",
    "vdivpd",
    "vsqrtss",
    "vsqrtsd",
    "vsqrtps",
    "vsqrtpd",
    "vminss",
    "vminsd",
    "vminps",
    "vminpd",
    "vmaxss",
    "vmaxsd",
    "vmaxps",
    "vmaxpd",
    "vrcpss",
    "vrcpps",
    "vrsqrtss",
    "vrsqrtps",
    "vcvtsi2ss",
    "vcvtsi2sd",
    "vcvttss2si",
    "vcvttsd2si",
    "vcvtss2si",
    "vcvtsd2si",
    "vcvtsd2ss",
    "vcvtss2sd",
    "vcvtps2pd",
    "vcvtpd2ps",
    "vcvtdq2ps",
    "vcvtps2dq",
    "vcvttps2dq",
    "vcvtdq2pd",
    "vcvtpd2dq",
    "vcvttpd2dq",
    "fadd",
    "faddp",
    "fiadd",
    "fsub",
    "fsubp",
    "fisub",
    "fsubr",
    "fsubrp",
    "fisubr",
    "fmul",
    "fmulp",
    "fimul",
    "fdiv",
    "fdivp",
    "fidiv",
    "fdivr",
    "fdivrp",
    "fidivr",
    "fild",
    "fist",
    "fistp",
    "fisttp",
    "fbld",
    "fbstp",
    "fld",
    "fst",
    "fstp",
    "f2xm1",
    "fabs",
    "fchs",
    "fscale",
    "fprem",
    "fprem1",
    "frndint",
    "fyl2x",
    "fyl2xp1",
    "fsqrt",
    "fsin",
    "fcos",
    "fptan",
    "fpatan",
];

fn is_float_mnemonic(mnemonic: &str) -> bool {
    if FLOAT.contains(&mnemonic) {
        return true;
    }
    let Some(suffix) = ["vfmadd", "vfmsub", "vfnmadd", "vfnmsub"].iter().find_map(|root| mnemonic.strip_prefix(root))
    else {
        return false;
    };
    ["132", "213", "231"]
        .iter()
        .any(|index| suffix.strip_prefix(index).is_some_and(|width| ["ss", "sd", "ps", "pd"].contains(&width)))
}

#[cfg(test)]
#[path = "instructions_tests.rs"]
mod tests;
