/*
 * xref — Ultra blazing fast cross-references of an x86-64 ELF binary
 * Copyright (c) 2026 Alexander Panasenko
 *
 * Contact: alex@prod.codes
 * Author: https://prod.codes/about/
 * Project: https://github.com/alex09x/xref
 * SPDX-License-Identifier: MIT OR Apache-2.0
 */

use std::collections::HashMap;

use iced_x86::Register;

use super::{XmmLive, mentions, replace_ident};
use crate::cond::Flags;
use crate::expr::State;
use crate::sig::xmm::FloatParam;

fn live() -> XmmLive {
    let params = vec![FloatParam { index: 0, ty: "f64" }, FloatParam { index: 1, ty: "f32" }];
    XmmLive { after: HashMap::new(), writes: HashMap::new(), clobbers: HashMap::new(), params }
}

fn state(regs: &[(Register, &str)]) -> State {
    State {
        homes: vec![(Register::ZMM0, "arg_f0".to_owned()), (Register::ZMM1, "arg_f1".to_owned())],
        regs: regs.iter().map(|(r, v)| (*r, (*v).to_owned())).collect(),
        ..State::default()
    }
}

#[test]
fn f64_abi_carry_assigns_only_live_changed_registers_to_their_homes() {
    let mut st = state(&[(Register::ZMM0, "fp_10"), (Register::ZMM2, "fp_14"), (Register::ZMM3, "fp_18")]);
    let mut lines = Vec::new();
    live().flush(&mut st, 0b0101, 0x20, &mut lines);
    assert_eq!(lines, vec!["arg_f0 = fp_10;", "zmm2 = fp_14;"], "xmm3 is dead and xmm1 unchanged");
    assert_eq!(st.reg(Register::ZMM0), "arg_f0");
    assert_eq!(st.reg(Register::ZMM3), "fp_18");
}

#[test]
fn f64_abi_carry_is_a_parallel_assignment() {
    // xmm2 holds the old xmm0 (a full-width copy), xmm0 a new value: copy xmm2 out first.
    let mut st = state(&[(Register::ZMM0, "fp_10"), (Register::ZMM2, "arg_f0")]);
    let mut lines = Vec::new();
    live().flush(&mut st, 0b0101, 0x20, &mut lines);
    assert_eq!(lines, vec!["zmm2 = arg_f0;", "arg_f0 = fp_10;"]);
    // A swap needs a snapshot of one side, typed like the parameter.
    let mut st = state(&[(Register::ZMM0, "arg_f1"), (Register::ZMM1, "arg_f0")]);
    let mut lines = Vec::new();
    live().flush(&mut st, 0b0011, 0x30, &mut lines);
    assert_eq!(lines, vec!["f64 fp_30_arg_f0 = arg_f0;", "arg_f0 = arg_f1;", "arg_f1 = fp_30_arg_f0;"]);
}

#[test]
fn f64_abi_carry_keeps_pending_flags_reading_the_old_value() {
    let mut st = state(&[(Register::ZMM0, "fp_14")]);
    st.flags = Some(Flags::float_cmp("arg_f0".to_owned(), "arg_f1".to_owned()));
    let mut lines = Vec::new();
    live().flush(&mut st, 0b0001, 0x18, &mut lines);
    assert_eq!(lines, vec!["f64 fp_18_arg_f0 = arg_f0;", "arg_f0 = fp_14;"]);
    let flags = st.flags.unwrap_or_default();
    assert_eq!((flags.lhs.as_str(), flags.rhs.as_str()), ("fp_18_arg_f0", "arg_f1"));
}

#[test]
fn f64_abi_identifier_matching_respects_word_boundaries() {
    assert!(mentions("(arg_f0 + 1.0)", "arg_f0"));
    assert!(!mentions("arg_f01 + xarg_f0", "arg_f0"));
    assert_eq!(replace_ident("arg_f0 * arg_f01 - arg_f0", "arg_f0", "t"), "t * arg_f01 - t");
}
