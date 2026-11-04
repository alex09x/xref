/*
 * XRef — Direct and indirect call analysis with argument recovery
 * Copyright (c) 2026 Alexander Panasenko
 * Contact: alex@prod.codes
 * Author: https://prod.codes/about/
 * Project: https://github.com/alex09x/xref
 * SPDX-License-Identifier: MIT OR Apache-2.0
 */

use std::collections::{BTreeSet, HashMap};
use std::ops::Range;

use iced_x86::{FlowControl, Instruction, Mnemonic};

use super::model::{CalleeCall, IndirectCall, PanicCall};
use crate::graph::call_target;
use crate::image::Image;
use crate::listing::{describe_branch, is_call};
use crate::runtime::RuntimeMap;
use crate::scan::decode;

/// Known terminating symbols only: Rust panic entry points (demangled or v0/legacy mangled paths
/// under `core::panicking` / `std::panicking`) and libc abort-like functions. A substring such as
/// `no_panic` is not evidence; real noreturn callees are also caught by `is_target_noreturn`.
fn is_panic_symbol(name: &str) -> bool {
    const EXACT: &[&str] = &[
        "abort",
        "exit",
        "_exit",
        "__assert_fail",
        "__stack_chk_fail",
        "rust_panic",
        "__rust_start_panic",
        "rust_begin_unwind",
    ];
    const PATHS: &[&str] = &["core::panicking::", "std::panicking::", "4core9panicking", "3std9panicking"];
    EXACT.contains(&name) || PATHS.iter().any(|path| name.contains(path))
}

#[test]
fn card_panic_symbols_are_exact_not_substrings() {
    assert!(is_panic_symbol("core::panicking::panic_fmt"));
    assert!(is_panic_symbol("_ZN4core9panicking5panic17h0123456789abcdefE"));
    assert!(is_panic_symbol("abort"));
    assert!(!is_panic_symbol("no_panic"));
    assert!(!is_panic_symbol("abort_transaction"));
}

/// Stack argument slots reported per call site, matching the `args` default.
const CARD_MAX_STACK: usize = 4;

fn callee_name(image: &Image, target: u64) -> String {
    image
        .symbols
        .iter()
        .find(|(addr, _)| *addr == target)
        .map(|(_, name)| name.clone())
        .or_else(|| crate::runtime::plt_import(image, target).map(str::to_owned))
        .unwrap_or_else(|| format!("{target:#x}"))
}

/// Analyze direct, indirect, and panic/abort calls made by `function`.
#[must_use]
pub fn analyze_calls(image: &Image, function: &Range<u64>) -> (Vec<CalleeCall>, Vec<IndirectCall>, Vec<PanicCall>) {
    let Some(bytes) = image.code(function) else {
        return (Vec::new(), Vec::new(), Vec::new());
    };

    let mut direct_calls: Vec<(u64, u64)> = Vec::new();
    let mut indirect_calls: Vec<IndirectCall> = Vec::new();
    let mut insns: Vec<Instruction> = Vec::new();

    decode(bytes, function.start, |ins| {
        insns.push(*ins);
        if is_call(ins, function) {
            if let Some(target) = call_target(image, ins) {
                direct_calls.push((ins.ip(), target));
            } else if ins.flow_control() == FlowControl::IndirectCall
                || (ins.mnemonic() == Mnemonic::Call && call_target(image, ins).is_none())
            {
                indirect_calls.push(IndirectCall { ip: ins.ip(), target: describe_branch(image, ins) });
            }
        }
    });

    let unique_targets: BTreeSet<u64> = direct_calls.iter().map(|&(_, target)| target).collect();
    let mut site_args: HashMap<u64, Vec<String>> = HashMap::new();

    // Analyze only this function's own call sites; scanning every caller of each callee across the
    // binary would cost one full pass per unique callee.
    let locs = crate::locations::locations(image);
    for &target in &unique_targets {
        for (ip, _, args) in crate::args::analyze_caller(image, &locs, function, bytes, target, CARD_MAX_STACK) {
            site_args.insert(ip, args);
        }
    }

    let runtime = RuntimeMap::detect(image);
    let mut callees: Vec<CalleeCall> = Vec::new();
    let mut panic_callees: Vec<PanicCall> = Vec::new();

    for &(ip, target) in &direct_calls {
        let name = callee_name(image, target);
        let args = site_args.remove(&ip).unwrap_or_default();

        let is_noreturn = crate::callee_meta::is_target_noreturn(image, &runtime, target);
        let is_panic_name = is_panic_symbol(&name);
        let followed_by_ud2 = insns
            .iter()
            .position(|i| i.ip() == ip)
            .and_then(|pos| insns.get(pos + 1))
            .is_some_and(|next| next.mnemonic() == Mnemonic::Ud2);

        if is_noreturn || is_panic_name || followed_by_ud2 {
            panic_callees.push(PanicCall { ip, target, name: name.clone() });
        }

        callees.push(CalleeCall { ip, target, name, args });
    }

    (callees, indirect_calls, panic_callees)
}
