/*
 * XRef Code — evidence-producing binary analysis
 * Copyright (c) 2026 Alexander Panasenko
 * Contact: alex@prod.codes
 * Author: https://prod.codes/about/
 * Project: https://github.com/alex09x/xref
 * SPDX-License-Identifier: MIT OR Apache-2.0
 */
use iced_x86::Instruction;
use super::facts::State;

#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) enum Origin {
    Address { register: usize, displacement: i64 },
    Loaded { register: usize, displacement: i64, width: usize, load_ip: u64 },
}

/// Effective address relative to a full-width entry register, without a dynamic index.
pub(super) fn memory_origin(_ins: &Instruction, _input: &State) -> Option<(Origin, usize)> {
    None
}

/// Exact address or unmodified loaded-value provenance for the written GPR.
pub(super) fn derive(_ins: &Instruction, _input: &State) -> Option<(Origin, usize)> {
    None
}
