/*
 * XRef — Function card data model and serialization
 * Copyright (c) 2026 Alexander Panasenko
 * Contact: alex@prod.codes
 * Author: https://prod.codes/about/
 * Project: https://github.com/alex09x/xref
 * SPDX-License-Identifier: MIT OR Apache-2.0
 */

use std::collections::BTreeMap;
use serde::Serialize;

/// Top-level function summary card.
#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
pub struct FunctionCard {
    pub function: FunctionSpan,
    pub inputs: CardInputs,
    pub return_registers: Vec<String>,
    pub stores: BTreeMap<String, Vec<FieldStore>>,
    pub callees: Vec<CalleeCall>,
    pub indirect_calls: Vec<IndirectCall>,
    pub panic_callees: Vec<PanicCall>,
    pub exits: Vec<ExitInfo>,
}

/// Address range and optional symbol name of the analyzed function.
#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
pub struct FunctionSpan {
    pub start: u64,
    pub end: u64,
    pub name: Option<String>,
}

/// Function inputs: registers and stack slots read before written.
#[derive(Clone, Debug, Default, Serialize, PartialEq, Eq)]
pub struct CardInputs {
    pub registers: Vec<String>,
    pub stack_args: Vec<String>,
}

/// A stored field offset with observed write widths.
#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
pub struct FieldStore {
    pub offset: i64,
    pub widths: Vec<usize>,
}

/// A direct call site with argument values recovered via call-site analysis.
#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
pub struct CalleeCall {
    pub ip: u64,
    pub target: u64,
    pub name: String,
    pub args: Vec<String>,
}

/// An indirect call site.
#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
pub struct IndirectCall {
    pub ip: u64,
    pub target: String,
}

/// A call to a panic, abort, or non-returning routine.
#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
pub struct PanicCall {
    pub ip: u64,
    pub target: u64,
    pub name: String,
}

/// An exit point (ret) with return registers, constant return code and error status.
#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
pub struct ExitInfo {
    pub ip: u64,
    pub return_registers: Vec<String>,
    pub constant_code: Option<i64>,
    pub is_error: bool,
}
