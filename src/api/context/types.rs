/*
 * XRef Code — evidence-producing binary analysis
 * Copyright (c) 2026 Alexander Panasenko
 * Contact: alex@prod.codes
 * Author: https://prod.codes/about/
 * Project: https://github.com/alex09x/xref
 * SPDX-License-Identifier: MIT OR Apache-2.0
 */
use super::super::types::{FunctionInfo, InstructionRow};
use schemars::JsonSchema;
use serde::Serialize;

#[derive(Debug, Serialize, JsonSchema)]
pub struct CallContext {
    pub function: FunctionInfo,
    pub call: InstructionRow,
    /// Candidates in the `SysV` integer argument registers, not a recovered arity.
    pub arguments: Vec<Argument>,
    pub guards: Vec<Guard>,
    pub instructions: Vec<InstructionRow>,
    pub complete_under_model: bool,
    pub warnings: Vec<&'static str>,
}
#[derive(Debug, Serialize, JsonSchema)]
pub struct Argument {
    pub register: &'static str,
    pub value: Value,
    pub definition_addresses: Vec<String>,
    pub definitions_truncated: bool,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, JsonSchema)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Value {
    Constant { bits: String },
    Address { address: String },
    EntryRegister { register: &'static str },
    Unknown,
}
#[derive(Debug, Serialize, JsonSchema)]
pub struct Guard {
    pub branch_address: String,
    pub required_edge: &'static str,
    pub flag_definition_addresses: Vec<String>,
    pub flag_definitions_complete: bool,
}
