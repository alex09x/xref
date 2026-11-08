/*
 * XRef Code — Core structured row and pagination DTOs
 * Copyright (c) 2026 Alexander Panasenko
 *
 * Contact: alex@prod.codes
 * Author: https://prod.codes/about/
 * Project: https://github.com/alex09x/xref
 * SPDX-License-Identifier: MIT OR Apache-2.0
 */

use schemars::JsonSchema;
use serde::Serialize;

use super::types::FunctionInfo;

#[derive(Debug, Serialize, JsonSchema)]
pub struct InstructionRow {
    pub address: String,
    pub rva: String,
    pub size_bytes: usize,
    pub bytes: String,
    pub valid: bool,
    pub text: String,
    pub memory_address: Option<String>,
    pub direct_branch_target: Option<String>,
}

#[derive(Debug, Serialize, JsonSchema)]
pub struct ReferenceRow {
    pub address: String,
    pub rva: String,
    pub function: FunctionInfo,
    pub memory_address: String,
    pub text: String,
}

#[derive(Debug, Serialize, JsonSchema)]
pub struct PointerSlot {
    pub address: String,
    pub target: String,
}

#[derive(Debug, Serialize, JsonSchema)]
pub struct CallRow {
    pub address: String,
    pub rva: String,
    pub kind: &'static str,
    pub target: Option<String>,
    pub description: String,
    pub description_truncated: bool,
}

#[derive(Debug, Serialize, JsonSchema)]
pub struct CallerRow {
    pub caller: FunctionInfo,
    pub call: CallRow,
}

#[derive(Debug, Serialize, JsonSchema)]
pub struct FormatDetails {
    pub entry_point: Option<String>,
    pub recorded_function_starts: usize,
    pub starts_without_fde: usize,
    pub return_contract: &'static str,
}

#[derive(Debug, Serialize, JsonSchema)]
pub struct Pagination {
    pub unit: &'static str,
    pub offset: usize,
    pub returned: usize,
    pub next_offset: Option<usize>,
    pub complete: bool,
}
