/*
 * XRef Code — evidence-producing binary analysis
 * Copyright (c) 2026 Alexander Panasenko
 * Contact: alex@prod.codes
 * Author: https://prod.codes/about/
 * Project: https://github.com/alex09x/xref
 * SPDX-License-Identifier: MIT OR Apache-2.0
 */
use super::{
    context::types::Guard,
    investigate::types::{Selection, Step},
    types::{ApiError, FunctionInfo, InstructionRow},
};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct FieldRequest {
    pub address: String,
    #[serde(default = "default_register")]
    pub register: String,
    #[serde(default)]
    pub offsets: Vec<String>,
    #[serde(default)]
    pub callees: bool,
    pub selection: Option<Selection>,
    #[serde(default)]
    pub limits: FieldLimits,
}
fn default_register() -> String {
    "rdi".into()
}

/// `field` search over serialized keys; mirrors `xref field --keys ...`.
#[derive(Clone, Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct FieldSearchRequest {
    /// Exact set of sibling serialized keys, e.g. `["c","m","e"]`.
    pub keys: Vec<String>,
    /// Rank accessor candidates that may write the queried fields.
    #[serde(default)]
    pub write: bool,
    /// Require writes to every named field (implies `write`).
    #[serde(default)]
    pub writes_all_of: Vec<String>,
    /// `any` (default), `argument`, `returned` (pointer returned by a call) or `loaded`.
    #[serde(default)]
    pub writer_root: Option<String>,
    /// Maximum accessor rows, 1..=128 (default 16 here; responses are size-limited).
    pub limit: Option<usize>,
    /// Accept layouts matching at least this many keys.
    pub min_keys: Option<usize>,
    /// Minimum distinct offsets per accessor root (default 2).
    pub min_offsets: Option<usize>,
    /// Context function budget, 1..=8192 (default 4096).
    pub max_functions: Option<usize>,
    /// Instruction budget per function, 1..=65536 (default 4096); functions up to 8 bytes per instruction (at least 32 KiB) are analysed.
    pub max_instructions: Option<usize>,
    /// Skip the accessor search.
    #[serde(default)]
    pub layout_only: bool,
    /// Include partial key-reference seeds.
    #[serde(default)]
    pub exhaustive_key_seeds: bool,
}

#[derive(Clone, Debug, Deserialize, JsonSchema)]
#[serde(default, deny_unknown_fields)]
pub struct FieldLimits {
    pub rows: usize,
    pub callees: usize,
    pub output_bytes: usize,
    pub slice_bytes: usize,
}
impl Default for FieldLimits {
    fn default() -> Self {
        Self { rows: 20, callees: 4, output_bytes: 32768, slice_bytes: 4096 }
    }
}
impl FieldLimits {
    pub fn validate(&self) -> Result<(), ApiError> {
        if !(1..=40).contains(&self.rows)
            || self.callees > 4
            || !(4096..=48000).contains(&self.output_bytes)
            || !(4..=8192).contains(&self.slice_bytes)
        {
            return Err(ApiError::new(
                "invalid_limits",
                "rows 1..40; callees 0..4; output_bytes 4096..48000; slice_bytes 4..8192",
            ));
        }
        Ok(())
    }
}
#[derive(Debug, Serialize, JsonSchema)]
pub struct FieldReport {
    pub function: FunctionInfo,
    pub entry_register: String,
    pub scope: &'static str,
    pub accesses: Vec<FieldAccess>,
    pub calls: Vec<FieldCall>,
    pub callee_scopes: Vec<Hop>,
    pub layout_hints: Vec<LayoutHint>,
    pub slice: Option<Step>,
    pub selected: Option<Selection>,
    pub complete_under_model: bool,
    pub unresolved_memory_operands: usize,
    pub calls_examined: usize,
    pub scope_errors: Vec<ScopeError>,
    pub stops: Vec<&'static str>,
}
#[derive(Clone, Debug, Serialize, JsonSchema)]
pub struct Hop {
    pub caller: String,
    pub call_site: String,
    pub target: String,
    pub argument_register: String,
    pub base_displacement: String,
}
#[derive(Debug, Serialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum AccessKind {
    Read,
    Write,
    ReadWrite,
    Address,
}

#[derive(Debug, Serialize, JsonSchema)]
pub struct FieldAccess {
    pub function: String,
    pub displacement: String,
    pub width_bytes: usize,
    pub access: AccessKind,
    pub conditional_access: bool,
    pub instruction: InstructionRow,
    pub definitions: Vec<InstructionRow>,
    pub definitions_truncated: bool,
    pub via: Option<Hop>,
}
#[derive(Debug, Serialize, JsonSchema)]
pub struct FieldCall {
    pub selection: Selection,
    pub target: Option<String>,
    pub instruction: InstructionRow,
    pub arguments: Vec<ArgumentOrigin>,
    pub guards: Vec<Guard>,
    pub guard_instructions: Vec<InstructionRow>,
    pub guards_complete: bool,
    pub via: Option<Hop>,
}
#[derive(Debug, Serialize, JsonSchema)]
pub struct ArgumentOrigin {
    pub register: &'static str,
    /// Base/address and unmodified loaded value are separate machine relationships.
    pub relation: &'static str,
    pub displacement: String,
    pub load_address: Option<String>,
    pub requested_offset_match: Option<bool>,
    pub load_width_bytes: Option<usize>,
    pub definitions: Vec<InstructionRow>,
    pub definitions_truncated: bool,
}
#[derive(Debug, Serialize, JsonSchema)]
pub struct LayoutHint {
    pub displacement: String,
    pub width_hint_bytes: usize,
    pub stride_hint: Option<String>,
    pub status: &'static str,
}
#[derive(Debug, Serialize, JsonSchema)]
pub struct ScopeError {
    pub function: String,
    pub error: ApiError,
    pub via: Option<Hop>,
}
pub(super) fn signed_hex(value: i64) -> String {
    if value < 0 { format!("-{:#x}", value.unsigned_abs()) } else { format!("{value:#x}") }
}
