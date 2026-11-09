/*
 * XRef Code — Agentic triage, confidence tiers, provenance, and extended query DTOs
 * Copyright (c) 2026 Alexander Panasenko
 *
 * Contact: alex@prod.codes
 * Author: https://prod.codes/about/
 * Project: https://github.com/alex09x/xref
 * SPDX-License-Identifier: MIT OR Apache-2.0
 */

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use super::types::FunctionInfo;

/// Epistemic confidence tier of a structured `xref` result.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum Confidence {
    /// Raw image bytes, section headers, symbol tables, `.eh_frame` FDE spans, `.dep-v0` / `.go.buildinfo`,
    /// or exact decoded machine instructions.
    Observed,
    /// Deterministic control-flow, relocation, or cross-reference derivation over decoded instructions.
    Derived,
    /// Heuristic ABI, register dataflow, struct layout, or structured pseudo-C recovery.
    Inferred,
}

/// Summary of embedded dependency manifest count and root package in `info.triage`.
#[derive(Clone, Debug, Serialize, JsonSchema)]
pub struct EmbeddedDepsSummary {
    pub ecosystem: &'static str,
    pub root_package: Option<String>,
    pub root_version: Option<String>,
    pub go_version: Option<String>,
    pub count: usize,
}

/// Ready-to-run next structured `xref_query` request tailored to the inspected binary.
#[derive(Clone, Debug, Serialize, JsonSchema)]
pub struct RecommendedQuery {
    pub reason: &'static str,
    pub request: serde_json::Value,
}

/// First-contact triage summary embedded in `Data::Info` to eliminate wasted agent discovery turns.
#[derive(Clone, Debug, Serialize, JsonSchema)]
pub struct TriageSummary {
    pub language: &'static str,
    pub stripped: bool,
    pub panic_locations: usize,
    pub source_files: usize,
    pub build_id: Option<String>,
    pub toolchains: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub embedded_dependencies: Option<EmbeddedDepsSummary>,
    pub high_entropy_executable: bool,
    pub recommended_queries: Vec<RecommendedQuery>,
}

/// A single crate or Go module dependency row from `operation = "dependencies"`.
#[derive(Clone, Debug, Serialize, JsonSchema)]
pub struct DependencyRow {
    pub name: String,
    pub version: String,
    pub kind: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub source: Option<String>,
    pub root: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub replaced_by: Option<String>,
}

/// A 64-bit integer: a JSON number, or a decimal or `0x` hexadecimal string (exact above 2^53).
#[derive(Clone, Debug, Deserialize, JsonSchema)]
#[serde(untagged)]
pub enum Integer {
    Number(u64),
    Text(String),
}

impl Integer {
    /// The value, as `xref find --imm` parses it.
    pub fn value(&self) -> Result<u64, String> {
        match self {
            Self::Number(value) => Ok(*value),
            Self::Text(text) => crate::cli::parse_number(text),
        }
    }
}

/// Grouped predicate inputs passed to `Analysis::find_functions`.
pub struct FindQueryArgs<'a> {
    pub calls: &'a [String],
    pub refs: &'a [String],
    pub imm: &'a [Integer],
    pub imm_mode: (bool, bool),
    pub disp: &'a [Integer],
    pub disp_mode: (bool, bool),
    pub src: &'a [String],
    pub size: Option<&'a str>,
    pub any: Option<usize>,
    pub back: Option<u64>,
    pub insn: &'a [String],
    pub class: &'a [String],
}

/// A single matched function row from `operation = "find"`.
#[derive(Debug, Serialize, JsonSchema)]
pub struct FindMatchRow {
    pub function: FunctionInfo,
    pub satisfied: usize,
    pub predicate_count: usize,
    pub matched_predicates: Vec<String>,
    pub instruction_hits: usize,
}

/// A reconstructed struct field row from `operation = "layout"`.
#[derive(Debug, Serialize, JsonSchema)]
pub struct LayoutFieldRow {
    pub offset: String,
    pub offset_bytes: u64,
    pub width_bytes: usize,
    pub inferred_type: &'static str,
    pub reads: usize,
    pub writes: usize,
    pub leas: usize,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub array_stride: Option<String>,
    pub pointer_callees: Vec<String>,
    pub value_callees: Vec<String>,
    pub via_callees: Vec<String>,
}

/// A forwarded sub-pointer hop followed during `operation = "layout"` when `callees = true`.
#[derive(Debug, Serialize, JsonSchema)]
pub struct LayoutHopRow {
    pub delta: String,
    pub callee: String,
    pub register: &'static str,
}

/// Source file panic-location density row from `operation = "files"`.
#[derive(Debug, Serialize, JsonSchema)]
pub struct SourceFileRow {
    pub file: String,
    pub panic_locations: usize,
}

/// Function referencing matching Rust source `file:line` locations from `operation = "where"`.
#[derive(Debug, Serialize, JsonSchema)]
pub struct SourceWhereRow {
    pub function: FunctionInfo,
    pub locations: Vec<String>,
}
