/*
 * XRef — Runtime stack symbolization and observed-edge evidence
 * Copyright (c) 2026 Alexander Panasenko
 * Contact: alex@prod.codes
 * Author: https://prod.codes/about/
 * Project: https://github.com/alex09x/xref
 * SPDX-License-Identifier: MIT OR Apache-2.0
 */

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct TraceIdentity {
    pub sha256: String,
    pub build_id: Option<String>,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum FrameKind {
    #[default]
    Auto,
    Instruction,
    ReturnAddress,
    Static,
    Symbol,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct SourceHint {
    pub file: String,
    pub line: u32,
    pub evidence: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct FrameFunction {
    pub start: String,
    pub end: String,
    pub offset: String,
    pub symbol: Option<String>,
    pub label: String,
    pub range_evidence: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct SymbolizedFrame {
    pub input: String,
    pub kind: FrameKind,
    pub runtime_address: Option<String>,
    pub static_address: Option<String>,
    pub mapping_evidence: Option<String>,
    pub function: Option<FrameFunction>,
    pub call_site: Option<String>,
    pub call_site_evidence: Option<String>,
    pub source: Option<SourceHint>,
    pub status: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct ObservedEdge {
    pub caller: String,
    pub callee: String,
    pub sample_count: u64,
    pub caller_call_site: Option<String>,
    pub evidence: String,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct TraceStats {
    pub samples: u64,
    pub samples_ignored: u64,
    pub kernel_mapping_records_ignored: u64,
    pub weight: u64,
    pub frames: u64,
    pub resolved_frames: u64,
    pub unresolved_frames: u64,
    pub malformed_lines: u64,
    pub lost_events: u64,
    pub input_bytes: u64,
    pub input_truncated: bool,
    pub aggregation_truncated: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ObservedStore {
    pub schema_version: u32,
    pub image: TraceIdentity,
    pub input_sha256: String,
    pub count_unit: String,
    pub edge_semantics: String,
    pub identity_evidence: String,
    pub stats: TraceStats,
    pub warnings: Vec<String>,
    pub edges: Vec<ObservedEdge>,
}

#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct StackInput {
    pub frames: Vec<String>,
    #[serde(default = "unit_weight")]
    pub weight: u64,
}

const fn unit_weight() -> u64 {
    1
}

#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct SymbolizeRequest {
    pub stacks: Vec<StackInput>,
    #[serde(default)]
    pub base: Option<String>,
    #[serde(default)]
    pub frame_kind: FrameKind,
    #[serde(default)]
    pub trace_build_id: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
pub struct SymbolizeBatch {
    pub image: TraceIdentity,
    pub mapping_evidence: String,
    pub frames: Vec<Vec<SymbolizedFrame>>,
    pub weights: Vec<u64>,
    pub warnings: Vec<String>,
}
