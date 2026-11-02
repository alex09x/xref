/*
 * XRef Code — Structured query contracts
 * Copyright (c) 2026 Alexander Panasenko
 * Contact: alex@prod.codes
 * Author: https://prod.codes/about/
 * Project: https://github.com/alex09x/xref
 * SPDX-License-Identifier: MIT OR Apache-2.0
 */

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Deserialize, JsonSchema)]
#[serde(default, deny_unknown_fields)]
pub struct Page {
    /// Number of sorted rows to skip (at most 10000).
    pub offset: usize,
    /// Rows to return, from 1 through 100.
    pub limit: usize,
}
impl Default for Page {
    fn default() -> Self {
        Self { offset: 0, limit: 20 }
    }
}

#[derive(Clone, Debug, Deserialize, JsonSchema)]
#[serde(default, deny_unknown_fields)]
pub struct TextPage {
    /// UTF-8 byte offset returned by an earlier response.
    pub offset: usize,
    /// Text bytes to return, from 4 through 16384.
    pub limit: usize,
}
impl Default for TextPage {
    fn default() -> Self {
        Self { offset: 0, limit: 8192 }
    }
}

#[derive(Clone, Debug, Deserialize, JsonSchema)]
#[serde(tag = "operation", rename_all = "snake_case", deny_unknown_fields)]
pub enum Query {
    Info {},
    Strings {
        text: String,
        #[serde(default)]
        page: Page,
    },
    Refs {
        address: String,
        #[serde(default)]
        back: u64,
        #[serde(default)]
        page: Page,
    },
    Function {
        address: String,
    },
    Calls {
        address: String,
        #[serde(default)]
        page: Page,
    },
    Callers {
        address: String,
        #[serde(default)]
        page: Page,
    },
    Asm {
        address: String,
        #[serde(default)]
        page: Page,
    },
    C {
        address: String,
        #[serde(default)]
        fields: bool,
        #[serde(default)]
        keep_gotos: bool,
        #[serde(default)]
        page: TextPage,
    },
    Slice {
        address: String,
        to: String,
        #[serde(default)]
        fields: bool,
        #[serde(default)]
        keep_gotos: bool,
        #[serde(default)]
        page: TextPage,
    },
}

impl Query {
    pub const fn name(&self) -> &'static str {
        match self {
            Self::Info { .. } => "info",
            Self::Strings { .. } => "strings",
            Self::Refs { .. } => "refs",
            Self::Function { .. } => "function",
            Self::Calls { .. } => "calls",
            Self::Callers { .. } => "callers",
            Self::Asm { .. } => "asm",
            Self::C { .. } => "c",
            Self::Slice { .. } => "slice",
        }
    }
}

#[derive(Clone, Debug, Serialize, JsonSchema)]
pub struct ImageIdentity {
    pub sha256: String,
    pub bytes: usize,
    pub format: &'static str,
    pub architecture: &'static str,
    pub base_address: String,
    pub rva_basis: &'static str,
}

#[derive(Clone, Debug, Serialize, JsonSchema)]
pub struct FunctionInfo {
    pub start: String,
    pub end: String,
    pub rva: String,
    pub size_bytes: u64,
    pub range_origin: &'static str,
    pub symbol: Option<String>,
    pub symbol_truncated: bool,
}

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
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Data {
    Info { functions: usize, segments: usize, symbols: usize, imports: usize, pointers: usize },
    Strings { locations: Vec<String> },
    Refs { references: Vec<ReferenceRow>, pointer_slots: Vec<PointerSlot>, pointer_slots_truncated: bool },
    Function { function: FunctionInfo },
    Calls { function: FunctionInfo, calls: Vec<CallRow>, unresolved_indirect_branches: usize },
    Callers { function: FunctionInfo, callers: Vec<CallerRow>, unresolved_indirect_edges: usize },
    Asm { function: FunctionInfo, instructions: Vec<InstructionRow> },
    Text { format: &'static str, function: FunctionInfo, text: String, total_bytes: usize, fragment: bool },
}

#[derive(Clone, Debug, Serialize, JsonSchema)]
pub struct ApiError {
    pub code: &'static str,
    pub message: String,
}

#[derive(Debug, Serialize, JsonSchema)]
pub struct Pagination {
    pub unit: &'static str,
    pub offset: usize,
    pub returned: usize,
    pub next_offset: Option<usize>,
    pub complete: bool,
}

#[derive(Debug, Serialize, JsonSchema)]
pub struct Response {
    pub schema_version: u32,
    pub tool: &'static str,
    pub tool_version: &'static str,
    pub build_revision: Option<&'static str>,
    pub image: Option<ImageIdentity>,
    pub operation: String,
    pub data: Option<Data>,
    pub error: Option<ApiError>,
    pub warnings: Vec<&'static str>,
    pub page: Option<Pagination>,
}
