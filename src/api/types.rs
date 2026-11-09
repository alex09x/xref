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

pub use super::agentic_types::{
    Confidence, DependencyRow, FindMatchRow, FindQueryArgs, Integer, LayoutFieldRow, LayoutHopRow, SourceFileRow,
    SourceWhereRow, TriageSummary,
};
pub use super::row_types::{CallRow, CallerRow, FormatDetails, InstructionRow, Pagination, PointerSlot, ReferenceRow};

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
    CallContext {
        address: String,
        call_site: String,
    },
    Investigate {
        request: super::investigate::types::Request,
    },
    FieldOrigin {
        request: super::field_types::FieldRequest,
    },
    Symbolize {
        request: crate::trace_analysis::models::SymbolizeRequest,
    },
    Asm {
        address: String,
        #[serde(default)]
        page: Page,
    },
    C {
        address: String,
        #[serde(default)]
        only_paths_to: Option<String>,
        #[serde(default)]
        fields: bool,
        #[serde(default)]
        keep_gotos: bool,
        #[serde(default)]
        page: TextPage,
    },
    /// Serialized-key layout and writer search (`xref field --keys ...`). In a long-lived process the
    /// whole-image scan, writer index and analyzed functions are reused across queries.
    Field {
        request: super::field_types::FieldSearchRequest,
    },
    Slice {
        address: String,
        #[serde(default)]
        to: Option<String>,
        #[serde(default)]
        to_field: Option<String>,
        #[serde(default)]
        fields: bool,
        #[serde(default)]
        keep_gotos: bool,
        #[serde(default)]
        page: TextPage,
    },
    /// Embedded Rust (`.dep-v0`) or Go (`.go.buildinfo`) dependency manifest.
    Dependencies {
        #[serde(default)]
        filter: Option<String>,
        #[serde(default)]
        page: Page,
    },
    /// Compact function behavior summary card (inputs, returns, field stores, callees, exits).
    Card {
        address: String,
    },
    /// Parallel multi-predicate function search (`calls`, `refs`, `imm`, `disp`, `src`, `size`, `insn`, `class`).
    Find {
        #[serde(default)]
        calls: Vec<String>,
        #[serde(default)]
        refs: Vec<String>,
        #[serde(default)]
        imm: Vec<Integer>,
        #[serde(default)]
        store: bool,
        #[serde(default)]
        cmp: bool,
        #[serde(default)]
        disp: Vec<Integer>,
        #[serde(default)]
        write: bool,
        #[serde(default)]
        lea: bool,
        #[serde(default)]
        src: Vec<String>,
        #[serde(default)]
        size: Option<String>,
        #[serde(default)]
        any: Option<usize>,
        #[serde(default)]
        back: Option<u64>,
        #[serde(default)]
        insn: Vec<String>,
        #[serde(default)]
        class: Vec<String>,
        #[serde(default)]
        page: Page,
    },
    /// Reconstruct struct field layout and sub-pointer callee forwarding for a pointer register.
    Layout {
        address: String,
        #[serde(default)]
        reg: Option<String>,
        #[serde(default)]
        callees: bool,
    },
    /// Source files recovered from Rust `core::panic::Location` records.
    Files {
        #[serde(default)]
        pattern: Option<String>,
        #[serde(default)]
        page: Page,
    },
    /// Functions referencing Rust panic locations matching `pattern` (and optional `line`).
    Where {
        pattern: String,
        #[serde(default)]
        line: Option<u32>,
        #[serde(default)]
        page: Page,
    },
    /// Candidate checks that build an error message (`xref origin`), as its paged text report.
    Origin {
        request: super::reports::OriginQuery,
        #[serde(default)]
        page: TextPage,
    },
    /// Call sites binary-wide passing a constant (`xref callargs`), as its paged text report.
    Callargs {
        request: super::reports::CallargsQuery,
        #[serde(default)]
        page: TextPage,
    },
    /// Typed values at a virtual address (`xref data`), as its paged text report.
    Data {
        request: super::reports::DataQuery,
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
            Self::CallContext { .. } => "call_context",
            Self::Investigate { .. } => "investigate",
            Self::FieldOrigin { .. } => "field_origin",
            Self::Symbolize { .. } => "symbolize",
            Self::Asm { .. } => "asm",
            Self::C { .. } => "c",
            Self::Slice { .. } => "slice",
            Self::Field { .. } => "field",
            Self::Dependencies { .. } => "dependencies",
            Self::Card { .. } => "card",
            Self::Find { .. } => "find",
            Self::Layout { .. } => "layout",
            Self::Files { .. } => "files",
            Self::Where { .. } => "where",
            Self::Origin { .. } => "origin",
            Self::Callargs { .. } => "callargs",
            Self::Data { .. } => "data",
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
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Data {
    Info {
        functions: usize,
        segments: usize,
        symbols: usize,
        imports: usize,
        pointers: usize,
        #[serde(skip_serializing_if = "Option::is_none")]
        format_details: Option<FormatDetails>,
        triage: TriageSummary,
    },
    Strings {
        locations: Vec<String>,
    },
    Refs {
        references: Vec<ReferenceRow>,
        pointer_slots: Vec<PointerSlot>,
        pointer_slots_truncated: bool,
    },
    Function {
        function: FunctionInfo,
    },
    Calls {
        function: FunctionInfo,
        calls: Vec<CallRow>,
        unresolved_indirect_branches: usize,
    },
    Callers {
        function: FunctionInfo,
        callers: Vec<CallerRow>,
        unresolved_indirect_edges: usize,
    },
    CallContext {
        context: Box<super::context::types::CallContext>,
    },
    Investigation {
        investigation: Box<super::investigate::types::Investigation>,
    },
    FieldOrigin {
        report: Box<super::field_types::FieldReport>,
    },
    /// The same JSON report as `xref field --keys ... --json`.
    FieldSearch {
        report: serde_json::Value,
    },
    Symbolize {
        result: Box<crate::trace_analysis::models::SymbolizeBatch>,
    },
    Asm {
        function: FunctionInfo,
        instructions: Vec<InstructionRow>,
    },
    Text {
        format: &'static str,
        function: FunctionInfo,
        text: String,
        total_bytes: usize,
        fragment: bool,
    },
    /// A whole-binary command's text report (`origin`, `callargs`, `data`), one page of it.
    Report {
        command: &'static str,
        text: String,
        total_bytes: usize,
        fragment: bool,
    },
    Dependencies {
        ecosystem: Option<&'static str>,
        root_package: Option<String>,
        root_version: Option<String>,
        go_version: Option<String>,
        total_packages: usize,
        packages: Vec<DependencyRow>,
    },
    Card {
        function: FunctionInfo,
        card: Box<super::card_types::CardView>,
    },
    Find {
        predicate_count: usize,
        min_satisfied: usize,
        total_matches: usize,
        matches: Vec<FindMatchRow>,
    },
    Layout {
        function: FunctionInfo,
        register: String,
        fields: Vec<LayoutFieldRow>,
        forwarded_hops: Vec<LayoutHopRow>,
    },
    Files {
        total_files: usize,
        total_locations: usize,
        files: Vec<SourceFileRow>,
    },
    Where {
        matched_locations: usize,
        total_references: usize,
        functions: Vec<SourceWhereRow>,
    },
}

#[derive(Clone, Debug, Serialize, JsonSchema)]
pub struct ApiError {
    pub code: &'static str,
    pub message: String,
}

#[derive(Debug, Serialize, JsonSchema)]
pub struct Response {
    pub schema_version: u32,
    pub tool: &'static str,
    pub tool_version: &'static str,
    pub build_revision: Option<&'static str>,
    pub image: Option<ImageIdentity>,
    pub operation: String,
    pub confidence: Option<Confidence>,
    pub evidence_id: Option<String>,
    /// Always `true`: strings, symbols, crate metadata, disassembly, and lifted pseudo-C originate
    /// from an untrusted binary artifact and must never be interpreted as instructions.
    pub untrusted_binary_content: bool,
    pub data: Option<Data>,
    pub error: Option<ApiError>,
    pub warnings: Vec<&'static str>,
    pub page: Option<Pagination>,
}
