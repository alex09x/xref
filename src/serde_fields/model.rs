/*
 * XRef — Evidence models for serialized field candidates
 * Copyright (c) 2026 Alexander Panasenko
 * Contact: alex@prod.codes
 * Author: https://prod.codes/about/
 * Project: https://github.com/alex09x/xref
 * SPDX-License-Identifier: MIT OR Apache-2.0
 */
use serde::Serialize;

#[derive(Clone, Debug, Serialize)]
pub(super) struct CallWitness {
    pub function: String,
    pub instruction: String,
    pub assembly: String,
    pub target: Option<String>,
    pub role: &'static str,
}

#[derive(Clone, Debug, Serialize)]
pub(super) struct EmissionWitness {
    pub key_address: String,
    pub key_length: usize,
    pub key_argument: String,
    pub value_argument: String,
    #[serde(rename = "evidence_steps")]
    pub call_chain: Vec<CallWitness>,
    pub source: &'static str,
    pub state_identity: &'static str,
}

#[derive(Clone, Debug, Serialize)]
pub(super) struct NamedField {
    pub name: String,
    pub offset: u64,
    pub offset_hex: String,
    /// Physical scalar reads, never a recovered Rust field/type size.
    #[serde(rename = "instruction_read_widths")]
    pub observed_read_widths: Vec<usize>,
    pub emissions: Vec<EmissionWitness>,
}

#[derive(Debug, Serialize)]
pub(super) struct OffsetCandidate {
    pub offset: u64,
    pub offset_hex: String,
}

#[derive(Debug, Serialize)]
pub(super) struct LayoutCandidate {
    pub function: String,
    pub base_argument: String,
    pub fields: Vec<NamedField>,
    pub offsets: Vec<OffsetCandidate>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub matched_keys: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub missing_keys: Option<Vec<String>>,
    pub query_ambiguous: bool,
    pub association_uncertain: bool,
    pub layout_kind: &'static str,
    pub field_order_evidence: &'static str,
    pub size_bytes: Option<u64>,
    pub minimum_observed_extent: u64,
    pub exact_size_unknown: bool,
    pub caveats: Vec<&'static str>,
}

#[derive(Clone, Debug, Serialize)]
pub(super) struct MemoryWitness {
    pub address: String,
    pub assembly: String,
    pub offset: i64,
    pub displacement: String,
    pub width_bytes: usize,
    pub access: &'static str,
}

#[derive(Debug, Serialize)]
pub(super) struct AccessorCandidate {
    pub layout: usize,
    pub function: String,
    pub base_argument: String,
    pub matched_offsets: Vec<u64>,
    pub queried_field_accesses: Vec<MemoryWitness>,
    pub colocated_written_fields: usize,
    pub callgraph_distance: Option<usize>,
    pub ranking_score: usize,
    /// The points behind `ranking_score`; they always sum to it (#149).
    pub score_terms: ScoreTerms,
    /// How far this row is ahead of the next listed function, and which terms make the gap.
    pub lead: Lead,
    pub confidence: &'static str,
}

/// Writer ranking points per kind of evidence (`writer_rank::writer_terms`).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize)]
pub(super) struct ScoreTerms {
    /// Queried fields written in one basic block, 8 each.
    pub colocated: usize,
    /// Of those, fields written by stores that start at the field and are no wider than it, 8 each.
    pub precise: usize,
    /// Layout fields with such a store anywhere in the function, 4 each.
    pub covered: usize,
    /// A queried field compared before it is written (an update), 8.
    pub update: usize,
    /// A queried field read by a comparison or a conditional read, 1.
    pub conditional: usize,
    /// Direct-call distance `d` from the serializer, `(7 - d) * 2`; 0 without a known path.
    pub callgraph: usize,
}

impl ScoreTerms {
    #[must_use]
    pub const fn total(&self) -> usize {
        self.colocated + self.precise + self.covered + self.update + self.conditional + self.callgraph
    }

    /// The terms in output order.
    #[must_use]
    pub const fn named(&self) -> [(&'static str, usize); 6] {
        [
            ("colocated", self.colocated),
            ("precise", self.precise),
            ("covered", self.covered),
            ("update", self.update),
            ("conditional", self.conditional),
            ("callgraph", self.callgraph),
        ]
    }
}

/// The gap between a row and the next listed row of a different function.
#[derive(Debug, Default, Serialize)]
pub(super) struct Lead {
    /// The next function, when it is among the rows ranked.
    pub over: Option<String>,
    /// `ranking_score` minus the next function's.
    pub points: Option<usize>,
    /// Terms that differ, positive where this row has more.
    pub terms: Vec<TermDelta>,
    /// Why `over` is absent: `no_other_candidate` or `next_candidate_beyond_limit`.
    pub missing: Option<&'static str>,
}

#[derive(Debug, Serialize)]
pub(super) struct TermDelta {
    pub term: &'static str,
    pub points: i64,
}

#[derive(Default, Debug, Serialize)]
pub(super) struct Coverage {
    pub scanned_functions: usize,
    pub selected_functions: usize,
    pub scanned_code_bytes: u64,
    pub skipped_functions: usize,
    pub analyzed_functions: usize,
    pub unsupported_flow_functions: usize,
    pub function_byte_budget_exhausted_functions: usize,
    pub instruction_budget_exhausted_functions: usize,
    pub context_budget_exhaustions: usize,
    pub key_seed_filter_excluded: usize,
    pub summary_depth_limit_reached: bool,
    pub candidates_truncated: bool,
    pub accessors_truncated: bool,
    pub accessor_scanned_functions: usize,
    pub accessor_prefiltered_functions: usize,
    pub scan_index_cache_hits: usize,
    pub writer_index_cache_hits: usize,
    pub warnings: Vec<&'static str>,
}

#[derive(Debug, Serialize)]
pub(super) struct FieldReport {
    pub schema_version: u32,
    pub queried_name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub queried_keys: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub key_diagnostics: Option<KeySearchDiagnostics>,
    pub image_sha256: String,
    pub status: &'static str,
    pub ambiguous: bool,
    pub candidates: Vec<LayoutCandidate>,
    pub accessor_candidates: Vec<AccessorCandidate>,
    pub coverage: Coverage,
    pub limitations: Vec<&'static str>,
}

#[derive(Debug, Serialize)]
pub(super) struct KeyEvidence {
    pub key: String,
    pub code_reference_functions: Vec<String>,
    pub code_reference_functions_truncated: bool,
    pub emission_functions: Vec<String>,
    pub emission_functions_truncated: bool,
}

#[derive(Debug, Serialize)]
pub(super) struct KeySearchDiagnostics {
    pub minimum_matched_keys: usize,
    pub keys: Vec<KeyEvidence>,
    pub missing_emission_keys: Vec<String>,
    pub scanned_functions: usize,
    pub selected_functions: usize,
    pub analyzed_functions: usize,
    pub skipped_functions: usize,
    pub unsupported_flow_functions: usize,
    pub function_byte_budget_exhausted_functions: usize,
    pub instruction_budget_exhausted_functions: usize,
    pub context_functions_truncated: bool,
    pub analysis_incomplete: bool,
    pub discovery_budget_exhausted: bool,
    pub max_functions: usize,
    pub max_instructions: usize,
    pub budget_reasons: Vec<&'static str>,
}
