/*
 * XRef Code — evidence-producing binary analysis
 * Copyright (c) 2026 Alexander Panasenko
 * Contact: alex@prod.codes
 * Author: https://prod.codes/about/
 * Project: https://github.com/alex09x/xref
 * SPDX-License-Identifier: MIT OR Apache-2.0
 */
use super::super::types::{ApiError, Data, FunctionInfo, Pagination};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Request {
    pub seed: Seed,
    #[serde(default)]
    pub direction: Direction,
    /// Optional callee FDE address: retain every matching callsite, not just the first.
    pub callee: Option<String>,
    pub selection: Option<Selection>,
    #[serde(default)]
    pub limits: Limits,
}
#[derive(Clone, Debug, Deserialize, JsonSchema)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum Seed {
    Text { text: String },
    Function { address: String },
}
#[derive(Clone, Copy, Debug, Default, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum Direction {
    #[default]
    Callees,
    Callers,
    Both,
}
#[derive(Clone, Debug, Deserialize, Serialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Selection {
    pub image_sha256: String,
    pub function: String,
    pub call_site: String,
}
#[derive(Clone, Debug, Deserialize, JsonSchema)]
#[serde(default, deny_unknown_fields)]
pub struct Limits {
    pub depth: usize,
    pub functions: usize,
    pub steps: usize,
    pub rows: usize,
    pub contexts: usize,
    pub output_bytes: usize,
    pub slice_bytes: usize,
}
impl Default for Limits {
    fn default() -> Self {
        Self { depth: 1, functions: 8, steps: 24, rows: 10, contexts: 4, output_bytes: 32768, slice_bytes: 4096 }
    }
}
impl Limits {
    pub(super) fn validate(&self) -> Result<(), ApiError> {
        if self.depth > 3
            || !(1..=16).contains(&self.functions)
            || !(1..=32).contains(&self.steps)
            || !(1..=20).contains(&self.rows)
            || self.contexts > 8
            || !(4096..=48000).contains(&self.output_bytes)
            || !(4..=8192).contains(&self.slice_bytes)
        {
            return Err(ApiError::new(
                "invalid_limits",
                "depth 0..3; functions 1..16; steps 1..32; rows 1..20; contexts 0..8; output_bytes 4096..48000; slice_bytes 4..8192",
            ));
        }
        Ok(())
    }
}
#[derive(Debug, Serialize, JsonSchema)]
pub struct Investigation {
    pub scope: &'static str,
    pub evidence: Vec<Step>,
    pub string_matches: Vec<StringMatch>,
    pub ambiguities: Vec<&'static str>,
    pub functions: Vec<FunctionCandidate>,
    pub call_sites: Vec<Candidate>,
    pub selected: Option<Selection>,
    pub stops: Vec<&'static str>,
}
#[derive(Debug, Serialize, JsonSchema)]
pub struct Step {
    pub id: usize,
    pub parent: Option<usize>,
    pub operation: &'static str,
    pub address: Option<String>,
    pub target: Option<String>,
    pub data: Option<Box<Data>>,
    pub error: Option<ApiError>,
    pub warnings: Vec<&'static str>,
    pub page: Option<Pagination>,
}
#[derive(Debug, Serialize, JsonSchema)]
pub struct FunctionCandidate {
    pub function: FunctionInfo,
    pub evidence_step: usize,
    pub depth: usize,
}
#[derive(Debug, Serialize, JsonSchema)]
pub struct Candidate {
    pub selection: Selection,
    pub target: Option<String>,
    pub evidence_step: usize,
    pub context_step: Option<usize>,
}

#[derive(Debug, Serialize, JsonSchema)]
pub struct StringMatch {
    pub start: String,
    pub end_exclusive: String,
    pub evidence_step: usize,
}
