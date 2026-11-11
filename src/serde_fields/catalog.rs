/*
 * XRef — Bounded single-pass discovery of field keys and static helper edges
 * Copyright (c) 2026 Alexander Panasenko
 * Contact: alex@prod.codes
 * Author: https://prod.codes/about/
 * Project: https://github.com/alex09x/xref
 * SPDX-License-Identifier: MIT OR Apache-2.0
 */
use super::{facts::Facts, model::Coverage};
use crate::image::{Image, Slot};
use std::{
    collections::{BTreeMap, BTreeSet},
    ops::Range,
    sync::Arc,
    time::{Duration, Instant},
};

pub(super) const MAX_CODE_BYTES: usize = 128 * 1024 * 1024;
// Large stripped Rust ELFs exceed 65,536 functions (over 130k observed). Below the real count the scan is
// never complete, so the reusable field index is never written and every query rescans (#76).
pub(super) const MAX_FUNCTIONS: usize = 262_144;
pub(super) const MAX_EDGES: usize = 2_097_152;
pub(super) const MAX_DEPTH: usize = 12;
pub(super) const MAX_CONTEXT: usize = 4096;
const MAX_FACTS: usize = 8192;
pub const MAX_FIELD_FUNCTION_BUDGET: usize = 8192;
pub const MAX_FIELD_INSTRUCTION_BUDGET: usize = 65_536;
pub(super) const MAX_KEY_DIAGNOSTIC_FUNCTIONS: usize = 32;

#[derive(Clone, Copy, Debug)]
pub struct SearchLimits {
    pub max_functions: usize,
    pub max_instructions: usize,
    pub min_keys: usize,
    pub exhaustive: bool,
}

impl Default for SearchLimits {
    fn default() -> Self {
        Self {
            max_functions: MAX_CONTEXT,
            max_instructions: super::facts::MAX_INSTRUCTIONS,
            min_keys: 1,
            exhaustive: true,
        }
    }
}

pub(super) struct Catalog<'a> {
    pub image: &'a Image,
    pub starts: Arc<BTreeMap<u64, Range<u64>>>,
    pub selected: BTreeSet<u64>,
    pub coverage: Coverage,
    facts: BTreeMap<u64, Option<Arc<Facts>>>,
    /// Parallel pre-analysis of selected functions; moved into `facts` (and counted) only on demand.
    prefetched: BTreeMap<u64, Result<Arc<Facts>, super::facts::AnalysisFailure>>,
    pub key_reference_functions: BTreeMap<String, Vec<u64>>,
    pub key_reference_functions_truncated: BTreeSet<String>,
    pub call_forward: Arc<CallGraph>,
    pub call_reverse: Arc<CallGraph>,
    /// Compact copy of the call graph when this process reuses a whole-image scan.
    pub dense: Option<Arc<super::dense_graph::DenseGraph>>,
    pub write_functions: Arc<BTreeSet<u64>>,
    pub full_scan: bool,
    pub identity: super::scan_index::Identity,
    pub(super) limits: SearchLimits,
    started: Instant,
}

/// Direct-call adjacency (caller → callees or callee → callers).
pub(super) type CallGraph = BTreeMap<u64, BTreeSet<u64>>;

/// Cooperative wall-clock budget for one field search.
const ANALYSIS_BUDGET: Duration = Duration::from_secs(30);

/// Analyze `ranges` in parallel; a task that starts after `deadline` is skipped (no `Facts` allocated).
pub(super) fn prefetch_facts(
    image: &Image,
    ranges: &[Range<u64>],
    max_instructions: usize,
    deadline: Instant,
) -> BTreeMap<u64, Result<Arc<Facts>, super::facts::AnalysisFailure>> {
    use rayon::prelude::*;
    ranges
        .par_iter()
        .filter_map(|range| {
            (Instant::now() <= deadline).then(|| {
                (range.start, Facts::analyze_with_instruction_limit(image, range, max_instructions).map(Arc::new))
            })
        })
        .collect()
}

fn key_reference(image: &Image, address: u64, name: &[u8]) -> bool {
    let length = u64::try_from(name.len()).unwrap_or(u64::MAX);
    (address.checked_add(length).is_some() && image.read(address, name.len()) == Some(name))
        || (address.checked_add(8).is_some()
            && matches!(image.slot(address),Some(Slot::Pointer(target))
            if target.checked_add(length).is_some() && image.read(target,name.len())==Some(name)))
}

fn merged_short_key_literal(image: &Image, address: u64, names: &[&str]) -> bool {
    if names.len() < 2 || names.iter().any(|name| name.len() != 1) {
        return false;
    }
    let mut packed = Vec::with_capacity(names.len() + 1);
    for name in names {
        packed.push(name.as_bytes()[0]);
    }
    packed.push(0);
    image.read(address, packed.len()) == Some(packed.as_slice())
}

pub(super) fn mark_key_references(image: &Image, address: u64, names: &[&str], found: &mut [bool]) {
    if merged_short_key_literal(image, address, names) {
        found.fill(true);
        return;
    }
    for (index, name) in names.iter().enumerate() {
        found[index] |= key_reference(image, address, name.as_bytes());
    }
}

impl<'a> Catalog<'a> {
    #[cfg(test)]
    pub fn open(image: &'a Image, name: &str, within: Option<&Range<u64>>) -> Self {
        Self::open_many_with_limits(image, &[name.to_owned()], within, SearchLimits::default())
    }

    pub fn open_many_with_limits(
        image: &'a Image,
        names: &[String],
        within: Option<&Range<u64>>,
        limits: SearchLimits,
    ) -> Self {
        let mut result = Self {
            image,
            starts: Arc::default(),
            selected: BTreeSet::new(),
            coverage: Coverage { instruction_limit: limits.max_instructions, ..Coverage::default() },
            facts: BTreeMap::new(),
            prefetched: BTreeMap::new(),
            key_reference_functions: BTreeMap::new(),
            key_reference_functions_truncated: BTreeSet::new(),
            call_forward: Arc::default(),
            call_reverse: Arc::default(),
            dense: None,
            write_functions: Arc::default(),
            full_scan: false,
            identity: super::scan_index::Identity::new(&image.data, within.is_none()),
            limits,
            started: Instant::now(),
        };
        let graphs = super::catalog_scan::scan(&mut result, names, within);
        let (selected, truncated, fallback, excluded) = match &graphs.dense {
            Some(dense) => {
                dense.select(&graphs.seeds, limits.min_keys, limits.max_functions, MAX_DEPTH, limits.exhaustive)
            }
            None => super::seeds::select(
                &graphs.seeds,
                &graphs.reverse,
                &graphs.forward,
                limits.min_keys,
                limits.max_functions,
                MAX_DEPTH,
                limits.exhaustive,
            ),
        };
        result.dense.clone_from(&graphs.dense);
        result.selected = selected;
        if truncated {
            result.coverage.context_budget_exhaustions += 1;
            result.coverage.summary_depth_limit_reached = true;
        }
        if fallback && limits.min_keys > 1 {
            result.coverage.warnings.push("key_intersection_unavailable_using_partial_seeds");
            result.coverage.summary_depth_limit_reached = true;
        }
        result.coverage.key_seed_filter_excluded = excluded;
        if excluded > 0 {
            result.coverage.warnings.push("partial_key_seeds_excluded_use_exhaustive_key_seeds_for_recall");
        }
        result.call_forward = graphs.forward;
        result.call_reverse = graphs.reverse;
        result.coverage.selected_functions = result.selected.len();
        result.prefetch_selected_facts();
        result
    }

    /// Analyze the selected context functions in parallel up front; key/value inference then reads
    /// them from `self.facts` instead of analyzing one by one on a single thread (#76 latency).
    /// Each task checks the cooperative deadline before it starts; functions not analyzed in time fall
    /// back to the lazy path in [`Self::facts`], which enforces the same budget.
    fn prefetch_selected_facts(&mut self) {
        let budget = MAX_FACTS.min(self.limits.max_functions);
        let image = self.image;
        let ranges: Vec<_> = self
            .selected
            .iter()
            .filter_map(|start| image.function_at(*start).filter(|f| f.start == *start))
            .take(budget)
            .collect();
        let max_instructions = self.limits.max_instructions;
        // Analyses from earlier queries in this process (e.g. an MCP session) are reused.
        let (mut known, missing) = super::session::known_facts(&self.identity, max_instructions, ranges);
        let fresh = prefetch_facts(image, &missing, max_instructions, self.started + ANALYSIS_BUDGET);
        super::session::remember_facts(&self.identity, max_instructions, &fresh);
        known.extend(fresh);
        self.prefetched = known;
    }

    fn record_facts(
        &mut self,
        function: u64,
        outcome: Result<Arc<Facts>, super::facts::AnalysisFailure>,
    ) -> Option<Arc<Facts>> {
        let (analyzed, unsupported) = match outcome {
            Ok(facts) => (Some(facts), false),
            Err(super::facts::AnalysisFailure::FunctionByteLimit) => {
                self.coverage.function_byte_budget_exhausted_functions += 1;
                note_budgeted(&mut self.coverage.byte_budgeted_examples, function);
                (None, false)
            }
            Err(super::facts::AnalysisFailure::InstructionBudgetExceeded) => {
                self.coverage.instruction_budget_exhausted_functions += 1;
                note_budgeted(&mut self.coverage.instruction_budgeted_examples, function);
                (None, false)
            }
            Err(_) => {
                note_budgeted(&mut self.coverage.unsupported_examples, function);
                (None, true)
            }
        };
        self.coverage.analyzed_functions += 1;
        if unsupported {
            self.coverage.unsupported_flow_functions += 1;
        }
        self.facts.insert(function, analyzed.clone());
        analyzed
    }
    /// End of the cooperative analysis budget.
    pub fn deadline(&self) -> Instant {
        self.started + ANALYSIS_BUDGET
    }
    pub fn expired(&self) -> bool {
        let expired = self.started.elapsed() > ANALYSIS_BUDGET;
        if expired {
            crate::field_result_cache::note_time_budget_hit();
        }
        expired
    }
    pub const fn max_functions(&self) -> usize {
        self.limits.max_functions
    }
    pub fn facts(&mut self, function: u64) -> Option<Arc<Facts>> {
        if let Some(known) = self.facts.get(&function) {
            return known.clone();
        }
        if self.facts.len() >= MAX_FACTS.min(self.limits.max_functions) || self.expired() {
            self.coverage.summary_depth_limit_reached = true;
            return None;
        }
        let outcome = if let Some(outcome) = self.prefetched.remove(&function) {
            outcome
        } else {
            let range = self.image.function_at(function).filter(|f| f.start == function)?;
            let max_instructions = self.limits.max_instructions;
            // Facts are deterministic per (function, instruction budget): reuse this process's earlier
            // analyses of callees outside the selected set, and remember new ones.
            let (mut known, missing) = super::session::known_facts(&self.identity, max_instructions, vec![range]);
            if let Some(range) = missing.first() {
                let fresh = Facts::analyze_with_instruction_limit(self.image, range, max_instructions).map(Arc::new);
                known.insert(function, fresh);
                super::session::remember_facts(&self.identity, max_instructions, &known);
            }
            known.remove(&function)?
        };
        self.record_facts(function, outcome)
    }
    pub fn known_facts(&self, function: u64) -> Option<Arc<Facts>> {
        self.facts.get(&function).cloned().flatten()
    }
    pub fn consumed(
        &mut self,
        function: u64,
        argument: usize,
        depth: usize,
        visited: &mut BTreeSet<(u64, usize)>,
    ) -> bool {
        if !visited.insert((function, argument)) || depth == 0 {
            return false;
        }
        let Some(facts) = self.facts(function) else { return false };
        if facts.local_used & (1_u8 << argument) != 0 {
            return true;
        }
        facts.calls.iter().any(|call| {
            call.destination.is_some_and(|target| {
                call.arguments.iter().enumerate().any(|(index, value)| {
                    value.and_then(Value::argument) == Some(argument)
                        && self.consumed(target, index, depth - 1, visited)
                })
            })
        })
    }
    pub fn memory_reader(
        &mut self,
        function: u64,
        argument: usize,
        depth: usize,
        visited: &mut BTreeSet<(u64, usize)>,
    ) -> bool {
        if depth == 0 || !visited.insert((function, argument)) {
            return false;
        }
        let Some(facts) = self.facts(function) else { return false };
        if facts
            .accesses
            .iter()
            .any(|access| access.argument == argument && access.width > 0 && access.kind.contains("read"))
        {
            return true;
        }
        facts.calls.iter().any(|call| {
            call.destination.is_some_and(|target| {
                call.arguments.iter().enumerate().any(|(index, value)| {
                    value.and_then(Value::argument) == Some(argument)
                        && self.memory_reader(target, index, depth - 1, visited)
                })
            })
        })
    }
    pub fn read_widths(
        &mut self,
        function: u64,
        argument: usize,
        depth: usize,
        visited: &mut BTreeSet<(u64, usize)>,
    ) -> BTreeSet<usize> {
        let mut result = BTreeSet::new();
        if depth == 0 || !visited.insert((function, argument)) {
            return result;
        }
        let Some(facts) = self.facts(function) else { return result };
        result.extend(
            facts
                .accesses
                .iter()
                .filter(|access| {
                    access.argument == argument
                        && access.offset == 0
                        && access.width > 0
                        && access.kind.contains("read")
                })
                .map(|access| access.width),
        );
        for call in &facts.calls {
            let Some(target) = call.destination else { continue };
            for (index, value) in call.arguments.iter().enumerate() {
                if *value == Some(Value::Input { argument, offset: 0 }) {
                    result.extend(self.read_widths(target, index, depth - 1, visited));
                }
            }
        }
        result
    }
}

use super::values::Value;

/// Keeps the first few functions a budget stopped, so the report can name them.
fn note_budgeted(examples: &mut Vec<String>, function: u64) {
    if examples.len() < super::model::BUDGETED_EXAMPLES {
        examples.push(format!("{function:#x}"));
    }
}
