/*
 * XRef — Bounded single-pass discovery of field keys and static helper edges
 * Copyright (c) 2026 Alexander Panasenko
 * Contact: alex@prod.codes
 * Author: https://prod.codes/about/
 * Project: https://github.com/alex09x/xref
 * SPDX-License-Identifier: MIT OR Apache-2.0
 */
use super::{facts::Facts, model::Coverage};
use crate::{
    image::{Image, Slot},
    listing, scan,
};
use std::{
    collections::{BTreeMap, BTreeSet, VecDeque},
    ops::Range,
    sync::Arc,
    time::{Duration, Instant},
};

const MAX_CODE_BYTES: usize = 128 * 1024 * 1024;
const MAX_FUNCTIONS: usize = 65_536;
const MAX_EDGES: usize = 524_288;
pub(super) const MAX_DEPTH: usize = 12;
pub(super) const MAX_CONTEXT: usize = 512;
const MAX_FACTS: usize = 8192;
pub const MAX_FIELD_FUNCTION_BUDGET: usize = 8192;
pub const MAX_FIELD_INSTRUCTION_BUDGET: usize = 16_384;
pub(super) const MAX_KEY_DIAGNOSTIC_FUNCTIONS: usize = 32;

#[derive(Clone, Copy, Debug)]
pub struct SearchLimits {
    pub max_functions: usize,
    pub max_instructions: usize,
}

impl Default for SearchLimits {
    fn default() -> Self {
        Self { max_functions: MAX_CONTEXT, max_instructions: super::facts::MAX_INSTRUCTIONS }
    }
}

pub(super) struct Catalog<'a> {
    pub image: &'a Image,
    pub starts: BTreeMap<u64, Range<u64>>,
    pub selected: BTreeSet<u64>,
    pub coverage: Coverage,
    facts: BTreeMap<u64, Option<Arc<Facts>>>,
    pub key_reference_functions: BTreeMap<String, Vec<u64>>,
    pub key_reference_functions_truncated: BTreeSet<String>,
    limits: SearchLimits,
    started: Instant,
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

fn scan_function(image: &Image, range: &Range<u64>, names: &[&str]) -> (Vec<bool>, BTreeSet<u64>) {
    let mut found = vec![false; names.len()];
    let mut targets = BTreeSet::new();
    if let Some(code) = image.code(range) {
        scan::decode(code, range.start, |instruction| {
            if instruction.is_ip_rel_memory_operand() {
                mark_key_references(image, instruction.ip_rel_memory_address(), names, &mut found);
            }
            for address in scan::immediates(instruction) {
                mark_key_references(image, address, names, &mut found);
            }
            if listing::is_call(instruction, range)
                && let Some(target) = super::static_target(image, instruction)
                && image.function_at(target).is_some_and(|f| f.start == target)
            {
                targets.insert(target);
            }
        });
    }
    (found, targets)
}

fn mark_key_references(image: &Image, address: u64, names: &[&str], found: &mut [bool]) {
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
        let name_refs = names.iter().map(String::as_str).collect::<Vec<_>>();
        let mut result = Self {
            image,
            starts: BTreeMap::new(),
            selected: BTreeSet::new(),
            coverage: Coverage::default(),
            facts: BTreeMap::new(),
            key_reference_functions: BTreeMap::new(),
            key_reference_functions_truncated: BTreeSet::new(),
            limits,
            started: Instant::now(),
        };
        let mut reverse: BTreeMap<u64, BTreeSet<u64>> = BTreeMap::new();
        let mut seed_scores = BTreeMap::new();
        let mut bytes = 0_usize;
        let mut edges = 0_usize;
        let mut queue: VecDeque<_> = within.map_or_else(
            || image.functions.iter().cloned().map(|f| (f, 0)).collect(),
            |f| VecDeque::from([(f.clone(), 0)]),
        );
        let mut visited = BTreeSet::new();
        while let Some((range, depth)) = queue.pop_front() {
            if !visited.insert(range.start) {
                continue;
            }
            let length = usize::try_from(range.end.saturating_sub(range.start)).unwrap_or(usize::MAX);
            if bytes.saturating_add(length) > MAX_CODE_BYTES || result.starts.len() >= MAX_FUNCTIONS || result.expired()
            {
                result.coverage.skipped_functions += 1;
                continue;
            }
            bytes += length;
            result.coverage.scanned_functions += 1;
            let (found, targets) = scan_function(image, &range, &name_refs);
            let matched = found.iter().filter(|matched| **matched).count();
            if matched > 0 {
                seed_scores.insert(range.start, matched);
                for (index, is_found) in found.iter().enumerate() {
                    if !is_found {
                        continue;
                    }
                    let key = names[index].clone();
                    let functions = result.key_reference_functions.entry(key.clone()).or_default();
                    if functions.len() < MAX_KEY_DIAGNOSTIC_FUNCTIONS {
                        functions.push(range.start);
                    } else {
                        result.key_reference_functions_truncated.insert(key);
                    }
                }
            }
            for target in targets {
                if edges < MAX_EDGES {
                    reverse.entry(target).or_default().insert(range.start);
                    edges += 1;
                } else {
                    result.coverage.summary_depth_limit_reached = true;
                }
                if within.is_some()
                    && depth < MAX_DEPTH
                    && let Some(function) = image.function_at(target)
                {
                    queue.push_back((function.clone(), depth + 1));
                }
            }
            result.starts.insert(range.start, range);
        }
        result.coverage.scanned_code_bytes = u64::try_from(bytes).unwrap_or(u64::MAX);
        let mut seeds = seed_scores.into_iter().collect::<Vec<_>>();
        seeds.sort_by(|(a_function, a_score), (b_function, b_score)| {
            b_score.cmp(a_score).then_with(|| a_function.cmp(b_function))
        });
        let mut pending: VecDeque<_> = seeds.into_iter().map(|(function, _)| (function, 0)).collect();
        while let Some((function, depth)) = pending.pop_front() {
            if !result.selected.insert(function) {
                continue;
            }
            if result.selected.len() > limits.max_functions {
                result.selected.remove(&function);
                result.coverage.context_budget_exhaustions += 1;
                result.coverage.summary_depth_limit_reached = true;
                break;
            }
            if depth == MAX_DEPTH {
                result.coverage.summary_depth_limit_reached = true;
                continue;
            }
            for &parent in reverse.get(&function).into_iter().flatten() {
                pending.push_back((parent, depth + 1));
            }
        }
        result.coverage.selected_functions = result.selected.len();
        result
    }
    pub fn expired(&self) -> bool {
        self.started.elapsed() > Duration::from_secs(30)
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
        let range = self.image.function_at(function).filter(|f| f.start == function)?;
        let (analyzed, unsupported) =
            match Facts::analyze_with_instruction_limit(self.image, &range, self.limits.max_instructions) {
                Ok(facts) => (Some(Arc::new(facts)), false),
                Err(super::facts::AnalysisFailure::FunctionByteLimit) => {
                    self.coverage.function_byte_budget_exhausted_functions += 1;
                    (None, false)
                }
                Err(super::facts::AnalysisFailure::InstructionBudgetExceeded) => {
                    self.coverage.instruction_budget_exhausted_functions += 1;
                    (None, false)
                }
                Err(_) => (None, true),
            };
        self.coverage.analyzed_functions += 1;
        if unsupported {
            self.coverage.unsupported_flow_functions += 1;
        }
        self.facts.insert(function, analyzed.clone());
        analyzed
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
