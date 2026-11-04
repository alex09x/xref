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
const MAX_CONTEXT: usize = 512;
const MAX_FACTS: usize = 2048;

pub(super) struct Catalog<'a> {
    pub image: &'a Image,
    pub starts: BTreeMap<u64, Range<u64>>,
    pub selected: BTreeSet<u64>,
    pub coverage: Coverage,
    facts: BTreeMap<u64, Option<Arc<Facts>>>,
    started: Instant,
}

fn key_reference(image: &Image, address: u64, name: &[u8]) -> bool {
    let length = u64::try_from(name.len()).unwrap_or(u64::MAX);
    (address.checked_add(length).is_some() && image.read(address, name.len()) == Some(name))
        || (address.checked_add(8).is_some()
            && matches!(image.slot(address),Some(Slot::Pointer(target))
            if target.checked_add(length).is_some() && image.read(target,name.len())==Some(name)))
}

fn scan_function(image: &Image, range: &Range<u64>, names: &[&str]) -> (Vec<bool>, BTreeSet<u64>) {
    let mut found = vec![false; names.len()];
    let mut targets = BTreeSet::new();
    if let Some(code) = image.code(range) {
        scan::decode(code, range.start, |instruction| {
            if instruction.is_ip_rel_memory_operand() {
                for (index, name) in names.iter().enumerate() {
                    found[index] |= key_reference(image, instruction.ip_rel_memory_address(), name.as_bytes());
                }
            }
            for address in scan::immediates(instruction) {
                for (index, name) in names.iter().enumerate() {
                    found[index] |= key_reference(image, address, name.as_bytes());
                }
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

impl<'a> Catalog<'a> {
    pub fn open(image: &'a Image, name: &str, within: Option<&Range<u64>>) -> Self {
        Self::open_many(image, &[name.to_owned()], within)
    }

    pub fn open_many(image: &'a Image, names: &[String], within: Option<&Range<u64>>) -> Self {
        let name_refs = names.iter().map(String::as_str).collect::<Vec<_>>();
        let mut result = Self {
            image,
            starts: BTreeMap::new(),
            selected: BTreeSet::new(),
            coverage: Coverage::default(),
            facts: BTreeMap::new(),
            started: Instant::now(),
        };
        let mut reverse: BTreeMap<u64, BTreeSet<u64>> = BTreeMap::new();
        let mut seeds = BTreeSet::new();
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
            if found.iter().any(|matched| *matched) {
                seeds.insert(range.start);
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
        let mut pending: VecDeque<_> = seeds.into_iter().map(|function| (function, 0)).collect();
        while let Some((function, depth)) = pending.pop_front() {
            if !result.selected.insert(function) {
                continue;
            }
            if result.selected.len() > MAX_CONTEXT {
                result.selected.remove(&function);
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
        result
    }
    pub fn expired(&self) -> bool {
        self.started.elapsed() > Duration::from_secs(30)
    }
    pub fn facts(&mut self, function: u64) -> Option<Arc<Facts>> {
        if let Some(known) = self.facts.get(&function) {
            return known.clone();
        }
        if self.facts.len() >= MAX_FACTS || self.expired() {
            self.coverage.summary_depth_limit_reached = true;
            return None;
        }
        let range = self.image.function_at(function).filter(|f| f.start == function)?;
        let analyzed = Facts::analyze(self.image, &range).map(Arc::new);
        self.coverage.analyzed_functions += 1;
        if analyzed.is_none() {
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
