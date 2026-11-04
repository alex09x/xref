/*
 * XRef — Key/value argument joins and bounded static-helper summaries
 * Copyright (c) 2026 Alexander Panasenko
 * Contact: alex@prod.codes
 * Author: https://prod.codes/about/
 * Project: https://github.com/alex09x/xref
 * SPDX-License-Identifier: MIT OR Apache-2.0
 */
use super::{
    catalog::{Catalog, MAX_DEPTH},
    facts::{CallFact, Facts},
    model::EmissionWitness,
    values::Value,
};
use crate::image::Image;
use std::collections::{BTreeMap, BTreeSet};

const MAX_EMISSIONS: usize = 128;
const MAX_NAME_BYTES: usize = 256;
pub(super) const MAX_FIELD_OFFSET: u64 = 0xffff_ffff;

#[derive(Clone)]
pub(super) struct Emission {
    pub name: String,
    pub argument: usize,
    pub offset: i64,
    pub read_width: Option<usize>,
    pub witness: EmissionWitness,
    pub stack_assumption: bool,
    pub sites: Vec<u64>,
}

pub(super) fn name_at(image: &Image, pointer: Option<Value>, length: Option<Value>) -> Option<(String, u64, usize)> {
    let (Value::Constant(address), Value::Constant(length)) = (pointer?, length?) else { return None };
    let length = usize::try_from(length).ok().filter(|n| (1..=MAX_NAME_BYTES).contains(n))?;
    address.checked_add(u64::try_from(length).ok()?)?;
    let name = std::str::from_utf8(image.read(address, length)?).ok()?;
    if name.contains(char::is_control) {
        return None;
    }
    Some((name.to_owned(), address, length))
}

pub(super) fn source(value: Value, spill: Option<Value>) -> Option<(usize, i64, Option<usize>, &'static str)> {
    match value {
        Value::Input { argument, offset } => Some((argument, offset, None, "input_address_argument")),
        Value::Loaded { argument, offset, width } => {
            Some((argument, offset, Some(width), "loaded_input_scalar_argument"))
        }
        Value::Stack(_) => match spill? {
            Value::Loaded { argument, offset, width } => {
                Some((argument, offset, Some(width), "stack_copy_of_input_scalar"))
            }
            Value::Input { argument, offset } => Some((argument, offset, None, "address_of_spilled_input_pointer")),
            _ => None,
        },
        Value::Constant(_) | Value::StackCell(_) => None,
    }
}

fn direct(catalog: &mut Catalog<'_>, call: &CallFact) -> Vec<Emission> {
    let mut result = Vec::new();
    let Some(target) = call.destination else { return result };
    for key in 0..4 {
        let Some((name, address, length)) = name_at(catalog.image, call.arguments[key], call.arguments[key + 1]) else {
            continue;
        };
        let Some(value) = call.arguments[key + 2] else { continue };
        let Some((argument, offset, mut width, kind)) = source(value, call.argument_spills[key + 2]) else { continue };
        if !valid_offset(offset) {
            continue;
        }
        // Leftover volatile registers do not establish an argument. Require a
        // real read/forwarding witness in the known callee before using this slot.
        if !catalog.consumed(target, key, 4, &mut BTreeSet::new())
            || !catalog.consumed(target, key + 1, 4, &mut BTreeSet::new())
            || !catalog.consumed(target, key + 2, 4, &mut BTreeSet::new())
        {
            continue;
        }
        if width.is_none() && matches!(value, Value::Input { .. }) {
            width = catalog.read_widths(target, key + 2, 4, &mut BTreeSet::new()).into_iter().max();
        }
        result.push(Emission {
            name,
            argument,
            offset,
            read_width: width,
            stack_assumption: call.escaped_stack,
            sites: vec![call.instruction.ip()],
            witness: EmissionWitness {
                key_address: format!("{address:#x}"),
                key_length: length,
                key_argument: Facts::argument_register(key),
                value_argument: Facts::argument_register(key + 2),
                call_chain: vec![call.witness.clone()],
                source: kind,
                state_identity: "same_call_arguments",
            },
        });
    }
    result
}

pub(super) fn valid_offset(offset: i64) -> bool {
    u64::try_from(offset).is_ok_and(|value| value <= MAX_FIELD_OFFSET)
}

fn rebase(call: &CallFact, child: &Emission) -> Option<Emission> {
    let actual = call.arguments.get(child.argument).copied().flatten()?;
    let (argument, offset, width, kind) = match actual {
        Value::Input { argument, offset } => {
            (argument, offset.checked_add(child.offset)?, child.read_width, child.witness.source)
        }
        Value::Stack(_) => {
            if child.offset != 0 {
                return None;
            }
            let spill = call.argument_spills.get(child.argument).copied().flatten();
            let (argument, offset, width, kind) = source(actual, spill)?;
            (argument, offset, width.or(child.read_width), kind)
        }
        // Dereferencing a loaded pointer enters another object; adding its
        // offset to the original containing object would fabricate a layout.
        Value::Loaded { .. } | Value::Constant(_) | Value::StackCell(_) => return None,
    };
    if !valid_offset(offset) {
        return None;
    }
    let mut result = child.clone();
    result.argument = argument;
    result.offset = offset;
    result.read_width = width;
    result.witness.source = kind;
    let mut step = call.witness.clone();
    step.role = "static_helper_argument_rebase";
    result.witness.call_chain.insert(0, step);
    result.sites.insert(0, call.instruction.ip());
    result.stack_assumption |= call.escaped_stack;
    Some(result)
}

fn append(target: &mut Vec<Emission>, entry: Emission) -> bool {
    let first = entry.witness.call_chain.first().map(|call| call.instruction.as_str());
    let last = entry.witness.call_chain.last().map(|call| call.instruction.as_str());
    if target.iter().any(|old| {
        old.name == entry.name
            && old.argument == entry.argument
            && old.offset == entry.offset
            && old.witness.call_chain.first().map(|call| call.instruction.as_str()) == first
            && old.witness.call_chain.last().map(|call| call.instruction.as_str()) == last
    }) {
        return false;
    }
    target.push(entry);
    true
}

pub(super) fn summaries(catalog: &mut Catalog<'_>) -> BTreeMap<u64, Vec<Emission>> {
    let functions: Vec<_> = catalog.selected.iter().copied().collect();
    let mut output: BTreeMap<u64, Vec<Emission>> = BTreeMap::new();
    for function in &functions {
        let Some(facts) = catalog.facts(*function) else { continue };
        let mut entries = Vec::new();
        for call in &facts.calls {
            for mut emission in direct(catalog, call) {
                emission.stack_assumption |= facts.stack_assumption;
                if entries.len() < MAX_EMISSIONS {
                    append(&mut entries, emission);
                } else {
                    catalog.coverage.candidates_truncated = true;
                }
            }
        }
        for emission in super::sequence::infer(catalog, &facts) {
            if entries.len() < MAX_EMISSIONS {
                append(&mut entries, emission);
            } else {
                catalog.coverage.candidates_truncated = true;
            }
        }
        output.insert(*function, entries);
    }
    for _ in 0..MAX_DEPTH {
        let mut changed = false;
        for function in &functions {
            if catalog.expired() {
                catalog.coverage.summary_depth_limit_reached = true;
                return output;
            }
            let Some(facts) = catalog.facts(*function) else { continue };
            let mut inherited = Vec::new();
            for call in &facts.calls {
                let Some(target) = call.destination.and_then(|target| output.get(&target)) else { continue };
                for child in target {
                    if child.witness.call_chain.len() >= MAX_DEPTH
                        || child.witness.call_chain.iter().any(|w| w.function == call.witness.function)
                    {
                        catalog.coverage.summary_depth_limit_reached = true;
                        continue;
                    }
                    if let Some(emission) = rebase(call, child) {
                        inherited.push(emission);
                    }
                }
            }
            let entries = output.entry(*function).or_default();
            for entry in inherited {
                if entries.len() < MAX_EMISSIONS {
                    changed |= append(entries, entry);
                } else {
                    catalog.coverage.candidates_truncated = true;
                }
            }
        }
        if !changed {
            break;
        }
    }
    output
}

/// Bring in sibling helpers only when they receive the same input root as an
/// established queried-field candidate. This recovers related key order without
/// treating every string/helper in the binary as part of that layout.
pub(super) fn expand_related(catalog: &mut Catalog<'_>, summaries: &BTreeMap<u64, Vec<Emission>>, query: &str) -> bool {
    let mut additions = BTreeSet::new();
    for (function, entries) in summaries {
        let roots: BTreeSet<_> =
            entries.iter().filter(|entry| entry.name == query).map(|entry| entry.argument).collect();
        if roots.is_empty() {
            continue;
        }
        let Some(facts) = catalog.facts(*function) else { continue };
        for call in &facts.calls {
            let related = call
                .arguments
                .iter()
                .chain(&call.argument_spills)
                .flatten()
                .any(|value| value.argument().is_some_and(|root| roots.contains(&root)));
            if related
                && let Some(target) = call.destination
                && catalog.starts.contains_key(&target)
                && !catalog.selected.contains(&target)
            {
                additions.insert(target);
            }
        }
    }
    let mut changed = false;
    for function in additions {
        if catalog.selected.len() >= catalog.max_functions() {
            catalog.coverage.context_budget_exhaustions += 1;
            catalog.coverage.summary_depth_limit_reached = true;
            break;
        }
        changed |= catalog.selected.insert(function);
    }
    catalog.coverage.selected_functions = catalog.selected.len();
    changed
}
