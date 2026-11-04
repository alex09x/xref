/*
 * XRef — Explicitly inferred JSON key/colon/value continuations
 * Copyright (c) 2026 Alexander Panasenko
 * Contact: alex@prod.codes
 * Author: https://prod.codes/about/
 * Project: https://github.com/alex09x/xref
 * SPDX-License-Identifier: MIT OR Apache-2.0
 */
use super::{
    catalog::Catalog,
    facts::{CallFact, Facts},
    infer::{self, Emission},
    model::{CallWitness, EmissionWitness},
    values::Value,
};
use crate::scan;
use std::collections::BTreeSet;

const MAX_KEYS: usize = 32;
const REACH_BUDGET: usize = 250_000;

struct StateAnchor {
    value: Value,
    spill: Option<Value>,
}
struct Key {
    call: CallFact,
    name: String,
    address: u64,
    length: usize,
    position: usize,
    states: Vec<StateAnchor>,
    completed: bool,
}

fn keys(catalog: &mut Catalog<'_>, facts: &Facts) -> Vec<Key> {
    let mut result = Vec::new();
    for call in &facts.calls {
        let Some(target) = call.destination else { continue };
        for position in 1..4 {
            let Some((name, address, length)) =
                infer::name_at(catalog.image, call.arguments[position], call.arguments[position + 1])
            else {
                continue;
            };
            if !name.chars().any(|ch| ch.is_alphanumeric() || ch == '_') {
                continue;
            }
            if !catalog.consumed(target, position, 4, &mut BTreeSet::new())
                || !catalog.consumed(target, position + 1, 4, &mut BTreeSet::new())
            {
                continue;
            }
            let states = (0..position)
                .filter_map(|index| {
                    let value = call.arguments[index]?;
                    catalog
                        .memory_reader(target, index, 4, &mut BTreeSet::new())
                        .then_some(StateAnchor { value, spill: call.argument_spills[index] })
                })
                .collect::<Vec<_>>();
            if states.is_empty() {
                continue;
            }
            let completed = catalog.consumed(target, position + 2, 4, &mut BTreeSet::new());
            result.push(Key { call: call.clone(), name, address, length, position, states, completed });
            if result.len() == MAX_KEYS {
                catalog.coverage.summary_depth_limit_reached = true;
                return result;
            }
        }
    }
    result
}

fn relation(anchor: &StateAnchor, value: Value) -> Option<&'static str> {
    if anchor.value == value || anchor.spill == Some(value) {
        return Some(match value {
            Value::StackCell(_) => "unverified_stack_cell_continuation",
            Value::Loaded { .. } => "unverified_input_cell_continuation",
            _ => "same_symbolic_state",
        });
    }
    match (anchor.value, value) {
        (Value::Stack(address), Value::StackCell(cell)) if address == cell => {
            Some("unverified_stack_cell_continuation")
        }
        (Value::Input { argument, offset }, Value::Loaded { argument: source, offset: position, width: 8 })
            if argument == source && offset == position =>
        {
            Some("unverified_input_cell_continuation")
        }
        _ => None,
    }
}

fn dominates(facts: &Facts, point: usize, target: usize, budget: &mut usize) -> bool {
    point != target
        && facts.flow.reaches(0, target, Some(point), budget) == Some(false)
        && facts.flow.reaches(point, target, None, budget) == Some(true)
}

fn last_key(facts: &Facts, all: &[Key], key: &Key, target: &CallFact, state: Value, budget: &mut usize) -> bool {
    if !dominates(facts, key.call.index, target.index, budget) {
        return false;
    }
    for other in all {
        if other.call.index == key.call.index || !other.states.iter().any(|anchor| relation(anchor, state).is_some()) {
            continue;
        }
        if facts.flow.reaches(key.call.index, other.call.index, Some(target.index), budget) == Some(true)
            && facts.flow.reaches(other.call.index, target.index, None, budget) == Some(true)
        {
            return false;
        }
        if *budget == 0 {
            return false;
        }
    }
    true
}

fn colon(facts: &Facts, key: &Key, target: &CallFact, budget: &mut usize) -> Option<CallWitness> {
    for (index, instruction) in &facts.colons {
        if dominates(facts, key.call.index, *index, budget) && dominates(facts, *index, target.index, budget) {
            return Some(CallWitness {
                function: format!("{:#x}", facts.range.start),
                instruction: format!("{:#x}", instruction.ip()),
                assembly: scan::format(instruction),
                target: None,
                role: "json_colon_store_between_key_and_value",
            });
        }
        if *budget == 0 {
            break;
        }
    }
    None
}

fn data_source(call: &CallFact, index: usize, anchor: &StateAnchor) -> Option<(usize, i64, Option<usize>)> {
    let (argument, offset, width, _) = infer::source(call.arguments[index]?, call.argument_spills[index])?;
    // Buffer sizes/capacities are not the serialized object. Keep the data root
    // separate from the key writer's own incoming root wherever it is known.
    if anchor.value.argument() == Some(argument) || anchor.spill.and_then(Value::argument) == Some(argument) {
        return None;
    }
    infer::valid_offset(offset).then_some((argument, offset, width))
}

pub(super) fn infer(catalog: &mut Catalog<'_>, facts: &Facts) -> Vec<Emission> {
    if facts.colons.is_empty() {
        return vec![];
    }
    let keys = keys(catalog, facts);
    let mut result = Vec::new();
    let mut budget = REACH_BUDGET;
    for target in &facts.calls {
        if budget == 0 || catalog.expired() {
            catalog.coverage.summary_depth_limit_reached = true;
            return result;
        }
        let Some(destination) = target.destination else { continue };
        for key in keys.iter().filter(|key| !key.completed && key.call.index != target.index) {
            if budget == 0 {
                catalog.coverage.summary_depth_limit_reached = true;
                return result;
            }
            for anchor in &key.states {
                for (state_index, state) in target.arguments.iter().enumerate() {
                    let Some(state) = state else { continue };
                    let Some(identity) = relation(anchor, *state) else { continue };
                    if !catalog.memory_reader(destination, state_index, 4, &mut BTreeSet::new()) {
                        continue;
                    }
                    if !last_key(facts, &keys, key, target, *state, &mut budget) {
                        continue;
                    }
                    let Some(separator) = colon(facts, key, target, &mut budget) else { continue };
                    for index in 0..6 {
                        if index == state_index {
                            continue;
                        }
                        let Some((argument, offset, mut width)) = data_source(target, index, anchor) else { continue };
                        if !catalog.consumed(destination, index, 4, &mut BTreeSet::new()) {
                            continue;
                        }
                        if width.is_none() && matches!(target.arguments[index], Some(Value::Input { .. })) {
                            width = catalog.read_widths(destination, index, 4, &mut BTreeSet::new()).into_iter().max();
                        }
                        if result.len() >= 128 {
                            catalog.coverage.candidates_truncated = true;
                            return result;
                        }
                        let mut key_step = key.call.witness.clone();
                        key_step.role = "json_key_string_call";
                        let mut value_step = target.witness.clone();
                        value_step.role = "subsequent_value_call";
                        result.push(Emission {
                            name: key.name.clone(),
                            argument,
                            offset,
                            read_width: width,
                            stack_assumption: facts.stack_assumption,
                            sites: vec![key.call.instruction.ip(), target.instruction.ip()],
                            witness: EmissionWitness {
                                key_address: format!("{:#x}", key.address),
                                key_length: key.length,
                                key_argument: Facts::argument_register(key.position),
                                value_argument: Facts::argument_register(index),
                                call_chain: vec![key_step, separator.clone(), value_step],
                                source: "json_key_colon_value_state_candidate",
                                state_identity: identity,
                            },
                        });
                    }
                    if budget == 0 {
                        catalog.coverage.summary_depth_limit_reached = true;
                        return result;
                    }
                }
            }
        }
    }
    result
}
