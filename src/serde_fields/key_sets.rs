/*
 * XRef — exact key-set matching for serialized field layouts
 * Copyright (c) 2026 Alexander Panasenko
 * Contact: alex@prod.codes
 * Author: https://prod.codes/about/
 * Project: https://github.com/alex09x/xref
 * SPDX-License-Identifier: MIT OR Apache-2.0
 */
use std::collections::BTreeSet;

use super::model::{LayoutCandidate, NamedField};

const REBASE: &str = "static_helper_argument_rebase";

/// Keys a layout emits at its own level: every field except those reached only by descending into
/// the value of a requested key (a nested struct serialized as that key's value).
///
/// A requested key's emission is a chain `P.., …, V@I`: leading helper rebases `P` (possibly through
/// a shared serializer helper) and, last, the call `V` at instruction `I` that serializes its value
/// (`key_value_call`, or the value call after a JSON key and colon). Another key is nested under it
/// when each of its emissions starts with the same rebases `P..` followed by a rebase through `I`.
pub(super) fn top_level_keys(layout: &LayoutCandidate, requested: &[String]) -> BTreeSet<String> {
    let value_chains = layout
        .fields
        .iter()
        .filter(|field| requested.contains(&field.name))
        .flat_map(|field| &field.emissions)
        .filter_map(|emission| {
            let value_call = emission.call_chain.last()?;
            let mut chain = emission
                .call_chain
                .iter()
                .take_while(|step| step.role == REBASE && !std::ptr::eq(*step, value_call))
                .map(|step| step.instruction.as_str())
                .collect::<Vec<_>>();
            chain.push(value_call.instruction.as_str());
            Some(chain)
        })
        .collect::<Vec<_>>();
    layout
        .fields
        .iter()
        .filter(|field| requested.contains(&field.name) || !nested_under(field, &value_chains))
        .map(|field| field.name.clone())
        .collect()
}

fn nested_under(field: &NamedField, value_chains: &[Vec<&str>]) -> bool {
    !field.emissions.is_empty()
        && field.emissions.iter().all(|emission| {
            value_chains.iter().any(|chain| {
                let Some((call, prefix)) = chain.split_last() else { return false };
                emission.call_chain.len() > chain.len()
                    && emission
                        .call_chain
                        .iter()
                        .zip(prefix)
                        .all(|(step, instruction)| step.instruction == *instruction)
                    && emission.call_chain[prefix.len()].instruction == *call
                    && emission.call_chain[prefix.len()].role == REBASE
            })
        })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::serde_fields::model::{CallWitness, EmissionWitness};

    fn step(instruction: &str, role: &'static str) -> CallWitness {
        CallWitness {
            function: "0x1000".into(),
            instruction: instruction.into(),
            assembly: format!("call {instruction}"),
            target: None,
            role,
        }
    }

    fn field(name: &str, offset: u64, chain: Vec<CallWitness>) -> NamedField {
        NamedField {
            name: name.into(),
            offset,
            offset_hex: format!("{offset:#x}"),
            observed_read_widths: vec![8],
            emissions: vec![EmissionWitness {
                key_address: "0x2000".into(),
                key_length: name.len(),
                key_argument: "rsi".into(),
                value_argument: "rcx".into(),
                call_chain: chain,
                source: "input_address_argument",
                state_identity: "same_call_arguments",
            }],
        }
    }

    fn layout(fields: Vec<NamedField>) -> LayoutCandidate {
        LayoutCandidate {
            function: "0x1000..0x1100".into(),
            base_argument: "rdi".into(),
            fields,
            offsets: vec![],
            matched_keys: None,
            missing_keys: None,
            query_ambiguous: false,
            association_uncertain: false,
            layout_kind: "input_relative_key_value_candidate",
            field_order_evidence: "lexical_call_site_order_not_source_declaration_or_runtime_order",
            size_bytes: None,
            minimum_observed_extent: 0x40,
            exact_size_unknown: true,
            caveats: vec![],
        }
    }

    fn keys(names: &[&str]) -> Vec<String> {
        names.iter().map(|name| (*name).to_owned()).collect()
    }

    /// A struct serializer whose `elapsed` value is a nested struct with its own `nanos` key: the
    /// requested top-level set must still match exactly.
    #[test]
    fn keys_inside_a_requested_value_do_not_break_an_exact_set() {
        let candidate = layout(vec![
            field("elapsed", 0x30, vec![step("0x1044", "key_value_call")]),
            field(
                "nanos",
                0x38,
                vec![step("0x1044", "static_helper_argument_rebase"), step("0x5027", "key_value_call")],
            ),
            field("searches", 0x0, vec![step("0x1064", "key_value_call")]),
        ]);
        let requested = keys(&["elapsed", "searches"]);
        assert_eq!(top_level_keys(&candidate, &requested), requested.into_iter().collect());
    }

    /// The whole serializer sits in a shared helper reached through `0x1010`: every chain starts with
    /// that rebase, and the nested key continues through the requested key's value call.
    #[test]
    fn nested_keys_behind_a_shared_serializer_helper_are_recognized() {
        let rebase = |at| step(at, "static_helper_argument_rebase");
        let candidate = layout(vec![
            field("elapsed", 0x30, vec![rebase("0x1010"), step("0x2044", "key_value_call")]),
            field("nanos", 0x38, vec![rebase("0x1010"), rebase("0x2044"), step("0x5027", "key_value_call")]),
            field("searches", 0x0, vec![rebase("0x1010"), step("0x2064", "key_value_call")]),
            // Same value call, different outer prefix: not under this layout's `elapsed`.
            field("stray", 0x40, vec![rebase("0x1020"), rebase("0x2044"), step("0x5030", "key_value_call")]),
        ]);
        let requested = keys(&["elapsed", "searches"]);
        assert_eq!(
            top_level_keys(&candidate, &requested),
            keys(&["elapsed", "searches", "stray"]).into_iter().collect()
        );
    }

    /// A requested key written as JSON key + colon whose value is then serialized by a call: keys
    /// reached through that value call are nested.
    #[test]
    fn nested_keys_after_a_json_key_and_value_call_are_recognized() {
        let candidate = layout(vec![
            field("tally", 0x10, vec![step("0x938", "key_value_call")]),
            field(
                "period",
                0x0,
                vec![
                    step("0x957", "json_key_str_call"),
                    step("0x978", "json_colon_store"),
                    step("0x98a", "subsequent_value_call"),
                ],
            ),
            field("secs", 0x0, vec![step("0x98a", REBASE), step("0xd46", "key_value_call")]),
            field("nanos", 0x8, vec![step("0x98a", REBASE), step("0xd66", "key_value_call")]),
        ]);
        let requested = keys(&["tally", "period"]);
        assert_eq!(top_level_keys(&candidate, &requested), requested.into_iter().collect());
    }

    /// A sibling key emitted by the layout's own calls is not nested and still breaks exactness.
    #[test]
    fn unrequested_sibling_keys_stay_top_level() {
        let candidate = layout(vec![
            field("elapsed", 0x30, vec![step("0x1044", "key_value_call")]),
            field("path", 0x40, vec![step("0x1080", "key_value_call")]),
            field(
                "extra",
                0x48,
                vec![step("0x1090", "static_helper_argument_rebase"), step("0x5000", "key_value_call")],
            ),
        ]);
        let top = top_level_keys(&candidate, &keys(&["elapsed"]));
        assert_eq!(top, keys(&["elapsed", "extra", "path"]).into_iter().collect());
    }
}
