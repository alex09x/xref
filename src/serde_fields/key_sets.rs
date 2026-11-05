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

/// Keys a layout emits at its own level: every field except those reached only by descending into
/// the value of a requested key (e.g. `nanos` inside a requested `elapsed: Duration`).
///
/// A field is nested under a requested key when each of its emissions starts with a helper rebase
/// through the very call instruction that serializes that requested key's value.
pub(super) fn top_level_keys(layout: &LayoutCandidate, requested: &[String]) -> BTreeSet<String> {
    let value_calls = layout
        .fields
        .iter()
        .filter(|field| requested.contains(&field.name))
        .flat_map(|field| &field.emissions)
        .filter_map(|emission| emission.call_chain.iter().find(|step| step.role == "key_value_call"))
        .map(|step| step.instruction.as_str())
        .collect::<BTreeSet<_>>();
    layout
        .fields
        .iter()
        .filter(|field| requested.contains(&field.name) || !nested_under(field, &value_calls))
        .map(|field| field.name.clone())
        .collect()
}

fn nested_under(field: &NamedField, value_calls: &BTreeSet<&str>) -> bool {
    !field.emissions.is_empty()
        && field.emissions.iter().all(|emission| {
            emission.call_chain.first().is_some_and(|step| {
                step.role == "static_helper_argument_rebase" && value_calls.contains(step.instruction.as_str())
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

    /// ripgrep's `Stats` serializer: `elapsed` is serialized by a helper that emits the nested
    /// `Duration` key `nanos`; the requested top-level set must still match exactly.
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
