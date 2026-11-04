/*
 * XRef — Group field-source candidates without inventing a Rust type
 * Copyright (c) 2026 Alexander Panasenko
 * Contact: alex@prod.codes
 * Author: https://prod.codes/about/
 * Project: https://github.com/alex09x/xref
 * SPDX-License-Identifier: MIT OR Apache-2.0
 */
use super::{
    catalog::Catalog,
    facts::Facts,
    infer::Emission,
    model::{LayoutCandidate, NamedField, OffsetCandidate},
};
use std::{
    collections::{BTreeMap, BTreeSet},
    ops::Range,
};

const MAX_LAYOUTS: usize = 32;
const MAX_WITNESSES: usize = 8;

fn group(function: &Range<u64>, argument: usize, entries: &[&Emission], query: &str) -> LayoutCandidate {
    let mut fields: BTreeMap<(String, u64), (NamedField, Vec<u64>)> = BTreeMap::new();
    for entry in entries {
        let Ok(offset) = u64::try_from(entry.offset) else { continue };
        let item = fields.entry((entry.name.clone(), offset)).or_insert_with(|| {
            (
                NamedField {
                    name: entry.name.clone(),
                    offset,
                    offset_hex: format!("{offset:#x}"),
                    observed_read_widths: vec![],
                    emissions: vec![],
                },
                entry.sites.clone(),
            )
        });
        if let Some(width) = entry.read_width
            && !item.0.observed_read_widths.contains(&width)
        {
            item.0.observed_read_widths.push(width);
        }
        if item.0.emissions.len() < MAX_WITNESSES {
            item.0.emissions.push(entry.witness.clone());
        }
        if entry.sites < item.1 {
            item.1.clone_from(&entry.sites);
        }
    }
    let mut fields: Vec<_> = fields.into_values().collect();
    fields
        .sort_by(|a, b| a.1.cmp(&b.1).then_with(|| a.0.offset.cmp(&b.0.offset)).then_with(|| a.0.name.cmp(&b.0.name)));
    let mut fields: Vec<_> = fields.into_iter().map(|(field, _)| field).collect();
    for field in &mut fields {
        field.observed_read_widths.sort_unstable();
    }
    let offsets: BTreeSet<_> = fields.iter().filter(|field| field.name == query).map(|field| field.offset).collect();
    let extent = fields
        .iter()
        .map(|field| {
            let width = field
                .observed_read_widths
                .iter()
                .max()
                .copied()
                .and_then(|width| u64::try_from(width).ok())
                .unwrap_or(0);
            field.offset.saturating_add(width)
        })
        .max()
        .unwrap_or(0);
    let mut caveats = vec![
        "input_argument_relationship_not_concrete_rust_type",
        "minimum_extent_is_addressed_span_not_allocation_or_exact_type_size",
        "known_cfg_and_sysv_integer_argument_model",
        "nested_inline_sources_may_be_flattened",
    ];
    if entries.iter().any(|entry| entry.stack_assumption) {
        caveats.push("stack_spills_assume_unmodelled_callee_writes_do_not_alias_private_slots");
    }
    let association_uncertain = entries.iter().any(|entry| entry.witness.state_identity.starts_with("unverified"));
    if association_uncertain {
        caveats.push("state_cell_continuity_does_not_prove_writer_identity_or_exclude_retargeting");
    }
    LayoutCandidate {
        function: format!("{:#x}..{:#x}", function.start, function.end),
        base_argument: Facts::argument_register(argument),
        association_uncertain,
        fields,
        query_ambiguous: offsets.len() > 1,
        offsets: offsets
            .into_iter()
            .map(|offset| OffsetCandidate { offset, offset_hex: format!("{offset:#x}") })
            .collect(),
        layout_kind: "input_relative_key_value_candidate",
        field_order_evidence: "lexical_call_site_order_not_source_declaration_or_runtime_order",
        size_bytes: None,
        minimum_observed_extent: extent,
        exact_size_unknown: true,
        caveats,
    }
}

pub(super) fn collect(
    catalog: &mut Catalog<'_>,
    summaries: &BTreeMap<u64, Vec<Emission>>,
    query: &str,
    within: Option<&Range<u64>>,
) -> Vec<LayoutCandidate> {
    let mut output = Vec::new();
    for (function, entries) in summaries {
        if within.is_some_and(|range| range.start != *function) {
            continue;
        }
        let Some(range) = catalog.starts.get(function) else { continue };
        let mut groups: BTreeMap<usize, Vec<&Emission>> = BTreeMap::new();
        for entry in entries {
            groups.entry(entry.argument).or_default().push(entry);
        }
        for (argument, entries) in groups {
            if entries.iter().any(|entry| entry.name == query) {
                output.push(group(range, argument, &entries, query));
            }
        }
    }
    output.sort_by(|a, b| {
        b.fields
            .len()
            .cmp(&a.fields.len())
            .then_with(|| a.function.cmp(&b.function))
            .then_with(|| a.base_argument.cmp(&b.base_argument))
    });
    if output.len() > MAX_LAYOUTS {
        catalog.coverage.candidates_truncated = true;
        output.truncate(MAX_LAYOUTS);
    }
    output
}
