/*
 * XRef — Serialized field-name to input-relative access candidates
 * Copyright (c) 2026 Alexander Panasenko
 * Contact: alex@prod.codes
 * Author: https://prod.codes/about/
 * Project: https://github.com/alex09x/xref
 * SPDX-License-Identifier: MIT OR Apache-2.0
 */
mod accessors;
mod catalog;
mod facts;
mod infer;
mod layouts;
mod model;
mod render;
mod sequence;
mod step;
#[cfg(test)]
mod tests;
mod values;

pub const DEFAULT_KEY_FUNCTION_BUDGET: usize = catalog::MAX_CONTEXT;
pub const MAX_KEY_FUNCTION_BUDGET: usize = catalog::MAX_FIELD_FUNCTION_BUDGET;
pub const DEFAULT_KEY_INSTRUCTION_BUDGET: usize = facts::MAX_INSTRUCTIONS;
pub const MAX_KEY_INSTRUCTION_BUDGET: usize = catalog::MAX_FIELD_INSTRUCTION_BUDGET;

use crate::{commands::Res, graph::resolve, image::Image};
use sha2::{Digest, Sha256};
use std::io::Write;

#[derive(Clone, Copy)]
pub struct FieldOptions {
    pub min_offsets: usize,
    pub write_only: bool,
    pub limit: usize,
    pub layout_only: bool,
    pub min_keys: Option<usize>,
    pub max_functions: usize,
    pub max_instructions: usize,
}
impl Default for FieldOptions {
    fn default() -> Self {
        Self {
            min_offsets: 2,
            write_only: false,
            limit: 64,
            layout_only: false,
            min_keys: None,
            max_functions: DEFAULT_KEY_FUNCTION_BUDGET,
            max_instructions: DEFAULT_KEY_INSTRUCTION_BUDGET,
        }
    }
}

fn validate_search_budgets(options: &FieldOptions) -> Res {
    if !(1..=MAX_KEY_FUNCTION_BUDGET).contains(&options.max_functions) {
        return Err(format!("--max-functions must be in 1..={MAX_KEY_FUNCTION_BUDGET}").into());
    }
    if !(1..=MAX_KEY_INSTRUCTION_BUDGET).contains(&options.max_instructions) {
        return Err(format!("--max-instructions must be in 1..={MAX_KEY_INSTRUCTION_BUDGET}").into());
    }
    Ok(())
}

fn static_target(image: &Image, instruction: &iced_x86::Instruction) -> Option<u64> {
    if instruction.is_ip_rel_memory_operand() && instruction.ip_rel_memory_address().checked_add(8).is_none() {
        return None;
    }
    crate::graph::call_target(image, instruction)
}

pub fn field(
    image: &Image,
    name: &str,
    within: Option<&str>,
    json: bool,
    options: FieldOptions,
    out: &mut dyn Write,
) -> Res {
    if name.is_empty() || name.len() > 256 || name.contains(char::is_control) {
        return Err("field name must be 1..=256 UTF-8 bytes without control characters".into());
    }
    if !(1..=32).contains(&options.min_offsets) || !(1..=128).contains(&options.limit) {
        return Err("field accessor budgets: --min-offsets 1..=32, --limit 1..=128".into());
    }
    validate_search_budgets(&options)?;
    if options.min_keys.is_some() {
        return Err("--min-keys requires --keys".into());
    }
    let within = within.map(|name| resolve(image, name)).transpose()?;
    let mut catalog = catalog::Catalog::open_many_with_limits(
        image,
        &[name.to_owned()],
        within.as_ref(),
        catalog::SearchLimits { max_functions: options.max_functions, max_instructions: options.max_instructions },
    );
    let mut summaries = infer::summaries(&mut catalog);
    for _ in 0..4 {
        if !infer::expand_related(&mut catalog, &summaries, name) {
            break;
        }
        summaries = infer::summaries(&mut catalog);
    }
    let candidates = layouts::collect(&mut catalog, &summaries, name, within.as_ref());
    let accessor_candidates =
        if options.layout_only { vec![] } else { accessors::collect(&mut catalog, &candidates, &options) };
    if catalog.expired() {
        catalog.coverage.warnings.push("cooperative_30_second_analysis_budget_exhausted");
    }
    if catalog.coverage.skipped_functions > 0 {
        catalog.coverage.warnings.push("code_or_function_discovery_budget_incomplete");
    }
    if catalog.coverage.unsupported_flow_functions > 0 {
        catalog.coverage.warnings.push("unsupported_cfg_or_instruction_budget_scopes_omitted");
    }
    if catalog.coverage.function_byte_budget_exhausted_functions > 0 {
        catalog.coverage.warnings.push("per_function_byte_budget_exhausted");
    }
    if catalog.coverage.instruction_budget_exhausted_functions > 0 {
        catalog.coverage.warnings.push("per_function_instruction_budget_exhausted");
    }
    let incomplete = catalog.expired()
        || catalog.coverage.summary_depth_limit_reached
        || catalog.coverage.skipped_functions > 0
        || catalog.coverage.unsupported_flow_functions > 0
        || catalog.coverage.function_byte_budget_exhausted_functions > 0
        || catalog.coverage.instruction_budget_exhausted_functions > 0
        || catalog.coverage.context_budget_exhaustions > 0;
    let status = if !candidates.is_empty() {
        "candidates"
    } else if incomplete {
        "not_found_under_limits"
    } else {
        "no_key_value_candidate"
    };
    let report = model::FieldReport {
        schema_version: 1,
        queried_name: name.to_owned(),
        queried_keys: None,
        key_diagnostics: None,
        image_sha256: crate::trace_analysis::index::hex_bytes(&Sha256::digest(&image.data)),
        status,
        ambiguous: candidates.len() > 1
            || candidates.iter().any(|layout| layout.query_ambiguous || layout.association_uncertain),
        candidates,
        accessor_candidates,
        coverage: catalog.coverage,
        limitations: vec![
            "key/value argument evidence is not proof of a Serde implementation or a concrete Rust type",
            "offsets are relative to the displayed input argument in the displayed function",
            "field order is lexical instruction evidence, not recovered declaration or universal runtime order",
            "exact size, alignment, tail padding, skipped fields and allocator identity are unknown",
            "only supported x86-64 SysV integer arguments and known static helper entry targets are summarized",
            "opaque calls, erased or zero-sized values, scalar promotion and unsupported flows may have no candidate",
            "accessors match a same-input-root offset constellation, not a proven common type; missing results do not prove absence",
        ],
    };
    if json {
        serde_json::to_writer_pretty(&mut *out, &report)?;
        writeln!(out)?;
        Ok(())
    } else {
        render::write(&report, out)
    }
}

pub fn field_by_keys(
    image: &Image,
    keys: &[String],
    within: Option<&str>,
    json: bool,
    options: FieldOptions,
    out: &mut dyn Write,
) -> Res {
    if !(2..=16).contains(&keys.len())
        || keys.iter().any(|key| key.is_empty() || key.len() > 256 || key.contains(char::is_control))
    {
        return Err("--keys requires 2..=16 non-empty UTF-8 keys of at most 256 bytes".into());
    }
    let key_set = keys.iter().cloned().collect::<std::collections::BTreeSet<_>>();
    if key_set.len() != keys.len() {
        return Err("--keys must not contain duplicate keys".into());
    }
    if !(1..=32).contains(&options.min_offsets) || !(1..=128).contains(&options.limit) {
        return Err("field accessor budgets: --min-offsets 1..=32, --limit 1..=128".to_owned().into());
    }
    validate_search_budgets(&options)?;
    let min_keys = options.min_keys.unwrap_or(keys.len());
    if !(1..=keys.len()).contains(&min_keys) {
        return Err(format!("--min-keys must be in 1..={}", keys.len()).into());
    }
    let within = within.map(|name| resolve(image, name)).transpose()?;
    let mut catalog = catalog::Catalog::open_many_with_limits(
        image,
        keys,
        within.as_ref(),
        catalog::SearchLimits { max_functions: options.max_functions, max_instructions: options.max_instructions },
    );
    let mut summaries = infer::summaries(&mut catalog);
    for _ in 0..4 {
        let mut changed = false;
        for key in keys {
            changed |= infer::expand_related(&mut catalog, &summaries, key);
        }
        if !changed {
            break;
        }
        summaries = infer::summaries(&mut catalog);
    }
    let candidates = collect_key_layout_candidates(&mut catalog, &summaries, keys, &key_set, min_keys, within.as_ref());
    let accessor_candidates =
        if options.layout_only { vec![] } else { accessors::collect(&mut catalog, &candidates, &options) };
    if catalog.expired() {
        catalog.coverage.warnings.push("cooperative_30_second_analysis_budget_exhausted");
    }
    if catalog.coverage.skipped_functions > 0 {
        catalog.coverage.warnings.push("code_or_function_discovery_budget_incomplete");
    }
    if catalog.coverage.unsupported_flow_functions > 0 {
        catalog.coverage.warnings.push("unsupported_cfg_or_instruction_budget_scopes_omitted");
    }
    if catalog.coverage.function_byte_budget_exhausted_functions > 0 {
        catalog.coverage.warnings.push("per_function_byte_budget_exhausted");
    }
    if catalog.coverage.instruction_budget_exhausted_functions > 0 {
        catalog.coverage.warnings.push("per_function_instruction_budget_exhausted");
    }
    let key_diagnostics = key_search_diagnostics(&catalog, &summaries, keys, min_keys, &options);
    let incomplete = catalog.expired()
        || catalog.coverage.summary_depth_limit_reached
        || catalog.coverage.skipped_functions > 0
        || catalog.coverage.unsupported_flow_functions > 0
        || catalog.coverage.function_byte_budget_exhausted_functions > 0
        || catalog.coverage.instruction_budget_exhausted_functions > 0
        || catalog.coverage.context_budget_exhaustions > 0;
    let status = if !candidates.is_empty() {
        "candidates"
    } else if incomplete {
        "not_found_under_limits"
    } else {
        "no_key_set_candidate"
    };
    let report = model::FieldReport {
        schema_version: 1,
        queried_name: keys.join(","),
        queried_keys: Some(keys.to_vec()),
        key_diagnostics: Some(key_diagnostics),
        image_sha256: crate::trace_analysis::index::hex_bytes(&Sha256::digest(&image.data)),
        status,
        ambiguous: candidates.len() > 1
            || candidates.iter().any(|layout| layout.query_ambiguous || layout.association_uncertain),
        candidates,
        accessor_candidates,
        coverage: catalog.coverage,
        limitations: vec![
            "key/value argument evidence is not proof of a Serde implementation or a concrete Rust type",
            "requested key set matches observed sibling emissions, not a source declaration",
            "offsets are relative to the displayed input argument in the displayed function",
            "field order is lexical instruction evidence, not recovered declaration or universal runtime order",
            "exact size, alignment, tail padding, skipped fields and allocator identity are unknown",
            "writer instructions are same-root offset witnesses, not proof of a common concrete type",
        ],
    };
    if json {
        serde_json::to_writer_pretty(&mut *out, &report)?;
        writeln!(out)?;
        Ok(())
    } else {
        render::write(&report, out)
    }
}

fn collect_key_layout_candidates(
    catalog: &mut catalog::Catalog<'_>,
    summaries: &std::collections::BTreeMap<u64, Vec<infer::Emission>>,
    keys: &[String],
    key_set: &std::collections::BTreeSet<String>,
    min_keys: usize,
    within: Option<&std::ops::Range<u64>>,
) -> Vec<model::LayoutCandidate> {
    let mut by_root = std::collections::BTreeMap::new();
    for key in keys {
        for mut layout in layouts::collect(catalog, summaries, key, within) {
            let candidate_keys =
                layout.fields.iter().map(|field| field.name.clone()).collect::<std::collections::BTreeSet<_>>();
            let matched_keys = keys.iter().filter(|key| candidate_keys.contains(*key)).cloned().collect::<Vec<_>>();
            if matched_keys.len() < min_keys || (min_keys == keys.len() && candidate_keys != *key_set) {
                continue;
            }
            let missing_keys = keys.iter().filter(|key| !candidate_keys.contains(*key)).cloned().collect::<Vec<_>>();
            let offsets = layout
                .fields
                .iter()
                .filter(|field| matched_keys.contains(&field.name))
                .map(|field| field.offset)
                .collect::<std::collections::BTreeSet<_>>();
            layout.offsets = offsets
                .iter()
                .map(|offset| model::OffsetCandidate { offset: *offset, offset_hex: format!("{offset:#x}") })
                .collect();
            layout.matched_keys = Some(matched_keys.clone());
            layout.missing_keys = Some(missing_keys);
            let ambiguous_key =
                keys.iter().any(|name| layout.fields.iter().filter(|field| &field.name == name).count() > 1);
            layout.query_ambiguous =
                ambiguous_key || offsets.len() < matched_keys.len() || matched_keys.len() < keys.len();
            by_root.entry((layout.function.clone(), layout.base_argument.clone())).or_insert(layout);
        }
    }
    by_root.into_values().collect()
}

fn key_search_diagnostics(
    catalog: &catalog::Catalog<'_>,
    summaries: &std::collections::BTreeMap<u64, Vec<infer::Emission>>,
    keys: &[String],
    min_keys: usize,
    options: &FieldOptions,
) -> model::KeySearchDiagnostics {
    let mut missing_emission_keys = Vec::new();
    let mut evidence = Vec::with_capacity(keys.len());
    for key in keys {
        let references = catalog.key_reference_functions.get(key).cloned().unwrap_or_default();
        let reference_truncated = catalog.key_reference_functions_truncated.contains(key);
        let mut emission_functions = Vec::new();
        let mut emission_functions_truncated = false;
        let mut emission_count = 0_usize;
        for (function, entries) in summaries {
            if entries.iter().any(|entry| &entry.name == key) {
                emission_count += 1;
                if emission_functions.len() < catalog::MAX_KEY_DIAGNOSTIC_FUNCTIONS {
                    emission_functions.push(format!("{function:#x}"));
                } else {
                    emission_functions_truncated = true;
                }
            }
        }
        if emission_count == 0 {
            missing_emission_keys.push(key.clone());
        }
        evidence.push(model::KeyEvidence {
            key: key.clone(),
            code_reference_functions: references.into_iter().map(|function| format!("{function:#x}")).collect(),
            code_reference_functions_truncated: reference_truncated,
            emission_functions,
            emission_functions_truncated,
        });
    }
    let mut budget_reasons = Vec::new();
    if catalog.expired() {
        budget_reasons.push("cooperative_time_budget_exhausted");
    }
    if catalog.coverage.skipped_functions > 0 {
        budget_reasons.push("function_or_code_byte_discovery_budget_exhausted");
    }
    if catalog.coverage.context_budget_exhaustions > 0 {
        budget_reasons.push("selected_function_context_budget_exhausted");
    }
    if catalog.coverage.function_byte_budget_exhausted_functions > 0 {
        budget_reasons.push("per_function_byte_budget_exhausted");
    }
    if catalog.coverage.instruction_budget_exhausted_functions > 0 {
        budget_reasons.push("per_function_instruction_budget_exhausted");
    }
    if catalog.coverage.summary_depth_limit_reached && catalog.coverage.context_budget_exhaustions == 0 {
        budget_reasons.push("analysis_depth_or_fact_limit_reached");
    }
    let discovery_budget_exhausted = !budget_reasons.is_empty();
    let analysis_incomplete = discovery_budget_exhausted || catalog.coverage.unsupported_flow_functions > 0;
    model::KeySearchDiagnostics {
        minimum_matched_keys: min_keys,
        keys: evidence,
        missing_emission_keys,
        scanned_functions: catalog.coverage.scanned_functions,
        selected_functions: catalog.coverage.selected_functions,
        analyzed_functions: catalog.coverage.analyzed_functions,
        skipped_functions: catalog.coverage.skipped_functions,
        unsupported_flow_functions: catalog.coverage.unsupported_flow_functions,
        function_byte_budget_exhausted_functions: catalog.coverage.function_byte_budget_exhausted_functions,
        instruction_budget_exhausted_functions: catalog.coverage.instruction_budget_exhausted_functions,
        context_functions_truncated: catalog.coverage.context_budget_exhaustions > 0,
        analysis_incomplete,
        discovery_budget_exhausted,
        max_functions: options.max_functions,
        max_instructions: options.max_instructions,
        budget_reasons,
    }
}
