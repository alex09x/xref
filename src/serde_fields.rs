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
mod catalog_scan;
mod dense_graph;
mod facts;
mod infer;
mod key_diagnostics;
mod key_sets;
mod layouts;
mod model;
mod render;
mod scan_index;
mod seeds;
mod sequence;
mod session;
mod step;
#[cfg(test)]
mod tests;
#[cfg(test)]
mod tests_rank;
mod values;
mod writer_index;
mod writer_rank;
mod writer_select;

pub const DEFAULT_KEY_FUNCTION_BUDGET: usize = catalog::MAX_CONTEXT;
pub const MAX_KEY_FUNCTION_BUDGET: usize = catalog::MAX_FIELD_FUNCTION_BUDGET;
pub const DEFAULT_KEY_INSTRUCTION_BUDGET: usize = facts::MAX_INSTRUCTIONS;
pub const MAX_KEY_INSTRUCTION_BUDGET: usize = catalog::MAX_FIELD_INSTRUCTION_BUDGET;

use crate::serde_fields::key_diagnostics::key_search_diagnostics;
use crate::{commands::Res, graph::resolve, image::Image};
use std::io::Write;

/// Run `f` (a field search over `image`) with `digest` as the image's SHA-256. The caller owns the
/// image immutably and computed `digest` from exactly these bytes, so per-image session state can be
/// reused without rehashing.
pub fn with_image_digest<T>(image: &[u8], digest: [u8; 32], f: impl FnOnce() -> T) -> T {
    scan_index::with_known_digest(image, digest, f)
}

/// Build the key-independent session state for `image` (whole-image scan, call graph, writer index)
/// so the first `field` query of a long-lived process does not pay for it. Results are unchanged;
/// state that is not complete within the analysis budget is simply not remembered.
#[cfg_attr(test, allow(dead_code))]
pub fn warm_session(image: &Image) {
    let defaults = FieldOptions::default();
    let catalog = catalog::Catalog::open_many_with_limits(
        image,
        &[],
        None,
        catalog::SearchLimits {
            max_functions: defaults.max_functions,
            max_instructions: defaults.max_instructions,
            min_keys: 1,
            exhaustive: false,
        },
    );
    accessors::warm_writers(&catalog, defaults.max_instructions);
}

/// Which pointer an accessor's offsets are relative to (`--writer-root`).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, clap::ValueEnum)]
pub enum WriterRoot {
    /// Any root.
    #[default]
    Any,
    /// An ABI argument register on entry (`rdi`, `rsi`, …).
    Argument,
    /// A pointer returned by a call (`call lookup; mov r, rax; mov [r+off], …`).
    Returned,
    /// A pointer loaded from memory (`mov r, [p+off]; mov [r+off], …`).
    Loaded,
}

impl WriterRoot {
    #[must_use]
    pub const fn admits(self, root: usize) -> bool {
        match self {
            Self::Any => true,
            Self::Argument => root < values::CALL_ROOT_START,
            Self::Returned => root >= values::CALL_ROOT_START && root < values::LOAD_ROOT_START,
            Self::Loaded => root >= values::LOAD_ROOT_START,
        }
    }
}

#[derive(Clone)]
pub struct FieldOptions {
    pub min_offsets: usize,
    pub write_only: bool,
    pub writes_all_of: Vec<String>,
    pub writer_root: WriterRoot,
    pub limit: usize,
    pub layout_only: bool,
    pub min_keys: Option<usize>,
    pub exhaustive_key_seeds: bool,
    pub max_functions: usize,
    pub max_instructions: usize,
}
impl Default for FieldOptions {
    fn default() -> Self {
        Self {
            min_offsets: 2,
            write_only: false,
            writes_all_of: Vec::new(),
            writer_root: WriterRoot::Any,
            limit: 64,
            layout_only: false,
            min_keys: None,
            exhaustive_key_seeds: false,
            max_functions: DEFAULT_KEY_FUNCTION_BUDGET,
            max_instructions: DEFAULT_KEY_INSTRUCTION_BUDGET,
        }
    }
}

fn validate_search_budgets(options: &FieldOptions) -> Res {
    if options.writes_all_of.iter().any(String::is_empty) {
        return Err("--writes-all-of requires non-empty comma-separated field names".into());
    }
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
    options: &FieldOptions,
    out: &mut dyn Write,
) -> Res {
    if name.is_empty() || name.len() > 256 || name.contains(char::is_control) {
        return Err("field name must be 1..=256 UTF-8 bytes without control characters".into());
    }
    if !(1..=32).contains(&options.min_offsets) || !(1..=128).contains(&options.limit) {
        return Err("field accessor budgets: --min-offsets 1..=32, --limit 1..=128".into());
    }
    validate_search_budgets(options)?;
    if options.min_keys.is_some() || options.exhaustive_key_seeds {
        return Err("--min-keys and --exhaustive-key-seeds require --keys".into());
    }
    let within = within.map(|name| resolve(image, name)).transpose()?;
    let mut catalog = catalog::Catalog::open_many_with_limits(
        image,
        &[name.to_owned()],
        within.as_ref(),
        catalog::SearchLimits {
            max_functions: options.max_functions,
            max_instructions: options.max_instructions,
            min_keys: 1,
            exhaustive: true,
        },
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
        if options.layout_only { vec![] } else { accessors::collect(&mut catalog, &candidates, options) };
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
        image_sha256: catalog.identity.image_hex.clone(),
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
    options: &FieldOptions,
    out: &mut dyn Write,
) -> Res {
    let (key_set, min_keys) = validate_key_query(keys, options)?;
    let within = within.map(|name| resolve(image, name)).transpose()?;
    let mut catalog = catalog::Catalog::open_many_with_limits(
        image,
        keys,
        within.as_ref(),
        catalog::SearchLimits {
            max_functions: options.max_functions,
            max_instructions: options.max_instructions,
            min_keys,
            exhaustive: options.exhaustive_key_seeds,
        },
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
        if options.layout_only { vec![] } else { accessors::collect(&mut catalog, &candidates, options) };
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
    let key_diagnostics = key_search_diagnostics(&catalog, &summaries, keys, min_keys, options);
    let incomplete = catalog.expired()
        || catalog.coverage.summary_depth_limit_reached
        || catalog.coverage.skipped_functions > 0
        || catalog.coverage.unsupported_flow_functions > 0
        || catalog.coverage.function_byte_budget_exhausted_functions > 0
        || catalog.coverage.instruction_budget_exhausted_functions > 0
        || catalog.coverage.context_budget_exhaustions > 0
        || catalog.coverage.key_seed_filter_excluded > 0;
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
        image_sha256: catalog.identity.image_hex.clone(),
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

fn validate_key_query(
    keys: &[String],
    options: &FieldOptions,
) -> Result<(std::collections::BTreeSet<String>, usize), Box<dyn std::error::Error>> {
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
    validate_search_budgets(options)?;
    let min_keys = options.min_keys.unwrap_or(keys.len());
    if !(1..=keys.len()).contains(&min_keys) {
        return Err(format!("--min-keys must be in 1..={}", keys.len()).into());
    }
    Ok((key_set, min_keys))
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
            if matched_keys.len() < min_keys
                || (min_keys == keys.len() && key_sets::top_level_keys(&layout, keys) != *key_set)
            {
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
