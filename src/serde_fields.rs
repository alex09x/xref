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

use crate::{commands::Res, graph::resolve, image::Image};
use sha2::{Digest, Sha256};
use std::io::Write;

#[derive(Clone, Copy)]
pub struct FieldOptions {
    pub min_offsets: usize,
    pub write_only: bool,
    pub limit: usize,
    pub layout_only: bool,
}
impl Default for FieldOptions {
    fn default() -> Self {
        Self { min_offsets: 2, write_only: false, limit: 64, layout_only: false }
    }
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
    let within = within.map(|name| resolve(image, name)).transpose()?;
    let mut catalog = catalog::Catalog::open(image, name, within.as_ref());
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
    let incomplete = catalog.coverage.summary_depth_limit_reached
        || catalog.coverage.skipped_functions > 0
        || catalog.coverage.unsupported_flow_functions > 0;
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
    let within = within.map(|name| resolve(image, name)).transpose()?;
    let mut catalog = catalog::Catalog::open_many(image, keys, within.as_ref());
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
    let mut by_root = std::collections::BTreeMap::new();
    for key in keys {
        for mut layout in layouts::collect(&mut catalog, &summaries, key, within.as_ref()) {
            let candidate_keys =
                layout.fields.iter().map(|field| field.name.clone()).collect::<std::collections::BTreeSet<_>>();
            if candidate_keys != key_set {
                continue;
            }
            let offsets = layout.fields.iter().map(|field| field.offset).collect::<std::collections::BTreeSet<_>>();
            layout.offsets = offsets
                .iter()
                .map(|offset| model::OffsetCandidate { offset: *offset, offset_hex: format!("{offset:#x}") })
                .collect();
            let ambiguous_key =
                keys.iter().any(|name| layout.fields.iter().filter(|field| &field.name == name).count() > 1);
            layout.query_ambiguous = ambiguous_key || offsets.len() < key_set.len();
            by_root.entry((layout.function.clone(), layout.base_argument.clone())).or_insert(layout);
        }
    }
    let candidates: Vec<_> = by_root.into_values().collect();
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
    let incomplete = catalog.coverage.summary_depth_limit_reached
        || catalog.coverage.skipped_functions > 0
        || catalog.coverage.unsupported_flow_functions > 0;
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
