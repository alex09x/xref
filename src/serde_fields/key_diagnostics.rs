/*
 * XRef — executable analysis
 * Copyright (c) 2026 Alexander Panasenko
 * Contact: alex@prod.codes
 * Author: https://prod.codes/about/
 * Project: https://github.com/alex09x/xref
 * SPDX-License-Identifier: MIT OR Apache-2.0
 */
use super::{FieldOptions, catalog, infer, model};

pub(super) fn key_search_diagnostics(
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
    let analysis_incomplete = discovery_budget_exhausted
        || catalog.coverage.unsupported_flow_functions > 0
        || catalog.coverage.key_seed_filter_excluded > 0;
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
