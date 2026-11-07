/*
 * XRef — Human-readable serialized-field evidence
 * Copyright (c) 2026 Alexander Panasenko
 * Contact: alex@prod.codes
 * Author: https://prod.codes/about/
 * Project: https://github.com/alex09x/xref
 * SPDX-License-Identifier: MIT OR Apache-2.0
 */
use super::model::{FieldReport, Lead};
use crate::commands::Res;
use std::io::Write;

/// `+10 over 0x121d..0x14a6 (callgraph +10)`: the gap to the next listed function and its terms.
pub(super) fn lead(lead: &Lead) -> String {
    match (&lead.over, lead.points) {
        (Some(over), Some(points)) => {
            let terms: Vec<String> =
                lead.terms.iter().map(|delta| format!("{} {:+}", delta.term, delta.points)).collect();
            if points == 0 {
                // Equal scores: the listed order between them carries no evidence.
                let why = if terms.is_empty() { "no term differs".to_owned() } else { terms.join(", ") };
                return format!(
                    "tie with {over} ({why}; tied rows are ordered by call-graph distance, matched offsets, then address)"
                );
            }
            format!("+{points} over {over} ({})", terms.join(", "))
        }
        _ => match lead.missing {
            Some("no_other_candidate") => "none (no other candidate function)".to_owned(),
            _ => "unknown (the next candidate function is beyond --limit)".to_owned(),
        },
    }
}

pub(super) fn write(report: &FieldReport, out: &mut dyn Write) -> Res {
    writeln!(
        out,
        "{:?}: {} layout candidates, {} accessor candidates; {}",
        report.queried_name,
        report.candidates.len(),
        report.accessor_candidates.len(),
        report.status
    )?;
    if let Some(diagnostics) = &report.key_diagnostics {
        write_key_diagnostics(diagnostics, out)?;
    }
    for (index, layout) in report.candidates.iter().enumerate() {
        writeln!(
            out,
            "layout {index}: {} base={} {} addressed-span>={:#x} exact-size=unknown",
            layout.function, layout.base_argument, layout.layout_kind, layout.minimum_observed_extent
        )?;
        if let Some(matched) = &layout.matched_keys {
            writeln!(
                out,
                "  matched keys: {matched:?}; missing keys: {:?}",
                layout.missing_keys.as_deref().unwrap_or(&[])
            )?;
        }
        writeln!(out, "  order: {}", layout.field_order_evidence)?;
        for field in &layout.fields {
            writeln!(
                out,
                "  {:?} -> {} instruction-read-widths={:?}",
                field.name, field.offset_hex, field.observed_read_widths
            )?;
            for witness in &field.emissions {
                writeln!(
                    out,
                    "    key {} len={} via {} value={} ({})",
                    witness.key_address,
                    witness.key_length,
                    witness.key_argument,
                    witness.value_argument,
                    witness.source
                )?;
                for step in &witness.call_chain {
                    writeln!(out, "      {} {} {} -> {}", step.role, step.function, step.instruction, step.assembly)?;
                }
            }
        }
        for caveat in &layout.caveats {
            writeln!(out, "  caveat: {caveat}")?;
        }
    }
    for accessor in &report.accessor_candidates {
        writeln!(
            out,
            "accessor: {} base={} layout={} matching-offsets={:?} {}",
            accessor.function, accessor.base_argument, accessor.layout, accessor.matched_offsets, accessor.confidence
        )?;
        let distance = accessor.callgraph_distance.map_or_else(|| "none".to_owned(), |hops| hops.to_string());
        writeln!(
            out,
            "  rank: score={} colocated-writes={} callgraph-distance={distance}",
            accessor.ranking_score, accessor.colocated_written_fields
        )?;
        let terms: Vec<String> =
            accessor.score_terms.named().iter().map(|(term, points)| format!("{term} {points}")).collect();
        writeln!(out, "  score: {} = {}", terms.join(" + "), accessor.score_terms.total())?;
        writeln!(out, "  lead: {}", lead(&accessor.lead))?;
        for access in &accessor.queried_field_accesses {
            writeln!(
                out,
                "  {} {} {} width={} {}",
                access.address, access.displacement, access.access, access.width_bytes, access.assembly
            )?;
        }
    }
    writeln!(
        out,
        "coverage: {} functions / {} code bytes; {} selected, {} analyzed, {} unsupported, {} byte-budgeted, {} instruction-budgeted, {} accessor functions checked",
        report.coverage.scanned_functions,
        report.coverage.scanned_code_bytes,
        report.coverage.selected_functions,
        report.coverage.analyzed_functions,
        report.coverage.unsupported_flow_functions,
        report.coverage.function_byte_budget_exhausted_functions,
        report.coverage.instruction_budget_exhausted_functions,
        report.coverage.accessor_scanned_functions
    )?;
    for limit in &report.limitations {
        writeln!(out, "limitation: {limit}")?;
    }
    for warning in &report.coverage.warnings {
        writeln!(out, "warning: {warning}")?;
    }
    Ok(())
}

fn write_key_diagnostics(diagnostics: &super::model::KeySearchDiagnostics, out: &mut dyn Write) -> Res {
    writeln!(
        out,
        "key diagnostics: min-matches={} max-functions={} max-instructions={} incomplete={} budget-exhausted={}",
        diagnostics.minimum_matched_keys,
        diagnostics.max_functions,
        diagnostics.max_instructions,
        diagnostics.analysis_incomplete,
        diagnostics.discovery_budget_exhausted
    )?;
    for key in &diagnostics.keys {
        writeln!(
            out,
            "  key {:?}: refs={:?}{} emissions={:?}{}",
            key.key,
            key.code_reference_functions,
            if key.code_reference_functions_truncated { " (+more)" } else { "" },
            key.emission_functions,
            if key.emission_functions_truncated { " (+more)" } else { "" }
        )?;
    }
    if !diagnostics.missing_emission_keys.is_empty() {
        writeln!(out, "  keys without emission witnesses: {:?}", diagnostics.missing_emission_keys)?;
    }
    for reason in &diagnostics.budget_reasons {
        writeln!(out, "  discovery limit: {reason}")?;
    }
    Ok(())
}
