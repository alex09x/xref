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
            _ => "unknown (no other analyzed candidate function; the accessor scan hit analysis limits)".to_owned(),
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
    write_budget_hints(&report.coverage, out)
}

/// Which functions a budget stopped, and what to change: a silent budget reads as "not found".
fn write_budget_hints(coverage: &super::model::Coverage, out: &mut dyn Write) -> Res {
    let list_examples = |n: usize, examples: &[String]| {
        let more = n.saturating_sub(examples.len());
        let tail = if more > 0 { format!(" and {more} more") } else { String::new() };
        format!("{}{tail}", examples.join(", "))
    };
    let n = coverage.instruction_budget_exhausted_functions;
    if n > 0 {
        let limit = coverage.instruction_limit;
        let advice = if limit < super::catalog::MAX_FIELD_INSTRUCTION_BUDGET {
            format!("rerun with --max-instructions {}", super::catalog::MAX_FIELD_INSTRUCTION_BUDGET)
        } else {
            "the limit is at its maximum; narrow the search with --within <function>".to_owned()
        };
        let names = list_examples(n, &coverage.instruction_budgeted_examples);
        let s = if n == 1 { "" } else { "s" };
        writeln!(out, "hint: {n} function{s} stopped at --max-instructions {limit} ({names}); {advice}")?;
    }
    let n = coverage.function_byte_budget_exhausted_functions;
    if n > 0 {
        let names = list_examples(n, &coverage.byte_budgeted_examples);
        let s = if n == 1 { "" } else { "s" };
        let limit = super::facts::function_byte_limit(coverage.instruction_limit);
        let cap = super::catalog::MAX_FIELD_INSTRUCTION_BUDGET;
        let advice = if coverage.instruction_limit < cap {
            format!("--max-instructions {cap} admits up to {} bytes", super::facts::function_byte_limit(cap))
        } else {
            "no option raises it further".to_owned()
        };
        writeln!(out, "hint: {n} function{s} not analysed, larger than {limit} bytes ({names}); {advice}")?;
    }
    let n = coverage.unsupported_flow_functions;
    if n > 0 {
        let s = if n == 1 { "" } else { "s" };
        let names = list_examples(n, &coverage.unsupported_examples);
        writeln!(
            out,
            "hint: {n} function{s} skipped for unsupported control flow or instructions ({names}); read them with `c`"
        )?;
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

#[cfg(test)]
mod tests {
    use super::super::model::Coverage;

    fn hints(coverage: &Coverage) -> String {
        let mut out = Vec::new();
        assert!(super::write_budget_hints(coverage, &mut out).is_ok());
        String::from_utf8_lossy(&out).into_owned()
    }

    #[test]
    fn budget_hints_name_the_functions_and_the_knob() {
        let coverage = Coverage {
            instruction_limit: 4096,
            instruction_budget_exhausted_functions: 3,
            instruction_budgeted_examples: vec!["0x1000".to_owned(), "0x2000".to_owned()],
            function_byte_budget_exhausted_functions: 1,
            byte_budgeted_examples: vec!["0x3000".to_owned()],
            unsupported_flow_functions: 1,
            unsupported_examples: vec!["0x4000".to_owned()],
            ..Coverage::default()
        };
        let text = hints(&coverage);
        assert!(
            text.contains("hint: 3 functions stopped at --max-instructions 4096 (0x1000, 0x2000 and 1 more); rerun with --max-instructions 65536"),
            "{text}"
        );
        assert!(text.contains("hint: 1 function not analysed, larger than 32768 bytes (0x3000); --max-instructions 65536 admits up to 524288 bytes"), "{text}");
        assert!(
            text.contains(
                "hint: 1 function skipped for unsupported control flow or instructions (0x4000); read them with `c`"
            ),
            "{text}"
        );
        let at_max =
            Coverage { instruction_limit: 65536, instruction_budget_exhausted_functions: 1, ..Coverage::default() };
        assert!(hints(&at_max).contains("the limit is at its maximum; narrow the search with --within <function>"));
        assert_eq!(hints(&Coverage::default()), "");
    }
}
