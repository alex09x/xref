/*
 * XRef — Cross-build matching output and compatibility wrappers
 * Copyright (c) 2026 Alexander Panasenko
 * Contact: alex@prod.codes
 * Author: https://prod.codes/about/
 * Project: https://github.com/alex09x/xref
 * SPDX-License-Identifier: MIT OR Apache-2.0
 */
use super::{MatchHit, MatchOptions, MatchReport};
use crate::{commands::Res, image::Image};
use std::io::Write;

#[allow(dead_code)] // Keep the guarded legacy accessor available to internal consumers.
pub fn best_matches(
    image: &Image,
    other: &Image,
    specs: &[String],
) -> Result<Vec<MatchHit>, Box<dyn std::error::Error>> {
    Ok(match_images_report(image, other, specs, MatchOptions::default())?
        .into_iter()
        .map(|report| {
            let selected = if report.ambiguous { None } else { report.selected.as_ref() };
            (report.query, selected.map(|c| (c.score, c.range.clone(), c.info.clone())))
        })
        .collect())
}

pub fn match_images(image: &Image, other: &Image, specs: &[String], top: usize, out: &mut dyn Write) -> Res {
    match_images_with_options(image, other, specs, top, MatchOptions::default(), out)
}

pub fn match_images_with_options(
    image: &Image,
    other: &Image,
    specs: &[String],
    top: usize,
    options: MatchOptions,
    out: &mut dyn Write,
) -> Res {
    for report in match_images_report(image, other, specs, options)? {
        let q = &report.query;
        writeln!(out, "query {:#x}..{:#x}", q.start, q.end)?;
        writeln!(
            out,
            "  structural score margin {} runner-up ratio {:.3} (heuristic; not a probability)",
            report.score_margin, report.score_ratio
        )?;
        if report.ambiguous {
            writeln!(
                out,
                "  ambiguous: score margin {} (ratio {:.3}); specify an explicit target",
                report.score_margin, report.score_ratio
            )?;
        } else if report.selected.is_none() {
            writeln!(out, "  no counterpart found")?;
        }
        for candidate in report.candidates.iter().take(top) {
            let pseudo = candidate
                .pseudo_c_similarity
                .map(|v| format!(" pseudo-C similarity {v:.3} (heuristic)"))
                .unwrap_or_default();
            writeln!(
                out,
                "  {:#x}..{:#x}  score {}{}  ({})",
                candidate.range.start, candidate.range.end, candidate.score, pseudo, candidate.info
            )?;
            for feature in &candidate.features {
                if !feature.query_only.is_empty() || !feature.candidate_only.is_empty() {
                    writeln!(
                        out,
                        "    {}: query-only {:?}, candidate-only {:?}; {}{}",
                        feature.kind,
                        feature.query_only,
                        feature.candidate_only,
                        feature.comparison_basis,
                        if feature.truncated { "; truncated" } else { "" }
                    )?;
                }
            }
        }
        for warning in report.warnings {
            writeln!(out, "  warning: {warning}")?;
        }
    }
    Ok(())
}

pub fn match_images_report(
    image: &Image,
    other: &Image,
    specs: &[String],
    options: MatchOptions,
) -> Result<Vec<MatchReport>, Box<dyn std::error::Error>> {
    super::report::match_images_report(image, other, specs, options)
}
