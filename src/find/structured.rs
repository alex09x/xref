/*
 * XRef Code — Structured multi-predicate function search for `xref query` / MCP
 * Copyright (c) 2026 Alexander Panasenko
 *
 * Contact: alex@prod.codes
 * Author: https://prod.codes/about/
 * Project: https://github.com/alex09x/xref
 * SPDX-License-Identifier: MIT OR Apache-2.0
 */

use std::error::Error;
use std::ops::Range;
use std::sync::atomic::{AtomicBool, Ordering};

use rayon::prelude::*;

use super::instructions::{MAX_SITES, build_instruction_predicates};
use super::{Bounds, FindResult, FindSpec, InstructionHits, PredKind, build_preds};
use crate::image::Image;
use crate::scan::decode;

/// Predicates of one structured search at most.
const MAX_PREDICATES: usize = 32;
/// Occurrences of one `refs` string at most (each widens to up to `back` + 1 addresses).
pub const MAX_REF_HITS: usize = 4096;

/// Structured match record returned by `find::structured::search`.
#[derive(Clone, Debug)]
pub struct StructuredFindMatch {
    pub satisfied: usize,
    pub function: Range<u64>,
    pub matched_predicates: Vec<String>,
    pub instruction_hit_count: usize,
}

/// Full ranked multi-predicate result set prior to pagination.
#[derive(Clone, Debug)]
pub struct StructuredFindReport {
    pub predicate_count: usize,
    pub min_satisfied: usize,
    pub matches: Vec<StructuredFindMatch>,
}

/// Run multi-predicate search across all functions in parallel and return structured hits.
pub fn search(
    image: &Image,
    spec: &FindSpec,
    patterns: &[String],
    classes: &[String],
    cancelled: &AtomicBool,
) -> Result<StructuredFindReport, Box<dyn Error>> {
    // Counted before any is built: building `refs` and `src` scans the whole image.
    let requested = spec.calls.len()
        + spec.refs.len()
        + spec.imm.len()
        + spec.disp.len()
        + spec.src.len()
        + usize::from(spec.size.is_some())
        + patterns.len()
        + classes.len();
    if requested == 0 {
        return Err("at least one predicate is required".into());
    }
    if requested > MAX_PREDICATES {
        return Err(format!("at most {MAX_PREDICATES} combined predicates are allowed").into());
    }
    let preds = build_preds(image, spec, Bounds { cancelled: Some(cancelled), max_ref_hits: Some(MAX_REF_HITS) })?;
    let instruction_patterns = build_instruction_predicates(patterns, classes)?;
    let total = preds.len() + instruction_patterns.len();
    if total == 0 {
        return Err("at least one predicate is required".into());
    }
    let min_req = spec.any.unwrap_or(total).clamp(1, total);

    let mut raw: Vec<FindResult> = image
        .functions
        .par_iter()
        .filter_map(|f| {
            if cancelled.load(Ordering::Relaxed) {
                return None;
            }
            let bytes = image.code(f)?;
            let mut hits: Vec<Option<u64>> = preds
                .iter()
                .map(|p| match &p.kind {
                    PredKind::Size(r) if r.contains(&(f.end - f.start)) => Some(f.start),
                    _ => None,
                })
                .collect();
            let mut instruction_hits: Vec<InstructionHits> = (0..instruction_patterns.len())
                .map(|_| InstructionHits { sites: Vec::with_capacity(MAX_SITES), total: 0 })
                .collect();
            decode(bytes, f.start, |instruction| {
                for (slot, pred) in hits.iter_mut().zip(&preds) {
                    if slot.is_none() && pred.matches_inst(image, f, instruction) {
                        *slot = Some(instruction.ip());
                    }
                }
                for (slot, pred) in instruction_hits.iter_mut().zip(&instruction_patterns) {
                    if pred.matches(instruction) {
                        slot.total += 1;
                        if slot.sites.len() < MAX_SITES {
                            slot.sites.push(instruction.ip());
                        }
                    }
                }
            });
            let satisfied =
                hits.iter().filter(|h| h.is_some()).count() + instruction_hits.iter().filter(|h| h.total != 0).count();
            (satisfied >= min_req).then_some((satisfied, f.clone(), hits, instruction_hits))
        })
        .collect();

    if cancelled.load(Ordering::Relaxed) {
        return Err("query cancelled".into());
    }
    raw.sort_by(|a, b| b.0.cmp(&a.0).then_with(|| a.1.start.cmp(&b.1.start)));

    let matches = raw
        .into_iter()
        .map(|(satisfied, function, hits, ins_hits)| {
            let mut matched_predicates: Vec<String> =
                preds.iter().zip(hits).filter_map(|(p, ip)| Some(format!("{}@{:#x}", p.label, ip?))).collect();
            let mut instruction_hit_count = 0usize;
            for (pred, sites) in instruction_patterns.iter().zip(ins_hits) {
                instruction_hit_count += sites.total;
                if let Some(&first_ip) = sites.sites.first() {
                    matched_predicates.push(format!("{}@{first_ip:#x}", pred.label));
                }
            }
            StructuredFindMatch { satisfied, function, matched_predicates, instruction_hit_count }
        })
        .collect();

    Ok(StructuredFindReport { predicate_count: total, min_satisfied: min_req, matches })
}
