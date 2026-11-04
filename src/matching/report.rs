/*
 * xref-code — Cross-build function matching reports
 * Copyright (c) 2026 Alexander Panasenko
 *
 * Contact: alex@prod.codes
 * Author: https://prod.codes/about/
 * Project: https://github.com/alex09x/xref
 * SPDX-License-Identifier: MIT OR Apache-2.0
 */

use std::collections::{HashMap, HashSet, VecDeque};
use std::fmt::Write as _;
use std::ops::Range;

use crate::graph::{CallGraph, resolve};
use crate::image::Image;

use super::{FnSig, Freqs, build_sigs, score_pair};

#[derive(Clone, Copy, Debug, serde::Serialize)]
pub struct MatchOptions {
    /// A best/runner-up ratio at or above this value is reported as ambiguous.
    pub ambiguity_ratio: f64,
    pub compare_pseudo_c: bool,
    /// Query-side and other-side caller function entry addresses.
    pub context: Option<(u64, u64)>,
}

impl Default for MatchOptions {
    fn default() -> Self {
        Self { ambiguity_ratio: 0.95, compare_pseudo_c: false, context: None }
    }
}

#[derive(Clone, Debug, serde::Serialize)]
pub struct MatchCandidate {
    pub range: Range<u64>,
    pub score: u64,
    pub info: String,
    pub pseudo_c_similarity: Option<f64>,
    /// Whether pseudo-C comparison was completed, or why it was not.
    pub pseudo_c_status: Option<String>,
    /// Small, deterministic clues explaining normalized pseudo-C differences.
    pub pseudo_c_differences: Vec<PseudoCDifference>,
    pub features: Vec<super::features::FeatureEvidence>,
}

#[derive(Clone, Debug, serde::Serialize)]
pub struct PseudoCDifference {
    pub feature: String,
    pub query: String,
    pub candidate: String,
}

#[derive(Clone, Debug, serde::Serialize)]
pub struct MatchReport {
    pub query: Range<u64>,
    pub candidates: Vec<MatchCandidate>,
    pub selected: Option<MatchCandidate>,
    pub ambiguous: bool,
    /// Absolute difference between the best and runner-up structural scores.
    pub score_margin: u64,
    /// Runner-up divided by best score. This is a heuristic score ratio.
    pub score_ratio: f64,
    pub warnings: Vec<String>,
}

pub(super) fn match_images_report(
    image: &Image,
    other: &Image,
    specs: &[String],
    options: MatchOptions,
) -> Result<Vec<MatchReport>, Box<dyn std::error::Error>> {
    if !options.ambiguity_ratio.is_finite() || !(0.0..=1.0).contains(&options.ambiguity_ratio) {
        return Err("ambiguity_ratio must be finite and between 0 and 1".into());
    }
    if specs.len() > 64 {
        return Err("at most 64 query functions per matching request".into());
    }
    let ((sigs_a, graph_a), (sigs_b, graph_b)) = rayon::join(|| build_sigs(image), || build_sigs(other));
    let freqs_b = Freqs::from_sigs(&sigs_b);
    let map_a: HashMap<u64, &FnSig> = sigs_a.iter().map(|s| (s.range.start, s)).collect();
    let map_b: HashMap<u64, &FnSig> = sigs_b.iter().map(|s| (s.range.start, s)).collect();
    let context = caller_context(&map_a, &map_b, (&graph_a, &graph_b), options.context, &freqs_b)?;
    let pseudo = options
        .compare_pseudo_c
        .then(|| (crate::diffc::PseudoCContext::new(image), crate::diffc::PseudoCContext::new(other)));
    let mut reports = Vec::with_capacity(specs.len());
    for spec in specs {
        let query = resolve(image, spec)?;
        let mut warnings=vec!["scores, ratios and pseudo-C similarities are heuristics, not calibrated probabilities or semantic equivalence proof".to_owned()];
        if context.is_some() {
            warnings.push(
                "caller reachability is a positive static heuristic only; absence under indirect calls is unknown"
                    .to_owned(),
            );
        }
        let Some(q) = map_a.get(&query.start).copied() else {
            reports.push(MatchReport {
                query,
                candidates: vec![],
                selected: None,
                ambiguous: false,
                score_margin: 0,
                score_ratio: 0.0,
                warnings,
            });
            continue;
        };
        let mut scored = Vec::new();
        for candidate in &sigs_b {
            let (mut score, mut info) = score_pair(q, candidate, &freqs_b);
            if score == 0 {
                continue;
            }
            if let Some(context) = &context
                && context.query.contains(&q.range.start)
                && context.other.contains(&candidate.range.start)
            {
                let bonus = 40 + (context.score / 4).min(80);
                score = score.saturating_add(bonus);
                let _ = write!(info, " caller-positive-static-reachability:+{bonus}");
            }
            scored.push(MatchCandidate {
                range: candidate.range.clone(),
                score,
                info,
                pseudo_c_similarity: None,
                pseudo_c_status: None,
                pseudo_c_differences: vec![],
                features: vec![],
            });
        }
        scored.sort_by(|a, b| b.score.cmp(&a.score).then_with(|| a.range.start.cmp(&b.range.start)));
        let best_score = scored.first().map_or(0, |c| c.score);
        let (score_margin, score_ratio, mut ambiguous) =
            ambiguity_status(best_score, scored.get(1).map(|c| c.score), options.ambiguity_ratio);
        // Count every plausible candidate before bounding the returned list.
        let eligible = if ambiguous {
            scored.iter().take_while(|c| relative_score(c.score, best_score) >= options.ambiguity_ratio).count()
        } else {
            scored.len().min(1)
        };
        if scored.len() > 128 {
            warnings.push(format!(
                "candidate list capped at 128 of {}; omitted plausible candidates keep ambiguity",
                scored.len()
            ));
            scored.truncate(128);
        }
        if let Some(contexts) = &pseudo {
            super::comparison::compare(image, other, &q.range, &mut scored, contexts, eligible, &mut warnings);
            if ambiguous {
                ambiguous = super::comparison::rerank(&mut scored, eligible, options.ambiguity_ratio);
            }
        }
        for candidate in &mut scored {
            if let Some(signature) = map_b.get(&candidate.range.start) {
                candidate.features = super::features::details(q, signature);
            }
        }
        let selected = if ambiguous { None } else { scored.first().cloned() };
        reports.push(MatchReport {
            query,
            candidates: scored,
            selected,
            ambiguous,
            score_margin,
            score_ratio,
            warnings,
        });
    }
    Ok(reports)
}

struct CallerContext {
    query: HashSet<u64>,
    other: HashSet<u64>,
    score: u64,
}
fn caller_context(
    source: &HashMap<u64, &FnSig>,
    target: &HashMap<u64, &FnSig>,
    graphs: (&CallGraph, &CallGraph),
    addresses: Option<(u64, u64)>,
    frequencies: &Freqs,
) -> Result<Option<CallerContext>, String> {
    addresses
        .map(|(a, b)| {
            let left = source
                .get(&a)
                .copied()
                .ok_or_else(|| format!("context caller {a:#x} is not indexed in query image"))?;
            let right = target
                .get(&b)
                .copied()
                .ok_or_else(|| format!("context caller {b:#x} is not indexed in other image"))?;
            Ok(CallerContext {
                query: reachable(graphs.0, a),
                other: reachable(graphs.1, b),
                score: score_pair(left, right, frequencies).0,
            })
        })
        .transpose()
}

// The ratio is deliberately approximate heuristic evidence, never an exact count or probability.
#[allow(clippy::cast_precision_loss)]
fn relative_score(value: u64, best: u64) -> f64 {
    value as f64 / best.max(1) as f64
}

fn ambiguity_status(best: u64, second: Option<u64>, threshold: f64) -> (u64, f64, bool) {
    let Some(second) = second else {
        return (best, 0.0, false);
    };
    let ratio = relative_score(second, best);
    (best.saturating_sub(second), ratio, best > 0 && (best == second || ratio >= threshold))
}

fn reachable(graph: &CallGraph, start: u64) -> HashSet<u64> {
    let mut found = HashSet::from([start]);
    let mut queue = VecDeque::from([start]);
    while let Some(node) = queue.pop_front() {
        for &(_, next) in graph.callees.get(&node).into_iter().flatten() {
            if found.insert(next) {
                queue.push_back(next);
            }
        }
    }
    found
}

#[cfg(test)]
#[path = "report_tests.rs"]
mod tests;
