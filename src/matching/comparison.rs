/*
 * XRef — Bounded pseudo-C ranking with explicit incomplete comparisons
 * Copyright (c) 2026 Alexander Panasenko
 * Contact: alex@prod.codes
 * Author: https://prod.codes/about/
 * Project: https://github.com/alex09x/xref
 * SPDX-License-Identifier: MIT OR Apache-2.0
 */
use super::report::{MatchCandidate, PseudoCDifference};
use crate::{diffc::PseudoCContext, image::Image};
use std::ops::Range;

const MAX_COMPARE: usize = 8;
const MAX_LINES: usize = 128;
const MAX_CODE_BYTES: u64 = 64 * 1024;

pub(super) fn compare(
    image: &Image,
    other: &Image,
    query: &Range<u64>,
    candidates: &mut [MatchCandidate],
    contexts: &(PseudoCContext, PseudoCContext),
    eligible: usize,
    warnings: &mut Vec<String>,
) {
    let count = eligible.min(candidates.len()).min(MAX_COMPARE);
    if eligible > count {
        warnings.push(format!("pseudo-C comparison capped at {count}; unexamined plausible candidates keep ambiguity"));
    }
    let left = if query.end.saturating_sub(query.start) <= MAX_CODE_BYTES {
        contexts.0.normalized(image, query)
    } else {
        Err("query exceeds 64 KiB code budget".to_owned())
    };
    for candidate in candidates.iter_mut().take(count) {
        let result = (|| -> Result<_, String> {
            if candidate.range.end.saturating_sub(candidate.range.start) > MAX_CODE_BYTES {
                return Err("candidate exceeds 64 KiB code budget".to_owned());
            }
            let left = left.as_ref().map_err(Clone::clone)?;
            let right = contexts.1.normalized(other, &candidate.range)?;
            if left.is_empty() || right.is_empty() {
                return Err("empty normalized output is insufficient evidence".to_owned());
            }
            if left.len() > MAX_LINES || right.len() > MAX_LINES {
                return Err("normalized output exceeds 128 line budget; not compared".to_owned());
            }
            Ok((line_similarity(left, &right), differences(left, &right)))
        })();
        match result {
            Ok((similarity, differences)) => {
                candidate.pseudo_c_similarity = Some(similarity);
                candidate.pseudo_c_differences = differences;
                candidate.pseudo_c_status = Some("compared: heuristic pseudo-C evidence".to_owned());
            }
            Err(reason) => candidate.pseudo_c_status = Some(format!("uncompared: {reason}")),
        }
    }
    warnings.push("pseudo-C ordering is heuristic inference; structural scores remain explicit".to_owned());
}

/// A total ordering is mandatory even when only some candidates could be compared.
/// Missing evidence sorts last for display, but always prevents automatic selection.
pub(super) fn rerank(candidates: &mut [MatchCandidate], eligible: usize, threshold: f64) -> bool {
    let available = eligible.min(candidates.len());
    candidates[..available].sort_by(|a, b| {
        b.pseudo_c_similarity
            .unwrap_or(-1.0)
            .total_cmp(&a.pseudo_c_similarity.unwrap_or(-1.0))
            .then_with(|| b.score.cmp(&a.score))
            .then_with(|| a.range.start.cmp(&b.range.start))
    });
    if eligible > available
        || eligible > MAX_COMPARE
        || candidates[..available].iter().any(|candidate| candidate.pseudo_c_similarity.is_none())
    {
        return true;
    }
    let best = candidates.first().and_then(|c| c.pseudo_c_similarity).unwrap_or(0.0);
    let second = candidates.get(1).and_then(|c| c.pseudo_c_similarity).unwrap_or(0.0);
    ambiguity_after_pseudo_c(true, Some(best), Some(second), true, threshold)
}

pub(super) fn ambiguity_after_pseudo_c(
    structural: bool,
    best: Option<f64>,
    second: Option<f64>,
    enabled: bool,
    threshold: f64,
) -> bool {
    if !enabled || !structural {
        return structural;
    }
    match (best, second) {
        (Some(a), Some(b)) if a > 0.0 => b / a >= threshold,
        _ => true,
    }
}

pub(super) fn line_similarity(a: &[String], b: &[String]) -> f64 {
    let a = &a[..a.len().min(MAX_LINES)];
    let b = &b[..b.len().min(MAX_LINES)];
    let mut previous = vec![0_u16; b.len() + 1];
    let mut next = previous.clone();
    for left in a.iter().take(MAX_LINES) {
        for (j, right) in b.iter().take(MAX_LINES).enumerate() {
            next[j + 1] = if left == right { previous[j] + 1 } else { next[j].max(previous[j + 1]) };
        }
        std::mem::swap(&mut previous, &mut next);
        next.fill(0);
    }
    if a.is_empty() && b.is_empty() {
        return 0.0;
    }
    let total = u32::try_from(a.len() + b.len()).unwrap_or(u32::MAX);
    2.0 * f64::from(previous[b.len().min(MAX_LINES)]) / f64::from(total)
}

fn differences(a: &[String], b: &[String]) -> Vec<PseudoCDifference> {
    let mut output = Vec::new();
    for index in 0..a.len().max(b.len()) {
        let left = a.get(index).map_or("<end>", String::as_str);
        let right = b.get(index).map_or("<end>", String::as_str);
        if left == right {
            continue;
        }
        let feature = if left.contains('"') || right.contains('"') {
            "string literal"
        } else if left.contains("fn_") || right.contains("fn_") {
            "callee or call shape"
        } else if numbers(left) != numbers(right) {
            "immediate value"
        } else {
            "operator"
        };
        output.push(PseudoCDifference {
            feature: feature.to_owned(),
            query: left.chars().take(256).collect(),
            candidate: right.chars().take(256).collect(),
        });
        if output.len() == 6 {
            break;
        }
    }
    output
}
fn numbers(line: &str) -> Vec<&str> {
    line.split(|ch: char| !ch.is_ascii_alphanumeric()).filter(|part| part.bytes().any(|b| b.is_ascii_digit())).collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    fn candidate(score: u64, ip: u64, similarity: Option<f64>) -> MatchCandidate {
        MatchCandidate {
            range: ip..ip + 4,
            score,
            info: String::new(),
            pseudo_c_similarity: similarity,
            pseudo_c_status: None,
            pseudo_c_differences: vec![],
            features: vec![],
        }
    }
    #[test]
    fn incomplete_comparisons_have_total_order_and_cannot_silently_resolve_ambiguity() {
        let mut candidates = vec![candidate(100, 1, Some(0.1)), candidate(98, 2, Some(0.9)), candidate(99, 3, None)];
        assert!(rerank(&mut candidates, 3, 0.95));
        assert_eq!(candidates.iter().map(|c| c.range.start).collect::<Vec<_>>(), vec![2, 1, 3]);
        let mut candidates = vec![candidate(100, 1, Some(0.9)), candidate(100, 2, Some(0.899))];
        assert!(rerank(&mut candidates, 2, 0.95), "tiny heuristic differences are still ambiguous");
        candidates[1].pseudo_c_similarity = Some(0.8);
        assert!(!rerank(&mut candidates, 2, 0.95));
        assert!(rerank(&mut candidates, 9, 0.95), "unexamined plausible candidates must prevent selection");
    }
}
