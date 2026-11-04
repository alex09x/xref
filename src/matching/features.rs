/*
 * XRef — Bounded evidence distinguishing cross-build candidates
 * Copyright (c) 2026 Alexander Panasenko
 * Contact: alex@prod.codes
 * Author: https://prod.codes/about/
 * Project: https://github.com/alex09x/xref
 * SPDX-License-Identifier: MIT OR Apache-2.0
 */
use super::FnSig;
use std::collections::BTreeSet;

#[derive(Clone, Debug, serde::Serialize)]
pub struct FeatureEvidence {
    pub kind: &'static str,
    pub comparison_basis: &'static str,
    pub shared: Vec<String>,
    pub query_only: Vec<String>,
    pub candidate_only: Vec<String>,
    pub truncated: bool,
}

fn values(kind: &'static str, basis: &'static str, a: &[u64], b: &[u64], comparable: bool) -> FeatureEvidence {
    let a: BTreeSet<_> = a.iter().copied().collect();
    let b: BTreeSet<_> = b.iter().copied().collect();
    let shared = if comparable { a.intersection(&b).copied().collect::<Vec<_>>() } else { vec![] };
    let left = if comparable { a.difference(&b).copied().collect::<Vec<_>>() } else { a.iter().copied().collect() };
    let right = if comparable { b.difference(&a).copied().collect::<Vec<_>>() } else { b.iter().copied().collect() };
    let truncated = shared.len() > 8 || left.len() > 8 || right.len() > 8;
    let hex = |v: Vec<u64>| v.into_iter().take(8).map(|n| format!("{n:#x}")).collect();
    FeatureEvidence {
        kind,
        comparison_basis: basis,
        shared: hex(shared),
        query_only: hex(left),
        candidate_only: hex(right),
        truncated,
    }
}

pub(super) fn details(query: &FnSig, candidate: &FnSig) -> Vec<FeatureEvidence> {
    vec![
        values("immediates", "literal values, heuristic correspondence", &query.imms, &candidate.imms, true),
        values(
            "string_fingerprints",
            "FNV-1a fingerprints, not string identity proof",
            &query.strings,
            &candidate.strings,
            true,
        ),
        values(
            "field_displacements",
            "literal displacements, not common type proof",
            &query.disps,
            &candidate.disps,
            true,
        ),
        values(
            "callee_addresses",
            "addresses are scoped to their own image; not compared across builds",
            &query.callees,
            &candidate.callees,
            false,
        ),
        values(
            "callee_immediates",
            "64-bit immediate evidence from static callees",
            &query.callee_imms64,
            &candidate.callee_imms64,
            true,
        ),
    ]
}
