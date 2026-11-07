/*
 * XRef — executable analysis
 * Copyright (c) 2026 Alexander Panasenko
 * Contact: alex@prod.codes
 * Author: https://prod.codes/about/
 * Project: https://github.com/alex09x/xref
 * SPDX-License-Identifier: MIT OR Apache-2.0
 */
use super::{
    FieldOptions,
    accessors::{Rank, candidates_entry},
    catalog::Catalog,
    model::{AccessorCandidate, LayoutCandidate, ScoreTerms},
    values::MAX_ROOTS,
    writer_index::Entry,
    writer_rank::Plan,
};
use rayon::prelude::*;
use std::{
    collections::BTreeMap,
    sync::atomic::{AtomicBool, AtomicUsize, Ordering},
};

type Best = BTreeMap<Rank, (usize, usize, usize, ScoreTerms)>;
type Batch = (Best, usize, usize);

pub(super) struct Selection {
    pub rows: BTreeMap<Rank, AccessorCandidate>,
    pub matched: usize,
    pub skipped: usize,
    pub processed: usize,
    pub limited: bool,
}

fn insert(best: &mut Best, rank: Rank, row: (usize, usize, usize, ScoreTerms), limit: usize) {
    if best.len() < limit || best.last_key_value().is_some_and(|(worst, _)| rank < *worst) {
        best.insert(rank, row);
        if best.len() > limit {
            best.pop_last();
        }
    }
}

pub(super) fn select(
    index: &[Entry],
    catalog: &Catalog<'_>,
    layouts: &[LayoutCandidate],
    options: &FieldOptions,
    distances: &[BTreeMap<u64, usize>],
) -> Selection {
    let plans: Vec<_> = layouts.iter().map(|layout| Plan::new(layout, options)).collect();
    // One row past the limit, so the last listed row's lead is known (#149).
    let keep = options.limit + 1;
    let limited = AtomicBool::new(false);
    let processed = AtomicUsize::new(0);
    let (best, matched, skipped): Batch = index
        .par_iter()
        .enumerate()
        .fold(
            || (BTreeMap::new(), 0, 0),
            |(mut best, mut total, mut skipped), (position, entry)| {
                if catalog.expired() {
                    limited.store(true, Ordering::Relaxed);
                    return (best, total, skipped);
                }
                processed.fetch_add(1, Ordering::Relaxed);
                let mut any = false;
                let present = entry.roots();
                for (layout, plan) in plans.iter().enumerate() {
                    let distance = distances[layout].get(&entry.start).copied();
                    for argument in
                        (0..MAX_ROOTS).filter(|root| present & (1 << root) != 0 && options.writer_root.admits(*root))
                    {
                        let Some((colocated, conditional, count)) = plan.score(entry, argument, options.min_offsets)
                        else {
                            continue;
                        };
                        any = true;
                        total += 1;
                        let precision = plan.precision(entry, argument);
                        let mut terms = super::writer_rank::writer_terms(colocated, precision, conditional != 0);
                        terms.callgraph = super::writer_rank::callgraph_points(distance);
                        let score = terms.total();
                        let rank = (
                            std::cmp::Reverse(score),
                            distance.unwrap_or(usize::MAX),
                            std::cmp::Reverse(count),
                            entry.start,
                            argument,
                            layout,
                        );
                        insert(&mut best, rank, (position, layout, argument, terms), keep);
                    }
                }
                if !any {
                    skipped += 1;
                }
                (best, total, skipped)
            },
        )
        .reduce(
            || (BTreeMap::new(), 0, 0),
            |(mut left, lt, ls), (right, rt, rs)| {
                for (rank, row) in right {
                    insert(&mut left, rank, row, keep);
                }
                (left, lt + rt, ls + rs)
            },
        );
    let mut rows = BTreeMap::new();
    for (rank, (position, layout, argument, terms)) in best {
        if let Some((_, mut row)) = candidates_entry(&index[position], layouts, options)
            .into_iter()
            .find(|(candidate, _)| candidate.4 == argument && candidate.5 == layout)
        {
            row.callgraph_distance = distances[layout].get(&index[position].start).copied();
            // The terms the rank was computed from, so the shown breakdown sums to the shown score.
            row.score_terms = terms;
            row.ranking_score = rank.0.0;
            rows.insert(rank, row);
        } else {
            limited.store(true, Ordering::Relaxed);
        }
    }
    Selection {
        rows,
        matched,
        skipped,
        processed: processed.load(Ordering::Relaxed),
        limited: limited.load(Ordering::Relaxed),
    }
}
