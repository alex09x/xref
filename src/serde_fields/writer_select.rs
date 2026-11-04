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
    model::{AccessorCandidate, LayoutCandidate},
    writer_index::Entry,
    writer_rank::Plan,
};
use rayon::prelude::*;
use std::{
    collections::BTreeMap,
    sync::atomic::{AtomicBool, AtomicUsize, Ordering},
};

type Best = BTreeMap<Rank, (usize, usize, usize)>;
type Batch = (Best, usize, usize);

pub(super) struct Selection {
    pub rows: BTreeMap<Rank, AccessorCandidate>,
    pub matched: usize,
    pub skipped: usize,
    pub processed: usize,
    pub limited: bool,
}

fn insert(best: &mut Best, rank: Rank, row: (usize, usize, usize), limit: usize) {
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
                for (layout, plan) in plans.iter().enumerate() {
                    let distance = distances[layout].get(&entry.start).copied();
                    for argument in 0..6 {
                        let Some((colocated, count)) = plan.score(entry, argument, options.min_offsets) else {
                            continue;
                        };
                        any = true;
                        total += 1;
                        let score = colocated * 4 + distance.map_or(0, |value| 7_usize.saturating_sub(value));
                        let rank = (
                            std::cmp::Reverse(score),
                            distance.unwrap_or(usize::MAX),
                            std::cmp::Reverse(count),
                            entry.start,
                            argument,
                            layout,
                        );
                        insert(&mut best, rank, (position, layout, argument), options.limit);
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
                    insert(&mut left, rank, row, options.limit);
                }
                (left, lt + rt, ls + rs)
            },
        );
    let mut rows = BTreeMap::new();
    for (rank, (position, layout, argument)) in best {
        if let Some((_, mut row)) = candidates_entry(&index[position], layouts, options)
            .into_iter()
            .find(|(candidate, _)| candidate.4 == argument && candidate.5 == layout)
        {
            row.callgraph_distance = distances[layout].get(&index[position].start).copied();
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
