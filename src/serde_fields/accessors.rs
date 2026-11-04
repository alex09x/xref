/*
 * XRef — Same-root offset-constellation accessor candidates
 * Copyright (c) 2026 Alexander Panasenko
 * Contact: alex@prod.codes
 * Author: https://prod.codes/about/
 * Project: https://github.com/alex09x/xref
 * SPDX-License-Identifier: MIT OR Apache-2.0
 */
use super::{
    FieldOptions,
    catalog::Catalog,
    facts::{Facts, MAX_FUNCTION_BYTES},
    model::{AccessorCandidate, LayoutCandidate, MemoryWitness},
    values::MAX_ROOTS,
    writer_index::{Access, Entry},
};
use rayon::prelude::*;
use std::{
    collections::{BTreeMap, BTreeSet},
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, AtomicUsize, Ordering},
    },
};

pub(super) type Rank = (std::cmp::Reverse<usize>, usize, std::cmp::Reverse<usize>, u64, usize, usize);

fn call_distances(catalog: &Catalog<'_>, layout: &LayoutCandidate) -> BTreeMap<u64, usize> {
    let Some(start) =
        layout.function.split("..").next().and_then(|s| u64::from_str_radix(s.trim_start_matches("0x"), 16).ok())
    else {
        return BTreeMap::new();
    };
    if let Some(dense) = &catalog.dense {
        return dense.distances(start);
    }
    let mut distance = BTreeMap::from([(start, 0)]);
    let mut queue = std::collections::VecDeque::from([start]);
    while let Some(function) = queue.pop_front() {
        let next = distance[&function] + 1;
        if next > 6 {
            continue;
        }
        for &neighbor in catalog
            .call_forward
            .get(&function)
            .into_iter()
            .flatten()
            .chain(catalog.call_reverse.get(&function).into_iter().flatten())
        {
            if let std::collections::btree_map::Entry::Vacant(entry) = distance.entry(neighbor) {
                entry.insert(next);
                queue.push_back(neighbor);
            }
        }
    }
    distance
}
const MAX_ACCESSOR_CODE: usize = 64 * 1024 * 1024;
const MAX_MEMORY_WITNESSES: usize = 16;

fn overlaps(access: &Access, offsets: &BTreeSet<u64>) -> bool {
    access.range().is_some_and(|range| offsets.range(range).next().is_some())
}

fn witnesses(
    matching: &[&Access],
    queried: &BTreeSet<u64>,
    required: &BTreeSet<u64>,
    write_only: bool,
) -> Vec<MemoryWitness> {
    let mut relevant: Vec<_> =
        matching.iter().copied().filter(|access| overlaps(access, queried) && (!write_only || access.write)).collect();
    relevant.sort_by_key(|access| (!access.write || !overlaps(access, required), access.ip));
    relevant
        .iter()
        .take(MAX_MEMORY_WITNESSES)
        .map(|access| MemoryWitness {
            address: format!("{:#x}", access.ip),
            assembly: access.assembly.clone(),
            offset: access.offset,
            displacement: if access.offset < 0 {
                format!("-{:#x}", access.offset.unsigned_abs())
            } else {
                format!("+{:#x}", access.offset)
            },
            width_bytes: access.width,
            access: access.kind,
        })
        .collect()
}

#[cfg(test)]
pub(super) fn candidates(
    facts: &Facts,
    layouts: &[LayoutCandidate],
    options: &FieldOptions,
) -> Vec<(Rank, AccessorCandidate)> {
    candidates_entry(&Entry::new(&facts.range, Some(facts)), layouts, options)
}

pub(super) fn candidates_entry(
    facts: &Entry,
    layouts: &[LayoutCandidate],
    options: &FieldOptions,
) -> Vec<(Rank, AccessorCandidate)> {
    let mut output = Vec::new();
    for (layout, description) in layouts.iter().enumerate() {
        let expected: BTreeSet<_> = description.fields.iter().map(|field| field.offset).collect();
        let mut queried: BTreeSet<_> = description.offsets.iter().map(|field| field.offset).collect();
        queried.extend(
            description
                .fields
                .iter()
                .filter(|field| options.writes_all_of.contains(&field.name))
                .map(|field| field.offset),
        );
        for argument in (0..MAX_ROOTS).filter(|root| options.writer_root.admits(*root)) {
            let matching: Vec<_> = facts.accesses.iter().filter(|access| access.argument == argument).collect();
            if options.writes_all_of.iter().any(|name| {
                !description
                    .fields
                    .iter()
                    .filter(|field| &field.name == name)
                    .any(|field| matching.iter().any(|access| access.write && access.covers(field.offset)))
            }) {
                continue;
            }
            let required_offsets: BTreeSet<_> = description
                .fields
                .iter()
                .filter(|field| options.writes_all_of.contains(&field.name))
                .map(|field| field.offset)
                .collect();
            let rank_offsets: BTreeSet<_> =
                if options.writes_all_of.is_empty() { expected.clone() } else { required_offsets.clone() };
            let mut matched = BTreeSet::new();
            let mut conditional = false;
            for access in &matching {
                // Same rule as `writer_rank::Plan::score`, with or without --writes-all-of (#118 review).
                conditional |= super::writer_rank::compares(access) && overlaps(access, &rank_offsets);
                if !required_offsets.is_empty() && !access.write {
                    continue;
                }
                if let Some(range) = access.range() {
                    matched.extend(expected.range(range).copied());
                }
            }
            if matched.len() < options.min_offsets {
                continue;
            }
            let accesses = witnesses(&matching, &queried, &required_offsets, options.write_only);
            if accesses.is_empty() {
                continue;
            }
            let score = matched.len();
            let mut writes_by_block = BTreeMap::<usize, BTreeSet<u64>>::new();
            for access in matching.iter().filter(|access| access.write) {
                if let Some(range) = access.range() {
                    writes_by_block.entry(access.block).or_default().extend(rank_offsets.range(range).copied());
                }
            }
            let colocated =
                if options.write_only { writes_by_block.values().map(BTreeSet::len).max().unwrap_or(0) } else { 0 };
            let precision = if options.write_only {
                super::writer_rank::write_precision(
                    matching.iter().copied(),
                    argument,
                    &facts.dereferenced,
                    &rank_offsets,
                    &super::writer_rank::field_widths(description),
                )
            } else {
                super::writer_rank::Precision::default()
            };
            let ranking_score = super::writer_rank::writer_score(colocated, precision, conditional);
            let sites: BTreeSet<_> =
                matching.iter().filter(|access| overlaps(access, &expected)).map(|access| access.ip).collect();
            output.push((
                (std::cmp::Reverse(ranking_score), usize::MAX, std::cmp::Reverse(score), facts.start, argument, layout),
                AccessorCandidate {
                    layout,
                    function: format!("{:#x}..{:#x}", facts.start, facts.end),
                    base_argument: Facts::argument_register(argument),
                    matched_offsets: matched.into_iter().collect(),
                    queried_field_accesses: accesses,
                    colocated_written_fields: colocated,
                    callgraph_distance: None,
                    ranking_score,
                    confidence: if score > 1 && sites.len() == 1 {
                        "single_span_overlap_not_type_proof"
                    } else if score > 1 {
                        "same_root_offset_constellation_not_type_proof"
                    } else {
                        "weak_offset_only_not_type_proof"
                    },
                },
            ));
        }
    }
    output
}

/// Writer index entries from this process's session, else from the on-disk index (then remembered).
fn indexed_writers(
    catalog: &Catalog<'_>,
    options: &FieldOptions,
    functions: &[&std::ops::Range<u64>],
) -> Option<Arc<Vec<Entry>>> {
    super::session::writers(&catalog.identity, options.max_instructions).or_else(|| {
        super::writer_index::load(&catalog.identity, options.max_instructions, functions)
            .map(|entries| super::session::remember_writers(&catalog.identity, options.max_instructions, entries))
    })
}

/// Functions the accessor search scans (and the writer index covers), the number prefiltered as
/// non-writing, and whether the code byte budget cut the list.
fn candidate_functions<'c>(catalog: &'c Catalog<'_>, write_only: bool) -> (Vec<&'c std::ops::Range<u64>>, usize, bool) {
    let mut bytes = 0_usize;
    let mut budget_limited = false;
    let mut prefiltered = 0_usize;
    let functions = catalog
        .image
        .functions
        .iter()
        .filter(|range| {
            if write_only
                && catalog.starts.contains_key(&range.start)
                && !catalog.write_functions.contains(&range.start)
            {
                prefiltered += 1;
                return false;
            }
            let size = usize::try_from(range.end.saturating_sub(range.start)).unwrap_or(usize::MAX);
            if size > MAX_FUNCTION_BYTES || bytes.saturating_add(size) > MAX_ACCESSOR_CODE {
                budget_limited = true;
                return false;
            }
            bytes += size;
            true
        })
        .collect();
    (functions, prefiltered, budget_limited)
}

/// Load the on-disk writer index into this process's session ahead of the first writer query.
#[cfg_attr(test, allow(dead_code))]
pub(super) fn warm_writers(catalog: &Catalog<'_>, max_instructions: usize) {
    if !catalog.full_scan {
        return;
    }
    let (functions, _, _) = candidate_functions(catalog, true);
    let options = FieldOptions { write_only: true, max_instructions, ..FieldOptions::default() };
    let _ = indexed_writers(catalog, &options, &functions);
}

pub(super) fn collect(
    catalog: &mut Catalog<'_>,
    layouts: &[LayoutCandidate],
    options: &FieldOptions,
) -> Vec<AccessorCandidate> {
    if layouts.is_empty() {
        return vec![];
    }
    let (functions, prefiltered, budget_limited) = candidate_functions(catalog, options.write_only);
    let cache_eligible = options.write_only && catalog.full_scan;
    let cached = cache_eligible.then(|| indexed_writers(catalog, options, &functions)).flatten();
    let cached_incomplete = cached.as_ref().is_some_and(|entries| entries.iter().any(|entry| entry.incomplete));
    let expected = functions.len();
    let entries = Mutex::new(Vec::new());
    let rows = Mutex::new(BTreeMap::<Rank, AccessorCandidate>::new());
    let distances: Vec<_> = layouts.iter().map(|layout| call_distances(catalog, layout)).collect();
    let limited = AtomicBool::new(budget_limited || cached_incomplete);
    let seen = AtomicUsize::new(0);
    let matched = AtomicUsize::new(0);
    let indexed_prefiltered = AtomicUsize::new(0);
    let shared: &Catalog<'_> = catalog;
    let process = |entry: &Entry| {
        seen.fetch_add(1, Ordering::Relaxed);
        if entry.incomplete {
            limited.store(true, Ordering::Relaxed);
        }
        for (mut rank, mut row) in candidates_entry(entry, layouts, options) {
            if options.write_only {
                row.callgraph_distance = distances[row.layout].get(&entry.start).copied();
                rank.1 = row.callgraph_distance.unwrap_or(usize::MAX);
                row.ranking_score +=
                    row.callgraph_distance.map_or(0, |distance| (7_usize.saturating_sub(distance)) * 2);
                rank.0 = std::cmp::Reverse(row.ranking_score);
            }
            matched.fetch_add(1, Ordering::Relaxed);
            let mut output = rows.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
            output.insert(rank, row);
            if output.len() > options.limit {
                output.pop_last();
            }
        }
    };
    if let Some(index) = &cached {
        let selected = super::writer_select::select(index, shared, layouts, options, &distances);
        indexed_prefiltered.store(selected.skipped, Ordering::Relaxed);
        seen.store(selected.processed.saturating_sub(selected.skipped), Ordering::Relaxed);
        matched.store(selected.matched, Ordering::Relaxed);
        if selected.limited {
            limited.store(true, Ordering::Relaxed);
        }
        rows.lock().unwrap_or_else(std::sync::PoisonError::into_inner).extend(selected.rows);
    } else {
        functions.par_iter().for_each(|range| {
            if shared.expired() {
                limited.store(true, Ordering::Relaxed);
                return;
            }
            let facts = shared.known_facts(range.start).or_else(|| {
                Facts::analyze_with_instruction_limit(shared.image, range, options.max_instructions).ok().map(Arc::new)
            });
            let entry = Entry::new(range, facts.as_deref());
            process(&entry);
            if cache_eligible {
                entries.lock().unwrap_or_else(std::sync::PoisonError::into_inner).push(entry);
            }
        });
    }
    catalog.coverage.accessor_scanned_functions = seen.load(Ordering::Relaxed);
    catalog.coverage.accessor_prefiltered_functions = prefiltered + indexed_prefiltered.load(Ordering::Relaxed);
    catalog.coverage.writer_index_cache_hits = usize::from(cached.is_some());
    if cache_eligible && cached.is_none() && seen.load(Ordering::Relaxed) == expected && !catalog.expired() {
        let mut entries = entries.into_inner().unwrap_or_else(std::sync::PoisonError::into_inner);
        super::writer_index::save(&catalog.identity, options.max_instructions, &mut entries);
        super::session::remember_writers(&catalog.identity, options.max_instructions, entries);
    }
    catalog.coverage.accessors_truncated =
        limited.load(Ordering::Relaxed) || matched.load(Ordering::Relaxed) > options.limit;
    rows.into_inner().unwrap_or_else(std::sync::PoisonError::into_inner).into_values().collect()
}
