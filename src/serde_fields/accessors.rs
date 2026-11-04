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
    facts::{AccessFact, Facts, MAX_FUNCTION_BYTES},
    model::{AccessorCandidate, LayoutCandidate, MemoryWitness},
};
use crate::scan;
use rayon::prelude::*;
use std::{
    collections::{BTreeMap, BTreeSet},
    ops::RangeInclusive,
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, AtomicUsize, Ordering},
    },
};

type Rank = (std::cmp::Reverse<usize>, u64, usize, usize);
const MAX_ACCESSOR_CODE: usize = 64 * 1024 * 1024;
const MAX_MEMORY_WITNESSES: usize = 16;

fn address_range(access: &AccessFact) -> Option<RangeInclusive<u64>> {
    if access.width == 0 && access.kind != "address" {
        return None;
    }
    let last = access.offset.checked_add(i64::try_from(access.width.saturating_sub(1)).ok()?)?;
    if last < 0 {
        return None;
    }
    Some(u64::try_from(access.offset.max(0)).ok()?..=u64::try_from(last).ok()?)
}
fn overlaps(access: &AccessFact, offsets: &BTreeSet<u64>) -> bool {
    address_range(access).is_some_and(|range| offsets.range(range).next().is_some())
}

pub(super) fn candidates(
    facts: &Facts,
    layouts: &[LayoutCandidate],
    options: &FieldOptions,
) -> Vec<(Rank, AccessorCandidate)> {
    let mut output = Vec::new();
    for (layout, description) in layouts.iter().enumerate() {
        let expected: BTreeSet<_> = description.fields.iter().map(|field| field.offset).collect();
        let queried: BTreeSet<_> = description.offsets.iter().map(|field| field.offset).collect();
        for argument in 0..6 {
            let matching: Vec<_> = facts.accesses.iter().filter(|access| access.argument == argument).collect();
            let mut matched = BTreeSet::new();
            for access in &matching {
                if let Some(range) = address_range(access) {
                    matched.extend(expected.range(range).copied());
                }
            }
            if matched.len() < options.min_offsets {
                continue;
            }
            let accesses: Vec<_> = matching
                .iter()
                .filter(|access| overlaps(access, &queried) && (!options.write_only || access.write))
                .take(MAX_MEMORY_WITNESSES)
                .map(|access| MemoryWitness {
                    address: format!("{:#x}", access.instruction.ip()),
                    assembly: scan::format(&access.instruction),
                    offset: access.offset,
                    displacement: if access.offset < 0 {
                        format!("-{:#x}", access.offset.unsigned_abs())
                    } else {
                        format!("+{:#x}", access.offset)
                    },
                    width_bytes: access.width,
                    access: access.kind,
                })
                .collect();
            if accesses.is_empty() {
                continue;
            }
            let score = matched.len();
            let sites: BTreeSet<_> = matching
                .iter()
                .filter(|access| overlaps(access, &expected))
                .map(|access| access.instruction.ip())
                .collect();
            output.push((
                (std::cmp::Reverse(score), facts.range.start, argument, layout),
                AccessorCandidate {
                    layout,
                    function: format!("{:#x}..{:#x}", facts.range.start, facts.range.end),
                    base_argument: Facts::argument_register(argument),
                    matched_offsets: matched.into_iter().collect(),
                    queried_field_accesses: accesses,
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

pub(super) fn collect(
    catalog: &mut Catalog<'_>,
    layouts: &[LayoutCandidate],
    options: &FieldOptions,
) -> Vec<AccessorCandidate> {
    if layouts.is_empty() {
        return vec![];
    }
    let mut bytes = 0_usize;
    let functions: Vec<_> = catalog
        .image
        .functions
        .iter()
        .filter(|range| {
            let size = usize::try_from(range.end.saturating_sub(range.start)).unwrap_or(usize::MAX);
            if size > MAX_FUNCTION_BYTES || bytes.saturating_add(size) > MAX_ACCESSOR_CODE {
                return false;
            }
            bytes += size;
            true
        })
        .collect();
    let rows = Mutex::new(BTreeMap::<Rank, AccessorCandidate>::new());
    let limited = AtomicBool::new(functions.len() != catalog.image.functions.len());
    let seen = AtomicUsize::new(0);
    let matched = AtomicUsize::new(0);
    let shared: &Catalog<'_> = catalog;
    functions.par_iter().for_each(|range| {
        if shared.expired() {
            limited.store(true, Ordering::Relaxed);
            return;
        }
        let facts = shared.known_facts(range.start).or_else(|| Facts::analyze(shared.image, range).map(Arc::new));
        seen.fetch_add(1, Ordering::Relaxed);
        let Some(facts) = facts else {
            limited.store(true, Ordering::Relaxed);
            return;
        };
        if facts.limited {
            limited.store(true, Ordering::Relaxed);
        }
        for (rank, row) in candidates(&facts, layouts, options) {
            matched.fetch_add(1, Ordering::Relaxed);
            let mut output = rows.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
            output.insert(rank, row);
            if output.len() > options.limit {
                output.pop_last();
            }
        }
    });
    catalog.coverage.accessor_scanned_functions = seen.load(Ordering::Relaxed);
    catalog.coverage.accessors_truncated =
        limited.load(Ordering::Relaxed) || matched.load(Ordering::Relaxed) > options.limit;
    rows.into_inner().unwrap_or_else(std::sync::PoisonError::into_inner).into_values().collect()
}
