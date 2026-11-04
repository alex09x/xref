/*
 * XRef — executable analysis
 * Copyright (c) 2026 Alexander Panasenko
 * Contact: alex@prod.codes
 * Author: https://prod.codes/about/
 * Project: https://github.com/alex09x/xref
 * SPDX-License-Identifier: MIT OR Apache-2.0
 */
use super::{
    catalog::{
        CallGraph, Catalog, MAX_CODE_BYTES, MAX_DEPTH, MAX_EDGES, MAX_FUNCTIONS, MAX_KEY_DIAGNOSTIC_FUNCTIONS,
        mark_key_references,
    },
    scan_index,
};
use rayon::prelude::*;
use std::{
    collections::{BTreeMap, BTreeSet, VecDeque},
    ops::Range,
    sync::Arc,
};

pub(super) struct Graphs {
    pub reverse: Arc<CallGraph>,
    pub forward: Arc<CallGraph>,
    pub seeds: BTreeMap<u64, u16>,
    pub dense: Option<Arc<super::dense_graph::DenseGraph>>,
}

fn parallel_records(result: &Catalog<'_>) -> Option<Vec<Option<scan_index::ScanRecord>>> {
    let functions = &result.image.functions;
    if functions.len() < 128 || functions.len() > MAX_FUNCTIONS {
        return None;
    }
    let bytes = functions.iter().fold(0_usize, |total, function| {
        total.saturating_add(usize::try_from(function.end.saturating_sub(function.start)).unwrap_or(usize::MAX))
    });
    if !(1024 * 1024..=MAX_CODE_BYTES).contains(&bytes) {
        return None;
    }
    Some(
        functions
            .par_iter()
            .map(|function| (!result.expired()).then(|| scan_index::scan_function(result.image, function)))
            .collect(),
    )
}

fn record_references(
    result: &mut Catalog<'_>,
    seeds: &mut BTreeMap<u64, u16>,
    names: &[String],
    function: u64,
    found: &[bool],
) {
    if !found.iter().any(|matched| *matched) {
        return;
    }
    let mask = found.iter().enumerate().fold(
        0_u16,
        |mask, (index, found)| {
            if *found { mask | (1_u16 << index) } else { mask }
        },
    );
    seeds.insert(function, mask);
    for (index, is_found) in found.iter().enumerate() {
        if !is_found {
            continue;
        }
        let key = names[index].clone();
        let functions = result.key_reference_functions.entry(key.clone()).or_default();
        if functions.len() < MAX_KEY_DIAGNOSTIC_FUNCTIONS {
            functions.push(function);
        } else {
            result.key_reference_functions_truncated.insert(key);
        }
    }
}

pub(super) fn scan(result: &mut Catalog<'_>, names: &[String], within: Option<&Range<u64>>) -> Graphs {
    if within.is_some() {
        return walk(result, names, within, &mut Vec::new());
    }
    if let Some(base) = super::session::full_scan(&result.identity) {
        return apply_full_scan(result, &base, names);
    }
    let mut references = Vec::new();
    let graphs = walk(result, names, None, &mut references);
    if result.full_scan && !result.expired() {
        super::session::remember_full_scan(
            &result.identity,
            super::session::FullScan {
                starts: result.starts.clone(),
                write_functions: result.write_functions.clone(),
                forward: Arc::clone(&graphs.forward),
                reverse: Arc::clone(&graphs.reverse),
                references,
                scanned_functions: result.coverage.scanned_functions,
                skipped_functions: result.coverage.skipped_functions,
                scanned_code_bytes: result.coverage.scanned_code_bytes,
                edges_truncated: result.coverage.summary_depth_limit_reached,
                complete: result.full_scan,
                dense: std::sync::OnceLock::new(),
            },
        );
    }
    graphs
}

/// Key masks of functions whose saved references hit `names`, in scan order, and how many functions
/// were skipped because `deadline` had passed before their task started.
pub(super) fn match_references(
    image: &crate::image::Image,
    references: &[(u64, Vec<u64>)],
    names: &[&str],
    deadline: std::time::Instant,
) -> (Vec<(u64, Vec<bool>)>, usize) {
    let skipped = std::sync::atomic::AtomicUsize::new(0);
    let matched = references
        .par_iter()
        .filter_map(|(function, addresses)| {
            if std::time::Instant::now() > deadline {
                skipped.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                return None;
            }
            let mut found = vec![false; names.len()];
            for &address in addresses {
                mark_key_references(image, address, names, &mut found);
            }
            found.iter().any(|hit| *hit).then_some((*function, found))
        })
        .collect();
    (matched, skipped.into_inner())
}

/// Reuse a complete whole-image scan of this process: only the key matching depends on `names`.
fn apply_full_scan(result: &mut Catalog<'_>, base: &super::session::FullScan, names: &[String]) -> Graphs {
    result.coverage.scan_index_cache_hits = 1;
    result.starts.clone_from(&base.starts);
    result.write_functions.clone_from(&base.write_functions);
    result.coverage.scanned_functions = base.scanned_functions;
    result.coverage.skipped_functions = base.skipped_functions;
    result.coverage.scanned_code_bytes = base.scanned_code_bytes;
    result.coverage.summary_depth_limit_reached |= base.edges_truncated;
    result.full_scan = base.complete;
    let image = result.image;
    let deadline = result.deadline();
    let name_refs = names.iter().map(String::as_str).collect::<Vec<_>>();
    // Each task checks the cooperative deadline; functions not matched in time are reported as
    // skipped, and the scan no longer counts as complete (no writer index reuse, warning in report).
    let (matched, skipped) = match_references(image, &base.references, &name_refs, deadline);
    if skipped > 0 || result.expired() {
        result.coverage.skipped_functions += skipped;
        result.coverage.summary_depth_limit_reached = true;
        result.full_scan = false;
        let _ = result.expired(); // records the budget hit for the result cache
    }
    let mut graphs = Graphs {
        forward: Arc::clone(&base.forward),
        reverse: Arc::clone(&base.reverse),
        seeds: BTreeMap::new(),
        // The compact graph is a one-off build per session; skip it once the budget is spent.
        dense: if result.expired() { None } else { base.dense() },
    };
    for (function, found) in matched {
        record_references(result, &mut graphs.seeds, names, function, &found);
    }
    graphs
}

/// Walk functions (the whole image, or the call tree under `within`), matching keys and building the
/// call graph; functions with static references are appended to `references` in scan order.
fn walk(
    result: &mut Catalog<'_>,
    names: &[String],
    within: Option<&Range<u64>>,
    references: &mut Vec<(u64, Vec<u64>)>,
) -> Graphs {
    let image = result.image;
    let name_refs = names.iter().map(String::as_str).collect::<Vec<_>>();
    let mut seeds = BTreeMap::new();
    let mut forward = CallGraph::new();
    let mut reverse = CallGraph::new();
    let mut bytes = 0_usize;
    let mut edges = 0_usize;
    let mut queue: VecDeque<_> = within.map_or_else(
        || image.functions.iter().cloned().map(|function| (function, 0)).collect(),
        |function| VecDeque::from([(function.clone(), 0)]),
    );
    let cached = within.is_none().then(|| scan_index::load(&result.identity, &image.functions)).flatten();
    result.coverage.scan_index_cache_hits = usize::from(cached.is_some());
    let mut parallel = if within.is_none() && cached.is_none() { parallel_records(result) } else { None };
    let mut records = Vec::new();
    let mut visited = BTreeSet::new();
    let mut position = 0_usize;
    while let Some((range, depth)) = queue.pop_front() {
        let current = position;
        position += 1;
        if !visited.insert(range.start) {
            continue;
        }
        let length = usize::try_from(range.end.saturating_sub(range.start)).unwrap_or(usize::MAX);
        if bytes.saturating_add(length) > MAX_CODE_BYTES
            || result.starts.len() >= MAX_FUNCTIONS
            || (parallel.is_none() && result.expired())
        {
            result.coverage.skipped_functions += 1;
            continue;
        }
        let precomputed = parallel.as_mut().and_then(|records| records.get_mut(current)).and_then(Option::take);
        if parallel.is_some() && precomputed.is_none() {
            result.coverage.skipped_functions += 1;
            continue;
        }
        bytes += length;
        result.coverage.scanned_functions += 1;
        let record = precomputed
            .or_else(|| {
                cached
                    .as_ref()
                    .and_then(|records| records.get(result.coverage.scanned_functions - 1))
                    .filter(|record| record.start == range.start)
                    .cloned()
            })
            .unwrap_or_else(|| scan_index::scan_function(image, &range));
        if record.has_write {
            result.write_functions.insert(range.start);
        }
        let mut found = vec![false; names.len()];
        for &address in &record.references {
            mark_key_references(image, address, &name_refs, &mut found);
        }
        record_references(result, &mut seeds, names, range.start, &found);
        if within.is_none() && !record.references.is_empty() {
            references.push((range.start, record.references.clone()));
        }
        for &target in &record.calls {
            if edges < MAX_EDGES {
                reverse.entry(target).or_default().insert(range.start);
                forward.entry(range.start).or_default().insert(target);
                edges += 1;
            } else {
                result.coverage.summary_depth_limit_reached = true;
            }
            if within.is_some()
                && depth < MAX_DEPTH
                && let Some(function) = image.function_at(target)
            {
                queue.push_back((function.clone(), depth + 1));
            }
        }
        result.starts.insert(range.start, range);
        if within.is_none() && cached.is_none() {
            records.push(record);
        }
    }
    if within.is_none()
        && cached.is_none()
        && result.coverage.skipped_functions == 0
        && records.len() == image.functions.len()
        && edges < MAX_EDGES
        && !result.expired()
    {
        scan_index::save(&result.identity, &records);
    }
    result.full_scan = within.is_none()
        && result.coverage.skipped_functions == 0
        && result.coverage.scanned_functions == image.functions.len();
    result.coverage.scanned_code_bytes = u64::try_from(bytes).unwrap_or(u64::MAX);
    Graphs { forward: Arc::new(forward), reverse: Arc::new(reverse), seeds, dense: None }
}
