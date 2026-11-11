/*
 * XRef — Binary analysis
 * Copyright (c) 2026 Alexander Panasenko
 * Contact: alex@prod.codes
 * Author: https://prod.codes/about/
 * Project: https://github.com/alex09x/xref
 * SPDX-License-Identifier: MIT OR Apache-2.0
 */
use super::analyze::Analysis;
use crate::image::Image;
use serde::Serialize;
use std::collections::{BTreeMap, BTreeSet};
use std::io::Write;

#[derive(Serialize)]
struct Row {
    before: Option<u64>,
    after: Option<u64>,
    before_percent: f64,
    after_percent: f64,
    delta_percent: Option<f64>,
    pairing: &'static str,
}

use super::report::percent;

#[allow(clippy::too_many_arguments, clippy::too_many_lines)] // Rendering keeps the two analyses and their matching policy together.
pub fn write(
    image: &Image,
    other: &Image,
    old: &Analysis,
    new: &Analysis,
    cross_build: bool,
    top: usize,
    json: bool,
    min_delta: f64,
    out: &mut dyn Write,
) -> Result<(), Box<dyn std::error::Error>> {
    if old.pt_aggregate.is_some() || new.pt_aggregate.is_some() {
        return Err("separate PT instruction diff is not yet supported".into());
    }
    if !(1..=128).contains(&top) {
        return Err("profile diff --top must be 1..=128".into());
    }
    // A heap snapshot weighs stacks by bytes and its leaf is the allocator (in libc): compare
    // the bytes under each target function (inclusive) rather than CPU self samples.
    let heap = old.header.event == super::heap::EVENT || new.header.event == super::heap::EVENT;
    let target_counts = |analysis: &Analysis| -> BTreeMap<u64, u64> {
        analysis
            .aggregate
            .functions
            .iter()
            .filter_map(|(key, counts)| {
                (key.module == 1).then_some((key.start?, if heap { counts.total_period } else { counts.self_samples }))
            })
            .collect()
    };
    let total = |analysis: &Analysis| if heap { analysis.aggregate.total_period } else { analysis.aggregate.samples };
    let old_counts = target_counts(old);
    let new_counts = target_counts(new);
    let mut selected: Vec<_> = old_counts.iter().map(|(&address, &count)| (address, count)).collect();
    selected.sort_by(|a, b| b.1.cmp(&a.1).then(a.0.cmp(&b.0)));
    let matching_truncated = cross_build && selected.len() > 128;
    if cross_build {
        selected.truncate(128);
    }
    let mut pairs = BTreeMap::new();
    if cross_build && !selected.is_empty() {
        let specs = selected.iter().map(|(address, _)| format!("{address:#x}")).collect::<Vec<_>>();
        let matches =
            crate::matching::match_images_report(image, other, &specs, crate::matching::MatchOptions::default())?;
        let mut used = BTreeSet::new();
        for result in matches {
            if !result.ambiguous
                && let Some(candidate) = result.selected
                && used.insert(candidate.range.start)
            {
                pairs.insert(result.query.start, candidate.range.start);
            }
        }
    } else if !cross_build {
        for &address in old_counts.keys() {
            pairs.insert(address, address);
        }
    }
    let mut used = BTreeSet::new();
    let mut rows = Vec::new();
    for (&address, &count) in &old_counts {
        let target = pairs.get(&address).copied();
        if let Some(target) = target {
            used.insert(target);
        }
        let before = percent(count, total(old));
        let after = percent(target.and_then(|target| new_counts.get(&target)).copied().unwrap_or(0), total(new));
        rows.push(Row {
            before: Some(address),
            after: target,
            before_percent: before,
            after_percent: after,
            delta_percent: target.map(|_| after - before),
            pairing: if target.is_none() {
                "unmatched"
            } else if cross_build {
                "heuristic"
            } else {
                "same_image"
            },
        });
    }
    for (&address, &count) in &new_counts {
        if !used.contains(&address) {
            let after = percent(count, total(new));
            rows.push(Row {
                before: if cross_build { None } else { Some(address) },
                after: Some(address),
                before_percent: 0.0,
                after_percent: after,
                delta_percent: if cross_build { None } else { Some(after) },
                pairing: if cross_build { "unmatched" } else { "same_image" },
            });
        }
    }
    rows.retain(|row| row.delta_percent.is_none_or(|delta| delta.abs() >= min_delta));
    rows.sort_by(|a, b| {
        b.delta_percent
            .is_some()
            .cmp(&a.delta_percent.is_some())
            .then_with(|| b.delta_percent.unwrap_or(0.0).abs().total_cmp(&a.delta_percent.unwrap_or(0.0).abs()))
            .then(a.before.cmp(&b.before))
            .then(a.after.cmp(&b.after))
    });
    rows.truncate(top);
    if json {
        serde_json::to_writer_pretty(
            &mut *out,
            &serde_json::json!({ "rows": rows, "matching_truncated": matching_truncated,
            "before_incomplete": old.aggregate.incomplete, "after_incomplete": new.aggregate.incomplete,
            "note": "percentages are sample shares; cross-build matches are heuristic; shared modules are omitted" }),
        )?;
        writeln!(out)?;
    } else {
        let share = if heap {
            "live-byte share delta (bytes under each function, callees included)"
        } else {
            "sample-share delta"
        };
        writeln!(out, "{share}; cross-build pairs are heuristic; shared modules omitted")?;
        if matching_truncated {
            writeln!(out, "warning: cross-build matching limited to 128 hottest old functions")?;
        }
        for row in rows {
            let delta = row.delta_percent.map_or_else(|| "unknown".to_owned(), |value| format!("{value:+.2}%"));
            writeln!(out, "{delta:>8}  {} -> {} [{}]", side(row.before), side(row.after), row.pairing)?;
        }
    }
    Ok(())
}

/// One side of a text diff row: the function address, or `-` when that profile has no counterpart.
fn side(address: Option<u64>) -> String {
    address.map_or_else(|| "-".to_owned(), |value| format!("{value:#x}"))
}

#[cfg(test)]
mod tests {
    #[test]
    fn text_rows_print_plain_addresses_not_debug_options() {
        assert_eq!(super::side(Some(0x43_0060)), "0x430060");
        assert_eq!(super::side(None), "-");
    }
}
