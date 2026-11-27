/*
 * XRef — Binary analysis
 * Copyright (c) 2026 Alexander Panasenko
 *
 * Contact: alex@prod.codes
 * Author: https://prod.codes/about/
 * Project: https://github.com/alex09x/xref
 * SPDX-License-Identifier: MIT OR Apache-2.0
 */
use super::aggregate::FunctionKey;
use super::analyze::Analysis;
use crate::image::Image;
use serde::Serialize;
use std::collections::{BTreeMap, BTreeSet};
use std::io::Write;

#[derive(Serialize)]
struct Row {
    /// Function start in the before profile's module (the target image for target rows).
    before: Option<u64>,
    after: Option<u64>,
    before_label: Option<String>,
    after_label: Option<String>,
    /// `target`, or the shared module, kernel or vdso path.
    module: String,
    before_percent: f64,
    after_percent: f64,
    delta_percent: Option<f64>,
    /// `same_image`, `heuristic` (cross-build target match), `same_module` (one library build),
    /// `by_name` (a library or kernel function of the same name in both), or `unmatched`.
    pairing: &'static str,
}

use super::report::{label, percent};

/// A function outside the target, keyed by its printed label (`/usr/lib/…/libc.so.6:memset`).
struct Shared {
    count: u64,
    start: Option<u64>,
    module: String,
    sha256: Option<String>,
}

fn shared_counts(analysis: &Analysis, image: &Image) -> BTreeMap<String, Shared> {
    let mut out: BTreeMap<String, Shared> = BTreeMap::new();
    for (key, counts) in &analysis.aggregate.functions {
        if key.module == 1 || counts.self_samples == 0 {
            continue;
        }
        let module = analysis.modules.iter().find(|module| module.id == key.module);
        let entry = out.entry(label(image, &analysis.modules, *key)).or_insert_with(|| Shared {
            count: 0,
            start: key.start,
            module: module.map_or_else(
                || "unknown".to_owned(),
                |m| if m.path.is_empty() { m.kind.to_owned() } else { m.path.clone() },
            ),
            sha256: module.and_then(|m| m.sha256.clone()),
        });
        entry.count = entry.count.saturating_add(counts.self_samples);
    }
    out
}

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
    let target_label = |image: &Image, analysis: &Analysis, start: u64| {
        label(image, &analysis.modules, FunctionKey { module: 1, start: Some(start) })
    };
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
            before_label: Some(target_label(image, old, address)),
            after_label: target.map(|target| target_label(other, new, target)),
            module: "target".to_owned(),
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
                before_label: (!cross_build).then(|| target_label(image, old, address)),
                after_label: Some(target_label(other, new, address)),
                module: "target".to_owned(),
                before_percent: 0.0,
                after_percent: after,
                delta_percent: if cross_build { None } else { Some(after) },
                pairing: if cross_build { "unmatched" } else { "same_image" },
            });
        }
    }
    // Libraries and the kernel are paired by the function name both reports print; a function
    // missing on one side is 0% there (memset at 65% before, gone after).
    let shared = !heap;
    if shared {
        let old_shared = shared_counts(old, image);
        let mut new_shared = shared_counts(new, other);
        for (name, before) in old_shared {
            let after = new_shared.remove(&name);
            let same_module =
                after.as_ref().is_some_and(|after| after.sha256.is_some() && after.sha256 == before.sha256);
            let (before_percent, after_percent) =
                (percent(before.count, total(old)), percent(after.as_ref().map_or(0, |a| a.count), total(new)));
            rows.push(Row {
                before: before.start,
                after: after.as_ref().and_then(|a| a.start),
                before_label: Some(name.clone()),
                after_label: Some(name),
                module: before.module,
                before_percent,
                after_percent,
                delta_percent: Some(after_percent - before_percent),
                pairing: if same_module { "same_module" } else { "by_name" },
            });
        }
        for (name, after) in new_shared {
            let after_percent = percent(after.count, total(new));
            rows.push(Row {
                before: after.start,
                after: after.start,
                before_label: Some(name.clone()),
                after_label: Some(name),
                module: after.module,
                before_percent: 0.0,
                after_percent,
                delta_percent: Some(after_percent),
                pairing: "by_name",
            });
        }
    }
    rows.retain(|row| row.delta_percent.is_none_or(|delta| delta.abs() >= min_delta));
    rows.sort_by(|a, b| {
        b.delta_percent
            .is_some()
            .cmp(&a.delta_percent.is_some())
            .then_with(|| b.delta_percent.unwrap_or(0.0).abs().total_cmp(&a.delta_percent.unwrap_or(0.0).abs()))
            .then(a.module.cmp(&b.module))
            .then(a.before.cmp(&b.before))
            .then(a.after.cmp(&b.after))
    });
    rows.truncate(top);
    let note = if shared {
        "percentages are sample shares; cross-build target matches are heuristic; library and kernel functions are paired by name"
    } else {
        "percentages are live-byte shares under each target function; cross-build matches are heuristic; shared modules are omitted"
    };
    if json {
        serde_json::to_writer_pretty(
            &mut *out,
            &serde_json::json!({ "rows": rows, "matching_truncated": matching_truncated,
            "before_incomplete": old.aggregate.incomplete, "after_incomplete": new.aggregate.incomplete,
            "note": note }),
        )?;
        writeln!(out)?;
    } else {
        let share = if heap {
            "live-byte share delta (bytes under each function, callees included); shared modules omitted"
        } else {
            "sample-share delta (self samples); libraries and the kernel paired by name"
        };
        writeln!(out, "{share}; cross-build target pairs are heuristic")?;
        if matching_truncated {
            writeln!(out, "warning: cross-build matching limited to 128 hottest old functions")?;
        }
        for row in rows {
            let delta = row.delta_percent.map_or_else(|| "unknown".to_owned(), |value| format!("{value:+.2}%"));
            let change = format!("{:.2}% -> {:.2}%", row.before_percent, row.after_percent);
            writeln!(out, "{delta:>8}  {change:<17} {} [{}]", sides(&row), row.pairing)?;
        }
    }
    Ok(())
}

/// The function of a text diff row: one label when both sides print the same, else both.
fn sides(row: &Row) -> String {
    let side = |label: Option<&String>, address: Option<u64>| {
        label.cloned().or_else(|| address.map(|value| format!("{value:#x}"))).unwrap_or_else(|| "-".to_owned())
    };
    let (before, after) = (side(row.before_label.as_ref(), row.before), side(row.after_label.as_ref(), row.after));
    if before == after { before } else { format!("{before} -> {after}") }
}

/// The image SHA-256 a profile was recorded against.
pub fn recorded_image(path: &std::path::Path) -> Result<String, Box<dyn std::error::Error>> {
    let mut input = std::io::BufReader::new(std::fs::File::open(path)?);
    let reader =
        super::codec::ProfileReader::new(&mut input).map_err(|error| format!("{}: {error}", path.display()))?;
    Ok(reader.header.image_sha256)
}

/// Checks that `before` was recorded against `-b` and `after` against `--other` (or `-b`), and
/// says which side is wrong, and whether the two builds are swapped.
pub fn check_sides(
    before: (&std::path::Path, &str),
    after: (&std::path::Path, &str),
    bin_sha: &str,
    other_sha: Option<&str>,
) -> Result<(), String> {
    let after_expected = other_sha.unwrap_or(bin_sha);
    if before.1 == bin_sha && after.1 == after_expected {
        return Ok(());
    }
    let short = |sha: &str| sha.get(..12).unwrap_or(sha).to_owned();
    if other_sha.is_some_and(|other| before.1 == other && after.1 == bin_sha) {
        return Err(format!(
            "the builds are swapped: {} was recorded against --other ({}) and {} against -b ({}); pass the before-build as -b and the after-build as --other",
            before.0.display(),
            short(before.1),
            after.0.display(),
            short(after.1)
        ));
    }
    let mut problems = Vec::new();
    if before.1 != bin_sha {
        problems.push(format!(
            "{} (before) was recorded against image {}, but -b is {}",
            before.0.display(),
            short(before.1),
            short(bin_sha)
        ));
    }
    if after.1 != after_expected {
        let flag = if other_sha.is_some() { "--other" } else { "-b (pass the after-build as --other)" };
        problems.push(format!(
            "{} (after) was recorded against image {}, but {flag} is {}",
            after.0.display(),
            short(after.1),
            short(after_expected)
        ));
    }
    Err(format!(
        "{}; -b is the build of the before profile, --other the build of the after profile",
        problems.join("; ")
    ))
}

#[cfg(test)]
mod tests {
    use super::{Row, check_sides, sides};
    use std::path::Path;

    fn row(before: Option<u64>, after: Option<u64>, labels: (Option<&str>, Option<&str>)) -> Row {
        Row {
            before,
            after,
            before_label: labels.0.map(str::to_owned),
            after_label: labels.1.map(str::to_owned),
            module: "target".to_owned(),
            before_percent: 0.0,
            after_percent: 0.0,
            delta_percent: None,
            pairing: "heuristic",
        }
    }

    #[test]
    fn text_rows_print_names_once_when_both_sides_agree() {
        let same = row(Some(0x88150), Some(0x87f30), (Some("target:styled_cells"), Some("target:styled_cells")));
        assert_eq!(sides(&same), "target:styled_cells");
        let renamed = row(Some(0x10), Some(0x20), (Some("target:a"), Some("target:b")));
        assert_eq!(sides(&renamed), "target:a -> target:b");
        assert_eq!(sides(&row(Some(0x43_0060), None, (None, None))), "0x430060 -> -");
    }

    #[test]
    fn sha_mismatch_names_the_side_and_detects_swapped_builds() {
        let (b, a) = (Path::new("before.xprof"), Path::new("after.xprof"));
        assert!(check_sides((b, "aa"), (a, "bb"), "aa", Some("bb")).is_ok());
        let error = |result: Result<(), String>| result.err().unwrap_or_default();
        let swapped = error(check_sides((b, "bb"), (a, "aa"), "aa", Some("bb")));
        assert!(swapped.contains("swapped") && swapped.contains("before-build as -b"), "{swapped}");
        let wrong = error(check_sides((b, "cc"), (a, "bb"), "aa", Some("bb")));
        assert!(wrong.contains("before.xprof (before)") && !wrong.contains("after.xprof (after)"), "{wrong}");
        let no_other = error(check_sides((b, "aa"), (a, "bb"), "aa", None));
        assert!(no_other.contains("--other"), "{no_other}");
    }
}
