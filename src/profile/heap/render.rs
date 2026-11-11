/*
 * XRef — `live heap` report: call stacks and functions by the bytes they hold
 * Copyright (c) 2026 Alexander Panasenko
 * Contact: alex@prod.codes
 * Author: https://prod.codes/about/
 * Project: https://github.com/alex09x/xref
 * SPDX-License-Identifier: MIT OR Apache-2.0
 */

use std::io::Write;
use std::path::PathBuf;

use serde::Serialize;

use super::super::analyze::Analysis;
use super::super::report::label;

#[derive(Debug, Serialize, PartialEq)]
pub struct StackRow {
    pub bytes: u64,
    pub percent: f64,
    /// Root first.
    pub frames: Vec<String>,
}

#[derive(Debug, Serialize, PartialEq)]
pub struct FunctionRow {
    pub label: String,
    pub total_bytes: u64,
    pub self_bytes: u64,
    pub percent: f64,
}

#[allow(clippy::cast_precision_loss)] // A percentage needs no more than f64 precision.
fn percent(part: u64, total: u64) -> f64 {
    if total == 0 { 0.0 } else { part as f64 * 100.0 / total as f64 }
}

/// `12.3 GiB`, `512.0 MiB`, `4.0 KiB`.
#[must_use]
#[allow(clippy::cast_precision_loss)] // One decimal of a size needs no more than f64 precision.
pub fn human(bytes: u64) -> String {
    let units = [("GiB", 30), ("MiB", 20), ("KiB", 10)];
    for (unit, shift) in units {
        if bytes >= 1 << shift {
            return format!("{:.1} {unit}", bytes as f64 / (1_u64 << shift) as f64);
        }
    }
    format!("{bytes} B")
}

pub fn stacks(analysis: &Analysis, image: &crate::image::Image, top: usize) -> Vec<StackRow> {
    let total = analysis.aggregate.total_period;
    let mut rows: Vec<StackRow> = analysis
        .aggregate
        .path_periods
        .iter()
        .map(|(path, bytes)| StackRow {
            bytes: *bytes,
            percent: percent(*bytes, total),
            frames: path.iter().map(|key| label(image, &analysis.modules, *key)).collect(),
        })
        .collect();
    rows.sort_by(|a, b| b.bytes.cmp(&a.bytes).then_with(|| a.frames.cmp(&b.frames)));
    rows.truncate(top);
    rows
}

pub fn functions(analysis: &Analysis, image: &crate::image::Image, top: usize) -> Vec<FunctionRow> {
    let total = analysis.aggregate.total_period;
    let mut rows: Vec<FunctionRow> = analysis
        .aggregate
        .functions
        .iter()
        .map(|(key, counts)| FunctionRow {
            label: label(image, &analysis.modules, *key),
            total_bytes: counts.total_period,
            self_bytes: counts.self_period,
            percent: percent(counts.total_period, total),
        })
        .collect();
    rows.sort_by(|a, b| b.total_bytes.cmp(&a.total_bytes).then_with(|| a.label.cmp(&b.label)));
    rows.truncate(top);
    rows
}

/// Folded stacks weighted by bytes: `root;...;leaf BYTES`.
pub fn folded(analysis: &Analysis, image: &crate::image::Image, out: &mut dyn Write) -> std::io::Result<()> {
    for row in stacks(analysis, image, usize::MAX) {
        writeln!(out, "{} {}", row.frames.join(";"), row.bytes)?;
    }
    Ok(())
}

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
pub fn report(
    analysis: &Analysis,
    image: &crate::image::Image,
    stats: &super::capture::HeapStats,
    snapshots: &[(PathBuf, u64)],
    args: &super::HeapArgs,
    out: &mut dyn Write,
) -> Result<(), Box<dyn std::error::Error>> {
    let live = analysis.aggregate.total_period;
    let (stack_rows, function_rows) = (stacks(analysis, image, args.top), functions(analysis, image, args.top));
    if args.json {
        let snaps: Vec<_> = snapshots
            .iter()
            .map(|(path, bytes)| serde_json::json!({"path": args.out.as_ref().map(|_| path), "live_bytes": bytes}))
            .collect();
        serde_json::to_writer_pretty(
            &mut *out,
            &serde_json::json!({
                "capture": stats, "live_bytes": live, "sample_bytes": args.sample_bytes,
                "snapshots": snaps, "stacks": stack_rows, "functions": function_rows,
                "caveat": "bytes mapped by memory syscalls while observed; small allocations are sampled by arena growth and freed small objects are not returned to the kernel (high-water)",
            }),
        )?;
        writeln!(out)?;
        return Ok(());
    }
    writeln!(
        out,
        "live heap: {} mapped while observed ({} memory syscalls, {} lost, {} threads, {} ms, stop {})",
        human(live),
        stats.events,
        stats.lost,
        stats.threads,
        stats.elapsed_ms,
        stats.stop_reason
    )?;
    if snapshots.len() > 1 {
        let series: Vec<String> = snapshots.iter().map(|(_, bytes)| human(*bytes)).collect();
        writeln!(out, "snapshots: {}", series.join(" -> "))?;
    }
    if let Some(dir) = &args.out {
        writeln!(out, "recordings: {} (compare two with `xref profile diff A B`)", dir.display())?;
    }
    writeln!(out, "stacks by live bytes (root -> leaf):")?;
    for row in &stack_rows {
        writeln!(out, "{:>11} {:>6.2}%  {}", human(row.bytes), row.percent, row.frames.join(" -> "))?;
    }
    writeln!(out, "functions by live bytes (including callees):")?;
    for row in &function_rows {
        writeln!(
            out,
            "{:>11} {:>6.2}%  self {:>11}  {}",
            human(row.total_bytes),
            row.percent,
            human(row.self_bytes),
            row.label
        )?;
    }
    if live == 0 {
        writeln!(
            out,
            "note: no anonymous memory was mapped while observed; memory mapped before xref attached is not attributed (start the capture with the run)"
        )?;
    }
    Ok(())
}

/// `profile report` on a heap snapshot: stacks and functions by the bytes they hold.
pub fn snapshot(
    analysis: &Analysis,
    image: &crate::image::Image,
    top: usize,
    json: bool,
    out: &mut dyn Write,
) -> Result<(), Box<dyn std::error::Error>> {
    let live = analysis.aggregate.total_period;
    let (stack_rows, function_rows) = (stacks(analysis, image, top), functions(analysis, image, top));
    if json {
        serde_json::to_writer_pretty(
            &mut *out,
            &serde_json::json!({"live_bytes": live, "stacks": stack_rows, "functions": function_rows}),
        )?;
        writeln!(out)?;
        return Ok(());
    }
    writeln!(out, "heap snapshot: {} held by {} kept stacks", human(live), analysis.aggregate.samples)?;
    writeln!(out, "stacks by live bytes (root -> leaf):")?;
    for row in &stack_rows {
        writeln!(out, "{:>11} {:>6.2}%  {}", human(row.bytes), row.percent, row.frames.join(" -> "))?;
    }
    writeln!(out, "functions by live bytes (including callees):")?;
    for row in &function_rows {
        writeln!(
            out,
            "{:>11} {:>6.2}%  self {:>11}  {}",
            human(row.total_bytes),
            row.percent,
            human(row.self_bytes),
            row.label
        )?;
    }
    Ok(())
}

/// `profile report --within FN` on a heap snapshot: the bytes under each direct callee of FN
/// (`(in FN)` for what FN itself allocated), largest first.
pub fn callees(
    analysis: &Analysis,
    image: &crate::image::Image,
    within: &std::collections::BTreeSet<u64>,
    top: usize,
    json: bool,
    out: &mut dyn Write,
) -> Result<(), Box<dyn std::error::Error>> {
    let mut by_child: std::collections::BTreeMap<String, u64> = std::collections::BTreeMap::new();
    let mut under = 0;
    for (path, bytes) in &analysis.aggregate.path_periods {
        let Some(at) = path.iter().position(|key| key.module == 1 && key.start.is_some_and(|s| within.contains(&s)))
        else {
            continue;
        };
        under += bytes;
        let child = path.get(at + 1).map_or_else(
            || format!("(in {})", label(image, &analysis.modules, path[at])),
            |key| label(image, &analysis.modules, *key),
        );
        *by_child.entry(child).or_insert(0) += bytes;
    }
    let mut rows: Vec<(String, u64)> = by_child.into_iter().collect();
    rows.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(&b.0)));
    rows.truncate(top);
    if json {
        let rows: Vec<_> = rows.iter().map(|(label, bytes)| serde_json::json!({"callee": label, "bytes": bytes, "percent": percent(*bytes, under)})).collect();
        serde_json::to_writer_pretty(&mut *out, &serde_json::json!({"under_bytes": under, "callees": rows}))?;
        writeln!(out)?;
        return Ok(());
    }
    writeln!(out, "{} under the --within functions, by direct callee:", human(under))?;
    for (label, bytes) in &rows {
        writeln!(out, "{:>11} {:>6.2}%  {label}", human(*bytes), percent(*bytes, under))?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::human;

    #[test]
    fn sizes_read_in_binary_units() {
        assert_eq!(human(512), "512 B");
        assert_eq!(human(4096), "4.0 KiB");
        assert_eq!(human(3 << 29), "1.5 GiB");
    }
}
