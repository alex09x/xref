/*
 * XRef — `live alloc` report: allocations, bytes and live bytes by call stack and function
 * Copyright (c) 2026 Alexander Panasenko
 * Contact: alex@prod.codes
 * Author: https://prod.codes/about/
 * Project: https://github.com/alex09x/xref
 * SPDX-License-Identifier: MIT OR Apache-2.0
 */
#![cfg_attr(not(all(target_os = "linux", target_arch = "x86_64")), allow(dead_code, unused_imports))]

use std::collections::HashMap;
use std::io::Write;

use serde::Serialize;

use super::super::analyze::Analysis;
use super::super::heap::render::{human, stacks};

#[derive(Debug, Serialize, PartialEq, Eq)]
pub struct Row {
    pub allocations: u64,
    pub bytes: u64,
    pub live_bytes: u64,
    /// Root first for a stack; one label for a function.
    pub frames: Vec<String>,
}

/// Stacks merged from the three recordings (bytes, allocations, live bytes), by allocations.
pub fn stack_rows(
    bytes: &Analysis,
    count: &Analysis,
    live: &Analysis,
    image: &crate::image::Image,
    top: usize,
) -> Vec<Row> {
    let mut merged: HashMap<Vec<String>, (u64, u64, u64)> = HashMap::new();
    for row in stacks(count, image, usize::MAX) {
        merged.entry(row.frames).or_default().0 += row.bytes;
    }
    for row in stacks(bytes, image, usize::MAX) {
        merged.entry(row.frames).or_default().1 += row.bytes;
    }
    for row in stacks(live, image, usize::MAX) {
        merged.entry(row.frames).or_default().2 += row.bytes;
    }
    let mut rows: Vec<Row> = merged
        .into_iter()
        .map(|(frames, (allocations, bytes, live_bytes))| Row { allocations, bytes, live_bytes, frames })
        .collect();
    rows.sort_by(|a, b| b.allocations.cmp(&a.allocations).then(b.bytes.cmp(&a.bytes)).then(a.frames.cmp(&b.frames)));
    rows.truncate(top);
    rows
}

/// The weight under each function (callees included) of the program and of its libraries, the
/// allocator's own file left out (every allocation is under its `malloc`).
fn weights(analysis: &Analysis, image: &crate::image::Image, allocator: &str) -> HashMap<String, u64> {
    // An allocator linked into the program (module 1) leaves the program's functions in: only the
    // allocator entries themselves, every chain's innermost frame, are left out.
    let entries: std::collections::HashSet<_> =
        analysis.aggregate.path_periods.keys().filter_map(|path| path.last().copied()).collect();
    let mut out = HashMap::new();
    for (key, counts) in &analysis.aggregate.functions {
        let module = analysis.modules.iter().find(|module| module.id == key.module);
        let in_allocator = module.is_some_and(|module| module.path == allocator);
        if key.module == 0 || (in_allocator && key.module != 1) || (key.module == 1 && entries.contains(key)) {
            continue;
        }
        *out.entry(super::super::report::label(image, &analysis.modules, *key)).or_insert(0) += counts.total_period;
    }
    out
}

/// Functions of the program and its libraries by the allocations made under them.
pub fn function_rows(
    bytes: &Analysis,
    count: &Analysis,
    live: &Analysis,
    image: &crate::image::Image,
    allocator: &str,
    top: usize,
) -> Vec<Row> {
    let mut merged: HashMap<String, (u64, u64, u64)> = HashMap::new();
    for (label, weight) in weights(count, image, allocator) {
        merged.entry(label).or_default().0 += weight;
    }
    for (label, weight) in weights(bytes, image, allocator) {
        merged.entry(label).or_default().1 += weight;
    }
    for (label, weight) in weights(live, image, allocator) {
        merged.entry(label).or_default().2 += weight;
    }
    let mut rows: Vec<Row> = merged
        .into_iter()
        .map(|(label, (allocations, bytes, live_bytes))| Row { allocations, bytes, live_bytes, frames: vec![label] })
        .collect();
    rows.sort_by(|a, b| b.allocations.cmp(&a.allocations).then(b.bytes.cmp(&a.bytes)).then(a.frames.cmp(&b.frames)));
    rows.truncate(top);
    rows
}

/// `profile report` on `alloc.xprof` (bytes allocated while observed) or `live.xprof` (bytes still
/// allocated at the end): stacks and functions by those bytes.
#[allow(clippy::cast_precision_loss)] // A percentage needs no more than f64 precision.
pub fn snapshot(
    analysis: &Analysis,
    image: &crate::image::Image,
    top: usize,
    json: bool,
    out: &mut dyn Write,
) -> Result<(), Box<dyn std::error::Error>> {
    let live = analysis.header.event == super::LIVE_EVENT;
    let what = if live { "still allocated at the end" } else { "allocated while observed" };
    let total = analysis.aggregate.total_period;
    let rows = stacks(analysis, image, top);
    // Bytes under each function, callees included, of the program and its libraries; the module
    // holding the allocator entry (every chain's innermost frame) is left out.
    let allocator = allocator_module(analysis);
    let mut by_function: Vec<(String, u64)> = weights(analysis, image, &allocator).into_iter().collect();
    by_function.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(&b.0)));
    by_function.truncate(top);
    let share = |bytes: u64| if total == 0 { 0.0 } else { bytes as f64 * 100.0 / total as f64 };
    if json {
        let functions: Vec<_> = by_function
            .iter()
            .map(|(label, bytes)| serde_json::json!({"label": label, "bytes": bytes, "percent": share(*bytes)}))
            .collect();
        serde_json::to_writer_pretty(
            &mut *out,
            &serde_json::json!({"bytes": total, "measure": what, "stacks": rows, "functions": functions,
                "incomplete": analysis.aggregate.incomplete}),
        )?;
        writeln!(out)?;
        return Ok(());
    }
    writeln!(out, "live alloc recording: {} {what}, {} call stacks", human(total), analysis.aggregate.samples)?;
    if analysis.aggregate.incomplete {
        writeln!(out, "warning: the recording is incomplete (records were lost or threads were not attached)")?;
    }
    writeln!(out, "stacks by bytes (root -> leaf):")?;
    for row in &rows {
        writeln!(out, "{:>11} {:>6.2}%  {}", human(row.bytes), row.percent, row.frames.join(" -> "))?;
    }
    writeln!(out, "functions by bytes (callees included):")?;
    for (label, bytes) in &by_function {
        writeln!(out, "{:>11} {:>6.2}%  {label}", human(*bytes), share(*bytes))?;
    }
    Ok(())
}

/// The path of the module the chains' innermost frames are in (the allocator), when one holds
/// most of them.
fn allocator_module(analysis: &Analysis) -> String {
    let mut by_module: HashMap<u32, u64> = HashMap::new();
    for (path, bytes) in &analysis.aggregate.path_periods {
        if let Some(leaf) = path.last() {
            *by_module.entry(leaf.module).or_insert(0) += bytes;
        }
    }
    by_module
        .into_iter()
        .max_by_key(|(_, bytes)| *bytes)
        .and_then(|(id, _)| analysis.modules.iter().find(|module| module.id == id))
        .map(|module| module.path.clone())
        .unwrap_or_default()
}

/// Folded stacks weighted by bytes, every frame kept (a library caller of the allocator is not
/// folded away): `root;...;leaf BYTES`.
pub fn folded(analysis: &Analysis, image: &crate::image::Image, out: &mut dyn Write) -> std::io::Result<()> {
    let mut lines: Vec<(String, u64)> = analysis
        .aggregate
        .path_periods
        .iter()
        .map(|(path, bytes)| {
            let frames: Vec<String> = path
                .iter()
                .map(|key| super::super::report::label(image, &analysis.modules, *key).replace([';', '\n', '\r'], "_"))
                .collect();
            (frames.join(";"), *bytes)
        })
        .collect();
    lines.sort();
    for (frames, bytes) in lines {
        writeln!(out, "{frames} {bytes}")?;
    }
    Ok(())
}

#[allow(clippy::cast_precision_loss)]
fn rate(count: u64, elapsed_ms: u64) -> f64 {
    if elapsed_ms == 0 { 0.0 } else { count as f64 * 1000.0 / elapsed_ms as f64 }
}

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
pub struct Context<'a> {
    pub allocator: &'a super::symbols::Allocator,
    pub stats: &'a super::capture::AllocStats,
    pub dir: Option<&'a std::path::Path>,
}

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
pub fn report(
    context: &Context<'_>,
    bytes: &Analysis,
    count: &Analysis,
    live: &Analysis,
    image: &crate::image::Image,
    args: &super::AllocArgs,
    out: &mut dyn Write,
) -> Result<(), Box<dyn std::error::Error>> {
    let stats = context.stats;
    let stack_table = stack_rows(bytes, count, live, image, args.top);
    let function_table = function_rows(bytes, count, live, image, &context.allocator.path, args.top);
    if args.json {
        serde_json::to_writer_pretty(
            &mut *out,
            &serde_json::json!({
                "allocator": context.allocator,
                "capture": stats,
                "allocations_per_second": rate(stats.allocations, stats.elapsed_ms),
                "stacks": stack_table,
                "functions": function_table,
                "recordings": context.dir,
                "caveat": "only the outermost allocator call of a thread counts; live bytes are blocks allocated while observed and not freed by the end; libraries loaded during the capture are not unwound",
            }),
        )?;
        writeln!(out)?;
        return Ok(());
    }
    writeln!(
        out,
        "live alloc: {} ms, allocator {} ({} threads, {} unattached, {} lost and {} undecoded records, stop {})",
        stats.elapsed_ms,
        context.allocator.path,
        stats.threads,
        stats.unattached_threads,
        stats.lost,
        stats.undecoded,
        stats.stop_reason
    )?;
    writeln!(
        out,
        "allocations: {} ({:.1}/s), {}; frees: {} ({} of blocks from before), reallocs: {}",
        stats.allocations,
        rate(stats.allocations, stats.elapsed_ms),
        human(stats.allocated_bytes),
        stats.frees,
        stats.frees_of_earlier_blocks,
        stats.reallocations
    )?;
    writeln!(
        out,
        "live at the end: {} in {} blocks allocated while observed",
        human(stats.live_bytes),
        stats.live_blocks
    )?;
    if !stack_table.is_empty() {
        writeln!(out, "stacks by allocations (root -> leaf):")?;
        writeln!(out, "  {:>9} {:>11} {:>11}  stack", "allocs", "bytes", "live")?;
        for row in &stack_table {
            writeln!(
                out,
                "  {:>9} {:>11} {:>11}  {}",
                row.allocations,
                human(row.bytes),
                human(row.live_bytes),
                row.frames.join(" -> ")
            )?;
        }
    }
    if !function_table.is_empty() {
        writeln!(out, "functions by allocations (callees included):")?;
        writeln!(out, "  {:>9} {:>11} {:>11}  function", "allocs", "bytes", "live")?;
        for row in &function_table {
            writeln!(
                out,
                "  {:>9} {:>11} {:>11}  {}",
                row.allocations,
                human(row.bytes),
                human(row.live_bytes),
                row.frames.join("")
            )?;
        }
    }
    if let Some(dir) = context.dir {
        writeln!(out, "recordings: {} (alloc.xprof, live.xprof; compare with `xref profile diff A B`)", dir.display())?;
    }
    if !context.allocator.alternatives.is_empty() {
        writeln!(
            out,
            "warning: {} also export malloc and free; calls the process makes to them are not seen",
            context.allocator.alternatives.join(", ")
        )?;
    }
    if stats.allocations == 0 && stats.frees == 0 {
        writeln!(out, "note: no successful allocation or free was recorded while observed")?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    #[test]
    fn rates_are_per_second() {
        assert!((super::rate(500, 2000) - 250.0).abs() < 1e-9);
        assert!(super::rate(1, 0).abs() < 1e-9);
    }
}
