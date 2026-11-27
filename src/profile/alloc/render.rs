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
use super::super::heap::render::{functions, human, stacks};

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

/// The program's functions by the allocations made under them (callees included).
pub fn function_rows(
    bytes: &Analysis,
    count: &Analysis,
    live: &Analysis,
    image: &crate::image::Image,
    top: usize,
) -> Vec<Row> {
    let mut merged: HashMap<String, (u64, u64, u64)> = HashMap::new();
    for row in functions(count, image, usize::MAX) {
        merged.entry(row.label).or_default().0 += row.total_bytes;
    }
    for row in functions(bytes, image, usize::MAX) {
        merged.entry(row.label).or_default().1 += row.total_bytes;
    }
    for row in functions(live, image, usize::MAX) {
        merged.entry(row.label).or_default().2 += row.total_bytes;
    }
    let mut rows: Vec<Row> = merged
        .into_iter()
        .map(|(label, (allocations, bytes, live_bytes))| Row { allocations, bytes, live_bytes, frames: vec![label] })
        .collect();
    rows.sort_by(|a, b| b.allocations.cmp(&a.allocations).then(b.bytes.cmp(&a.bytes)).then(a.frames.cmp(&b.frames)));
    rows.truncate(top);
    rows
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
    let function_table = function_rows(bytes, count, live, image, args.top);
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
        "live alloc: {} ms, allocator {} ({} threads, {} lost and {} undecoded records, stop {})",
        stats.elapsed_ms, context.allocator.path, stats.threads, stats.lost, stats.undecoded, stats.stop_reason
    )?;
    writeln!(
        out,
        "allocations: {} ({:.1}/s), {}; frees: {} (+{} of blocks from before), reallocs: {}",
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
    if stats.allocations == 0 && stats.frees == 0 {
        writeln!(out, "note: the process made no allocator calls while observed")?;
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
