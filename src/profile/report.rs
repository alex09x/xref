/*
 * XRef — profile report rendering
 * Copyright (c) 2026 Alexander Panasenko
 * Contact: alex@prod.codes
 * Author: https://prod.codes/about/
 * Project: https://github.com/alex09x/xref
 * SPDX-License-Identifier: MIT OR Apache-2.0
 */
use super::{
    aggregate::{Counts, FunctionKey},
    analyze::Analysis,
    blocks::BlockRow,
    resolve::Module,
    types::{Footer, Header},
};
use serde::Serialize;
use std::io::{self, Write};

#[derive(Debug, Serialize)]
pub struct FunctionRow {
    pub function: FunctionKey,
    pub label: String,
    pub counts: Counts,
    pub self_percent: f64,
    pub total_percent: f64,
}

#[derive(Debug, Serialize)]
pub struct InstructionRow {
    pub function: FunctionKey,
    pub address: u64,
    pub samples: u64,
    pub percent: f64,
}

#[derive(Debug, Serialize)]
pub struct PathRow {
    pub frames: Vec<FunctionKey>,
    pub samples: u64,
    pub percent: f64,
}

#[derive(Debug, Serialize)]
pub struct Report {
    pub schema_version: u32,
    pub header: Header,
    pub footer: Footer,
    pub samples: u64,
    pub total_period: u64,
    pub ignored_samples: u64,
    pub unresolved_frames: u64,
    pub incomplete: bool,
    pub modules: Vec<Module>,
    pub functions: Vec<FunctionRow>,
    pub instructions: Vec<InstructionRow>,
    pub blocks: Vec<BlockRow>,
    pub paths: Vec<PathRow>,
    pub warnings: Vec<String>,
}

#[allow(clippy::cast_precision_loss)] // Percentages are display estimates, counts remain exact u64 values.
pub(super) fn percent(count: u64, total: u64) -> f64 {
    if total == 0 { 0.0 } else { (count as f64) * 100.0 / (total as f64) }
}

fn label(image: &crate::image::Image, modules: &[Module], function: FunctionKey) -> String {
    let module = modules.iter().find(|module| module.id == function.module);
    let name =
        module.map_or("unknown", |module| if module.path.is_empty() { module.kind } else { module.path.as_str() });
    function.start.map_or_else(
        || format!("{name}:unknown"),
        |address| {
            let symbol = (function.module == 1)
                .then(|| image.symbols.binary_search_by_key(&address, |(va, _)| *va).ok())
                .flatten()
                .and_then(|index| image.symbols.get(index))
                .map(|(_, symbol)| symbol.as_str());
            symbol.map_or_else(|| format!("{name}:fn_{address:x}"), |symbol| format!("{name}:{symbol}"))
        },
    )
}

pub fn build(analysis: &Analysis, image: &crate::image::Image, top: usize) -> Result<Report, String> {
    if !(1..=10_000).contains(&top) {
        return Err("profile --top must be in 1..=10000".to_owned());
    }
    let samples = analysis.aggregate.samples;
    let mut functions: Vec<_> = analysis
        .aggregate
        .functions
        .iter()
        .map(|(function, counts)| FunctionRow {
            function: *function,
            label: label(image, &analysis.modules, *function),
            counts: *counts,
            self_percent: percent(counts.self_samples, samples),
            total_percent: percent(counts.total_samples, samples),
        })
        .collect();
    functions.sort_by(|a, b| {
        b.counts
            .self_samples
            .cmp(&a.counts.self_samples)
            .then_with(|| b.counts.total_samples.cmp(&a.counts.total_samples))
            .then_with(|| a.function.cmp(&b.function))
    });
    let mut instructions: Vec<_> = analysis
        .aggregate
        .instructions
        .iter()
        .map(|((function, address), count)| InstructionRow {
            function: *function,
            address: *address,
            samples: *count,
            percent: percent(*count, samples),
        })
        .collect();
    instructions
        .sort_by(|a, b| b.samples.cmp(&a.samples).then_with(|| (a.function, a.address).cmp(&(b.function, b.address))));
    let mut paths: Vec<_> = analysis
        .aggregate
        .paths
        .iter()
        .map(|(frames, count)| PathRow { frames: frames.clone(), samples: *count, percent: percent(*count, samples) })
        .collect();
    paths.sort_by(|a, b| b.samples.cmp(&a.samples).then_with(|| a.frames.cmp(&b.frames)));
    let mut blocks = super::blocks::collect(image, &analysis.aggregate);
    functions.truncate(top);
    instructions.truncate(top);
    blocks.truncate(top);
    paths.truncate(top);
    Ok(Report {
        schema_version: 1,
        header: analysis.header.clone(),
        footer: analysis.footer.clone(),
        samples,
        total_period: analysis.aggregate.total_period,
        ignored_samples: analysis.ignored_samples,
        unresolved_frames: analysis.unresolved_frames,
        incomplete: analysis.aggregate.incomplete,
        modules: analysis.modules.clone(),
        functions,
        instructions,
        blocks,
        paths,
        warnings: analysis.warnings.iter().cloned().collect(),
    })
}

pub fn folded(analysis: &Analysis, image: &crate::image::Image, output: &mut dyn Write) -> io::Result<()> {
    let mut paths: Vec<_> = analysis.aggregate.paths.iter().collect();
    paths.sort_unstable_by_key(|(a, _)| *a);
    for (frames, count) in paths {
        let stack = frames
            .iter()
            .map(|frame| label(image, &analysis.modules, *frame).replace([';', '\n', '\r'], "_"))
            .collect::<Vec<_>>()
            .join(";");
        writeln!(output, "{stack} {count}")?;
    }
    Ok(())
}

pub fn write(
    analysis: &Analysis,
    image: &crate::image::Image,
    top: usize,
    by: super::cli::GroupBy,
    json: bool,
    output: &mut dyn Write,
) -> Result<(), Box<dyn std::error::Error>> {
    if matches!(by, super::cli::GroupBy::Line) {
        let (mut lines, unresolved, truncated) = super::lines::collect(image, &analysis.aggregate)?;
        lines.truncate(top);
        if json {
            serde_json::to_writer_pretty(
                &mut *output,
                &serde_json::json!({ "lines": lines, "unresolved_samples": unresolved, "line_budget_exhausted": truncated,
                "incomplete": analysis.aggregate.incomplete || truncated }),
            )?;
            writeln!(output)?;
        } else {
            for row in lines {
                writeln!(output, "{:>7.2}% {:>10} {}:{}", row.percent, row.samples, row.file, row.line)?;
            }
            writeln!(output, "unresolved samples: {unresolved}; line budget exhausted: {truncated}")?;
        }
        return Ok(());
    }
    let report = build(analysis, image, top)?;
    if json {
        serde_json::to_writer_pretty(&mut *output, &report)?;
        writeln!(output)?;
        return Ok(());
    }
    writeln!(
        output,
        "{} samples, {} lost, {} dropped; partial={}",
        report.samples, report.footer.lost, report.footer.dropped, report.incomplete
    )?;
    match by {
        super::cli::GroupBy::Function => {
            for row in &report.functions {
                writeln!(
                    output,
                    "{:>7.2}% self {:>7.2}% total {:>10} {}",
                    row.self_percent, row.total_percent, row.counts.self_samples, row.label
                )?;
            }
        }
        super::cli::GroupBy::Block => {
            for row in &report.blocks {
                writeln!(
                    output,
                    "{:>7.2}% {:>10} {:#x}..{:#x}{}",
                    row.percent,
                    row.samples,
                    row.start,
                    row.end,
                    if row.cfg_incomplete { " [incomplete CFG]" } else { "" }
                )?;
            }
        }
        super::cli::GroupBy::Instruction => {
            for row in &report.instructions {
                writeln!(output, "{:>7.2}% {:>10} {:#x}", row.percent, row.samples, row.address)?;
            }
        }
        super::cli::GroupBy::CallerPath => {
            for row in &report.paths {
                let stack = row
                    .frames
                    .iter()
                    .map(|frame| label(image, &analysis.modules, *frame))
                    .collect::<Vec<_>>()
                    .join(" -> ");
                writeln!(output, "{:>7.2}% {:>10} {stack}", row.percent, row.samples)?;
            }
        }
        super::cli::GroupBy::Line => unreachable!(),
    }
    for warning in &report.warnings {
        writeln!(output, "warning: {warning}")?;
    }
    Ok(())
}
