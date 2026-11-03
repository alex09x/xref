/*
 * xref — Ultra blazing fast cross-references of an x86-64 ELF binary
 * Copyright (c) 2026 Alexander Panasenko
 *
 * Contact: alex@prod.codes
 * Author: https://prod.codes/about/
 * SPDX-License-Identifier: MIT OR Apache-2.0
 */

//! Command dispatch and the reference commands: stats, func, refs, imm, callers and error.

use std::collections::HashMap;
use std::error::Error;
use std::io::Write;
use std::ops::{Range, RangeInclusive};

use crate::cli::{Command, hex_address};
use crate::image::Image;
use crate::reach::{reach, windows};
use crate::scan::{self, Hit, Query};
use crate::tables::{Table, arm_indices, tables};
use crate::{listing, source};

pub type Res = Result<(), Box<dyn Error>>;

pub fn function(image: &Image, addr: u64) -> Result<Range<u64>, Box<dyn Error>> {
    image.function_at(addr).ok_or_else(|| format!("no function contains {addr:#x}").into())
}

pub fn print_hits(out: &mut dyn Write, hits: &[Hit]) -> Res {
    for hit in hits {
        writeln!(out, "{:#x}  in {:#x}  {}", hit.ip, hit.function.start, hit.text)?;
    }
    writeln!(out, "{} hits", hits.len())?;
    Ok(())
}

pub fn run(image: &Image, command: Command, out: &mut dyn Write) -> Res {
    match command {
        Command::Query { .. } | Command::Mcp { .. } | Command::Live(_) => {
            Err("structured and live modes require the process-level dispatcher".into())
        }
        Command::Stats => stats(image, out),
        Command::Sym { pattern } => {
            let matched: Vec<_> = image.symbols.iter().filter(|(_, name)| name.contains(&pattern)).collect();
            for (addr, name) in &matched {
                writeln!(out, "{addr:#x}  {name}")?;
            }
            writeln!(out, "{} symbols", matched.len())?;
            Ok(())
        }
        Command::Func { addrs } => func(image, &addrs, out),
        Command::Refs { targets, back: _, inline: true } | Command::Istr { targets } => {
            crate::inline::refs_inline(image, &targets, out)
        }
        Command::Refs { targets, back, inline: false } => refs(image, &targets, back, out),
        Command::Imm { value, store, cmp, within } => scoped(image, within, &Query::Imm { value, store, cmp }, out),
        Command::Disp { values, write, lea, all, stride, stack, within } => {
            disp(image, &values, crate::disp::DispOptions { write, lea, stride, stack }, all, within, out)
        }
        Command::Callers { addr } => callers(image, addr, out),
        Command::Calls { addr } => listing::calls(image, addr, out),
        Command::Args { addr, max } => crate::args::args(image, &addr, max, out),
        Command::Find { calls, refs, imm, store, cmp, disp, write, lea, src, size, any, back } => {
            let (imm_mode, disp_mode) = ((store, cmp), (write, lea));
            crate::find::find(
                image,
                &crate::find::FindSpec { calls, refs, imm, imm_mode, disp, disp_mode, src, size, any, back },
                out,
            )
        }
        Command::Path { from, to, depth } => crate::graph::path(image, &from, &to, depth, out),
        Command::Tree { addr, callers, callees: _, depth } => crate::graph::tree(image, &addr, callers, depth, out),
        Command::Match { other, addrs, top } => {
            crate::matching::match_images(image, &Image::load(&other)?, &addrs, top, out)
        }
        Command::Asm { addr, from, to } => listing::asm(image, addr, from, to, out),
        Command::C { addrs, from, to, out: out_dir, fields, keep_gotos } => {
            if keep_gotos {
                crate::dump::decomp_with_mode(image, &addrs, (from, to), fields, true, out_dir.as_deref(), out)
            } else {
                crate::dump::decomp(image, &addrs, from, to, fields, out_dir.as_deref(), out)
            }
        }
        Command::Slice { addr, to, fields, keep_gotos } => {
            if keep_gotos {
                crate::slice::slice_fn_with_mode(image, &addr, &to, fields, true, out)
            } else {
                crate::slice::slice_fn(image, &addr, &to, fields, out)
            }
        }
        Command::DiffC { other, addrs, target, fields } => {
            crate::diffc::diff_c(image, &Image::load(&other)?, &addrs, target.as_deref(), fields, out)
        }
        Command::Dump { out: out_dir, src, fields, keep_gotos } => {
            if keep_gotos {
                crate::dump::dump_tree_with_mode(image, &out_dir, src.as_deref(), fields, true, out)
            } else {
                crate::dump::dump_tree(image, &out_dir, src.as_deref(), fields, out)
            }
        }
        Command::Error { text, back } => error(image, &text, back, out),
        Command::Variant { addr, indices } => {
            let indices: Vec<usize> = indices.iter().filter_map(|index| usize::try_from(*index).ok()).collect();
            crate::variant::variants(image, addr, &indices, out)
        }
        Command::Arm { addrs } => crate::variant::arms(image, &addrs, out),
        Command::Src { addr } => source::src(image, addr, out),
        Command::Where { pattern, line } => source::places(image, &pattern, line, out),
        Command::Files { pattern } => source::files(image, pattern.as_deref(), out),
        Command::Layout { addr, reg, callees } => crate::layout::layout(image, &addr, &reg, callees, out),
    }
}

/// Hits of `query` in every function, or only in the one containing `within`.
fn scoped(image: &Image, within: Option<u64>, query: &Query, out: &mut dyn Write) -> Res {
    let one;
    let functions: &[Range<u64>] = match within {
        Some(addr) => {
            one = [function(image, addr)?];
            &one
        }
        None => &image.functions,
    };
    print_hits(out, &scan::search_in(image, functions, query))
}

fn disp(
    image: &Image,
    values: &[u64],
    options: crate::disp::DispOptions,
    all: bool,
    within: Option<u64>,
    out: &mut dyn Write,
) -> Res {
    let one;
    let functions: &[Range<u64>] = match within {
        Some(addr) => {
            one = [function(image, addr)?];
            &one
        }
        None => &image.functions,
    };
    let hits = if options.stack {
        crate::disp::search(image, functions, values, options)
    } else {
        scan::search_disp(image, functions, values, options.write, options.lea, options.stride)
    };
    if !all {
        let plain: Vec<Hit> = hits.into_iter().map(|d| d.hit).collect();
        return print_hits(out, &plain);
    }
    let matched = crate::disp::summarize(hits, values);
    for summary in &matched {
        let counts: Vec<String> =
            summary.counts.iter().map(|(offset, count)| format!("{offset:#x}: {count}")).collect();
        let stack_note = if options.stack {
            let mut note = format!("  ; {} stack hits", summary.stack_hits);
            if !summary.anchors.is_empty() {
                let frames: Vec<String> = summary
                    .anchors
                    .iter()
                    .map(
                        |frame| {
                            if *frame < 0 { format!("-{:#x}", frame.unsigned_abs()) } else { format!("{frame:#x}") }
                        },
                    )
                    .collect();
                note.push_str("; anchors (entry rsp): ");
                note.push_str(&frames.join(", "));
            }
            note
        } else {
            String::new()
        };
        writeln!(
            out,
            "{:#x}..{:#x}  {} hits ({}){stack_note}",
            summary.function.start,
            summary.function.end,
            summary.count,
            counts.join(", ")
        )?;
    }
    writeln!(out, "{} functions", matched.len())?;
    Ok(())
}

fn stats(image: &Image, out: &mut dyn Write) -> Res {
    let code: u64 = image.functions.iter().map(|f| f.end - f.start).sum();
    let largest = image.functions.iter().max_by_key(|f| f.end - f.start);
    writeln!(out, "functions {}  code {code:#x} bytes", image.functions.len())?;
    if let Some(f) = largest {
        writeln!(out, "largest {:#x}..{:#x} ({:#x} bytes)", f.start, f.end, f.end - f.start)?;
    }
    writeln!(
        out,
        "pointers {}  imports {}  symbols {}",
        image.pointers.len(),
        image.imports.len(),
        image.symbols.len()
    )?;
    let locations = crate::locations::locations(image);
    let mut files: Vec<&str> = locations.iter().map(|l| l.file.as_str()).collect();
    files.sort_unstable();
    files.dedup();
    writeln!(out, "panic locations {}  source files {}", locations.len(), files.len())?;
    Ok(())
}

fn func(image: &Image, addrs: &[u64], out: &mut dyn Write) -> Res {
    for &addr in addrs {
        match image.function_at(addr) {
            Some(f) => writeln!(
                out,
                "{addr:#x}  in {:#x}..{:#x}  size {:#x}  offset {:#x}",
                f.start,
                f.end,
                f.end - f.start,
                addr - f.start
            )?,
            None => writeln!(out, "{addr:#x}  no function")?,
        }
    }
    Ok(())
}

fn refs(image: &Image, targets: &[String], back: u64, out: &mut dyn Write) -> Res {
    let mut spans: Vec<RangeInclusive<u64>> = Vec::new();
    for target in targets {
        if let Some(addr) = hex_address(target) {
            spans.push(addr..=addr);
            continue;
        }
        let found = image.find(target.as_bytes());
        if found.is_empty() {
            writeln!(out, "text {target:?} not found")?;
        }
        for at in &found {
            writeln!(out, "text {at:#x}  {target:?}")?;
        }
        spans.extend(windows(&found, back));
    }
    let reach = reach(image, spans);
    for (place, target) in &reach.slots {
        writeln!(out, "slot {place:#x} -> {target:#x}")?;
    }
    print_hits(out, &scan::search(image, &Query::Ref(reach.addresses)))
}

fn callers(image: &Image, addr: u64, out: &mut dyn Write) -> Res {
    writeln!(out, "branches")?;
    print_hits(out, &scan::search(image, &Query::Branch(addr)))?;
    let reach = reach(image, std::iter::once(addr..=addr));
    for (place, _) in &reach.slots {
        writeln!(out, "slot {place:#x} -> {addr:#x}")?;
    }
    writeln!(out, "address taken")?;
    print_hits(out, &scan::search(image, &Query::Ref(reach.addresses)))
}

/// The jump-table arm of `tables` closest before `ip`: `(distance, table, indices, arm)`.
pub fn closest_arm(tables: &[Table], ip: u64) -> Option<(u64, &Table, Vec<usize>, u64)> {
    tables
        .iter()
        .filter_map(|table| {
            let indices = arm_indices(&table.arms, ip);
            let arm = table.arms[*indices.first()?];
            Some((ip - arm, table, indices, arm))
        })
        .min_by_key(|(distance, ..)| *distance)
}

fn error(image: &Image, text: &str, back: u64, out: &mut dyn Write) -> Res {
    let found = image.find(text.as_bytes());
    if found.is_empty() {
        return Err(format!("text {text:?} not found").into());
    }
    let reach = reach(image, windows(&found, back));
    let hits = scan::search(image, &Query::Ref(reach.addresses));
    let mut cache: HashMap<u64, Vec<Table>> = HashMap::new();
    for hit in &hits {
        let tables = cache.entry(hit.function.start).or_insert_with(|| tables(image, &hit.function));
        match closest_arm(tables, hit.ip) {
            Some((_, table, indices, arm)) => {
                let variants: Vec<String> = indices.iter().map(|i| format!("{i} ({i:#x})")).collect();
                writeln!(
                    out,
                    "{:#x}  in {:#x}  variant {}  table {:#x} (dispatch {:#x}, {} arms)  arm {arm:#x}",
                    hit.ip,
                    hit.function.start,
                    variants.join(", "),
                    table.base,
                    table.dispatch,
                    table.arms.len()
                )?;
            }
            None => writeln!(out, "{:#x}  in {:#x}  no jump table  {}", hit.ip, hit.function.start, hit.text)?,
        }
    }
    writeln!(out, "{} references", hits.len())?;
    Ok(())
}

#[cfg(test)]
mod tests;
