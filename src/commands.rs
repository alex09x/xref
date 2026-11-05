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

#[allow(clippy::too_many_lines)]
pub fn run(image: &Image, command: Command, out: &mut dyn Write) -> Res {
    match command {
        Command::Query { .. }
        | Command::Mcp { .. }
        | Command::Live(_)
        | Command::Symbolize(_)
        | Command::Profile { .. }
        | Command::Edges { .. } => Err("structured and live modes require the process-level dispatcher".into()),
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
        Command::Callers { addr, with_observed } => match with_observed {
            Some(path) => crate::trace_frontend::observed_graph::callers(image, &format!("{addr:#x}"), &path, out),
            None => callers(image, addr, out),
        },
        Command::Calls { addr } => listing::calls(image, addr, out),
        Command::Args { addr, max, filter } => crate::args::args(image, &addr, max, filter.as_deref(), out),
        Command::Card { addr, json } => crate::card::card(image, &addr, json, out),
        Command::Find { calls, refs, imm, store, cmp, disp, write, lea, src, size, any, back, insn, class } => {
            let (imm_mode, disp_mode) = ((store, cmp), (write, lea));
            let spec = crate::find::FindSpec { calls, refs, imm, imm_mode, disp, disp_mode, src, size, any, back };
            if insn.is_empty() && class.is_empty() {
                crate::find::find(image, &spec, out)
            } else {
                crate::find::find_with_instructions(image, &spec, &insn, &class, out)
            }
        }
        Command::Path { from, to, depth, with_observed } => match with_observed {
            Some(path) => crate::trace_frontend::observed_graph::path(image, &from, &to, depth, &path, out),
            None => crate::graph::path(image, &from, &to, depth, out),
        },
        Command::Tree { addr, callers, callees, depth, with_observed } => match with_observed {
            Some(path) => crate::trace_frontend::observed_graph::tree(
                image,
                &addr,
                callers,
                callees || !callers,
                depth,
                &path,
                out,
            ),
            None => crate::graph::tree(image, &addr, callers, depth, out),
        },
        Command::Match(args) => crate::matching_cli::run(image, &args, out),
        Command::Asm { addr, from, to } => listing::asm(image, addr, from, to, out),
        Command::C { addrs, from, to, out: out_dir, fields, keep_gotos, only_paths_to } => {
            crate::dump::decomp_with_mode(
                image,
                &addrs,
                &crate::c::COptions { from, to, keep_gotos, only_paths_to, ..Default::default() },
                fields,
                out_dir.as_deref(),
                out,
            )
        }
        Command::Slice { addr, to, to_field, fields, keep_gotos } => {
            let target = to_field.as_deref().or(to.as_deref()).ok_or("either --to or --to-field is required")?;
            if keep_gotos {
                crate::slice::slice_fn_with_mode(image, &addr, target, fields, true, out)
            } else {
                crate::slice::slice_fn(image, &addr, target, fields, out)
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
        field @ Command::Field { .. } => run_field(image, field, out),
        Command::FieldDaemon => Err("field-daemon is started by `xref field`; it is not a query".into()),
        Command::Data { va, as_type, count, max_len } => crate::data::run(image, va, as_type, count, max_len, out),
    }
}

fn run_field(image: &Image, command: Command, out: &mut dyn Write) -> Res {
    let Command::Field {
        name,
        keys,
        within,
        json,
        min_offsets,
        min_keys,
        exhaustive_key_seeds,
        max_functions,
        max_instructions,
        write,
        writes_all_of,
        writer_root,
        limit,
        layout_only,
    } = command
    else {
        return Err("field command expected".into());
    };
    let options = crate::serde_fields::FieldOptions {
        min_offsets,
        write_only: write,
        writes_all_of: writes_all_of
            .map_or_else(Vec::new, |names| names.split(',').map(str::trim).map(str::to_owned).collect()),
        writer_root,
        limit,
        layout_only,
        min_keys,
        exhaustive_key_seeds,
        max_functions,
        max_instructions,
    };
    match (name, keys) {
        (Some(name), None) => crate::serde_fields::field(image, &name, within.as_deref(), json, &options, out),
        (None, Some(keys)) => {
            let keys = keys.split(',').map(str::trim).map(str::to_owned).collect::<Vec<_>>();
            crate::serde_fields::field_by_keys(image, &keys, within.as_deref(), json, &options, out)
        }
        _ => Err("provide either positional NAME or --keys, but not both".into()),
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
    use crate::fmt_template::{MAX_TEXT_MATCHES, candidate_starts, verified};
    let mut spans: Vec<RangeInclusive<u64>> = Vec::new();
    // Text (or address) spans a rustc fmt template piece may hold: code loads the template start.
    let mut template_spans: Vec<(u64, u64)> = Vec::new();
    for target in targets {
        if let Some(addr) = hex_address(target) {
            spans.push(addr..=addr);
            template_spans.push((addr, addr.saturating_add(1)));
            continue;
        }
        let found = image.find(target.as_bytes());
        if found.is_empty() {
            writeln!(out, "text {target:?} not found")?;
        }
        for at in &found {
            writeln!(out, "text {at:#x}  {target:?}")?;
        }
        if found.len() <= MAX_TEXT_MATCHES {
            let len = target.len() as u64;
            template_spans.extend(found.iter().map(|&at| (at, at.saturating_add(len))));
        }
        spans.extend(windows(&found, back));
    }
    let reach = reach(image, spans);
    for (place, target) in &reach.slots {
        writeln!(out, "slot {place:#x} -> {target:#x}")?;
    }
    let direct = reach.addresses.clone();
    let mut addresses = reach.addresses;
    addresses.extend(candidate_starts(&template_spans));
    addresses.sort_unstable();
    addresses.dedup();
    let (hits, candidates): (Vec<_>, Vec<_>) = scan::search(image, &Query::Ref(addresses))
        .into_iter()
        .partition(|hit| hit.memory.is_none_or(|m| direct.binary_search(&m).is_ok()));
    let mut rows: Vec<_> = hits
        .into_iter()
        .map(|hit| {
            let template = crate::fmt_template::template_of(image, &hit, &template_spans);
            (hit, template)
        })
        .collect();
    rows.extend(verified(image, candidates, &template_spans).into_iter().map(|(hit, t)| (hit, Some(t))));
    rows.sort_by_key(|(hit, _)| hit.ip);
    for (hit, template) in &rows {
        let pieces = crate::pieces::hit_suffix(&reach.pieces, hit.memory);
        let template =
            template.map(|t| format!("  ; likely fmt template {:#x}, piece {}", t.start, t.piece)).unwrap_or_default();
        writeln!(out, "{:#x}  in {:#x}  {}{pieces}{template}", hit.ip, hit.function.start, hit.text)?;
    }
    let hits = rows;
    writeln!(out, "{} hits", hits.len())?;
    Ok(())
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
