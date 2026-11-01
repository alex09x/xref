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
        Command::Refs { targets, back } => refs(image, &targets, back, out),
        Command::Imm { value, store, cmp, within } => scoped(image, within, &Query::Imm { value, store, cmp }, out),
        Command::Disp { value, write, within } => scoped(image, within, &Query::Disp { value, write }, out),
        Command::Callers { addr } => callers(image, addr, out),
        Command::Calls { addr } => listing::calls(image, addr, out),
        Command::Asm { addr, from, to } => listing::asm(image, addr, from, to, out),
        Command::Error { text, back } => error(image, &text, back, out),
        Command::Variant { addr, indices } => {
            let indices: Vec<usize> = indices.iter().filter_map(|index| usize::try_from(*index).ok()).collect();
            crate::variant::variants(image, addr, &indices, out)
        }
        Command::Arm { addrs } => crate::variant::arms(image, &addrs, out),
        Command::Src { addr } => source::src(image, addr, out),
        Command::Where { pattern, line } => source::places(image, &pattern, line, out),
        Command::Files { pattern } => source::files(image, pattern.as_deref(), out),
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
mod tests {
    use super::closest_arm;
    use crate::tables::Table;

    #[test]
    fn the_closest_arm_across_tables_wins() {
        let far = Table { dispatch: 0x10, base: 0x900, arms: vec![0x100, 0x200] };
        let near = Table { dispatch: 0x20, base: 0xa00, arms: vec![0x2f0, 0x300] };
        let tables = [far, near];
        let (distance, table, indices, arm) = closest_arm(&tables, 0x2f8).unwrap_or_else(|| unreachable!());
        assert_eq!((distance, table.base, indices, arm), (8, 0xa00, vec![0], 0x2f0));
    }
}
