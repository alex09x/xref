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
use std::path::Path;
use std::time::Instant;

use rayon::prelude::*;

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
        Command::Refs { targets, back, inline } => {
            if inline {
                crate::inline::refs_inline(image, &targets, out)
            } else {
                refs(image, &targets, back, out)
            }
        }
        Command::Istr { targets } => crate::inline::refs_inline(image, &targets, out),
        Command::Imm { value, store, cmp, within } => scoped(image, within, &Query::Imm { value, store, cmp }, out),
        Command::Disp { values, write, all, stride, within } => disp(image, &values, write, all, stride, within, out),
        Command::Callers { addr } => callers(image, addr, out),
        Command::Calls { addr } => listing::calls(image, addr, out),
        Command::Args { addr, max } => crate::args::args(image, &addr, max, out),
        Command::Find { calls, refs, imm, store, cmp, disp, write, src, size, any, back } => {
            let spec = crate::find::FindSpec { calls, refs, imm, store, cmp, disp, write, src, size, any, back };
            crate::find::find(image, &spec, out)
        }
        Command::Path { from, to, depth } => crate::graph::path(image, &from, &to, depth, out),
        Command::Tree { addr, callers, callees: _, depth } => crate::graph::tree(image, &addr, callers, depth, out),
        Command::Match { other, addrs, top } => {
            crate::matching::match_images(image, &Image::load(&other)?, &addrs, top, out)
        }
        Command::Asm { addr, from, to } => listing::asm(image, addr, from, to, out),
        Command::C { addrs, from, to, out: out_dir } => decomp(image, &addrs, from, to, out_dir.as_deref(), out),
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

fn decomp(
    image: &Image,
    addrs: &[u64],
    from: Option<u64>,
    to: Option<u64>,
    out_dir: Option<&Path>,
    out: &mut dyn Write,
) -> Res {
    let all_locs = crate::locations::locations(image);
    let rendered: Vec<Result<(u64, String, std::time::Duration), String>> = addrs
        .par_iter()
        .map(|&addr| {
            let t0 = Instant::now();
            let (start, body) = crate::c::c_one(image, &all_locs, addr, from, to)?;
            Ok((start, body, t0.elapsed()))
        })
        .collect();
    if let Some(dir) = out_dir {
        std::fs::create_dir_all(dir)?;
    }
    for item in rendered {
        let (start, body, elapsed) = item?;
        if let Some(dir) = out_dir {
            let path = dir.join(format!("{start:#x}.c"));
            std::fs::write(&path, &body)?;
            writeln!(out, "{}  {} bytes  {elapsed:.1?}", path.display(), body.len())?;
        } else {
            out.write_all(body.as_bytes())?;
        }
    }
    Ok(())
}

type FieldAccess = (u64, iced_x86::Register);

fn disp(
    image: &Image,
    values: &[u64],
    write: bool,
    all: bool,
    stride: Option<u64>,
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
    let hits = scan::search_disp(image, functions, values, write, stride);
    if !all {
        let plain: Vec<Hit> = hits.into_iter().map(|d| d.hit).collect();
        return print_hits(out, &plain);
    }
    let mut by_fn: HashMap<u64, (Range<u64>, Vec<FieldAccess>)> = HashMap::new();
    for d in hits {
        let entry = by_fn.entry(d.hit.function.start).or_insert_with(|| (d.hit.function.clone(), Vec::new()));
        entry.1.push((d.offset, d.base));
    }
    let mut matched: Vec<(bool, Range<u64>, Vec<FieldAccess>)> = by_fn
        .into_values()
        .filter(|(_, list)| values.iter().all(|&v| list.iter().any(|(off, _)| *off == v)))
        .map(|(f, list)| {
            let same_base = list
                .iter()
                .map(|(_, b)| *b)
                .any(|base| values.iter().all(|&v| list.iter().any(|(off, b)| *off == v && *b == base)));
            (same_base, f, list)
        })
        .collect();
    matched.sort_by_key(|(same_base, f, _)| (!*same_base, f.start));
    for (_, f, list) in &matched {
        let counts: Vec<String> =
            values.iter().map(|&v| format!("{v:#x}: {}", list.iter().filter(|(off, _)| *off == v).count())).collect();
        writeln!(out, "{:#x}..{:#x}  {} hits ({})", f.start, f.end, list.len(), counts.join(", "))?;
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
mod tests {
    use super::{closest_arm, run};
    use crate::cli::Command;
    use crate::image::{Image, Segment};
    use crate::tables::Table;

    #[test]
    fn the_closest_arm_across_tables_wins() {
        let far = Table { dispatch: 0x10, base: 0x900, arms: vec![0x100, 0x200] };
        let near = Table { dispatch: 0x20, base: 0xa00, arms: vec![0x2f0, 0x300] };
        let tables = [far, near];
        assert_eq!(closest_arm(&tables, 0x2f8).map(|(d, t, i, a)| (d, t.base, i, a)), Some((8, 0xa00, vec![0], 0x2f0)));
        let mut data = vec![0u8; 0x200];
        // 0x1000: lea rcx, [rip + 0xf9] (0x1100); movsxd rax, [rcx + rcx*4]; jmp rax
        // 0x100d (arm 0): lea rax, [rip + 0x1c] (0x1030 "hello"); lea rdx, [rip + 0x25] (0x1040 Location); ret
        let code: &[u8] = &[
            0x48, 0x8d, 0x0d, 0xf9, 0x00, 0x00, 0x00, // 0x1000: lea rcx, [0x1100]
            0x48, 0x63, 0x04, 0x89, // 0x1007: movsxd rax, [rcx + rcx*4]
            0xff, 0xe0, // 0x100b: jmp rax
            0x48, 0x8d, 0x05, 0x1c, 0x00, 0x00, 0x00, // 0x100d: lea rax, [0x1030]
            0xc3, // 0x1014: ret
        ];
        data[..code.len()].copy_from_slice(code);
        // 0x1020 (no jump table): lea rdx, [0x1040]; ret
        data[0x20..0x28].copy_from_slice(&[0x48, 0x8d, 0x15, 0x19, 0x00, 0x00, 0x00, 0xc3]);
        data[0x30..0x35].copy_from_slice(b"hello");
        data[0x35..0x3b].copy_from_slice(b"lib.rs");
        // Location at 0x1040: ptr -> 0x1035 ("lib.rs"), len = 6, line = 1, col = 1
        data[0x48..0x50].copy_from_slice(&6u64.to_le_bytes());
        data[0x50..0x54].copy_from_slice(&1u32.to_le_bytes());
        data[0x54..0x58].copy_from_slice(&1u32.to_le_bytes());
        // Jump table at 0x1100: arm 0 -> 0x100d (offset -0xf3)
        data[0x100..0x104].copy_from_slice(&(-0xf3i32).to_le_bytes());
        let image = Image {
            data,
            segments: vec![Segment { va: 0x1000, offset: 0, size: 0x200 }],
            functions: vec![0x1000..0x1015, 0x1020..0x1028],
            pointers: vec![(0x1040, 0x1035), (0x1060, 0x1030)],
            imports: Vec::new(),
            symbols: vec![(0x1000, "main_fn".to_owned())],
        };
        let empty = Image {
            data: Vec::new(),
            segments: Vec::new(),
            functions: Vec::new(),
            pointers: Vec::new(),
            imports: Vec::new(),
            symbols: Vec::new(),
        };
        let mut out = Vec::new();
        assert!(run(&empty, Command::Stats, &mut out).is_ok());
        for cmd in [
            Command::Stats,
            Command::Sym { pattern: "main".to_owned() },
            Command::Func { addrs: vec![0x1000, 0x9999] },
            Command::Refs {
                targets: vec!["0x1030".to_owned(), "hello".to_owned(), "missing".to_owned()],
                back: 1,
                inline: false,
            },
            Command::Refs { targets: vec!["missing".to_owned()], back: 1, inline: true },
            Command::Istr { targets: vec!["missing".to_owned()] },
            Command::Imm { value: 0, store: false, cmp: false, within: Some(0x1000) },
            Command::Imm { value: 0, store: false, cmp: false, within: None },
            Command::Disp { values: vec![0], write: false, all: false, stride: None, within: Some(0x1000) },
            Command::Disp { values: vec![0], write: false, all: true, stride: None, within: None },
            Command::Callers { addr: 0x1030 },
            Command::Calls { addr: 0x1000 },
            Command::Path { from: "0x1000".to_owned(), to: "0x1020".to_owned(), depth: 2 },
            Command::Tree { addr: "0x1000".to_owned(), callers: false, callees: true, depth: 1 },
            Command::Asm { addr: 0x1000, from: Some(0x1000), to: Some(0x1007) },
            Command::C { addrs: vec![0x1000], from: None, to: None, out: None },
            Command::Error { text: "hello".to_owned(), back: 1 },
            Command::Error { text: "lib.rs".to_owned(), back: 1 },
            Command::Variant { addr: 0x1000, indices: vec![0, 9] },
            Command::Arm { addrs: vec![0x100d, 0x1020] },
            Command::Src { addr: 0x1020 },
            Command::Where { pattern: "lib.rs".to_owned(), line: Some(1) },
            Command::Files { pattern: Some("lib.rs".to_owned()) },
        ] {
            assert!(run(&image, cmd, &mut out).is_ok());
        }
        assert!(
            crate::scan::search_in(&image, std::slice::from_ref(&(0x9000..0x9004)), &crate::scan::Query::Branch(0))
                .is_empty()
        );
        assert!(run(&image, Command::Error { text: "missing".to_owned(), back: 1 }, &mut out).is_err());
        assert!(run(&image, Command::Variant { addr: 0x1020, indices: vec![0] }, &mut out).is_err());
    }
}
