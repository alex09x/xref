/*
 * xref — Ultra blazing fast cross-references of an x86-64 ELF binary
 * Copyright (c) 2026 Alexander Panasenko
 *
 * Contact: alex@prod.codes
 * Author: https://prod.codes/about/
 * SPDX-License-Identifier: MIT OR Apache-2.0
 */

//! Machine code to Rust source through panic locations: `src`, `where` and `files`.

use std::collections::BTreeMap;
use std::io::Write;

use crate::commands::{Res, function};
use crate::image::Image;
use crate::locations::{Location, locations};
use crate::scan::{self, Query, decode};

/// Size of a `core::panic::Location` (file pointer, file length, line, column).
const LOCATION_SIZE: u64 = 24;

/// The location whose struct holds `addr`, from locations sorted by place.
pub fn location_at(locations: &[Location], addr: u64) -> Option<&Location> {
    let end = locations.partition_point(|l| l.place <= addr);
    locations[..end].last().filter(|l| addr < l.place + LOCATION_SIZE)
}

pub fn src(image: &Image, addr: u64, out: &mut dyn Write) -> Res {
    let f = function(image, addr)?;
    let code = image.code(&f).ok_or("function outside the image")?;
    let all = locations(image);
    let mut lines = Vec::new();
    decode(code, f.start, |instruction| {
        if instruction.is_ip_rel_memory_operand()
            && let Some(l) = location_at(&all, instruction.ip_rel_memory_address())
        {
            lines.push(format!("{:#x}  {}:{}:{}", instruction.ip(), l.file, l.line, l.col));
        }
    });
    writeln!(out, "function {:#x}..{:#x}", f.start, f.end)?;
    for line in &lines {
        writeln!(out, "{line}")?;
    }
    writeln!(out, "{} locations", lines.len())?;
    Ok(())
}

pub fn places(image: &Image, pattern: &str, line: Option<u32>, out: &mut dyn Write) -> Res {
    let all = locations(image);
    let matched: Vec<&Location> =
        all.iter().filter(|l| l.file.contains(pattern) && line.is_none_or(|wanted| l.line == wanted)).collect();
    let mut addresses: Vec<u64> = matched.iter().map(|l| l.place).collect();
    addresses.sort_unstable();
    let hits = scan::search(image, &Query::Ref(addresses));
    let mut by_function: BTreeMap<(u64, u64), Vec<String>> = BTreeMap::new();
    for hit in &hits {
        if let Some(l) = hit.memory.and_then(|addr| location_at(&all, addr)) {
            by_function
                .entry((hit.function.start, hit.function.end))
                .or_default()
                .push(format!("{}:{}", l.file, l.line));
        }
    }
    for ((start, end), mut lines) in by_function {
        lines.sort_unstable();
        lines.dedup();
        writeln!(out, "{start:#x}..{end:#x}  {}", lines.join("  "))?;
    }
    writeln!(out, "{} locations, {} references", matched.len(), hits.len())?;
    Ok(())
}

pub fn files(image: &Image, pattern: Option<&str>, out: &mut dyn Write) -> Res {
    let mut counts: BTreeMap<&str, usize> = BTreeMap::new();
    let all = locations(image);
    for l in all.iter().filter(|l| pattern.is_none_or(|p| l.file.contains(p))) {
        *counts.entry(l.file.as_str()).or_default() += 1;
    }
    for (file, count) in &counts {
        writeln!(out, "{count:>6}  {file}")?;
    }
    writeln!(out, "{} files", counts.len())?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::location_at;
    use crate::locations::Location;

    #[test]
    fn an_address_inside_a_location_struct_maps_to_it() {
        let at = |place, line| Location { place, file: "src/order.rs".to_owned(), line, col: 1 };
        let all = [at(0x100, 7), at(0x200, 9)];
        assert_eq!(location_at(&all, 0x100).map(|l| l.line), Some(7));
        assert_eq!(location_at(&all, 0x117).map(|l| l.line), Some(7));
        assert!(location_at(&all, 0x118).is_none());
        assert!(location_at(&all, 0xff).is_none());
        assert_eq!(location_at(&all, 0x210).map(|l| l.line), Some(9));
    }
}
