/*
 * xref — Ultra blazing fast cross-references of an x86-64 ELF binary
 * Copyright (c) 2026 Alexander Panasenko
 *
 * Contact: alex@prod.codes
 * Author: https://prod.codes/about/
 * Project: https://github.com/alex09x/xref
 * SPDX-License-Identifier: MIT OR Apache-2.0
 */

//! `xref const`: a constant by value — where an f64/f32/u64/u32 is stored in data and which
//! instructions load it, plus immediates carrying the same bits (`movabs rax, 0x3ff0…`).

use std::collections::BTreeMap;
use std::io::Write;

use crate::commands::Res;
use crate::image::Image;
use crate::scan::{self, Hit, Query};

/// A constant to look for: its little-endian bytes and how to name it.
pub struct Constant {
    pub label: String,
    pub bytes: Vec<u8>,
    /// The bit pattern, for immediates.
    pub bits: u64,
}

impl Constant {
    pub fn f64(value: f64) -> Self {
        Self { label: format!("f64 {value}"), bytes: value.to_le_bytes().to_vec(), bits: value.to_bits() }
    }

    pub fn f32(value: f32) -> Self {
        Self { label: format!("f32 {value}"), bytes: value.to_le_bytes().to_vec(), bits: u64::from(value.to_bits()) }
    }

    pub fn u64(value: u64) -> Self {
        Self { label: format!("u64 {value:#x}"), bytes: value.to_le_bytes().to_vec(), bits: value }
    }

    pub fn u32(value: u32) -> Self {
        Self { label: format!("u32 {value:#x}"), bytes: value.to_le_bytes().to_vec(), bits: u64::from(value) }
    }
}

/// Copies of the constant in data (aligned to its width, outside function code) with the
/// instructions naming each, and immediates with the same bits.
pub struct Found {
    pub copies: BTreeMap<u64, Vec<Hit>>,
    pub immediates: Vec<Hit>,
}

pub fn find(image: &Image, constant: &Constant) -> Found {
    let width = constant.bytes.len() as u64;
    let places: Vec<u64> = image
        .find(&constant.bytes)
        .into_iter()
        .filter(|&at| at.is_multiple_of(width) && image.function_at(at).is_none())
        .collect();
    let mut copies: BTreeMap<u64, Vec<Hit>> = places.iter().map(|&at| (at, Vec::new())).collect();
    for hit in scan::search(image, &Query::Ref(places)) {
        if let Some(users) = hit.memory.and_then(|at| copies.get_mut(&at)) {
            users.push(hit);
        }
    }
    let immediates = scan::search(image, &Query::Imm { value: constant.bits, store: false, cmp: false });
    Found { copies, immediates }
}

pub fn run(image: &Image, constant: &Constant, limit: usize, out: &mut dyn Write) -> Res {
    let found = find(image, constant);
    writeln!(out, "{} = {:#x}", constant.label, constant.bits)?;
    let mut total = 0;
    let mut unused = Vec::new();
    for (at, users) in &found.copies {
        if users.is_empty() {
            unused.push(*at);
            continue;
        }
        writeln!(out, "data {at:#x}  {} users", users.len())?;
        total += users.len();
        write_hits(users, limit, out)?;
    }
    if !found.immediates.is_empty() {
        writeln!(out, "imm  {} users", found.immediates.len())?;
        total += found.immediates.len();
        write_hits(&found.immediates, limit, out)?;
    }
    if let Some(first) = unused.first() {
        writeln!(out, "{} data copies without RIP-relative users (first {first:#x})", unused.len())?;
    }
    writeln!(out, "{total} hits")?;
    Ok(())
}

fn write_hits(hits: &[Hit], limit: usize, out: &mut dyn Write) -> Res {
    for hit in hits.iter().take(limit) {
        writeln!(out, "  {:#x}  in {:#x}  {}", hit.ip, hit.function.start, hit.text)?;
    }
    if hits.len() > limit {
        writeln!(out, "  ... {} more (raise --limit)", hits.len() - limit)?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::image::Segment;

    #[test]
    fn an_f64_in_data_lists_its_loads_and_immediates() {
        let mut data = vec![0xc3u8; 0x200];
        let code: &[u8] = &[
            0xf2, 0x0f, 0x10, 0x05, 0xf8, 0x00, 0x00, 0x00, // 0x1000: movsd xmm0, [rip+0xf8] (0x1100)
            0x48, 0xb8, 0x29, 0x5c, 0x8f, 0xc2, 0xf5, 0x28, 0xf0, 0x3f, // 0x1008: movabs rax, 1.01 bits
            0xc3,
        ];
        data[..code.len()].copy_from_slice(code);
        data[0x100..0x108].copy_from_slice(&1.01f64.to_le_bytes());
        data[0x181..0x189].copy_from_slice(&1.01f64.to_le_bytes()); // unaligned: not a constant
        data[0x110..0x118].copy_from_slice(&1.01f64.to_le_bytes()); // aligned, unused
        let image = Image {
            data,
            segments: vec![Segment { va: 0x1000, offset: 0, size: 0x200 }],
            functions: vec![0x1000..0x1013, 0x1020..0x1021],
            pointers: Vec::new(),
            imports: Vec::new(),
            symbols: Vec::new(),
            metadata: crate::image_format::Metadata::default(),
        };
        let mut out = Vec::new();
        assert!(run(&image, &Constant::f64(1.01), 10, &mut out).is_ok());
        let text = String::from_utf8_lossy(&out);
        assert!(text.contains("f64 1.01 = 0x3ff028f5c28f5c29"), "{text}");
        assert!(text.contains("data 0x1100  1 users"), "{text}");
        assert!(text.contains("0x1000  in 0x1000  movsd"), "{text}");
        assert!(text.contains("imm  1 users"), "{text}");
        assert!(text.contains("1 data copies without RIP-relative users (first 0x1110)"), "{text}");
        assert!(text.contains("2 hits"), "{text}");
    }
}

#[cfg(test)]
mod cli_tests {
    use clap::Parser;

    use crate::cli::Cli;

    #[test]
    fn const_takes_exactly_one_value_and_negative_floats() {
        assert!(Cli::try_parse_from(["xref", "-b", "x", "const", "--f64", "-0.5"]).is_ok());
        assert!(Cli::try_parse_from(["xref", "-b", "x", "const", "--u64", "0x10"]).is_ok());
        assert!(Cli::try_parse_from(["xref", "-b", "x", "const"]).is_err());
        assert!(Cli::try_parse_from(["xref", "-b", "x", "const", "--f64", "1", "--u32", "2"]).is_err());
    }
}
