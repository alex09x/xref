/*
 * xref — Ultra blazing fast cross-references of an x86-64 ELF binary
 * Copyright (c) 2026 Alexander Panasenko
 *
 * Contact: alex@prod.codes
 * Author: https://prod.codes/about/
 * Project: https://github.com/alex09x/xref
 * SPDX-License-Identifier: MIT OR Apache-2.0
 */

//! `xref const --bytes HEX`: an arbitrary byte string (a 20-byte account address, a hash) and
//! the pieces code compares it in. A 20-byte value is rarely loaded whole: the compiler compares
//! 16 bytes with `pcmpeqb xmm0, [const]` and the last 4 with `cmp dword ptr [rdi+0x10], imm32`,
//! or keeps one 20-byte copy and loads it at +0 and +0x10. So besides the copies of the whole
//! string (with users at any offset into them) this lists the copies and immediates of each piece
//! and, at the end, the functions touching any of them.

use std::collections::BTreeMap;
use std::io::Write;
use std::ops::Range;

use crate::commands::Res;
use crate::image::Image;
use crate::scan::{self, Hit, Query};

/// Longest string accepted; longer values are not compared as constants.
const MAX_LEN: usize = 256;

/// Parses `0x0011aabb`, `00 11 aa bb`, `00:11:aa:bb` or `00_11_aa_bb`: bytes in memory order.
pub fn parse_hex(text: &str) -> Result<Vec<u8>, String> {
    let digits: String =
        text.trim().trim_start_matches("0x").chars().filter(|c| !matches!(c, ' ' | ':' | '_' | '-')).collect();
    if digits.is_empty() || !digits.len().is_multiple_of(2) {
        return Err(format!("--bytes takes an even number of hex digits, got {text:?}"));
    }
    let bytes = (0..digits.len())
        .step_by(2)
        .map(|at| u8::from_str_radix(&digits[at..at + 2], 16))
        .collect::<Result<Vec<u8>, _>>()
        .map_err(|_| format!("--bytes takes hex digits, got {text:?}"))?;
    if bytes.len() > MAX_LEN {
        return Err(format!("--bytes takes at most {MAX_LEN} bytes, got {}", bytes.len()));
    }
    Ok(bytes)
}

/// The pieces a compiler compares a `len`-byte value in: 16-byte chunks, the rest in powers of
/// two (20 = 16 + 4, 28 = 16 + 8 + 4), and the overlapping last 16 (or 8) bytes that a compare
/// of an odd length loads instead. Empty for a value of 8 bytes or less: it is one piece.
pub fn pieces(len: usize) -> Vec<Range<usize>> {
    if len <= 8 {
        return Vec::new();
    }
    let mut out = Vec::new();
    let mut at = 0;
    while len - at >= 16 {
        out.push(at..at + 16);
        at += 16;
    }
    for width in [8, 4, 2, 1] {
        if len - at >= width {
            out.push(at..at + width);
            at += width;
        }
    }
    let tail = if len > 16 { 16 } else { 8 };
    if !len.is_multiple_of(tail) {
        out.push(len - tail..len);
    }
    out.retain(|piece| *piece != (0..len));
    out
}

/// Copies of `bytes` outside function code at a multiple of `align`.
fn copies(image: &Image, bytes: &[u8], align: u64) -> Vec<u64> {
    image.find(bytes).into_iter().filter(|&at| at.is_multiple_of(align) && image.function_at(at).is_none()).collect()
}

/// RIP-relative users of each copy, at any byte of it: `(copy, [(offset into it, hit)])`.
fn users(image: &Image, copies: &[u64], len: u64) -> BTreeMap<u64, Vec<(u64, Hit)>> {
    let mut places: Vec<u64> = copies.iter().flat_map(|&at| at..at + len).collect();
    places.sort_unstable();
    places.dedup();
    let mut found: BTreeMap<u64, Vec<(u64, Hit)>> = BTreeMap::new();
    for hit in scan::search(image, &Query::Ref(places)) {
        let Some(memory) = hit.memory else { continue };
        if let Some(&copy) = copies.iter().filter(|&&c| c <= memory && memory < c + len).max() {
            found.entry(copy).or_default().push((memory - copy, hit));
        }
    }
    found
}

/// One labelled list of users, for the by-function summary.
struct Group {
    label: String,
    hits: Vec<(u64, Hit)>,
}

/// The users of the whole value and of each piece, in the order they are printed.
fn groups(image: &Image, bytes: &[u8]) -> (Vec<Group>, usize) {
    let len = bytes.len() as u64;
    let whole = copies(image, bytes, 1);
    let whole_users = users(image, &whole, len);
    let mut unused = whole.iter().filter(|c| !whole_users.contains_key(c)).count();
    let mut out: Vec<Group> =
        whole_users.into_iter().map(|(copy, hits)| Group { label: format!("full  data {copy:#x}"), hits }).collect();
    out.extend(immediates(image, bytes, "full"));
    // Bytes of a whole copy are already covered above, so a piece copy inside one is skipped.
    let inside_whole = |at: u64, width: u64| whole.iter().any(|&c| c <= at && at + width <= c + len);
    for piece in pieces(bytes.len()) {
        let part = &bytes[piece.clone()];
        let width = part.len() as u64;
        let name = format!("piece {}..{}", piece.start, piece.end);
        let mut found = copies(image, part, width.min(16));
        found.retain(|&at| !inside_whole(at, width));
        let piece_users = users(image, &found, width);
        unused += found.iter().filter(|c| !piece_users.contains_key(c)).count();
        out.extend(
            piece_users.into_iter().map(|(copy, hits)| Group { label: format!("{name}  data {copy:#x}"), hits }),
        );
        out.extend(immediates(image, part, &name));
    }
    (out, unused)
}

/// Instructions with a 4- or 8-byte part as an immediate (`cmp dword ptr [rdi+0x10], imm32`,
/// `movabs rax, imm64`); shorter parts would match every small constant in the program.
fn immediates(image: &Image, part: &[u8], name: &str) -> Option<Group> {
    if !matches!(part.len(), 4 | 8) {
        return None;
    }
    let mut value = [0u8; 8];
    value[..part.len()].copy_from_slice(part);
    let bits = u64::from_le_bytes(value);
    let hits: Vec<(u64, Hit)> = scan::search(image, &Query::Imm { value: bits, store: false, cmp: false })
        .into_iter()
        .map(|hit| (0, hit))
        .collect();
    (!hits.is_empty()).then(|| Group { label: format!("{name}  imm {bits:#x}"), hits })
}

/// `xref const --bytes HEX`.
pub fn run(image: &Image, bytes: &[u8], limit: usize, out: &mut dyn Write) -> Res {
    write!(out, "bytes {} = ", bytes.len())?;
    for byte in bytes {
        write!(out, "{byte:02x}")?;
    }
    writeln!(out)?;
    let (found, unused) = groups(image, bytes);
    let mut total = 0;
    for group in &found {
        writeln!(out, "{}  {} users", group.label, group.hits.len())?;
        total += group.hits.len();
        for (offset, hit) in group.hits.iter().take(limit) {
            let at = if *offset == 0 { String::new() } else { format!("  (+{offset:#x})") };
            writeln!(out, "  {:#x}  in {:#x}  {}{at}", hit.ip, hit.function.start, hit.text)?;
        }
        if group.hits.len() > limit {
            writeln!(out, "  ... {} more (raise --limit)", group.hits.len() - limit)?;
        }
    }
    if found.is_empty() {
        writeln!(out, "no copy of the value or of its pieces is named by code")?;
    }
    if unused > 0 {
        writeln!(out, "{unused} data copies without RIP-relative users")?;
    }
    // Which functions use which parts: the comparison is usually one function using every piece.
    let mut by_function: BTreeMap<u64, Vec<&str>> = BTreeMap::new();
    for group in &found {
        let part = group.label.split("  ").next().unwrap_or_default();
        for (_, hit) in &group.hits {
            let parts = by_function.entry(hit.function.start).or_default();
            if !parts.contains(&part) {
                parts.push(part);
            }
        }
    }
    if !by_function.is_empty() {
        writeln!(out, "by function:")?;
        for (function, parts) in &by_function {
            writeln!(out, "  {function:#x}  {}", parts.join(", "))?;
        }
    }
    writeln!(out, "{total} hits")?;
    Ok(())
}

#[cfg(test)]
#[path = "const_bytes_tests.rs"]
mod tests;
