/*
 * xref — Ultra blazing fast cross-references of an x86-64 ELF binary
 * Copyright (c) 2026 Alexander Panasenko
 *
 * Contact: alex@prod.codes
 * Author: https://prod.codes/about/
 * Project: https://github.com/alex09x/xref
 * SPDX-License-Identifier: MIT OR Apache-2.0
 */

use std::fmt::Write as _;
use std::hint::black_box;
use std::io::{self, Write};

const RODATA_BLOB: &str = "BLOB_HEAD::alpha= beta_sum= gamma=\n::BLOB_TAIL";

const fn sub_piece(blob: &str, start: usize, len: usize) -> &str {
    let (_, rest) = blob.split_at(start);
    let (piece, _) = rest.split_at(len);
    piece
}

static RELOC_REFS_PIECES: [&str; 4] = [
    sub_piece(RODATA_BLOB, 11, 6),  // "alpha="
    sub_piece(RODATA_BLOB, 17, 10), // " beta_sum="
    sub_piece(RODATA_BLOB, 27, 7),  // " gamma="
    sub_piece(RODATA_BLOB, 34, 1),  // "\n"
];

#[no_mangle]
#[inline(never)]
pub fn format_reloc_message(a: u64, b: u64, c: u64) -> io::Result<()> {
    let pieces: &[&str] = black_box(&RELOC_REFS_PIECES);
    let values = [a, b, c];
    let mut rendered = String::with_capacity(64);
    for (prefix, value) in pieces.iter().zip(values) {
        rendered.push_str(prefix);
        let _ = write!(rendered, "{value}");
    }
    if let Some(tail) = pieces.get(3) {
        rendered.push_str(tail);
    }
    io::stdout().write_all(rendered.as_bytes())
}

fn main() {
    let _ = format_reloc_message(black_box(10), black_box(20), black_box(30));
}
