/*
 * XRef — x86-64 binary analysis and cross-reference tooling
 * Copyright (c) 2026 Alexander Panasenko
 *
 * Contact: alex@prod.codes
 * Author: https://prod.codes/about/
 * Project: https://github.com/alex09x/xref
 * SPDX-License-Identifier: MIT OR Apache-2.0
 */

//! rustc `fmt::Arguments` byte templates (the representation of recent Rust `core::fmt`).
//!
//! A template is one byte sequence: literal pieces prefixed by their length (`len < 0x80`, or
//! `0x80` + u16 length), placeholders (`0b11xxxxxx` followed by the optional 32-bit flags and
//! 16-bit width / precision / `arg_index` fields its low bits announce) and a terminating `0`.
//! Code loads the address of the first byte, so the text of a later piece is never referenced
//! directly; this module finds the template start that owns a piece.

use crate::image::Image;
use crate::scan::Hit;

/// How far before a matched text a template start is searched.
pub const MAX_TEMPLATE_BACK: u64 = 4096;
/// Matched texts beyond this count are not expanded into template candidates (too broad a query).
pub const MAX_TEXT_MATCHES: usize = 64;
const MAX_PARTS: usize = 512;

/// The template that starts at `start` and the index of its literal piece covering `lo..hi`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TemplatePiece {
    pub start: u64,
    pub piece: usize,
}

fn byte(image: &Image, va: u64) -> Option<u8> {
    image.read(va, 1).map(|b| b[0])
}

/// Parse a template from `start`; return the index of the literal piece containing `lo..hi`.
/// `None` when the bytes are not a valid template, a piece is not UTF-8, or no piece covers it.
#[must_use]
pub fn piece_covering(image: &Image, start: u64, lo: u64, hi: u64) -> Option<usize> {
    let mut at = start;
    let mut piece = 0usize;
    for _ in 0..MAX_PARTS {
        let n = byte(image, at)?;
        at = at.checked_add(1)?;
        // 0 ends the template before reaching the span; 0x81..=0xbf is not a valid part.
        let (text_start, len) = match n {
            1..=0x7f => (at, u64::from(n)),
            0x80 => {
                let raw = image.read(at, 2)?;
                (at.checked_add(2)?, u64::from(u16::from_le_bytes([raw[0], raw[1]])))
            }
            0xc0..=0xff => {
                let skip = u64::from(n & 1) * 4
                    + u64::from(n >> 1 & 1) * 2
                    + u64::from(n >> 2 & 1) * 2
                    + u64::from(n >> 3 & 1) * 2;
                at = at.checked_add(skip)?;
                continue;
            }
            _ => return None,
        };
        let end = text_start.checked_add(len)?;
        let text = image.read(text_start, usize::try_from(len).ok()?)?;
        std::str::from_utf8(text).ok()?;
        if lo >= text_start && hi <= end {
            return Some(piece);
        }
        if text_start > lo {
            return None;
        }
        piece += 1;
        at = end;
    }
    None
}

/// Addresses at most [`MAX_TEMPLATE_BACK`] bytes before each `lo..hi` span: candidate template starts.
#[must_use]
pub fn candidate_starts(spans: &[(u64, u64)]) -> Vec<u64> {
    let mut out: Vec<u64> = spans.iter().flat_map(|&(lo, _)| lo.saturating_sub(MAX_TEMPLATE_BACK)..lo).collect();
    out.sort_unstable();
    out.dedup();
    out
}

/// The template piece a code hit loads, when its memory operand starts a template covering a span.
#[must_use]
pub fn template_of(image: &Image, hit: &Hit, spans: &[(u64, u64)]) -> Option<TemplatePiece> {
    let start = hit.memory?;
    let piece = spans
        .iter()
        .filter(|&&(lo, _)| start < lo && lo - start <= MAX_TEMPLATE_BACK)
        .find_map(|&(lo, hi)| piece_covering(image, start, lo, hi))?;
    Some(TemplatePiece { start, piece })
}

/// Keep the code hits that load a template whose literal piece covers one of `spans`.
#[must_use]
pub fn verified(image: &Image, hits: Vec<Hit>, spans: &[(u64, u64)]) -> Vec<(Hit, TemplatePiece)> {
    hits.into_iter().filter_map(|hit| template_of(image, &hit, spans).map(|t| (hit, t))).collect()
}

#[cfg(test)]
mod tests {
    use super::piece_covering;
    use crate::image::{Image, Segment};

    fn image(bytes: &[u8]) -> Image {
        Image {
            data: bytes.to_vec(),
            segments: vec![Segment { va: 0x1000, offset: 0, size: bytes.len() }],
            ..Image::default()
        }
    }

    #[test]
    fn reloc_refs_template_finds_the_piece_after_placeholders() {
        // rustc 1.99: format!("alpha={} beta_sum={} gamma={}")
        let t = image(b"\x06alpha=\xc0\x0a beta_sum=\xc0\x07 gamma=\xc0\x00");
        let beta = 0x1000 + 1 + 6 + 1 + 1 + 1; // " beta_sum=" text, skipping its leading space
        assert_eq!(piece_covering(&t, 0x1000, beta, beta + 9), Some(1));
        assert_eq!(piece_covering(&t, 0x1000, 0x1001, 0x1007), Some(0));
        let gamma = 0x1000 + 0x14 + 1;
        assert_eq!(piece_covering(&t, 0x1000, gamma, gamma + 7), Some(2));
    }

    #[test]
    fn reloc_refs_template_skips_placeholder_fields_and_long_pieces() {
        // {:>5.2} with flags+width+precision (0xC7: 4 + 2 + 2 bytes), then a 0x80 long piece.
        let mut b = vec![0x02, b'a', b'=', 0xc7, 1, 2, 3, 4, 5, 0, 2, 0, 0x80, 3, 0];
        b.extend_from_slice(b"xyz\0");
        let t = image(&b);
        assert_eq!(piece_covering(&t, 0x1000, 0x1000 + 15, 0x1000 + 18), Some(1));
    }

    #[test]
    fn reloc_refs_template_rejects_invalid_or_unrelated_bytes() {
        // 0x81..0xBF is not a valid part; a non-UTF-8 piece is not a template piece.
        assert_eq!(piece_covering(&image(b"\x90abc\0"), 0x1000, 0x1001, 0x1002), None);
        assert_eq!(piece_covering(&image(b"\x02\xff\xfe\0"), 0x1000, 0x1001, 0x1002), None);
        // The end byte before the span: not covered.
        assert_eq!(piece_covering(&image(b"\x01a\0zzz"), 0x1000, 0x1004, 0x1005), None);
        // Starting in the middle of text rather than at a part boundary does not cover it either.
        assert_eq!(piece_covering(&image(b"\x05hello\0"), 0x1003, 0x1004, 0x1005), None);
    }
}
