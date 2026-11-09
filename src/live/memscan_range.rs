/*
 * XRef — What a live memory scan matches: a byte sequence or a range of word values
 * Copyright (c) 2026 Alexander Panasenko
 * Contact: alex@prod.codes
 * Author: https://prod.codes/about/
 * Project: https://github.com/alex09x/xref
 * SPDX-License-Identifier: MIT OR Apache-2.0
 */

//! `live memscan VALUES...` looks for one exact little-endian sequence. `live memscan --range LO HI`
//! looks for every aligned little-endian word (`--width 4` or `8` bytes) whose value is in
//! `[LO, HI)`: a counter whose current value is unknown but bounded.

use crate::image::occurrence_iter;

/// A half-open range of word values and the word width in bytes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ValueRange {
    pub lo: u64,
    pub hi: u64,
    pub width: usize,
}

impl ValueRange {
    /// `[lo, hi)` over `width`-byte words (4 or 8); a 4-byte range must fit in 32 bits.
    pub fn new(lo: u64, hi: u64, width: usize) -> Result<Self, String> {
        if !matches!(width, 4 | 8) {
            return Err(format!("invalid --width {width}: allowed values are 4 or 8"));
        }
        if lo >= hi {
            return Err(format!("empty --range: LO {lo:#x} must be below HI {hi:#x}"));
        }
        if width == 4 && hi > 1 << 32 {
            return Err(format!("--range HI {hi:#x} does not fit a 4-byte word (at most 0x100000000)"));
        }
        Ok(Self { lo, hi, width })
    }

    /// The little-endian word at the start of `bytes` (at least `width` long).
    fn word(self, bytes: &[u8]) -> Option<u64> {
        match self.width {
            4 => bytes.get(..4).and_then(|b| b.try_into().ok()).map(|b| u64::from(u32::from_le_bytes(b))),
            _ => bytes.get(..8).and_then(|b| b.try_into().ok()).map(u64::from_le_bytes),
        }
    }

    pub const fn contains(self, value: u64) -> bool {
        self.lo <= value && value < self.hi
    }
}

/// What a scan matches.
#[derive(Clone, Copy, Debug)]
pub enum Pattern<'a> {
    /// One exact byte sequence (the encoded `VALUES`).
    Bytes(&'a [u8]),
    /// Every aligned word whose value is in the range.
    Range(ValueRange),
}

impl Pattern<'_> {
    /// Bytes one match covers.
    pub const fn len(&self) -> usize {
        match self {
            Self::Bytes(needle) => needle.len(),
            Self::Range(range) => range.width,
        }
    }

    pub const fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Offsets in `buf` (read from address `base`) where the pattern matches at an address that
    /// is a multiple of `align`, with the matched word for a range.
    pub fn matches(&self, buf: &[u8], base: u64, align: u64) -> Vec<(usize, Option<u64>)> {
        let aligned = |offset: usize| u64::try_from(offset).is_ok_and(|o| base.wrapping_add(o).is_multiple_of(align));
        match *self {
            Self::Bytes(needle) => occurrence_iter(buf, needle).filter(|&o| aligned(o)).map(|o| (o, None)).collect(),
            Self::Range(range) => {
                let Some(last) = buf.len().checked_sub(range.width) else { return Vec::new() };
                let step = usize::try_from(align.max(1)).unwrap_or(1);
                let first = usize::try_from((align - base % align) % align).unwrap_or(0);
                (first..=last)
                    .step_by(step)
                    .filter_map(|o| range.word(&buf[o..]).filter(|&v| range.contains(v)).map(|v| (o, Some(v))))
                    .collect()
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{Pattern, ValueRange};

    #[test]
    fn a_range_matches_aligned_words_in_it_and_reports_their_values() -> Result<(), String> {
        // Words 5, 9, 10 at 0x1000, 0x1008, 0x1010; a 4-byte 7 at 0x1018.
        let mut buf = Vec::new();
        for v in [5u64, 9, 10] {
            buf.extend_from_slice(&v.to_le_bytes());
        }
        buf.extend_from_slice(&7u32.to_le_bytes());
        buf.extend_from_slice(&0u32.to_le_bytes());
        let eight = Pattern::Range(ValueRange::new(6, 10, 8)?);
        assert_eq!(eight.matches(&buf, 0x1000, 8), vec![(8, Some(9)), (24, Some(7))]);
        // 4-byte words at every 4 bytes: the low halves 5, 9, 10, 7 and the zero high halves.
        let four = Pattern::Range(ValueRange::new(5, 8, 4)?);
        assert_eq!(four.matches(&buf, 0x1000, 4), vec![(0, Some(5)), (24, Some(7))]);
        // A base off the alignment: only offsets landing on aligned addresses count.
        assert_eq!(eight.matches(&buf[4..], 0x1004, 8), vec![(4, Some(9)), (20, Some(7))]);
        assert!(ValueRange::new(5, 5, 8).is_err() && ValueRange::new(1, 2, 2).is_err());
        assert!(ValueRange::new(0, (1 << 32) + 1, 4).is_err());
        Ok(())
    }

    #[test]
    fn a_byte_pattern_matches_aligned_occurrences_only() {
        let buf = [0u8, 1, 2, 1, 2, 0, 0, 0, 1, 2];
        assert_eq!(Pattern::Bytes(&[1, 2]).matches(&buf, 0x2000, 1), vec![(1, None), (3, None), (8, None)]);
        assert_eq!(Pattern::Bytes(&[1, 2]).matches(&buf, 0x2000, 8), vec![(8, None)]);
    }
}
