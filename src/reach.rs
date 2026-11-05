/*
 * xref — Ultra blazing fast cross-references of an x86-64 ELF binary
 * Copyright (c) 2026 Alexander Panasenko
 *
 * Contact: alex@prod.codes
 * Author: https://prod.codes/about/
 * SPDX-License-Identifier: MIT OR Apache-2.0
 */

//! The addresses code may name to reach data: the data itself, a few bytes before it (a rustc
//! format piece starts with its length byte, so `lea` points one byte early) and every relocated
//! data slot pointing into that window (`&str` pairs, vtables, static tables).

use std::ops::RangeInclusive;

use crate::image::Image;
use crate::pieces::{PieceMatch, infer_slots};

pub struct Reach {
    /// Sorted addresses for a [`crate::scan::Query::Ref`] search.
    pub addresses: Vec<u64>,
    /// `(place, target)` data slots pointing into a window.
    pub slots: Vec<(u64, u64)>,
    /// Inferred `fmt` pieces arrays whose elements include a matched slot.
    pub pieces: Vec<PieceMatch>,
}

pub fn windows(targets: &[u64], back: u64) -> Vec<RangeInclusive<u64>> {
    let mut windows: Vec<_> = targets.iter().map(|t| t.saturating_sub(back)..=*t).collect();
    windows.sort_by_key(|w| *w.start());
    windows
}

pub fn in_windows(windows: &[RangeInclusive<u64>], addr: u64) -> bool {
    let end = windows.partition_point(|w| *w.start() <= addr);
    windows[..end].iter().any(|w| w.contains(&addr))
}

/// What reaches the data in `windows`.
pub fn reach(image: &Image, windows: impl IntoIterator<Item = RangeInclusive<u64>>) -> Reach {
    let mut windows: Vec<_> = windows.into_iter().collect();
    windows.sort_by_key(|w| *w.start());
    let slots: Vec<(u64, u64)> =
        image.pointers.iter().copied().filter(|(_, target)| in_windows(&windows, *target)).collect();
    let pieces = infer_slots(image, &windows, &slots);
    let mut addresses: Vec<u64> = windows.iter().flat_map(Clone::clone).collect();
    addresses.extend(slots.iter().map(|(place, _)| *place));
    addresses.extend(pieces.iter().flat_map(crate::pieces::element_starts));
    addresses.sort_unstable();
    addresses.dedup();
    Reach { addresses, slots, pieces }
}

#[cfg(test)]
mod tests {
    use super::{in_windows, windows};

    #[test]
    fn a_window_covers_the_length_byte_before_the_text() {
        // A format piece at 0x439042 whose length byte at 0x439041 is what `lea` names.
        let windows = windows(&[0x43_9042, 0x10], 1);
        assert!(in_windows(&windows, 0x43_9041));
        assert!(in_windows(&windows, 0x43_9042));
        assert!(!in_windows(&windows, 0x43_9040));
        assert!(!in_windows(&windows, 0x43_9043));
        assert!(in_windows(&windows, 0xf));
    }
}
