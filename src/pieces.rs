/*
 * xref — Ultra blazing fast cross-references of an x86-64 ELF binary
 * Copyright (c) 2026 Alexander Panasenko
 *
 * Contact: alex@prod.codes
 * Author: https://prod.codes/about/
 * Project: https://github.com/alex09x/xref
 * SPDX-License-Identifier: MIT OR Apache-2.0
 */

//! Infer rustc `fmt` pieces arrays (`&[&str]`) from relocated `(ptr, len)` slots in `.data.rel.ro`.
//! Code loads the array start via RIP-relative `lea`, not individual piece `k > 0` slots.

use std::fmt::Write as _;
use std::ops::{Range, RangeInclusive};

use crate::image::{Image, Slot};

const ELEMENT_SIZE: u64 = 16;
const MAX_PIECE_LEN: u64 = 4096;
const MAX_WALK_BACK: usize = 256;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PieceMatch {
    pub array_start: u64,
    pub slot: u64,
    pub index: usize,
    pub target: u64,
    pub len: u64,
}

fn rodata_segment_end(image: &Image, va: u64) -> Option<u64> {
    let seg = image.metadata.load_segments.iter().find(|seg| {
        if seg.writable || seg.executable {
            return false;
        }
        let span = seg.file_size.min(seg.mem_size);
        seg.va.checked_add(span).is_some_and(|end| (seg.va..end).contains(&va))
    })?;
    seg.va.checked_add(seg.file_size.min(seg.mem_size))
}

fn containing_segment_range(image: &Image, elem_va: u64) -> Option<Range<u64>> {
    let elem_end = elem_va.checked_add(ELEMENT_SIZE)?;
    let seg = image.segments.iter().find(|seg| {
        let Ok(size) = u64::try_from(seg.size) else {
            return false;
        };
        seg.va.checked_add(size).is_some_and(|end| elem_va >= seg.va && elem_end <= end)
    })?;
    let size = u64::try_from(seg.size).ok()?;
    Some(seg.va..seg.va.checked_add(size)?)
}

fn piece_element(image: &Image, elem_va: u64) -> Option<(u64, u64)> {
    let Some(Slot::Pointer(ptr)) = image.slot(elem_va) else {
        return None;
    };
    let len_va = elem_va.checked_add(8)?;
    if image.slot(len_va).is_some() {
        return None;
    }
    let seg_end = rodata_segment_end(image, ptr)?;
    let len = image.read_u64(len_va)?;
    if !(1..=MAX_PIECE_LEN).contains(&len) {
        return None;
    }
    if ptr.checked_add(len).is_none_or(|end| end > seg_end) {
        return None;
    }
    Some((ptr, len))
}

/// Walk back over consecutive 16-byte `(ptr, len)` elements to locate the pieces array start.
#[must_use]
pub fn infer_slot(image: &Image, slot: u64) -> Option<PieceMatch> {
    let seg_range = containing_segment_range(image, slot)?;
    let (target, len) = piece_element(image, slot)?;
    let mut array_start = slot;
    let mut index = 0usize;
    while index < MAX_WALK_BACK {
        let Some(prev) = array_start.checked_sub(ELEMENT_SIZE) else {
            break;
        };
        if prev < seg_range.start || piece_element(image, prev).is_none() {
            break;
        }
        array_start = prev;
        index += 1;
    }
    if index == 0 {
        let next = slot.checked_add(ELEMENT_SIZE)?;
        if next.checked_add(ELEMENT_SIZE).is_none_or(|end| end > seg_range.end) || piece_element(image, next).is_none()
        {
            return None;
        }
    }
    Some(PieceMatch { array_start, slot, index, target, len })
}

fn covers_window_end(piece: &PieceMatch, windows: &[RangeInclusive<u64>]) -> bool {
    let Some(piece_end) = piece.target.checked_add(piece.len) else {
        return false;
    };
    let range = piece.target..piece_end;
    windows.iter().any(|window| range.contains(window.end()))
}

/// Infer piece-array entries for matched slots, dropping `--back` spillover into preceding pieces
/// when another piece of the same array directly covers a queried target address.
#[must_use]
pub fn infer_slots(image: &Image, windows: &[RangeInclusive<u64>], slots: &[(u64, u64)]) -> Vec<PieceMatch> {
    let mut raw: Vec<PieceMatch> = slots.iter().filter_map(|&(place, _)| infer_slot(image, place)).collect();
    raw.sort_by_key(|piece| (piece.array_start, piece.index));
    raw.dedup_by_key(|piece| (piece.array_start, piece.index));
    let mut out = Vec::with_capacity(raw.len());
    let mut start = 0;
    while start < raw.len() {
        let array_start = raw[start].array_start;
        let count = raw[start..].iter().take_while(|piece| piece.array_start == array_start).count();
        let group = &raw[start..start + count];
        let any_covers = group.iter().any(|piece| covers_window_end(piece, windows));
        for piece in group {
            if !any_covers || covers_window_end(piece, windows) {
                out.push(*piece);
            }
        }
        start += count;
    }
    out
}

/// Trailing `; fmt pieces array ...` suffix for a code hit whose RIP-relative target lands in
/// `[array_start, slot]`.
#[must_use]
pub fn hit_suffix(pieces: &[PieceMatch], memory: Option<u64>) -> String {
    let Some(addr) = memory else {
        return String::new();
    };
    let mut suffix = String::new();
    for piece in pieces {
        if (piece.array_start..=piece.slot).contains(&addr) {
            let sep = if suffix.is_empty() { "  ; " } else { "; " };
            let _ = write!(suffix, "{sep}fmt pieces array {:#x}, piece {}", piece.array_start, piece.index);
        }
    }
    suffix
}

#[cfg(test)]
mod tests {
    use super::{PieceMatch, hit_suffix, infer_slot, infer_slots};
    use crate::image::{Image, Segment};
    use crate::image_format::{LoadSegment, Metadata};

    fn write_u64(data: &mut [u8], offset: usize, value: u64) {
        data[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
    }

    fn test_image() -> Image {
        let mut data = vec![0u8; 0x600];
        let segments = vec![
            Segment { va: 0x1000, offset: 0x000, size: 0x100 },
            Segment { va: 0x2000, offset: 0x100, size: 0x200 },
            Segment { va: 0x4000, offset: 0x300, size: 0x300 },
        ];
        let metadata = Metadata {
            load_segments: vec![
                LoadSegment {
                    va: 0x1000,
                    file_offset: 0x000,
                    file_size: 0x100,
                    mem_size: 0x100,
                    executable: true,
                    writable: false,
                },
                LoadSegment {
                    va: 0x2000,
                    file_offset: 0x100,
                    file_size: 0x200,
                    mem_size: 0x200,
                    executable: false,
                    writable: false,
                },
                LoadSegment {
                    va: 0x4000,
                    file_offset: 0x300,
                    file_size: 0x300,
                    mem_size: 0x300,
                    executable: false,
                    writable: true,
                },
            ],
            ..Metadata::default()
        };

        // 0x40f0: preceding code pointer + integer 8 (must not be treated as a piece element).
        write_u64(&mut data, 0x3f8, 8);
        // 0x4100..0x4130: 3-piece array ("alpha=", " beta_sum=", " gamma=").
        write_u64(&mut data, 0x408, 6);
        write_u64(&mut data, 0x418, 10);
        write_u64(&mut data, 0x428, 7);
        // 0x4200: standalone &str / panic::Location-like pair.
        write_u64(&mut data, 0x508, 12);
        // 0x4230..0x4250: pointer table where +8 is also a relocated pointer with small value 5.
        write_u64(&mut data, 0x538, 5);
        write_u64(&mut data, 0x548, 8);
        // 0x4260: out-of-bounds piece length (exceeds 0x2200 segment end).
        write_u64(&mut data, 0x568, 0x180);

        let mut pointers = vec![
            (0x40f0, 0x1020),
            (0x4100, 0x2100),
            (0x4110, 0x2106),
            (0x4120, 0x2110),
            (0x4200, 0x2140),
            (0x4230, 0x2150),
            (0x4238, 0x2158),
            (0x4240, 0x2160),
            (0x4260, 0x2100),
        ];
        pointers.sort_unstable();

        Image { data, segments, pointers, metadata, ..Image::default() }
    }

    #[test]
    fn reloc_refs_pieces_walks_back_to_array_start_and_stops_at_non_piece() {
        let image = test_image();
        assert_eq!(
            infer_slot(&image, 0x4100),
            Some(PieceMatch { array_start: 0x4100, slot: 0x4100, index: 0, target: 0x2100, len: 6 })
        );
        assert_eq!(
            infer_slot(&image, 0x4110),
            Some(PieceMatch { array_start: 0x4100, slot: 0x4110, index: 1, target: 0x2106, len: 10 })
        );
        assert_eq!(
            infer_slot(&image, 0x4120),
            Some(PieceMatch { array_start: 0x4100, slot: 0x4120, index: 2, target: 0x2110, len: 7 })
        );
    }

    #[test]
    fn reloc_refs_pieces_rejects_standalone_str_relocated_len_and_bad_lengths() {
        let image = test_image();
        assert_eq!(infer_slot(&image, 0x40f0), None);
        assert_eq!(infer_slot(&image, 0x4200), None);
        assert_eq!(infer_slot(&image, 0x4230), None);
        assert_eq!(infer_slot(&image, 0x4240), None);
        assert_eq!(infer_slot(&image, 0x4260), None);
    }

    #[test]
    fn reloc_refs_pieces_prefers_piece_covering_window_anchor_when_back_spills() {
        let image = test_image();
        // Searching "beta_sum=" at 0x2107 with --back 8 gives window 0x20ff..=0x2107,
        // which hits both piece 0 (0x2100..0x2106) and piece 1 (0x2106..0x2110).
        let windows = crate::reach::windows(&[0x2107], 8);
        let slots = vec![(0x4100, 0x2100), (0x4110, 0x2106)];
        let pieces = infer_slots(&image, &windows, &slots);
        assert_eq!(pieces, vec![PieceMatch { array_start: 0x4100, slot: 0x4110, index: 1, target: 0x2106, len: 10 }]);
        assert_eq!(hit_suffix(&pieces, Some(0x4100)), "  ; fmt pieces array 0x4100, piece 1");
        assert_eq!(hit_suffix(&pieces, Some(0x4200)), "");
        assert_eq!(hit_suffix(&pieces, None), "");
    }
}
