/*
 * xref — Ultra blazing fast cross-references of an x86-64 ELF binary
 * Copyright (c) 2026 Alexander Panasenko
 *
 * Contact: alex@prod.codes
 * Author: https://prod.codes/about/
 * Project: https://github.com/alex09x/xref
 * SPDX-License-Identifier: MIT OR Apache-2.0
 */

//! Decode packed relative relocations (`SHT_RELR` / `DT_RELR`) per the ELF gABI RELR spec.
//! Every relocated 8-byte slot stores its link-time target address as an implicit addend in the
//! file image.

use object::read::elf::{Dyn, ProgramHeader, SectionHeader};

use crate::image::Segment;
use crate::image_format::InputError;

const SHT_RELR: u32 = 0x13;
const DT_NULL: u64 = 0;
const DT_RELRSZ: u64 = 0x23;
const DT_RELR: u64 = 0x24;
const DT_RELRENT: u64 = 0x25;

const ENTRY_BYTES: usize = 8;
const ENTRY_SIZE_U64: u64 = 8;
const BITMAP_STRIDE: u64 = 63 * ENTRY_SIZE_U64;
const MAX_TABLE_BYTES: usize = 16 * 1024 * 1024;
const MAX_RELR_SLOTS: usize = 4_000_000;

fn read_bytes<'a>(data: &'a [u8], segments: &[Segment], va: u64, len: usize) -> Option<&'a [u8]> {
    let virtual_len = u64::try_from(len).ok()?;
    let segment = segments.iter().find(|seg| match (va.checked_sub(seg.va), u64::try_from(seg.size)) {
        (Some(delta), Ok(size)) => delta.checked_add(virtual_len).is_some_and(|end| end <= size),
        _ => false,
    })?;
    let offset = usize::try_from(va.checked_sub(segment.va)?).ok()?;
    let start = segment.offset.checked_add(offset)?;
    data.get(start..start.checked_add(len)?)
}

fn read_u64_at(data: &[u8], segments: &[Segment], va: u64) -> Option<u64> {
    let bytes: [u8; 8] = read_bytes(data, segments, va, ENTRY_BYTES)?.try_into().ok()?;
    Some(u64::from_le_bytes(bytes))
}

fn va_to_file_range(data: &[u8], segments: &[Segment], va: u64, size: u64) -> Result<(usize, usize), InputError> {
    let len = usize::try_from(size).map_err(|_| InputError::invalid("RELR table size overflow"))?;
    let segment = segments
        .iter()
        .find(|seg| match (va.checked_sub(seg.va), u64::try_from(seg.size)) {
            (Some(delta), Ok(seg_size)) => delta.checked_add(size).is_some_and(|end| end <= seg_size),
            _ => false,
        })
        .ok_or_else(|| InputError::invalid("DT_RELR range outside loadable file segment"))?;
    let delta =
        usize::try_from(va.checked_sub(segment.va).ok_or_else(|| InputError::invalid("DT_RELR address underflow"))?)
            .map_err(|_| InputError::invalid("DT_RELR offset overflow"))?;
    let start = segment.offset.checked_add(delta).ok_or_else(|| InputError::invalid("DT_RELR file offset overflow"))?;
    if start.checked_add(len).is_none_or(|end| end > data.len()) {
        return Err(InputError::invalid("DT_RELR range out of file bounds"));
    }
    Ok((start, len))
}

/// Decode one raw `Elf64_Relr` byte slice into `(place, implicit_addend)` pairs.
pub fn decode_table(
    table: &[u8],
    data: &[u8],
    segments: &[Segment],
    max_slots: usize,
    out: &mut Vec<(u64, u64)>,
) -> Result<(), InputError> {
    let (chunks, remainder) = table.as_chunks::<ENTRY_BYTES>();
    if !remainder.is_empty() {
        return Err(InputError::invalid("malformed RELR table: size is not a multiple of 8"));
    }
    if table.len() > MAX_TABLE_BYTES {
        return Err(InputError::invalid("malformed RELR table: exceeds byte budget"));
    }
    let mut next_va: Option<u64> = None;
    for &raw in chunks {
        let entry = u64::from_le_bytes(raw);
        if entry & 1 == 0 {
            if out.len() >= max_slots {
                return Err(InputError::invalid("RELR relocation count exceeds bound"));
            }
            let target = read_u64_at(data, segments, entry)
                .ok_or_else(|| InputError::invalid("malformed RELR address outside loadable file segment"))?;
            let after = entry
                .checked_add(ENTRY_SIZE_U64)
                .ok_or_else(|| InputError::invalid("malformed RELR address overflow"))?;
            out.push((entry, target));
            next_va = Some(after);
        } else {
            let Some(base) = next_va else {
                return Err(InputError::invalid("malformed RELR bitmap entry before address entry"));
            };
            let after = base
                .checked_add(BITMAP_STRIDE)
                .ok_or_else(|| InputError::invalid("malformed RELR bitmap address overflow"))?;
            let mut bits = entry >> 1;
            while bits != 0 {
                if out.len() >= max_slots {
                    return Err(InputError::invalid("RELR relocation count exceeds bound"));
                }
                let bit = u64::from(bits.trailing_zeros());
                let offset = bit
                    .checked_mul(ENTRY_SIZE_U64)
                    .ok_or_else(|| InputError::invalid("malformed RELR bitmap bit offset"))?;
                let place = base
                    .checked_add(offset)
                    .ok_or_else(|| InputError::invalid("malformed RELR bitmap slot overflow"))?;
                let target = read_u64_at(data, segments, place)
                    .ok_or_else(|| InputError::invalid("malformed RELR bitmap slot outside loadable file segment"))?;
                out.push((place, target));
                bits &= bits - 1;
            }
            next_va = Some(after);
        }
    }
    Ok(())
}

/// Collect `(place, target)` pairs from all `SHT_RELR` sections and `DT_RELR` dynamic tables.
pub fn collect(file: &object::File<'_>, data: &[u8], segments: &[Segment]) -> Result<Vec<(u64, u64)>, InputError> {
    let object::File::Elf64(elf) = file else {
        return Ok(Vec::new());
    };
    let endian = elf.endian();
    let mut ranges: Vec<(usize, usize)> = Vec::new();
    for section in elf.elf_section_table().iter() {
        if section.sh_type(endian) != SHT_RELR {
            continue;
        }
        let entsize = section.sh_entsize(endian);
        if entsize != 0 && entsize != ENTRY_SIZE_U64 {
            return Err(InputError::invalid("malformed SHT_RELR sh_entsize"));
        }
        let (offset, size) =
            section.file_range(endian).ok_or_else(|| InputError::invalid("malformed SHT_RELR section range"))?;
        if !size.is_multiple_of(ENTRY_SIZE_U64) {
            return Err(InputError::invalid("malformed SHT_RELR section size"));
        }
        let start = usize::try_from(offset).map_err(|_| InputError::invalid("SHT_RELR offset overflow"))?;
        let len = usize::try_from(size).map_err(|_| InputError::invalid("SHT_RELR size overflow"))?;
        if start.checked_add(len).is_none_or(|end| end > data.len()) {
            return Err(InputError::invalid("SHT_RELR section out of file bounds"));
        }
        if len > 0 {
            ranges.push((start, len));
        }
    }
    for phdr in elf.elf_program_headers() {
        let Some(entries) =
            phdr.dynamic(endian, data).map_err(|_| InputError::invalid("malformed PT_DYNAMIC segment"))?
        else {
            continue;
        };
        let mut dt_relr = None;
        let mut dt_relrsz = None;
        let mut dt_relrent = None;
        for dyn_entry in entries {
            let tag = dyn_entry.d_tag(endian);
            if tag == DT_NULL {
                break;
            }
            let val = dyn_entry.d_val(endian);
            match tag {
                DT_RELR => dt_relr = Some(val),
                DT_RELRSZ => dt_relrsz = Some(val),
                DT_RELRENT => dt_relrent = Some(val),
                _ => {}
            }
        }
        if let Some(ent) = dt_relrent
            && ent != ENTRY_SIZE_U64
        {
            return Err(InputError::invalid("malformed DT_RELRENT"));
        }
        match (dt_relr, dt_relrsz) {
            (None, None | Some(0)) | (Some(_), Some(0)) => {}
            (Some(_), None) | (None, Some(_)) => {
                return Err(InputError::invalid("incomplete DT_RELR dynamic tags"));
            }
            (Some(va), Some(size)) => {
                if !size.is_multiple_of(ENTRY_SIZE_U64) {
                    return Err(InputError::invalid("malformed DT_RELRSZ"));
                }
                ranges.push(va_to_file_range(data, segments, va, size)?);
            }
        }
    }
    ranges.sort_unstable();
    ranges.dedup();
    let mut out = Vec::new();
    for (start, len) in ranges {
        let table = data.get(start..start + len).ok_or_else(|| InputError::invalid("RELR table out of bounds"))?;
        decode_table(table, data, segments, MAX_RELR_SLOTS, &mut out)?;
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use std::error::Error;

    use super::decode_table;
    use crate::image::Segment;

    fn write_u64(buf: &mut [u8], offset: usize, value: u64) {
        buf[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
    }

    #[test]
    fn reloc_refs_relr_decodes_address_and_chained_bitmap_entries() -> Result<(), Box<dyn Error>> {
        let mut data = vec![0u8; 0x800];
        let segments = vec![Segment { va: 0x4000, offset: 0, size: data.len() }];

        // Address entry at 0x4100, then first bitmap (bit 0 => 0x4108, bit 2 => 0x4118, bit 62 => 0x42f8),
        // then chained second bitmap starting at 0x4300 (bit 1 => 0x4308), then address entry at 0x4500.
        write_u64(&mut data, 0x100, 0x2010);
        write_u64(&mut data, 0x108, 0x2020);
        write_u64(&mut data, 0x118, 0x2030);
        write_u64(&mut data, 0x2f8, 0x2040);
        write_u64(&mut data, 0x308, 0x2050);
        write_u64(&mut data, 0x500, 0x2060);

        let bitmap1 = 1u64 | (1u64 << 1) | (1u64 << 3) | (1u64 << 63);
        let bitmap2 = 1u64 | (1u64 << 2);
        let entries = [0x4100u64, bitmap1, bitmap2, 0x4500u64];
        let mut table = Vec::with_capacity(entries.len() * 8);
        for entry in entries {
            table.extend_from_slice(&entry.to_le_bytes());
        }

        let mut decoded = Vec::new();
        decode_table(&table, &data, &segments, 64, &mut decoded)?;
        assert_eq!(
            decoded,
            vec![
                (0x4100, 0x2010),
                (0x4108, 0x2020),
                (0x4118, 0x2030),
                (0x42f8, 0x2040),
                (0x4308, 0x2050),
                (0x4500, 0x2060),
            ]
        );
        Ok(())
    }

    #[test]
    fn reloc_refs_relr_rejects_malformed_and_unbounded_tables() {
        let data = vec![0u8; 0x400];
        let segments = vec![Segment { va: 0x4000, offset: 0, size: data.len() }];

        // Unaligned byte length.
        let mut out = Vec::new();
        assert!(decode_table(&[1, 2, 3], &data, &segments, 64, &mut out).is_err());

        // Bitmap entry without a preceding address entry.
        out.clear();
        assert!(decode_table(&3u64.to_le_bytes(), &data, &segments, 64, &mut out).is_err());

        // Address entry outside loadable segment.
        out.clear();
        assert!(decode_table(&0x9000u64.to_le_bytes(), &data, &segments, 64, &mut out).is_err());

        // Bitmap slot extending past segment end.
        let mut oob_bitmap = Vec::new();
        oob_bitmap.extend_from_slice(&0x43f8u64.to_le_bytes());
        oob_bitmap.extend_from_slice(&3u64.to_le_bytes());
        out.clear();
        assert!(decode_table(&oob_bitmap, &data, &segments, 64, &mut out).is_err());

        // Address overflow on +8 advance.
        out.clear();
        assert!(decode_table(&0xffff_ffff_ffff_fffeu64.to_le_bytes(), &data, &segments, 64, &mut out).is_err());

        // Slot budget exceeded by dense bitmap expansion.
        let mut dense = Vec::new();
        dense.extend_from_slice(&0x4000u64.to_le_bytes());
        dense.extend_from_slice(&u64::MAX.to_le_bytes());
        out.clear();
        assert!(decode_table(&dense, &data, &segments, 4, &mut out).is_err());
    }
}
