/*
 * xref — Ultra blazing fast cross-references of an x86-64 ELF binary
 * Copyright (c) 2026 Alexander Panasenko
 *
 * Contact: alex@prod.codes
 * Author: https://prod.codes/about/
 * SPDX-License-Identifier: MIT OR Apache-2.0
 */

//! The ELF image: loadable segments for reads by virtual address, the exact function ranges of
//! `.eh_frame`, the `R_X86_64_RELATIVE` pointers stored in data and the imported symbol slots.

use std::error::Error;
use std::ops::Range;
use std::path::Path;

use gimli::{BaseAddresses, CieOrFde, EhFrame, LittleEndian, UnwindSection};
use object::{Object, ObjectSection, ObjectSegment, ObjectSymbol, ObjectSymbolTable, RelocationTarget, SymbolKind};

pub struct Segment {
    pub va: u64,
    pub offset: usize,
    pub size: usize,
}

#[derive(Default)]
pub struct Image {
    pub data: Vec<u8>,
    pub segments: Vec<Segment>,
    /// Sorted, deduplicated function ranges.
    pub functions: Vec<Range<u64>>,
    /// `(place, target)` of every relative relocation, sorted by place.
    pub pointers: Vec<(u64, u64)>,
    /// `(place, symbol)` of every relocation naming a dynamic symbol (GOT and PLT slots).
    pub imports: Vec<(u64, String)>,
    /// `(address, name)` of the function symbols a non-stripped binary keeps, sorted.
    pub symbols: Vec<(u64, String)>,
    pub metadata: crate::image_format::Metadata,
}

/// Byte offsets of every occurrence of `needle` in `haystack`.
pub fn occurrences(haystack: &[u8], needle: &[u8]) -> Vec<usize> {
    occurrence_iter(haystack, needle).collect()
}

pub fn occurrence_iter<'a>(haystack: &'a [u8], needle: &'a [u8]) -> impl Iterator<Item = usize> + 'a {
    let mut from = 0;
    std::iter::from_fn(move || {
        let (&first, rest) = needle.split_first()?;
        while let Some(index) = haystack[from..].iter().position(|byte| *byte == first) {
            let at = from + index;
            from = at + 1;
            if haystack[at + 1..].starts_with(rest) {
                return Some(at);
            }
        }
        None
    })
}

fn parse_eh_frame_section(
    file: &object::File<'_>,
    section: &object::Section<'_, '_>,
) -> Result<Vec<Range<u64>>, Box<dyn Error>> {
    let eh_frame = EhFrame::new(section.data()?, LittleEndian);
    let mut bases = BaseAddresses::default().set_eh_frame(section.address());
    if let Some(text) = file.section_by_name(".text") {
        bases = bases.set_text(text.address());
    }
    let mut functions = Vec::new();
    let mut entries = eh_frame.entries(&bases);
    while let Some(entry) = entries.next()? {
        if let CieOrFde::Fde(partial) = entry {
            let fde = partial.parse(EhFrame::cie_from_offset)?;
            if fde.len() > 0 {
                let end = fde.initial_address().checked_add(fde.len()).ok_or("function range overflow")?;
                functions.push(fde.initial_address()..end);
            }
        }
    }
    functions.sort_by_key(|range| (range.start, range.end));
    functions.dedup();
    Ok(functions)
}

type UnwindFunctions = (Vec<Range<u64>>, Option<&'static str>);

fn function_ranges(file: &object::File<'_>, require_eh_frame: bool) -> Result<UnwindFunctions, Box<dyn Error>> {
    let Some(section) = file.section_by_name(".eh_frame") else {
        if require_eh_frame {
            return Err("no .eh_frame section".into());
        }
        return Ok((Vec::new(), Some("missing_eh_frame")));
    };
    match parse_eh_frame_section(file, &section) {
        Ok(functions) => Ok((functions, None)),
        Err(err) if require_eh_frame => Err(err),
        Err(_) => Ok((Vec::new(), Some("invalid_eh_frame"))),
    }
}

impl Image {
    pub fn load(path: &Path) -> Result<Self, Box<dyn Error>> {
        let data = std::fs::read(path)?;
        Self::parse(data)
    }

    pub fn parse(data: Vec<u8>) -> Result<Self, Box<dyn Error>> {
        Self::parse_inner(data, true)
    }

    pub fn parse_for_live(data: Vec<u8>) -> Result<Self, Box<dyn Error>> {
        Self::parse_inner(data, false)
    }

    fn parse_inner(data: Vec<u8>, require_eh_frame: bool) -> Result<Self, Box<dyn Error>> {
        let file = crate::image_format::parse(&data)?;
        let segments = file
            .segments()
            .filter(|segment| segment.file_range().1 > 0)
            .map(|segment| {
                let (offset, size) = segment.file_range();
                if offset.checked_add(size).is_none_or(|end| end > data.len() as u64)
                    || segment.address().checked_add(size).is_none()
                {
                    return Err("segment range overflow".into());
                }
                Ok(Segment { va: segment.address(), offset: usize::try_from(offset)?, size: usize::try_from(size)? })
            })
            .collect::<Result<Vec<_>, Box<dyn Error>>>()?;
        let (functions, unwind_warning) = function_ranges(&file, require_eh_frame)?;
        let mut metadata = crate::image_format::metadata(&file, &data, &segments, &functions)?;
        if let Some(warning) = unwind_warning {
            metadata.warn(warning);
        }
        let symbols = file.dynamic_symbol_table();
        let mut pointers = Vec::new();
        let mut imports = Vec::new();
        for (place, relocation) in file.dynamic_relocations().into_iter().flatten() {
            match relocation.target() {
                RelocationTarget::Symbol(index) => {
                    let name = symbols.as_ref().and_then(|table| table.symbol_by_index(index).ok()?.name().ok());
                    imports.push((place, name.unwrap_or("?").to_owned()));
                }
                _ if matches!(relocation.flags(), object::RelocationFlags::Elf { r_type } if r_type == object::elf::R_X86_64_RELATIVE) =>
                {
                    pointers.push((place, relocation.addend().cast_unsigned()));
                }
                _ => {}
            }
        }
        pointers.extend(crate::relr::collect(&file, &data, &segments)?);
        if let object::File::MachO64(macho) = &file {
            let linkage = crate::macho::linkage::collect(macho, &data, metadata.base)?;
            imports = linkage.imports;
            pointers = linkage.pointers;
            metadata.exports.extend(linkage.exports);
            if let Some(entry) = metadata.entry {
                metadata.exports.insert(entry);
            }
            if !linkage.imports_complete {
                metadata.warn("macho_import_metadata_incomplete");
            }
            if !linkage.fixups_complete {
                metadata.warn("macho_fixup_metadata_incomplete");
            }
            if !linkage.exports_complete {
                metadata.warn("macho_export_metadata_incomplete");
            }
            for warning in linkage.warnings {
                metadata.warn(warning);
            }
        }
        pointers.sort_unstable();
        pointers.dedup();
        imports.sort_unstable();
        let mut symbols: Vec<(u64, String)> = file
            .symbols()
            .filter(|symbol| symbol.kind() == SymbolKind::Text && symbol.address() != 0)
            .filter_map(|symbol| Some((symbol.address(), symbol.name().ok()?.to_owned())))
            .collect();
        symbols.sort_unstable();
        drop(file);
        Ok(Self { data, segments, functions, pointers, imports, symbols, metadata })
    }

    /// `len` bytes at virtual address `va`, when one segment holds them.
    pub fn read(&self, va: u64, len: usize) -> Option<&[u8]> {
        let virtual_len = u64::try_from(len).ok()?;
        let segment =
            self.segments.iter().find(|segment| match (va.checked_sub(segment.va), u64::try_from(segment.size)) {
                (Some(delta), Ok(size)) => delta.checked_add(virtual_len).is_some_and(|end| end <= size),
                _ => false,
            })?;
        let offset = usize::try_from(va.checked_sub(segment.va)?).ok()?;
        let start = segment.offset.checked_add(offset)?;
        self.data.get(start..start.checked_add(len)?)
    }

    pub fn read_u64(&self, va: u64) -> Option<u64> {
        Some(u64::from_le_bytes(self.read(va, 8)?.try_into().ok()?))
    }

    pub fn read_u32(&self, va: u64) -> Option<u32> {
        Some(u32::from_le_bytes(self.read(va, 4)?.try_into().ok()?))
    }

    /// The function containing `addr` (the innermost one when ranges nest).
    pub fn function_at(&self, addr: u64) -> Option<Range<u64>> {
        let end = self.functions.partition_point(|range| range.start <= addr);
        self.functions[..end].iter().rev().take(64).find(|range| range.contains(&addr)).cloned()
    }

    /// The `.eh_frame` function containing `addr`, or a synthetic range up to the next function.
    pub fn function_or_span(&self, addr: u64, to: Option<u64>) -> Option<Range<u64>> {
        if let Some(f) = self.function_at(addr) {
            return Some(f);
        }
        if self.metadata.kind == crate::image_format::Kind::MachO {
            let section = self.metadata.code_ranges.iter().find(|r| r.contains(&addr))?;
            let next = self.metadata.function_starts.iter().copied().find(|&s| s > addr).unwrap_or(section.end);
            let end = next.min(section.end).min(addr.saturating_add(0x1000));
            let end = to.unwrap_or(end).min(end);
            return (addr < end).then_some(addr..end);
        }
        let seg = self.segments.iter().find(|s| addr >= s.va && addr < s.va + s.size as u64)?;
        let seg_end = seg.va + seg.size as u64;
        let next = self.functions.iter().find(|f| f.start > addr).map_or(seg_end, |f| f.start);
        Some(addr..to.unwrap_or_else(|| next.min(seg_end).min(addr + 0x1000)))
    }

    /// Bytes of a function range.
    pub fn code(&self, function: &Range<u64>) -> Option<&[u8]> {
        self.read(function.start, usize::try_from(function.end - function.start).ok()?)
    }

    /// What a data slot holds: an imported symbol or a relocated pointer.
    pub fn slot(&self, place: u64) -> Option<Slot<'_>> {
        if let Ok(index) = self.imports.binary_search_by_key(&place, |(at, _)| *at) {
            return Some(Slot::Import(&self.imports[index].1));
        }
        let index = self.pointers.binary_search_by_key(&place, |(at, _)| *at).ok()?;
        Some(Slot::Pointer(self.pointers[index].1))
    }

    /// Virtual addresses of every occurrence of `needle` in the loadable segments.
    pub fn find(&self, needle: &[u8]) -> Vec<u64> {
        let mut found = Vec::new();
        for segment in self.searchable_segments() {
            let Some(bytes) = self.data.get(segment.offset..segment.offset + segment.size) else { continue };
            found.extend(occurrences(bytes, needle).into_iter().map(|at| segment.va + at as u64));
        }
        found.sort_unstable();
        found.dedup();
        found
    }
    pub fn searchable_segments(&self) -> impl Iterator<Item = &Segment> {
        self.segments.iter().filter(|s| !self.metadata.search_excluded.iter().any(|r| r.contains(&s.va)))
    }

    /// Printable preview at `va` plus whether its byte length is self-delimited (`true` for
    /// NUL-terminated C strings or length-prefixed rustc format pieces; `false` for packed `.rodata`).
    pub fn rodata_preview(&self, va: u64) -> Option<(String, bool)> {
        let bytes = self.read(va, 64).or_else(|| self.read(va, 8))?;
        let printable = |slice: &[u8]| slice.iter().all(|b| (0x20..0x7f).contains(b));
        let length = usize::from(bytes[0]);
        if (2..bytes.len()).contains(&length)
            && printable(&bytes[1..=length])
            && (bytes[0] < 0x20 || bytes.get(1 + length).is_some_and(|&b| b < 0x20))
        {
            return Some((String::from_utf8_lossy(&bytes[1..=length]).into_owned(), true));
        }
        let run = bytes.iter().take_while(|b| (0x20..0x7f).contains(*b)).count();
        (run >= 4).then(|| (String::from_utf8_lossy(&bytes[..run]).into_owned(), bytes.get(run) == Some(&0)))
    }

    /// A short printable preview of the bytes at `va`: a C string, or a rustc format piece whose
    /// first byte is its length.
    pub fn preview(&self, va: u64) -> Option<String> {
        self.rodata_preview(va).map(|(s, _)| s)
    }
}

pub enum Slot<'a> {
    Import(&'a str),
    Pointer(u64),
}

#[cfg(test)]
mod tests {
    use super::occurrences;

    #[test]
    fn occurrences_include_overlapping_matches() {
        assert_eq!(occurrences(b"abababa", b"aba"), [0, 2, 4]);
        assert_eq!(occurrences(b"some text\0some text", b"some text"), [0, 10]);
        assert_eq!(occurrences(b"abc", b""), Vec::<usize>::new());
    }
}
