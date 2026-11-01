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
}

/// Byte offsets of every occurrence of `needle` in `haystack`.
pub fn occurrences(haystack: &[u8], needle: &[u8]) -> Vec<usize> {
    let Some((&first, rest)) = needle.split_first() else { return Vec::new() };
    let mut found = Vec::new();
    let mut from = 0;
    while let Some(index) = haystack[from..].iter().position(|byte| *byte == first) {
        let at = from + index;
        if haystack[at + 1..].starts_with(rest) {
            found.push(at);
        }
        from = at + 1;
    }
    found
}

fn function_ranges(file: &object::File<'_>) -> Result<Vec<Range<u64>>, Box<dyn Error>> {
    let section = file.section_by_name(".eh_frame").ok_or("no .eh_frame section")?;
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
                functions.push(fde.initial_address()..fde.initial_address() + fde.len());
            }
        }
    }
    functions.sort_by_key(|range| (range.start, range.end));
    functions.dedup();
    Ok(functions)
}

impl Image {
    pub fn load(path: &Path) -> Result<Self, Box<dyn Error>> {
        let data = std::fs::read(path)?;
        let file = object::File::parse(&*data)?;
        let segments = file
            .segments()
            .map(|segment| {
                let (offset, size) = segment.file_range();
                Ok(Segment { va: segment.address(), offset: usize::try_from(offset)?, size: usize::try_from(size)? })
            })
            .collect::<Result<Vec<_>, Box<dyn Error>>>()?;
        let functions = function_ranges(&file)?;
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
        pointers.sort_unstable();
        imports.sort_unstable();
        let mut symbols: Vec<(u64, String)> = file
            .symbols()
            .filter(|symbol| symbol.kind() == SymbolKind::Text && symbol.address() != 0)
            .filter_map(|symbol| Some((symbol.address(), symbol.name().ok()?.to_owned())))
            .collect();
        symbols.sort_unstable();
        drop(file);
        Ok(Self { data, segments, functions, pointers, imports, symbols })
    }

    /// `len` bytes at virtual address `va`, when one segment holds them.
    pub fn read(&self, va: u64, len: usize) -> Option<&[u8]> {
        let segment = self.segments.iter().find(|s| va >= s.va && va - s.va + len as u64 <= s.size as u64)?;
        let start = segment.offset + usize::try_from(va - segment.va).ok()?;
        self.data.get(start..start + len)
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
        for segment in &self.segments {
            let Some(bytes) = self.data.get(segment.offset..segment.offset + segment.size) else { continue };
            found.extend(occurrences(bytes, needle).into_iter().map(|at| segment.va + at as u64));
        }
        found.sort_unstable();
        found.dedup();
        found
    }

    /// A short printable preview of the bytes at `va`: a C string, or a rustc format piece whose
    /// first byte is its length.
    pub fn preview(&self, va: u64) -> Option<String> {
        let bytes = self.read(va, 64).or_else(|| self.read(va, 8))?;
        let printable = |slice: &[u8]| slice.iter().all(|b| (0x20..0x7f).contains(b));
        let length = usize::from(bytes[0]);
        if (2..bytes.len()).contains(&length) && printable(&bytes[1..=length]) {
            return Some(String::from_utf8_lossy(&bytes[1..=length]).into_owned());
        }
        let run = bytes.iter().take_while(|b| (0x20..0x7f).contains(*b)).count();
        (run >= 4).then(|| String::from_utf8_lossy(&bytes[..run]).into_owned())
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
