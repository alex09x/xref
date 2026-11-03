/*
 * XRef Code — evidence-producing binary analysis
 * Copyright (c) 2026 Alexander Panasenko
 * Contact: alex@prod.codes
 * Author: https://prod.codes/about/
 * Project: https://github.com/alex09x/xref
 * SPDX-License-Identifier: MIT OR Apache-2.0
 */
use crate::image::Segment;
use object::{Architecture, BinaryFormat, Object, ObjectSymbol};
use std::{collections::BTreeSet, error::Error, fmt, ops::Range};

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum Kind {
    #[default]
    Elf,
    MachO,
}
#[derive(Default)]
pub struct Metadata {
    pub kind: Kind,
    pub base: u64,
    pub entry: Option<u64>,
    pub function_starts: Vec<u64>,
    pub code_ranges: Vec<Range<u64>>,
    pub search_excluded: Vec<Range<u64>>,
    pub exports: BTreeSet<u64>,
    pub uncovered_starts: usize,
    pub warnings: Vec<&'static str>,
}
impl Metadata {
    pub const fn format(&self) -> &'static str {
        match self.kind {
            Kind::Elf => "elf",
            Kind::MachO => "macho",
        }
    }
    pub const fn rva_basis(&self) -> &'static str {
        match self.kind {
            Kind::Elf => "lowest_load_segment_va",
            Kind::MachO => "macho_text_segment_vmaddr",
        }
    }
    pub fn warn(&mut self, value: &'static str) {
        if !self.warnings.contains(&value) {
            self.warnings.push(value);
        }
    }
}
#[derive(Debug)]
pub struct InputError {
    pub unsupported: bool,
    pub message: String,
}
impl InputError {
    pub fn unsupported(message: impl Into<String>) -> Self {
        Self { unsupported: true, message: message.into() }
    }
    pub fn invalid(message: impl Into<String>) -> Self {
        Self { unsupported: false, message: message.into() }
    }
}
impl fmt::Display for InputError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.message.fmt(f)
    }
}
impl Error for InputError {}

pub fn parse(data: &[u8]) -> Result<object::File<'_>, InputError> {
    let magic = data.get(..4).unwrap_or_default();
    let supported_magic = magic == b"\x7fELF" || magic == [0xcf, 0xfa, 0xed, 0xfe];
    let file = object::File::parse(data).map_err(|e| {
        if supported_magic {
            InputError::invalid(e.to_string())
        } else {
            InputError::unsupported("supported input: little-endian x86-64 ELF or thin 64-bit Mach-O")
        }
    })?;
    if !matches!(file.format(), BinaryFormat::Elf | BinaryFormat::MachO)
        || file.architecture() != Architecture::X86_64
        || !file.is_little_endian()
        || !file.is_64()
    {
        return Err(InputError::unsupported(
            "supported input: little-endian x86-64 ELF or thin 64-bit Mach-O; ARM64/fat/32-bit inputs are unsupported",
        ));
    }
    if file.format() == BinaryFormat::MachO {
        crate::macho::profile::validate(data)?;
        if file.section_by_name(".eh_frame").is_none() {
            return Err(InputError::unsupported(
                "Mach-O requires DWARF __eh_frame; compact-unwind-only images are unsupported",
            ));
        }
    }
    Ok(file)
}
pub fn metadata(
    file: &object::File<'_>,
    data: &[u8],
    segments: &[Segment],
    functions: &[Range<u64>],
) -> Result<Metadata, Box<dyn Error>> {
    if file.format() == BinaryFormat::MachO {
        return crate::macho::profile::metadata(file, data, segments, functions).map_err(Into::into);
    }
    let mut out = Metadata { base: segments.iter().map(|s| s.va).min().unwrap_or(0), ..Metadata::default() };
    if file.entry() != 0 {
        out.entry = Some(file.entry());
        out.exports.insert(file.entry());
    }
    for symbol in file.dynamic_symbols() {
        if symbol.is_definition() && symbol.address() != 0 {
            out.exports.insert(symbol.address());
        }
    }
    Ok(out)
}
