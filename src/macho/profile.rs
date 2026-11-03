/*
 * XRef Code — evidence-producing binary analysis
 * Copyright (c) 2026 Alexander Panasenko
 * Contact: alex@prod.codes
 * Author: https://prod.codes/about/
 * Project: https://github.com/alex09x/xref
 * SPDX-License-Identifier: MIT OR Apache-2.0
 */
use crate::{
    image::Segment,
    image_format::{InputError, Kind, Metadata},
};
use gimli::Reader;
use object::{Object, ObjectSection, ObjectSegment, ObjectSymbol, SectionFlags, SectionKind};
use std::{collections::BTreeSet, ops::Range};
fn u32_at(data: &[u8], at: usize) -> Result<u32, InputError> {
    Ok(u32::from_le_bytes(
        data.get(at..at + 4)
            .ok_or_else(|| InputError::invalid("truncated Mach-O command"))?
            .try_into()
            .map_err(|_| InputError::invalid("u32"))?,
    ))
}
fn u64_at(data: &[u8], at: usize) -> Result<u64, InputError> {
    Ok(u64::from_le_bytes(
        data.get(at..at + 8)
            .ok_or_else(|| InputError::invalid("truncated Mach-O command"))?
            .try_into()
            .map_err(|_| InputError::invalid("u64"))?,
    ))
}
pub fn commands(data: &[u8]) -> Result<Vec<(u32, &[u8])>, InputError> {
    let count = usize::try_from(u32_at(data, 16)?).map_err(|_| InputError::invalid("command count"))?;
    let size = usize::try_from(u32_at(data, 20)?).map_err(|_| InputError::invalid("command size"))?;
    let end = 32usize
        .checked_add(size)
        .filter(|&v| v <= data.len())
        .ok_or_else(|| InputError::invalid("load commands out of file"))?;
    if count > 100_000 {
        return Err(InputError::invalid("load-command budget exceeded"));
    }
    let mut at = 32;
    let mut out = Vec::with_capacity(count);
    for _ in 0..count {
        let cmd = u32_at(data, at)?;
        let len = usize::try_from(u32_at(data, at + 4)?).map_err(|_| InputError::invalid("command size"))?;
        let next = at
            .checked_add(len)
            .filter(|&v| len >= 8 && len % 8 == 0 && v <= end)
            .ok_or_else(|| InputError::invalid("invalid load-command extent"))?;
        out.push((cmd, &data[at..next]));
        at = next;
    }
    if at != end {
        return Err(InputError::invalid("load-command count/size mismatch"));
    }
    Ok(out)
}
fn starts(data: &[u8], cmd: &[u8], base: u64) -> Result<Vec<u64>, InputError> {
    let off = usize::try_from(u32_at(cmd, 8)?).map_err(|_| InputError::invalid("function starts offset"))?;
    let len = usize::try_from(u32_at(cmd, 12)?).map_err(|_| InputError::invalid("function starts size"))?;
    let end = off.checked_add(len).ok_or_else(|| InputError::invalid("function starts overflow"))?;
    let raw = data.get(off..end).ok_or_else(|| InputError::invalid("function starts out of file"))?;
    let mut bytes = gimli::EndianSlice::new(raw, gimli::LittleEndian);
    let mut out = vec![];
    let mut va = base;
    while !bytes.is_empty() {
        let delta = gimli::leb128::read::unsigned(&mut bytes)
            .map_err(|_| InputError::invalid("invalid function-start delta"))?;
        if delta == 0 {
            if bytes.slice().iter().any(|&b| b != 0) {
                return Err(InputError::invalid("nonzero function-start padding"));
            }
            break;
        }
        if out.len() >= 100_000 {
            return Err(InputError::invalid("function-start budget exceeded"));
        }
        va = va.checked_add(delta).ok_or_else(|| InputError::invalid("function-start address overflow"))?;
        out.push(va);
    }
    Ok(out)
}
pub fn validate(data: &[u8]) -> Result<(), InputError> {
    if !matches!(u32_at(data, 12)?, 2 | 6 | 8) {
        return Err(InputError::unsupported("unsupported Mach-O file type"));
    }
    for (cmd, bytes) in commands(data)? {
        if matches!(cmd, 0x21 | 0x2c) && u32_at(bytes, 16)? != 0 {
            return Err(InputError::unsupported("encrypted Mach-O code is unsupported"));
        }
    }
    Ok(())
}
pub fn metadata(
    file: &object::File<'_>,
    data: &[u8],
    segments: &[Segment],
    functions: &[Range<u64>],
) -> Result<Metadata, InputError> {
    let filetype = u32_at(data, 12)?;
    if !matches!(filetype, 2 | 6 | 8) {
        return Err(InputError::unsupported("unsupported Mach-O file type"));
    }
    let text = file
        .segments()
        .find(|s| s.name().ok() == Some(Some("__TEXT")))
        .ok_or_else(|| InputError::invalid("missing __TEXT"))?;
    if text.file_range().0 != 0 {
        return Err(InputError::unsupported("nonzero __TEXT file offset is unsupported"));
    }
    let mut out = Metadata {
        kind: Kind::MachO,
        base: text.address(),
        load_segments: crate::image_format::collect_load_segments(file)?,
        ..Metadata::default()
    };
    for s in file.segments() {
        if s.name().ok() == Some(Some("__LINKEDIT")) {
            let end =
                s.address().checked_add(s.file_range().1).ok_or_else(|| InputError::invalid("segment overflow"))?;
            out.search_excluded.push(s.address()..end);
        }
    }
    collect_code_ranges(file, &mut out)?;
    let mut entries = 0;
    let mut start_table = false;
    for (cmd, bytes) in commands(data)? {
        match cmd {
            0x21 | 0x2c if u32_at(bytes, 16)? != 0 => {
                return Err(InputError::unsupported("encrypted Mach-O code is unsupported"));
            }
            0x8000_0028 => {
                if filetype != 2 || entries != 0 {
                    return Err(InputError::invalid("invalid/duplicate LC_MAIN"));
                }
                entries += 1;
                out.entry =
                    Some(out.base.checked_add(u64_at(bytes, 8)?).ok_or_else(|| InputError::invalid("entry overflow"))?);
            }
            0x5 => {
                if filetype != 2 || entries != 0 {
                    return Err(InputError::invalid("invalid/duplicate LC_UNIXTHREAD"));
                }
                let mut at = 8;
                while at < bytes.len() {
                    let flavor = u32_at(bytes, at)?;
                    let count =
                        usize::try_from(u32_at(bytes, at + 4)?).map_err(|_| InputError::invalid("thread count"))?;
                    let size = count.checked_mul(4).ok_or_else(|| InputError::invalid("thread size overflow"))?;
                    let end = at
                        .checked_add(8)
                        .and_then(|v| v.checked_add(size))
                        .filter(|&v| v <= bytes.len())
                        .ok_or_else(|| InputError::invalid("truncated thread state"))?;
                    if flavor == 4 && count == 42 {
                        out.entry = Some(u64_at(bytes, at + 8 + 128)?);
                    }
                    at = end;
                }
                if out.entry.is_none() {
                    return Err(InputError::unsupported("unsupported x86-64 thread entry state"));
                }
                entries += 1;
            }
            0x26 => {
                if start_table {
                    return Err(InputError::invalid("duplicate function-start table"));
                }
                start_table = true;
                out.function_starts = starts(data, bytes, out.base)?;
            }
            _ => {}
        }
    }
    if filetype == 2 && entries != 1 {
        return Err(InputError::unsupported("Mach-O executable entry point unavailable"));
    }
    if let Some(entry) = out.entry
        && (!out.code_ranges.iter().any(|r| r.contains(&entry))
            || !segments.iter().any(|s| entry >= s.va && entry - s.va < u64::try_from(s.size).unwrap_or(0)))
    {
        return Err(InputError::invalid("entry point is outside file-backed code"));
    }
    let fdes: BTreeSet<_> = functions.iter().map(|r| r.start).collect();
    out.uncovered_starts = out.function_starts.iter().filter(|start| !fdes.contains(start)).count();
    if !start_table || out.uncovered_starts > 0 {
        out.warn("macho_function_coverage_incomplete");
    }
    if file.symbols().any(|s| {
        s.is_definition()
            && s.kind() == object::SymbolKind::Text
            && out.code_ranges.iter().any(|r| r.contains(&s.address()))
            && !functions.iter().any(|r| r.contains(&s.address()))
    }) {
        out.warn("macho_function_coverage_incomplete");
    }
    out.warn("macho_return_contract_not_proven");
    Ok(out)
}

fn collect_code_ranges(file: &object::File<'_>, out: &mut Metadata) -> Result<(), InputError> {
    for section in file.sections() {
        let code = section.kind() == SectionKind::Text
            || matches!(section.flags(),SectionFlags::MachO{flags}
            if flags & (object::macho::S_ATTR_PURE_INSTRUCTIONS|object::macho::S_ATTR_SOME_INSTRUCTIONS)!=0);
        if code && section.size() > 0 {
            let end =
                section.address().checked_add(section.size()).ok_or_else(|| InputError::invalid("section overflow"))?;
            out.code_ranges.push(section.address()..end);
        }
    }
    Ok(())
}
