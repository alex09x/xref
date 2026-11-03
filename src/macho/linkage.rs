/*
 * XRef Code — evidence-producing binary analysis
 * Copyright (c) 2026 Alexander Panasenko
 * Contact: alex@prod.codes
 * Author: https://prod.codes/about/
 * Project: https://github.com/alex09x/xref
 * SPDX-License-Identifier: MIT OR Apache-2.0
 */
use super::Linkage;
use object::read::macho::MachOFile64;
use std::collections::{BTreeMap, BTreeSet};

mod chained;
mod commands;
mod exports;
mod legacy;
#[cfg(test)]
mod tests;
mod util;

use crate::macho::linkage::chained::FixupRange;
use crate::macho::linkage::commands::parse_commands;
use util::{add, bytes, u32_at, u64_at};

#[derive(Clone)]
struct Segment {
    vmaddr: u64,
    vmsize: u64,
    fileoff: u64,
    filesize: u64,
}

#[derive(Clone)]
struct Section {
    addr: u64,
    size: u64,
    fileoff: u32,
    kind: u32,
    indirect: u32,
    stub_size: u32,
}

#[derive(Clone)]
struct Symbol {
    name: String,
    kind: u8,
}

#[derive(Default)]
struct Commands {
    segments: Vec<Segment>,
    sections: Vec<Section>,
    symtab: Option<(u32, u32, u32, u32)>,
    dysymtab: Option<(u32, u32)>,
    dyld: Option<[u32; 10]>,
    chained: Option<(u32, u32)>,
    trie: Option<(u32, u32)>,
    classic_relocations: bool,
}

struct Collected {
    operations: usize,
    name_bytes: usize,
    imports: BTreeMap<u64, String>,
    pointers: BTreeMap<u64, u64>,
    exports: BTreeSet<u64>,
    imports_complete: bool,
    fixups_complete: bool,
    exports_complete: bool,
    warnings: Vec<&'static str>,
}

impl Collected {
    const fn new() -> Self {
        Self {
            operations: 0,
            name_bytes: 0,
            imports: BTreeMap::new(),
            pointers: BTreeMap::new(),
            exports: BTreeSet::new(),
            imports_complete: true,
            fixups_complete: true,
            exports_complete: true,
            warnings: Vec::new(),
        }
    }

    fn warning(&mut self, warning: &'static str) {
        if !self.warnings.contains(&warning) {
            self.warnings.push(warning);
        }
    }
    fn charge(&mut self, count: u64) -> Result<(), String> {
        let count = usize::try_from(count).map_err(|_| "Mach-O operation budget")?;
        self.operations =
            self.operations.checked_add(count).filter(|&n| n <= 1_000_000).ok_or("Mach-O operation budget exceeded")?;
        Ok(())
    }
    fn name(&mut self, raw: &[u8]) -> Result<String, String> {
        self.name_bytes = self
            .name_bytes
            .checked_add(raw.len())
            .filter(|&n| n <= 64 * 1024 * 1024)
            .ok_or("Mach-O name budget exceeded")?;
        if std::str::from_utf8(raw).is_err() {
            self.imports_complete = false;
            self.warning("Mach-O non-UTF8 symbol name");
        }
        Ok(String::from_utf8_lossy(raw).into_owned())
    }

    fn import(&mut self, slot: u64, name: &str, addend: i64) {
        self.pointers.remove(&slot);
        if addend != 0 {
            self.imports.remove(&slot);
            self.imports_complete = false;
            self.warning("Mach-O bind with nonzero addend unresolved");
        } else {
            let normalized = name.strip_prefix('_').unwrap_or(name);
            self.imports.insert(slot, normalized.to_owned());
        }
    }

    fn pointer(&mut self, slot: u64, target: u64) {
        if !self.imports.contains_key(&slot) {
            self.pointers.insert(slot, target);
        }
    }
}

pub fn collect(file: &MachOFile64<'_>, data: &[u8], text_base: u64) -> Result<Linkage, String> {
    let le = match data.get(..4) {
        Some([0xcf, 0xfa, 0xed, 0xfe]) => true,
        Some([0xfe, 0xed, 0xfa, 0xcf]) => false,
        _ => return Err("Invalid Mach-O 64-bit magic".into()),
    };
    let cpu = u32_at(data, 4, le)?;
    let cmds = parse_commands(file, data, le)?;
    let mut out = Collected::new();
    let dynamic_fixups = cmds.chained.is_some_and(|(_, size)| size > 0)
        || cmds.dyld.is_some_and(|v| [v[1], v[3], v[5], v[7]].iter().any(|&n| n > 0));
    if cmds.classic_relocations && !dynamic_fixups {
        out.imports_complete = false;
        out.fixups_complete = false;
        out.warning("Mach-O classic relocations are not decoded");
    }
    let symbols = symbols(data, cmds.symtab, le, &mut out)?;
    indirect(data, &cmds, &symbols, le, cpu, &mut out)?;
    let declared = std::mem::take(&mut out.imports);
    let binding_program = cmds.chained.is_some_and(|(_, size)| size > 0)
        || cmds.dyld.is_some_and(|v| [v[3], v[5], v[7]].iter().any(|&n| n > 0));
    if !binding_program && !cmds.classic_relocations {
        out.imports = declared.clone();
    }
    if let Some(info) = cmds.dyld {
        legacy::collect(data, &cmds.segments, info, le, &mut out)?;
    }
    if let Some((off, size)) = cmds.chained {
        chained::collect(data, &cmds.segments, FixupRange { off, size }, le, cpu, text_base, &mut out)?;
    }
    if binding_program && declared.keys().any(|slot| !out.imports.contains_key(slot)) {
        out.imports_complete = false;
        out.warning("Mach-O declared import binding unresolved");
    }
    let trie = cmds.trie.or_else(|| cmds.dyld.map(|v| (v[8], v[9])));
    let reliable_symbols =
        cmds.symtab.is_some_and(|(_, count, _, _)| count > 0) && u32_at(data, 24, le)? & 0x0400_0000 == 0;
    if trie.is_none_or(|(_, size)| size == 0) && !reliable_symbols {
        out.exports_complete = false;
        out.warning("Mach-O export inventory unavailable");
    }
    if let Some((off, size)) = trie
        && size != 0
    {
        exports::collect(bytes(data, off as usize, size as usize)?, text_base, &mut out)?;
    }
    Ok(Linkage {
        imports: out.imports.into_iter().collect(),
        pointers: out.pointers.into_iter().collect(),
        exports: out.exports,
        imports_complete: out.imports_complete,
        fixups_complete: out.fixups_complete,
        exports_complete: out.exports_complete,
        warnings: out.warnings,
    })
}

fn symbols(
    data: &[u8],
    symtab: Option<(u32, u32, u32, u32)>,
    le: bool,
    out: &mut Collected,
) -> Result<Vec<Symbol>, String> {
    let Some((off, count, str_off, str_size)) = symtab else {
        return Ok(Vec::new());
    };
    let count = count as usize;
    out.charge(count as u64)?;
    let table = bytes(data, off as usize, count.checked_mul(16).ok_or("Mach-O symbol count overflow")?)?;
    let strings = bytes(data, str_off as usize, str_size as usize)?;
    let mut result = Vec::with_capacity(count);
    for i in 0..count {
        let at = i * 16;
        let name_off = u32_at(table, at, le)? as usize;
        let name = if name_off == 0 {
            String::new()
        } else {
            let tail = strings.get(name_off..).ok_or("Mach-O symbol name offset out of bounds")?;
            let end = tail.iter().position(|b| *b == 0).ok_or("Unterminated Mach-O symbol name")?;
            out.name(&tail[..end])?
        };
        let kind = *table.get(at + 4).ok_or("Truncated Mach-O symbol")?;
        let value = u64_at(table, at + 8, le)?;
        if kind & 0xe0 == 0 && kind & 1 != 0 && matches!(kind & 0xe, 0x2 | 0xe) && value != 0 {
            out.exports.insert(value);
        }
        result.push(Symbol { name, kind });
    }
    Ok(result)
}

fn indirect(
    data: &[u8],
    cmds: &Commands,
    symbols: &[Symbol],
    le: bool,
    cpu: u32,
    out: &mut Collected,
) -> Result<(), String> {
    let relevant: Vec<&Section> = cmds.sections.iter().filter(|s| matches!(s.kind, 6 | 7 | 8 | 0x10 | 0x14)).collect();
    if relevant.is_empty() {
        return Ok(());
    }
    let Some((off, count)) = cmds.dysymtab else {
        out.imports_complete = false;
        out.warning("Mach-O indirect symbol table absent");
        return Ok(());
    };
    let table = bytes(data, off as usize, (count as usize).checked_mul(4).ok_or("Mach-O indirect count overflow")?)?;
    for section in relevant {
        validate_indirect_section(data, cmds, section)?;
        let stride = if section.kind == 8 { u64::from(section.stub_size) } else { 8 };
        if stride == 0 || section.size % stride != 0 {
            return Err("Invalid Mach-O indirect section stride".into());
        }
        let slots = section.size / stride;
        out.charge(slots)?;
        let start = u64::from(section.indirect);
        let end = add(start, slots)?;
        if end > u64::from(count) {
            return Err("Mach-O indirect symbol range out of bounds".into());
        }
        for i in 0..slots {
            let index_off = add(start, i)?.checked_mul(4).ok_or("Mach-O indirect index overflow")?;
            let index = u32_at(table, usize::try_from(index_off).map_err(|_| "Mach-O indirect index overflow")?, le)?;
            if index & 0xc000_0000 != 0 {
                if !matches!(index, 0x8000_0000 | 0x4000_0000 | 0xc000_0000) {
                    return Err("Invalid Mach-O indirect sentinel".into());
                }
                continue;
            }
            let symbol = symbols.get(index as usize).ok_or("Mach-O indirect symbol index out of bounds")?;
            if symbol.kind & 0xe0 != 0 {
                continue;
            }
            if symbol.kind & 0xe == 0xa {
                out.imports_complete = false;
                out.warning("Mach-O indirect symbol alias unresolved");
                continue;
            }
            if !matches!(symbol.kind & 0xe, 0 | 0xc) || symbol.kind & 1 == 0 || symbol.name.is_empty() {
                continue;
            }
            let position = i.checked_mul(stride).ok_or("Mach-O slot overflow")?;
            let slot = if section.kind == 8 {
                if cpu != 0x0100_0007 || stride < 6 {
                    out.imports_complete = false;
                    out.warning("Unsupported Mach-O stub encoding");
                    continue;
                }
                let stub_off = add(u64::from(section.fileoff), position)?;
                let stub = bytes(data, usize::try_from(stub_off).map_err(|_| "Mach-O stub offset overflow")?, 6)?;
                if stub[0] != 0xff || stub[1] != 0x25 {
                    out.imports_complete = false;
                    out.warning("Unsupported Mach-O stub encoding");
                    continue;
                }
                let displacement = i32::from_le_bytes([stub[2], stub[3], stub[4], stub[5]]);
                let next = add(add(section.addr, position)?, 6)?;
                if displacement >= 0 {
                    add(next, displacement.unsigned_abs().into())?
                } else {
                    next.checked_sub(displacement.unsigned_abs().into()).ok_or("Mach-O stub slot underflow")?
                }
            } else {
                add(section.addr, position)?
            };
            if section.kind == 8 {
                let mut mapped_slot = false;
                for segment in &cmds.segments {
                    let end = add(segment.vmaddr, segment.vmsize)?;
                    if slot >= segment.vmaddr && add(slot, 8)? <= end {
                        let offset = slot - segment.vmaddr;
                        if add(offset, 8)? <= segment.filesize
                            && add(add(segment.fileoff, offset)?, 8)? <= data.len() as u64
                        {
                            mapped_slot = true;
                            break;
                        }
                    }
                }
                if !mapped_slot {
                    return Err("Mach-O stub pointer slot outside file".into());
                }
            }
            out.import(slot, &symbol.name, 0);
        }
    }
    Ok(())
}

fn validate_indirect_section(data: &[u8], cmds: &Commands, section: &Section) -> Result<(), String> {
    let section_end = add(section.addr, section.size)?;
    let file_end = add(u64::from(section.fileoff), section.size)?;
    let mut mapped = false;
    for segment in &cmds.segments {
        let segment_end = add(segment.vmaddr, segment.vmsize)?;
        let segment_file_end = add(segment.fileoff, segment.filesize)?;
        let mapped_address = u64::from(section.fileoff)
            .checked_sub(segment.fileoff)
            .and_then(|offset| segment.vmaddr.checked_add(offset));
        if (segment.vmaddr..=segment_end).contains(&section.addr)
            && section_end <= segment_end
            && u64::from(section.fileoff) >= segment.fileoff
            && file_end <= segment_file_end
            && mapped_address == Some(section.addr)
        {
            mapped = true;
            break;
        }
    }
    if !mapped {
        return Err("Mach-O indirect section outside segment".into());
    }
    bytes(data, section.fileoff as usize, usize::try_from(section.size).map_err(|_| "Mach-O section size overflow")?)?;
    Ok(())
}
