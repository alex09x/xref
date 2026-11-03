/*
 * XRef Code — evidence-producing binary analysis
 * Copyright (c) 2026 Alexander Panasenko
 * Contact: alex@prod.codes
 * Author: https://prod.codes/about/
 * Project: https://github.com/alex09x/xref
 * SPDX-License-Identifier: MIT OR Apache-2.0
 */
use super::util::{Cursor, add, bytes, u16_at, u32_at, u64_at};
use super::{Collected, Segment};
use std::collections::BTreeSet;

struct Import {
    name: String,
    addend: i64,
}

struct WalkContext<'a> {
    data: &'a [u8],
    segment: &'a Segment,
    page_size: u64,
    format: u16,
    le: bool,
    image_base: u64,
    imports: Option<&'a [Import]>,
    out: &'a mut Collected,
}
/// The parameters `collect` takes together.
#[derive(Clone, Copy)]
pub(super) struct FixupRange {
    pub off: u32,
    pub size: u32,
}

pub(super) fn collect(
    data: &[u8],
    segments: &[Segment],
    range: FixupRange,
    le: bool,
    cpu: u32,
    image_base: u64,
    out: &mut Collected,
) -> Result<(), String> {
    let blob = bytes(data, range.off as usize, range.size as usize)?;
    bytes(blob, 0, 28)?;
    let version = u32_at(blob, 0, le)?;
    if version != 0 {
        out.imports_complete = false;
        out.fixups_complete = false;
        out.warning("Unsupported Mach-O chained fixups version");
        return Ok(());
    }
    let starts_off = u32_at(blob, 4, le)? as usize;
    let imports_off = u32_at(blob, 8, le)? as usize;
    let symbols_off = u32_at(blob, 12, le)? as usize;
    let imports_count = u32_at(blob, 16, le)? as usize;
    let imports_format = u32_at(blob, 20, le)?;
    let symbols_format = u32_at(blob, 24, le)?;
    let imports = if symbols_format != 0 {
        out.imports_complete = false;
        out.warning("Unsupported Mach-O compressed chained symbols");
        None
    } else {
        parse_imports(blob, imports_off, symbols_off, imports_count, imports_format, le, out)?
    };
    if cpu != 0x0100_0007 {
        out.imports_complete = false;
        out.fixups_complete = false;
        out.warning("Unsupported Mach-O chained fixups architecture");
        return Ok(());
    }
    let count = u32_at(blob, starts_off, le)? as usize;
    let starts_len = count.checked_mul(4).ok_or("Mach-O chained segment count overflow")?;
    bytes(blob, starts_off.checked_add(4).ok_or("Mach-O chained offset overflow")?, starts_len)?;
    if count > segments.len() {
        return Err("Mach-O chained segment count out of bounds".into());
    }
    for index in 0..count {
        let rel = u32_at(blob, starts_off + 4 + index * 4, le)? as usize;
        if rel == 0 {
            continue;
        }
        let at = starts_off.checked_add(rel).ok_or("Mach-O chained starts offset overflow")?;
        let size = u32_at(blob, at, le)? as usize;
        let start = bytes(blob, at, size)?;
        bytes(start, 0, 22)?;
        let page_size = u64::from(u16_at(start, 4, le)?);
        let format = u16_at(start, 6, le)?;
        let segment_offset = u64_at(start, 8, le)?;
        let page_count = u16_at(start, 20, le)? as usize;
        bytes(start, 22, page_count.checked_mul(2).ok_or("Mach-O chained page count overflow")?)?;
        let segment = segments.get(index).ok_or("Mach-O chained segment out of bounds")?;
        if page_size == 0 || add(image_base, segment_offset)? != segment.vmaddr {
            return Err("Invalid Mach-O chained segment offset".into());
        }
        let covered = (page_count as u64).checked_mul(page_size).ok_or("Mach-O chained page range overflow")?;
        if covered > add(segment.vmsize, page_size)? {
            return Err("Mach-O chained pages exceed segment".into());
        }
        if !matches!(format, 2 | 6) {
            let end = add(segment.vmaddr, segment.vmsize)?;
            out.imports.retain(|&slot, _| slot < segment.vmaddr || slot >= end);
            out.pointers.retain(|&slot, _| slot < segment.vmaddr || slot >= end);
            out.imports_complete = false;
            out.fixups_complete = false;
            out.warning("Unsupported Mach-O chained pointer format");
            continue;
        }
        let mut context =
            WalkContext { data, segment, page_size, format, le, image_base, imports: imports.as_deref(), out };
        for page in 0..page_count {
            let first = u16_at(start, 22 + page * 2, le)?;
            if first == 0xffff {
                continue;
            }
            if first & 0x8000 == 0 {
                walk(&mut context, page as u64, u64::from(first))?;
            } else {
                let mut extra = usize::from(first & 0x7fff);
                let extra_base = 22 + page_count * 2;
                let max_extra = (start.len() - extra_base) / 2;
                loop {
                    if extra >= max_extra {
                        return Err("Mach-O chained multi-start out of bounds".into());
                    }
                    let entry = u16_at(start, extra_base + extra * 2, le)?;
                    walk(&mut context, page as u64, u64::from(entry & 0x7fff))?;
                    if entry & 0x8000 != 0 {
                        break;
                    }
                    extra += 1;
                }
            }
        }
    }
    Ok(())
}

fn parse_imports(
    blob: &[u8],
    off: usize,
    symbols_off: usize,
    count: usize,
    format: u32,
    le: bool,
    out: &mut Collected,
) -> Result<Option<Vec<Import>>, String> {
    let stride = match format {
        1 => 4,
        2 => 8,
        3 => 16,
        _ => {
            out.imports_complete = false;
            out.warning("Unsupported Mach-O chained import format");
            return Ok(None);
        }
    };
    let table = bytes(blob, off, count.checked_mul(stride).ok_or("Mach-O chained import count overflow")?)?;
    let pool = blob.get(symbols_off..).ok_or("Mach-O chained symbol pool out of bounds")?;
    let mut imports = Vec::with_capacity(count);
    for i in 0..count {
        out.charge(1)?;
        let at = i * stride;
        let word = u32_at(table, at, le)?;
        let (name_off, addend) = match format {
            1 => ((word >> 9) as usize, 0),
            2 => ((word >> 9) as usize, i64::from(u32_at(table, at + 4, le)?.cast_signed())),
            3 => (u32_at(table, at + 4, le)? as usize, u64_at(table, at + 8, le)?.cast_signed()),
            _ => return Err("Invalid Mach-O chained import format".into()),
        };
        let mut cur = Cursor::at(pool, name_off)?;
        let name = out.name(cur.cstr()?)?;
        imports.push(Import { name, addend });
    }
    Ok(Some(imports))
}

fn walk(context: &mut WalkContext<'_>, page: u64, first: u64) -> Result<(), String> {
    let WalkContext { data, segment, page_size, format, le, image_base, imports, out } = context;
    let page_size = *page_size;
    if first >= page_size {
        return Err("Mach-O chained start outside page".into());
    }
    let page_offset = page.checked_mul(page_size).ok_or("Mach-O chained page offset overflow")?;
    let mut offset = add(page_offset, first)?;
    let mut seen = BTreeSet::new();
    loop {
        out.charge(1)?;
        if !seen.insert(offset) {
            return Err("Mach-O chained pointer cycle".into());
        }
        if seen.len() as u64 > page_size / 4 + 1 {
            return Err("Mach-O chained pointer count out of bounds".into());
        }
        if add(offset, 8)? > segment.filesize || add(offset, 8)? > segment.vmsize {
            return Err("Mach-O chained pointer outside segment".into());
        }
        let fileoff = add(segment.fileoff, offset)?;
        let raw = u64_at(data, usize::try_from(fileoff).map_err(|_| "Mach-O chained file offset overflow")?, *le)?;
        let slot = add(segment.vmaddr, offset)?;
        if raw >> 63 != 0 {
            out.pointers.remove(&slot);
            let ordinal = (raw & 0x00ff_ffff) as usize;
            let pointer_addend = i64::from((raw >> 24).to_le_bytes()[0]);
            if let Some(imports) = imports {
                let import = imports.get(ordinal).ok_or("Mach-O chained import ordinal out of bounds")?;
                let addend = import.addend.checked_add(pointer_addend).ok_or("Mach-O chained addend overflow")?;
                out.import(slot, &import.name, addend);
            } else {
                out.imports.remove(&slot);
                out.imports_complete = false;
            }
        } else {
            let target = (raw & 0x0000_000f_ffff_ffff) | (((raw >> 36) & 0xff) << 56);
            let target = if *format == 6 { add(*image_base, target)? } else { target };
            out.imports.remove(&slot);
            out.pointer(slot, target);
        }
        let next = (raw >> 51) & 0xfff;
        if next == 0 {
            break;
        }
        let stride = next.checked_mul(4).ok_or("Mach-O chained stride overflow")?;
        offset = add(offset, stride)?;
        if offset / page_size != page {
            return Err("Mach-O chained pointer leaves page".into());
        }
    }
    Ok(())
}
