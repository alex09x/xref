/*
 * XRef Code — evidence-producing binary analysis
 * Copyright (c) 2026 Alexander Panasenko
 * Contact: alex@prod.codes
 * Author: https://prod.codes/about/
 * Project: https://github.com/alex09x/xref
 * SPDX-License-Identifier: MIT OR Apache-2.0
 */
use super::util::{Cursor, add, bytes, u64_at};
use super::{Collected, Segment};

pub(super) fn collect(
    data: &[u8],
    segments: &[Segment],
    info: [u32; 10],
    le: bool,
    out: &mut Collected,
) -> Result<(), String> {
    let streams = [(info[0], info[1]), (info[2], info[3]), (info[4], info[5]), (info[6], info[7])];
    for (index, (off, size)) in streams.into_iter().enumerate() {
        if size == 0 {
            continue;
        }
        let stream = bytes(data, off as usize, size as usize)?;
        if index == 0 {
            rebase(stream, data, segments, le, out)?;
        } else {
            bind(stream, data.len(), segments, index == 3, out)?;
        }
    }
    Ok(())
}

fn slot(
    segments: &[Segment],
    index: Option<usize>,
    offset: u64,
    width: u64,
    data: &[u8],
) -> Result<(u64, u64), String> {
    let segment =
        segments.get(index.ok_or("Mach-O fixup segment not selected")?).ok_or("Mach-O fixup segment out of bounds")?;
    if add(offset, width)? > segment.vmsize || add(offset, width)? > segment.filesize {
        return Err("Mach-O fixup outside segment".into());
    }
    let fileoff = add(segment.fileoff, offset)?;
    let file_end = add(fileoff, width)?;
    if file_end > data.len() as u64 {
        return Err("Mach-O fixup file offset out of bounds".into());
    }
    Ok((add(segment.vmaddr, offset)?, fileoff))
}

fn rebase(stream: &[u8], data: &[u8], segments: &[Segment], le: bool, out: &mut Collected) -> Result<(), String> {
    let mut cur = Cursor::new(stream);
    let mut segment = None;
    let mut offset = 0u64;
    let mut typ = 1u8;
    while cur.remaining() {
        let opcode = cur.byte()?;
        let imm = opcode & 0x0f;
        match opcode & 0xf0 {
            0x00 => break,
            0x10 => typ = imm,
            0x20 => {
                segment = Some(imm as usize);
                offset = cur.uleb()?;
            }
            0x30 => offset = offset.wrapping_add(cur.uleb()?),
            0x40 => offset = offset.wrapping_add(u64::from(imm) * 8),
            0x50 => {
                emit_rebases(u64::from(imm), 8, segment, &mut offset, typ, RebaseInput { data, segments, le }, out)?;
            }
            0x60 => {
                let count = cur.uleb()?;
                emit_rebases(count, 8, segment, &mut offset, typ, RebaseInput { data, segments, le }, out)?;
            }
            0x70 => {
                emit_rebases(
                    1,
                    8u64.wrapping_add(cur.uleb()?),
                    segment,
                    &mut offset,
                    typ,
                    RebaseInput { data, segments, le },
                    out,
                )?;
            }
            0x80 => {
                let count = cur.uleb()?;
                let skip = cur.uleb()?;
                emit_rebases(
                    count,
                    8u64.wrapping_add(skip),
                    segment,
                    &mut offset,
                    typ,
                    RebaseInput { data, segments, le },
                    out,
                )?;
            }
            _ => return Err("Invalid Mach-O rebase opcode".into()),
        }
    }
    Ok(())
}
/// The parameters `emit_rebases` takes together.
#[derive(Clone, Copy)]
struct RebaseInput<'a> {
    pub data: &'a [u8],
    pub segments: &'a [Segment],
    pub le: bool,
}

fn emit_rebases(
    count: u64,
    stride: u64,
    segment: Option<usize>,
    offset: &mut u64,
    typ: u8,
    input: RebaseInput<'_>,
    out: &mut Collected,
) -> Result<(), String> {
    let seg = input
        .segments
        .get(segment.ok_or("Mach-O rebase segment not selected")?)
        .ok_or("Mach-O rebase segment out of bounds")?;
    let width = if typ == 1 { 8 } else { 4 };
    if count > seg.vmsize / width + 1 || count > input.data.len() as u64 / width + 1 {
        return Err("Mach-O rebase count out of bounds".into());
    }
    for _ in 0..count {
        out.charge(1)?;
        let (va, fileoff) = slot(input.segments, segment, *offset, width, input.data)?;
        if typ == 1 {
            let raw =
                u64_at(input.data, usize::try_from(fileoff).map_err(|_| "Mach-O file offset overflow")?, input.le)?;
            out.pointer(va, raw);
        } else {
            out.fixups_complete = false;
            out.warning("Unsupported Mach-O rebase type");
        }
        *offset = offset.wrapping_add(stride);
    }
    Ok(())
}

fn bind(stream: &[u8], file_len: usize, segments: &[Segment], lazy: bool, out: &mut Collected) -> Result<(), String> {
    let mut cur = Cursor::new(stream);
    let mut segment = None;
    let mut offset = 0u64;
    let mut name: Option<String> = None;
    let mut addend = 0i64;
    let mut typ = 1u8;
    while cur.remaining() {
        let opcode = cur.byte()?;
        let imm = opcode & 0x0f;
        match opcode & 0xf0 {
            0x00 => {
                if lazy {
                    segment = None;
                    offset = 0;
                    name = None;
                    addend = 0;
                    typ = 1;
                } else {
                    break;
                }
            }
            0x10 | 0x30 => {}
            0x20 => {
                cur.uleb()?;
            }
            0x40 => {
                name = Some(out.name(cur.cstr()?)?);
            }
            0x50 => typ = imm,
            0x60 => addend = cur.sleb()?,
            0x70 => {
                segment = Some(imm as usize);
                offset = cur.uleb()?;
            }
            0x80 => offset = offset.wrapping_add(cur.uleb()?),
            0x90 => emit_binds(
                1,
                8,
                BindInput { file_len, segments },
                segment,
                &mut offset,
                Binding { typ, name: name.as_deref(), addend },
                out,
            )?,
            0xa0 => {
                let skip = cur.uleb()?;
                emit_binds(
                    1,
                    8u64.wrapping_add(skip),
                    BindInput { file_len, segments },
                    segment,
                    &mut offset,
                    Binding { typ, name: name.as_deref(), addend },
                    out,
                )?;
            }
            0xb0 => emit_binds(
                1,
                8u64.wrapping_add(u64::from(imm) * 8),
                BindInput { file_len, segments },
                segment,
                &mut offset,
                Binding { typ, name: name.as_deref(), addend },
                out,
            )?,
            0xc0 => {
                let count = cur.uleb()?;
                let skip = cur.uleb()?;
                emit_binds(
                    count,
                    8u64.wrapping_add(skip),
                    BindInput { file_len, segments },
                    segment,
                    &mut offset,
                    Binding { typ, name: name.as_deref(), addend },
                    out,
                )?;
            }
            0xd0 => {
                if imm == 0 {
                    cur.uleb()?;
                }
                out.imports_complete = false;
                out.fixups_complete = false;
                out.warning("Unsupported Mach-O threaded bind");
                out.imports.clear();
                return Ok(());
            }
            _ => return Err("Invalid Mach-O bind opcode".into()),
        }
    }
    Ok(())
}
/// The parameters `emit_binds` takes together.
#[derive(Clone, Copy)]
struct BindInput<'a> {
    pub file_len: usize,
    pub segments: &'a [Segment],
}
/// The parameters `emit_binds` takes together.
#[derive(Clone, Copy)]
struct Binding<'a> {
    pub typ: u8,
    pub name: Option<&'a str>,
    pub addend: i64,
}

fn emit_binds(
    count: u64,
    stride: u64,
    input: BindInput<'_>,
    segment: Option<usize>,
    offset: &mut u64,
    binding: Binding<'_>,
    out: &mut Collected,
) -> Result<(), String> {
    let seg = input
        .segments
        .get(segment.ok_or("Mach-O bind segment not selected")?)
        .ok_or("Mach-O bind segment out of bounds")?;
    let name = binding.name.ok_or("Mach-O bind symbol not selected")?;
    let width = if binding.typ == 1 { 8 } else { 4 };
    if count > seg.vmsize / width + 1 || count > input.file_len as u64 / width + 1 {
        return Err("Mach-O bind count out of bounds".into());
    }
    for _ in 0..count {
        out.charge(1)?;
        if add(*offset, width)? > seg.vmsize || add(*offset, width)? > seg.filesize {
            return Err("Mach-O bind outside segment".into());
        }
        if add(add(seg.fileoff, *offset)?, width)? > input.file_len as u64 {
            return Err("Mach-O bind file offset out of bounds".into());
        }
        if binding.typ == 1 {
            out.import(add(seg.vmaddr, *offset)?, name, binding.addend);
        } else {
            out.imports_complete = false;
            out.warning("Unsupported Mach-O bind type");
        }
        *offset = offset.wrapping_add(stride);
    }
    Ok(())
}
