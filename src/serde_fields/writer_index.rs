/*
 * XRef — executable analysis
 * Copyright (c) 2026 Alexander Panasenko
 * Contact: alex@prod.codes
 * Author: https://prod.codes/about/
 * Project: https://github.com/alex09x/xref
 * SPDX-License-Identifier: MIT OR Apache-2.0
 */
use super::{facts::Facts, scan_index, values::MAX_ROOTS};
use crate::scan;
use std::ops::{Range, RangeInclusive};

#[derive(Clone)]
pub(super) struct Access {
    pub argument: usize,
    pub offset: i64,
    pub width: usize,
    pub ip: u64,
    pub assembly: String,
    pub kind: &'static str,
    pub write: bool,
    pub block: usize,
}

impl Access {
    pub fn range(&self) -> Option<RangeInclusive<u64>> {
        if self.width == 0 && self.kind != "address" {
            return None;
        }
        let last = self.offset.checked_add(i64::try_from(self.width.saturating_sub(1)).ok()?)?;
        if last < 0 {
            return None;
        }
        Some(u64::try_from(self.offset.max(0)).ok()?..=u64::try_from(last).ok()?)
    }
    pub fn covers(&self, offset: u64) -> bool {
        self.range().is_some_and(|range| range.contains(&offset))
    }
}

#[derive(Clone)]
pub(super) struct Entry {
    pub start: u64,
    pub end: u64,
    pub incomplete: bool,
    pub accesses: Vec<Access>,
    /// `(root, offset)` slots used as pointers in this function (see `Facts::dereferenced`).
    pub dereferenced: Vec<(usize, i64)>,
}

impl Entry {
    pub fn new(range: &Range<u64>, facts: Option<&Facts>) -> Self {
        let mut block = 0;
        let blocks: Vec<_> = facts.map_or_else(Vec::new, |facts| {
            (0..facts.flow.predecessors.len())
                .map(|index| {
                    if index > 0
                        && (facts.flow.predecessors[index].as_slice() != [index - 1]
                            || facts.flow.successors[index - 1].as_slice() != [index])
                    {
                        block += 1;
                    }
                    block
                })
                .collect()
        });
        Self {
            start: range.start,
            end: range.end,
            incomplete: facts.is_none_or(|facts| facts.limited),
            accesses: facts.map_or_else(Vec::new, |facts| {
                facts
                    .accesses
                    .iter()
                    .map(|access| Access {
                        argument: access.argument,
                        offset: access.offset,
                        width: access.width,
                        ip: access.instruction.ip(),
                        assembly: scan::format(&access.instruction),
                        kind: access.kind,
                        write: access.write,
                        block: blocks[access.index],
                    })
                    .collect()
            }),
            dereferenced: facts.map_or_else(Vec::new, |facts| facts.dereferenced.clone()),
        }
    }
}

const CACHE_KIND: &[u8] = b"writers-v4";

const KINDS: [&str; 7] =
    ["address", "read_conditional_write", "conditional_write", "conditional_read", "read_write", "write", "read"];

pub(super) fn load(
    identity: &scan_index::Identity,
    max_instructions: usize,
    functions: &[&Range<u64>],
) -> Option<Vec<Entry>> {
    let data = scan_index::read_cache(identity, CACHE_KIND, u64::try_from(max_instructions).ok()?)?;
    let mut cursor = 0;
    if usize::try_from(scan_index::number(&data, &mut cursor, 4)?).ok()? != functions.len() {
        return None;
    }
    let mut entries = Vec::with_capacity(functions.len());
    for function in functions {
        let start = scan_index::number(&data, &mut cursor, 8)?;
        let end = scan_index::number(&data, &mut cursor, 8)?;
        if start != function.start || end != function.end {
            return None;
        }
        let incomplete = match scan_index::number(&data, &mut cursor, 1)? {
            0 => false,
            1 => true,
            _ => return None,
        };
        let count = usize::try_from(scan_index::number(&data, &mut cursor, 4)?).ok()?;
        if count > 512 || count.checked_mul(29)? > data.len().checked_sub(cursor)? {
            return None;
        }
        let mut accesses = Vec::with_capacity(count);
        for _ in 0..count {
            let argument = usize::try_from(scan_index::number(&data, &mut cursor, 1)?).ok()?;
            if argument >= MAX_ROOTS {
                return None;
            }
            let offset = i64::from_le_bytes(scan_index::number(&data, &mut cursor, 8)?.to_le_bytes());
            let width = usize::try_from(scan_index::number(&data, &mut cursor, 4)?).ok()?;
            let ip = scan_index::number(&data, &mut cursor, 8)?;
            if !(start..end).contains(&ip) {
                return None;
            }
            let block = usize::try_from(scan_index::number(&data, &mut cursor, 4)?).ok()?;
            let kind = *KINDS.get(usize::try_from(scan_index::number(&data, &mut cursor, 1)?).ok()?)?;
            let write = match scan_index::number(&data, &mut cursor, 1)? {
                0 => false,
                1 => true,
                _ => return None,
            };
            let length = usize::try_from(scan_index::number(&data, &mut cursor, 2)?).ok()?;
            if length > 512 {
                return None;
            }
            let end_string = cursor.checked_add(length)?;
            let assembly = std::str::from_utf8(data.get(cursor..end_string)?).ok()?.to_owned();
            cursor = end_string;
            accesses.push(Access { argument, offset, width, ip, assembly, kind, write, block });
        }
        let pointers = usize::try_from(scan_index::number(&data, &mut cursor, 1)?).ok()?;
        let mut dereferenced = Vec::with_capacity(pointers);
        for _ in 0..pointers {
            let argument = usize::try_from(scan_index::number(&data, &mut cursor, 1)?).ok()?;
            if argument >= MAX_ROOTS {
                return None;
            }
            let offset = i64::from_le_bytes(scan_index::number(&data, &mut cursor, 8)?.to_le_bytes());
            dereferenced.push((argument, offset));
        }
        entries.push(Entry { start, end, incomplete, accesses, dereferenced });
    }
    (cursor == data.len()).then_some(entries)
}

pub(super) fn save(identity: &scan_index::Identity, max_instructions: usize, entries: &mut [Entry]) {
    entries.sort_unstable_by_key(|entry| entry.start);
    let Ok(count) = u32::try_from(entries.len()) else { return };
    let mut data = Vec::new();
    data.extend_from_slice(&count.to_le_bytes());
    for entry in entries {
        let Ok(count) = u32::try_from(entry.accesses.len()) else { return };
        data.extend_from_slice(&entry.start.to_le_bytes());
        data.extend_from_slice(&entry.end.to_le_bytes());
        data.push(u8::from(entry.incomplete));
        data.extend_from_slice(&count.to_le_bytes());
        for access in &entry.accesses {
            if access
                .assembly
                .len()
                .checked_add(29)
                .and_then(|length| data.len().checked_add(length))
                .is_none_or(|length| length > 256 * 1024 * 1024 - 40)
            {
                return;
            }
            let (Ok(argument), Ok(width), Ok(block), Ok(length)) = (
                u8::try_from(access.argument),
                u32::try_from(access.width),
                u32::try_from(access.block),
                u16::try_from(access.assembly.len()),
            ) else {
                return;
            };
            let Some(kind) =
                KINDS.iter().position(|kind| *kind == access.kind).and_then(|index| u8::try_from(index).ok())
            else {
                return;
            };
            data.push(argument);
            data.extend_from_slice(&access.offset.to_le_bytes());
            data.extend_from_slice(&width.to_le_bytes());
            data.extend_from_slice(&access.ip.to_le_bytes());
            data.extend_from_slice(&block.to_le_bytes());
            data.push(kind);
            data.push(u8::from(access.write));
            data.extend_from_slice(&length.to_le_bytes());
            data.extend_from_slice(access.assembly.as_bytes());
        }
        let Ok(pointers) = u8::try_from(entry.dereferenced.len()) else { return };
        data.push(pointers);
        for &(argument, offset) in &entry.dereferenced {
            let Ok(argument) = u8::try_from(argument) else { return };
            data.push(argument);
            data.extend_from_slice(&offset.to_le_bytes());
        }
    }
    if let Ok(limit) = u64::try_from(max_instructions) {
        scan_index::write_cache(identity, CACHE_KIND, limit, &data);
    }
}
