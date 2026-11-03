/*
 * XRef Code — evidence-producing binary analysis
 * Copyright (c) 2026 Alexander Panasenko
 * Contact: alex@prod.codes
 * Author: https://prod.codes/about/
 * Project: https://github.com/alex09x/xref
 * SPDX-License-Identifier: MIT OR Apache-2.0
 */
use super::util::{bytes, u32_at, u64_at};
use super::{Commands, Section, Segment};
use object::read::macho::MachOFile64;

pub(super) fn parse_commands(file: &MachOFile64<'_>, data: &[u8], le: bool) -> Result<Commands, String> {
    let mut cmds = Commands::default();
    let mut iter = file.macho_load_commands().map_err(|e| e.to_string())?;
    while let Some(command) = iter.next().map_err(|e| e.to_string())? {
        let raw = command.raw_data();
        match command.cmd() {
            0x19 => {
                bytes(raw, 0, 72)?;
                let nsects = u32_at(raw, 64, le)? as usize;
                let section_bytes = nsects.checked_mul(80).ok_or("Mach-O section count overflow")?;
                bytes(raw, 72, section_bytes)?;
                cmds.segments.push(Segment {
                    vmaddr: u64_at(raw, 24, le)?,
                    vmsize: u64_at(raw, 32, le)?,
                    fileoff: u64_at(raw, 40, le)?,
                    filesize: u64_at(raw, 48, le)?,
                });
                for i in 0..nsects {
                    let off = 72 + i * 80;
                    let count = u32_at(raw, off + 60, le)?;
                    if count != 0 {
                        bytes(
                            data,
                            u32_at(raw, off + 56, le)? as usize,
                            (count as usize).checked_mul(8).ok_or("relocation count overflow")?,
                        )?;
                        cmds.classic_relocations = true;
                    }
                    cmds.sections.push(Section {
                        addr: u64_at(raw, off + 32, le)?,
                        size: u64_at(raw, off + 40, le)?,
                        fileoff: u32_at(raw, off + 48, le)?,
                        kind: u32_at(raw, off + 64, le)? & 0xff,
                        indirect: u32_at(raw, off + 68, le)?,
                        stub_size: u32_at(raw, off + 72, le)?,
                    });
                }
            }
            0x2 => {
                if cmds.symtab.is_some() {
                    return Err("Duplicate Mach-O LC_SYMTAB".into());
                }
                bytes(raw, 0, 24)?;
                cmds.symtab =
                    Some((u32_at(raw, 8, le)?, u32_at(raw, 12, le)?, u32_at(raw, 16, le)?, u32_at(raw, 20, le)?));
            }
            0xb => {
                if cmds.dysymtab.is_some() {
                    return Err("Duplicate Mach-O LC_DYSYMTAB".into());
                }
                bytes(raw, 0, 80)?;
                for (off, count) in
                    [(u32_at(raw, 64, le)?, u32_at(raw, 68, le)?), (u32_at(raw, 72, le)?, u32_at(raw, 76, le)?)]
                {
                    if count != 0 {
                        bytes(data, off as usize, (count as usize).checked_mul(8).ok_or("relocation count overflow")?)?;
                        cmds.classic_relocations = true;
                    }
                }
                cmds.dysymtab = Some((u32_at(raw, 56, le)?, u32_at(raw, 60, le)?));
            }
            0x22 | 0x8000_0022 => {
                if cmds.dyld.is_some() {
                    return Err("Duplicate Mach-O dyld info".into());
                }
                bytes(raw, 0, 48)?;
                let mut fields = [0; 10];
                for (i, field) in fields.iter_mut().enumerate() {
                    *field = u32_at(raw, 8 + i * 4, le)?;
                }
                cmds.dyld = Some(fields);
            }
            0x8000_0034 | 0x8000_0033 => {
                bytes(raw, 0, 16)?;
                let pair = (u32_at(raw, 8, le)?, u32_at(raw, 12, le)?);
                if command.cmd() == 0x8000_0034 {
                    if cmds.chained.is_some() {
                        return Err("Duplicate Mach-O chained fixups".into());
                    }
                    cmds.chained = Some(pair);
                } else {
                    if cmds.trie.is_some() {
                        return Err("Duplicate Mach-O export trie".into());
                    }
                    cmds.trie = Some(pair);
                }
            }
            _ => {}
        }
    }
    Ok(cmds)
}
