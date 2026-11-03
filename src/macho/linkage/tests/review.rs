/*
 * XRef Code — evidence-producing binary analysis
 * Copyright (c) 2026 Alexander Panasenko
 * Contact: alex@prod.codes
 * Author: https://prod.codes/about/
 * Project: https://github.com/alex09x/xref
 * SPDX-License-Identifier: MIT OR Apache-2.0
 */
use super::*;
use crate::macho::linkage::chained::FixupRange;
fn file(data: &[u8]) -> Result<MachOFile64<'_>, String> {
    MachOFile64::parse(data).map_err(|e| e.to_string())
}
fn base(commands: &[Vec<u8>], kind: u32) -> Vec<u8> {
    let mut data = vec![0u8; 0x400];
    data[..4].copy_from_slice(&[0xcf, 0xfa, 0xed, 0xfe]);
    put32(&mut data, 4, 0x0100_0007);
    put32(&mut data, 12, kind);
    put32(&mut data, 16, u32::try_from(commands.len()).unwrap_or(u32::MAX));
    put32(&mut data, 20, u32::try_from(commands.iter().map(Vec::len).sum::<usize>()).unwrap_or(u32::MAX));
    let mut at = 32;
    for command in commands {
        data[at..at + command.len()].copy_from_slice(command);
        at += command.len();
    }
    data
}
fn indirect_fixture() -> Vec<u8> {
    let mut seg = vec![0u8; 152];
    put32(&mut seg, 0, 0x19);
    put32(&mut seg, 4, 152);
    put64(&mut seg, 24, 0x1000);
    put64(&mut seg, 32, 0x400);
    put64(&mut seg, 48, 0x400);
    put32(&mut seg, 64, 1);
    put64(&mut seg, 104, 0x1300);
    put64(&mut seg, 112, 8);
    put32(&mut seg, 120, 0x300);
    put32(&mut seg, 136, 6);
    let mut sym = vec![0u8; 24];
    put32(&mut sym, 0, 2);
    put32(&mut sym, 4, 24);
    put32(&mut sym, 8, 0x200);
    put32(&mut sym, 12, 1);
    put32(&mut sym, 16, 0x210);
    put32(&mut sym, 20, 8);
    let mut dysym = vec![0u8; 80];
    put32(&mut dysym, 0, 0xb);
    put32(&mut dysym, 4, 80);
    put32(&mut dysym, 56, 0x230);
    put32(&mut dysym, 60, 1);
    let mut data = base(&[seg, sym, dysym], 2);
    put32(&mut data, 0x200, 1);
    data[0x204] = 1;
    data[0x211..0x217].copy_from_slice(b"_puts\0");
    data
}
fn uleb(value: u64) -> Vec<u8> {
    let mut value = value;
    let mut out = vec![];
    loop {
        let mut b = (value & 0x7f) as u8;
        value >>= 7;
        if value != 0 {
            b |= 0x80;
        }
        out.push(b);
        if value == 0 {
            break;
        }
    }
    out
}
#[test]
fn macho_linkage_review_section_kind_and_indirect_symbol_validation() -> Result<(), String> {
    let mut data = indirect_fixture();
    put32(&mut data, 32 + 136, 0x16);
    put64(&mut data, 32 + 112, 4);
    assert!(collect(&file(&data)?, &data, 0x1000)?.imports.is_empty());
    put32(&mut data, 32 + 136, 0x14);
    put64(&mut data, 32 + 112, 8);
    assert_eq!(collect(&file(&data)?, &data, 0x1000)?.imports, vec![(0x1300, "puts".into())]);
    put32(&mut data, 0x230, 0x8000_0005);
    assert!(collect(&file(&data)?, &data, 0x1000).is_err());
    put32(&mut data, 0x230, 0);
    data[0x204] = 0xe1;
    assert!(collect(&file(&data)?, &data, 0x1000)?.imports.is_empty());
    data[0x204] = 0x0d;
    assert_eq!(collect(&file(&data)?, &data, 0x1000)?.imports, vec![(0x1300, "puts".into())]);
    data[0x204] = 0x0b;
    assert!(!collect(&file(&data)?, &data, 0x1000)?.imports_complete);
    Ok(())
}
#[test]
fn macho_linkage_review_unsigned_inline_addend_and_rebase_precedence() -> Result<(), String> {
    let mut data = vec![0u8; 0x400];
    let at = 0x100;
    put32(&mut data, at + 4, 0x20);
    put32(&mut data, at + 8, 0x80);
    put32(&mut data, at + 12, 0xa0);
    put32(&mut data, at + 16, 1);
    put32(&mut data, at + 20, 2);
    put32(&mut data, at + 0x20, 1);
    put32(&mut data, at + 0x24, 8);
    put32(&mut data, at + 0x28, 24);
    data[at + 0x2c..at + 0x2e].copy_from_slice(&0x1000u16.to_le_bytes());
    data[at + 0x2e..at + 0x30].copy_from_slice(&6u16.to_le_bytes());
    data[at + 0x3c..at + 0x3e].copy_from_slice(&1u16.to_le_bytes());
    data[at + 0x3e..at + 0x40].copy_from_slice(&0x20u16.to_le_bytes());
    put32(&mut data, at + 0x84, 56);
    data[at + 0xa0..at + 0xa6].copy_from_slice(b"_puts\0");
    put64(&mut data, 0x220, (1u64 << 63) | (200u64 << 24));
    let segment = Segment { vmaddr: 0x1000, vmsize: 0x200, fileoff: 0x200, filesize: 0x200 };
    let mut result = Collected::new();
    chained::collect(
        &data,
        std::slice::from_ref(&segment),
        FixupRange { off: 0x100, size: 0x100 },
        true,
        0x0100_0007,
        0x1000,
        &mut result,
    )?;
    assert!(result.imports.is_empty());
    assert!(!result.imports_complete);
    put64(&mut data, 0x220, 0x44);
    let mut result = Collected::new();
    result.import(0x1020, "_puts", 0);
    chained::collect(
        &data,
        &[segment],
        FixupRange { off: 0x100, size: 0x100 },
        true,
        0x0100_0007,
        0x1000,
        &mut result,
    )?;
    assert_eq!(result.pointers.get(&0x1020), Some(&0x1044));
    assert!(!result.imports.contains_key(&0x1020));
    Ok(())
}
#[test]
fn macho_linkage_review_backward_legacy_cursor() -> Result<(), String> {
    let mut data = vec![0u8; 0x400];
    put64(&mut data, 0x10, 0x1111);
    put64(&mut data, 0x20, 0x2222);
    let mut rebase = vec![0x11, 0x20, 0x20, 0x51, 0x30];
    rebase.extend(uleb(0u64.wrapping_sub(0x18)));
    rebase.extend([0x51, 0]);
    data[0x180..0x180 + rebase.len()].copy_from_slice(&rebase);
    let segment = Segment { vmaddr: 0x1000, vmsize: 0x100, fileoff: 0, filesize: 0x100 };
    let mut info = [0; 10];
    info[0] = 0x180;
    info[1] = u32::try_from(rebase.len()).map_err(|e| e.to_string())?;
    let mut out = Collected::new();
    legacy::collect(&data, std::slice::from_ref(&segment), info, true, &mut out)?;
    assert_eq!(out.pointers.get(&0x1010), Some(&0x1111));
    assert_eq!(out.pointers.get(&0x1020), Some(&0x2222));
    let mut bind = vec![0x40, b'_', b'f', 0, 0x70, 0x20, 0x90, 0x80];
    bind.extend(uleb(0u64.wrapping_sub(0x18)));
    bind.extend([0x90, 0]);
    data[0x200..0x200 + bind.len()].copy_from_slice(&bind);
    info = [0; 10];
    info[2] = 0x200;
    info[3] = u32::try_from(bind.len()).map_err(|e| e.to_string())?;
    let mut out = Collected::new();
    legacy::collect(&data, &[segment], info, true, &mut out)?;
    assert!(out.imports.contains_key(&0x1010) && out.imports.contains_key(&0x1020));
    Ok(())
}
#[test]
fn macho_linkage_review_singletons_and_missing_exports() -> Result<(), String> {
    let data = base(&[], 6);
    assert!(!collect(&file(&data)?, &data, 0x1000)?.exports_complete);
    for (cmd, len) in [(2, 24), (0xb, 80), (0x8000_0022, 48), (0x8000_0034, 16), (0x8000_0033, 16)] {
        let mut command = vec![0u8; len];
        put32(&mut command, 0, cmd);
        put32(&mut command, 4, u32::try_from(len).map_err(|e| e.to_string())?);
        if cmd == 0x8000_0034 {
            put32(&mut command, 8, 0x300);
            put32(&mut command, 12, 32);
        }
        if cmd == 0x8000_0033 {
            put32(&mut command, 8, 0x300);
            put32(&mut command, 12, 2);
        }
        let mut data = base(&[command.clone(), command], 2);
        if cmd == 0x8000_0034 {
            put32(&mut data, 0x304, 28);
            put32(&mut data, 0x314, 1);
        }
        assert!(collect(&file(&data)?, &data, 0x1000).is_err(), "duplicate {cmd:#x}");
    }
    Ok(())
}

#[test]
fn macho_linkage_review_deep_exports_and_classic_metadata() -> Result<(), String> {
    let count: usize = 5000;
    let mut trie = vec![];
    for i in 0..count {
        trie.extend([0, 1, b'a', 0]);
        let target = (i + 1) * 9;
        for j in 0..5 {
            trie.push((target >> (7 * j)).to_le_bytes()[0] & 0x7f | if j < 4 { 0x80 } else { 0 });
        }
    }
    trie.extend([2, 0, 0x20, 0]);
    let mut out = Collected::new();
    exports::collect(&trie, 0x1000, &mut out)?;
    assert_eq!(out.exports.iter().copied().collect::<Vec<_>>(), vec![0x1020]);
    let mut data = indirect_fixture();
    put32(&mut data, 24, 0x0400_0000);
    assert!(!collect(&file(&data)?, &data, 0x1000)?.exports_complete);
    put32(&mut data, 24, 0);
    let dysym = 32 + 152 + 24;
    put32(&mut data, dysym + 64, 0x280);
    put32(&mut data, dysym + 68, 1);
    let result = collect(&file(&data)?, &data, 0x1000)?;
    assert!(!result.imports_complete && !result.fixups_complete);
    Ok(())
}
