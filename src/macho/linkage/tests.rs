/*
 * XRef Code — evidence-producing binary analysis
 * Copyright (c) 2026 Alexander Panasenko
 * Contact: alex@prod.codes
 * Author: https://prod.codes/about/
 * Project: https://github.com/alex09x/xref
 * SPDX-License-Identifier: MIT OR Apache-2.0
 */
use super::{Collected, Segment, chained, collect, exports, legacy};
mod review;
use crate::macho::linkage::chained::FixupRange;
use object::read::macho::MachOFile64;

fn put32(data: &mut [u8], at: usize, value: u32) {
    data[at..at + 4].copy_from_slice(&value.to_le_bytes());
}
fn put64(data: &mut [u8], at: usize, value: u64) {
    data[at..at + 8].copy_from_slice(&value.to_le_bytes());
}

#[test]
fn macho_linkage_real_compiler_fixture() -> Result<(), String> {
    let data = include_bytes!("../../../tests/fixtures/macho/basic.macho").to_vec();
    let file = MachOFile64::parse(data.as_slice()).map_err(|e| e.to_string())?;
    let result = collect(&file, &data, 0x1_0000_0000)?;
    assert!(result.imports.windows(2).all(|w| w[0].0 < w[1].0));
    assert!(result.pointers.windows(2).all(|w| w[0].0 < w[1].0));
    Ok(())
}

#[test]
fn macho_linkage_indirect_pointer_symbol() -> Result<(), String> {
    let mut data = vec![0u8; 0x400];
    data[..4].copy_from_slice(&[0xcf, 0xfa, 0xed, 0xfe]);
    put32(&mut data, 4, 0x0100_0007);
    put32(&mut data, 12, 2);
    put32(&mut data, 16, 3);
    put32(&mut data, 20, 72 + 80 + 24 + 80);
    let segment = 32;
    put32(&mut data, segment, 0x19);
    put32(&mut data, segment + 4, 152);
    put64(&mut data, segment + 24, 0x1000);
    put64(&mut data, segment + 32, 0x400);
    put64(&mut data, segment + 48, 0x400);
    put32(&mut data, segment + 64, 1);
    put64(&mut data, segment + 72 + 32, 0x1300);
    put64(&mut data, segment + 72 + 40, 8);
    put32(&mut data, segment + 72 + 48, 0x300);
    put32(&mut data, segment + 72 + 64, 6);
    let sym = segment + 152;
    put32(&mut data, sym, 2);
    put32(&mut data, sym + 4, 24);
    put32(&mut data, sym + 8, 0x200);
    put32(&mut data, sym + 12, 1);
    put32(&mut data, sym + 16, 0x210);
    put32(&mut data, sym + 20, 8);
    let dysym = sym + 24;
    put32(&mut data, dysym, 0xb);
    put32(&mut data, dysym + 4, 80);
    put32(&mut data, dysym + 56, 0x230);
    put32(&mut data, dysym + 60, 1);
    put32(&mut data, 0x200, 1);
    data[0x204] = 1;
    data[0x211..0x217].copy_from_slice(b"_puts\0");
    let file = MachOFile64::parse(data.as_slice()).map_err(|e| e.to_string())?;
    let result = collect(&file, &data, 0x1000)?;
    assert_eq!(result.imports, vec![(0x1300, "puts".to_owned())]);
    assert!(result.imports_complete);
    data.copy_within(sym..dysym + 80, sym + 80);
    put32(&mut data, 20, 72 + 160 + 24 + 80);
    put32(&mut data, segment + 4, 232);
    put32(&mut data, segment + 64, 2);
    put64(&mut data, segment + 152 + 32, 0x1180);
    put64(&mut data, segment + 152 + 40, 6);
    put32(&mut data, segment + 152 + 48, 0x180);
    put32(&mut data, segment + 152 + 64, 8);
    put32(&mut data, segment + 152 + 72, 6);
    data[0x180..0x186].copy_from_slice(&[0xff, 0x25, 0x7a, 0x01, 0, 0]);
    let file = MachOFile64::parse(data.as_slice()).map_err(|e| e.to_string())?;
    let with_stub = collect(&file, &data, 0x1000)?;
    assert_eq!(with_stub.imports, vec![(0x1300, "puts".to_owned())]);
    Ok(())
}

#[test]
fn macho_linkage_legacy_rebase_and_bind_precedence() -> Result<(), String> {
    let mut data = vec![0u8; 0x200];
    put64(&mut data, 0x20, 0x1234);
    data[0x180..0x185].copy_from_slice(&[0x11, 0x20, 0x20, 0x51, 0]);
    let bind = [0x40, b'_', b'p', b'u', b't', b's', 0, 0x70, 0x20, 0x90, 0];
    data[0x1a0..0x1a0 + bind.len()].copy_from_slice(&bind);
    let segment = Segment { vmaddr: 0x1000, vmsize: 0x100, fileoff: 0, filesize: 0x100 };
    let mut info = [0u32; 10];
    info[0] = 0x180;
    info[1] = 5;
    info[2] = 0x1a0;
    info[3] = u32::try_from(bind.len()).map_err(|e| e.to_string())?;
    let mut result = Collected::new();
    legacy::collect(&data, &[segment], info, true, &mut result)?;
    assert_eq!(result.imports.get(&0x1020).map(String::as_str), Some("puts"));
    assert!(!result.pointers.contains_key(&0x1020));
    Ok(())
}

#[test]
fn macho_linkage_legacy_text_fixups_are_explicitly_incomplete() -> Result<(), String> {
    let mut data = vec![0u8; 0x200];
    let rebase = [0x12, 0x20, 0xfc, 0x01, 0x51, 0];
    data[0x180..0x180 + rebase.len()].copy_from_slice(&rebase);
    let bind = [0x40, b'_', b'f', 0, 0x52, 0x70, 0xfc, 0x01, 0x90, 0];
    data[0x1a0..0x1a0 + bind.len()].copy_from_slice(&bind);
    let segment = Segment { vmaddr: 0x1000, vmsize: 0x100, fileoff: 0, filesize: 0x100 };
    let mut info = [0u32; 10];
    info[0] = 0x180;
    info[1] = u32::try_from(rebase.len()).map_err(|e| e.to_string())?;
    info[2] = 0x1a0;
    info[3] = u32::try_from(bind.len()).map_err(|e| e.to_string())?;
    let mut result = Collected::new();
    legacy::collect(&data, &[segment], info, true, &mut result)?;
    assert!(!result.fixups_complete && !result.imports_complete);
    assert!(result.pointers.is_empty() && result.imports.is_empty());
    Ok(())
}

#[test]
fn macho_linkage_chained_64_offset_bind_and_rebase() -> Result<(), String> {
    let mut data = vec![0u8; 0x400];
    let base = 0x100;
    put32(&mut data, base + 4, 0x20);
    put32(&mut data, base + 8, 0x80);
    put32(&mut data, base + 12, 0x90);
    put32(&mut data, base + 16, 1);
    put32(&mut data, base + 20, 1);
    put32(&mut data, base + 0x20, 1);
    put32(&mut data, base + 0x24, 8);
    put32(&mut data, base + 0x28, 24);
    data[base + 0x2c..base + 0x2e].copy_from_slice(&0x1000u16.to_le_bytes());
    data[base + 0x2e..base + 0x30].copy_from_slice(&6u16.to_le_bytes());
    data[base + 0x3c..base + 0x3e].copy_from_slice(&1u16.to_le_bytes());
    data[base + 0x3e..base + 0x40].copy_from_slice(&0x20u16.to_le_bytes());
    put32(&mut data, base + 0x80, 0);
    data[base + 0x90..base + 0x96].copy_from_slice(b"_puts\0");
    put64(&mut data, 0x220, (1u64 << 63) | (2u64 << 51));
    put64(&mut data, 0x228, 0x44);
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
    assert_eq!(result.imports.get(&0x1020).map(String::as_str), Some("puts"));
    assert_eq!(result.pointers.get(&0x1028), Some(&0x1044));
    assert!(result.imports_complete && result.fixups_complete);
    put32(&mut data, base + 20, 2);
    put32(&mut data, base + 12, 0xa0);
    put32(&mut data, base + 0x84, 5);
    data[base + 0xa0..base + 0xa6].copy_from_slice(b"_puts\0");
    let mut with_addend = Collected::new();
    chained::collect(
        &data,
        std::slice::from_ref(&segment),
        FixupRange { off: 0x100, size: 0x100 },
        true,
        0x0100_0007,
        0x1000,
        &mut with_addend,
    )?;
    assert!(with_addend.imports.is_empty());
    assert!(!with_addend.imports_complete);
    assert_eq!(with_addend.pointers.get(&0x1028), Some(&0x1044));
    put32(&mut data, base + 20, 3);
    put32(&mut data, base + 12, 0xb0);
    put32(&mut data, base + 0x84, 0);
    put64(&mut data, base + 0x88, 0);
    data[base + 0xb0..base + 0xb6].copy_from_slice(b"_puts\0");
    let mut wide_import = Collected::new();
    chained::collect(
        &data,
        std::slice::from_ref(&segment),
        FixupRange { off: 0x100, size: 0x100 },
        true,
        0x0100_0007,
        0x1000,
        &mut wide_import,
    )?;
    assert_eq!(wide_import.imports.get(&0x1020).map(String::as_str), Some("puts"));
    data[base + 0x2e..base + 0x30].copy_from_slice(&1u16.to_le_bytes());
    let mut unsupported = Collected::new();
    chained::collect(
        &data,
        &[segment],
        FixupRange { off: 0x100, size: 0x100 },
        true,
        0x0100_0007,
        0x1000,
        &mut unsupported,
    )?;
    assert!(unsupported.imports.is_empty() && unsupported.pointers.is_empty());
    assert!(!unsupported.imports_complete && !unsupported.fixups_complete);
    Ok(())
}

#[test]
fn macho_linkage_export_resolver_and_reexport() -> Result<(), String> {
    let mut result = Collected::new();
    exports::collect(&[3, 0x10, 0x20, 0x30, 0], 0x1000, &mut result)?;
    exports::collect(&[4, 8, 1, b'_', 0, 0], 0x1000, &mut result)?;
    assert!(result.exports.contains(&0x1020));
    assert!(result.exports.contains(&0x1030));
    assert_eq!(result.exports.len(), 2);
    assert!(exports::collect(&[0, 1, b'a', 0, 0], 0x1000, &mut Collected::new()).is_err());
    Ok(())
}
