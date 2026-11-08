/*
 * XRef — `xref table`: fixed-size records with their relocated pointers
 * Copyright (c) 2026 Alexander Panasenko
 * Contact: alex@prod.codes
 * Author: https://prod.codes/about/
 * Project: https://github.com/alex09x/xref
 * SPDX-License-Identifier: MIT OR Apache-2.0
 */

use crate::commands::Res;
use crate::image::{Image, Slot};

/// `xref table ADDR --stride N --count K`: `K` records of `N` bytes from `ADDR`, each 8-byte field
/// with what fills it: a relocated pointer (to a function, an import, data), or the file's bytes.
pub fn table(image: &Image, address: u64, stride: u64, count: u64, out: &mut dyn std::io::Write) -> Res {
    if stride == 0 || !stride.is_multiple_of(8) {
        return Err("--stride must be a positive multiple of 8".into());
    }
    // The last field of the last record must be addressable too.
    if let Some(last) = count.checked_sub(1) {
        last.checked_mul(stride)
            .and_then(|start| start.checked_add(stride - 8))
            .and_then(|end| address.checked_add(end))
            .ok_or("table too large")?;
    }
    for index in 0..count {
        let record = address + index * stride;
        writeln!(out, "record {index} at {record:#x}")?;
        for offset in (0..stride).step_by(8) {
            let place = record + offset;
            let filled = match image.slot(place) {
                Some(Slot::Pointer(target)) => format!("-> {}", crate::listing::describe_code(image, target)),
                Some(Slot::Import(name)) => format!("-> {name} (import)"),
                None => image.read(place, 8).map_or_else(
                    || "(outside the image)".to_owned(),
                    |bytes| format!("{:#x}", u64::from_le_bytes(bytes.try_into().unwrap_or_default())),
                ),
            };
            writeln!(out, "  +{offset:#04x}  {filled}")?;
        }
    }
    Ok(())
}
