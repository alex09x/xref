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

pub fn collect(_file: &MachOFile64<'_>, _data: &[u8], _text_base: u64) -> Result<Linkage, String> {
    Err("Mach-O linkage collection pending".into())
}
