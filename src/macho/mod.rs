/*
 * XRef Code — evidence-producing binary analysis
 * Copyright (c) 2026 Alexander Panasenko
 * Contact: alex@prod.codes
 * Author: https://prod.codes/about/
 * Project: https://github.com/alex09x/xref
 * SPDX-License-Identifier: MIT OR Apache-2.0
 */
pub mod linkage;
use std::collections::BTreeSet;

#[derive(Default)]
pub struct Linkage {
    pub imports: Vec<(u64, String)>,
    pub pointers: Vec<(u64, u64)>,
    pub exports: BTreeSet<u64>,
    pub imports_complete: bool,
    pub fixups_complete: bool,
    pub exports_complete: bool,
    pub warnings: Vec<&'static str>,
}
