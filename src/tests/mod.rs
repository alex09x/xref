/*
 * xref — Ultra blazing fast cross-references of an x86-64 ELF binary
 * Copyright (c) 2026 Alexander Panasenko
 *
 * Contact: alex@prod.codes
 * Author: https://prod.codes/about/
 * Project: https://github.com/alex09x/xref
 * SPDX-License-Identifier: MIT OR Apache-2.0
 */

//! Dedicated unit-test suites decomposed by subsystem to maintain compact source files.

mod alu_cond;
mod alu_wide;
mod cfg_structuring;
mod commands_search;
mod edge_branches;
mod interproc_types;
mod slice_diff_dump;
mod ssa_stack_fields;
