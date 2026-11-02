/*
 * XRef Code — Redistributable MCP investigation fixture
 * Copyright (c) 2026 Alexander Panasenko
 * Contact: alex@prod.codes
 * Author: https://prod.codes/about/
 * Project: https://github.com/alex09x/xref
 * SPDX-License-Identifier: MIT OR Apache-2.0
 */

#[no_mangle]
#[inline(never)]
pub extern "C" fn mcp_sink(pointer: *const u8, length: usize) -> usize {
    std::hint::black_box(pointer);
    std::hint::black_box(length)
}

#[no_mangle]
#[inline(never)]
pub extern "C" fn mcp_entry() -> usize {
    let message = b"XREF_MCP_BOUNDARY_NEEDLE\0";
    mcp_sink(message.as_ptr(), message.len()).wrapping_add(1)
}

fn main() { std::hint::black_box(mcp_entry()); }
