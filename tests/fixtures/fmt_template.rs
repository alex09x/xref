/*
 * XRef — x86-64 binary analysis and cross-reference tooling
 * Copyright (c) 2026 Alexander Panasenko
 *
 * Contact: alex@prod.codes
 * Author: https://prod.codes/about/
 * Project: https://github.com/alex09x/xref
 * SPDX-License-Identifier: MIT OR Apache-2.0
 */

// A real `format!` call: recent rustc encodes its pieces as one fmt::Arguments byte template.

#[inline(never)]
#[no_mangle]
pub fn report(a: u64, b: f64, c: i32) -> String {
    format!("alpha={} beta_sum={:>8.2} gamma={}", a, b, c)
}

fn main() {
    let s = report(std::hint::black_box(7), std::hint::black_box(1.5), std::hint::black_box(-3));
    std::hint::black_box(s);
}
