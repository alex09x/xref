/*
 * XRef — x86-64 binary analysis and cross-reference tooling
 * Copyright (c) 2026 Alexander Panasenko
 *
 * Contact: alex@prod.codes
 * Author: https://prod.codes/about/
 * Project: https://github.com/alex09x/xref
 * SPDX-License-Identifier: MIT OR Apache-2.0
 */

#[repr(C)]
pub struct Target {
    pub value: f64,
}

#[no_mangle]
#[inline(never)]
pub extern "C" fn conv_div(x: u64, d: f64) -> f64 {
    x as f64 / d
}

#[no_mangle]
#[inline(never)]
pub extern "C" fn conv_div_store(x: u64, d: f64, out: *mut Target) {
    unsafe {
        (*out).value = x as f64 / d;
    }
}

fn main() {
    let mut target = Target { value: 0.0 };
    let res = conv_div(std::hint::black_box(42), std::hint::black_box(3.5));
    conv_div_store(std::hint::black_box(42), std::hint::black_box(3.5), &mut target);
    std::hint::black_box(res);
    std::hint::black_box(target.value);
}
