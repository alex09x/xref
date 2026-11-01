/*
 * xref — Ultra blazing fast cross-references of an x86-64 ELF binary
 * Copyright (c) 2026 Alexander Panasenko
 *
 * Contact: alex@prod.codes
 * Author: https://prod.codes/about/
 * SPDX-License-Identifier: MIT OR Apache-2.0
 */

// Fixture program for the end-to-end tests: an enum whose Display is a jump table, a compare
// with a constant, a direct call and a bounds check that passes a panic location.

use std::fmt;
use std::hint::black_box;

#[repr(u8)]
pub enum Fault {
    Empty,
    Small(u8),
    Wide(u64),
    Pair(u32, u32),
    Ratio(f64),
    Flag(bool),
    Letter(char),
    Signed(i64),
    Triple(u16, u16, u16),
    Short(i16),
    Text(&'static str),
}

impl fmt::Display for Fault {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Empty => f.write_str("fixture fault empty"),
            Self::Small(v) => write!(f, "fixture fault small {v}"),
            Self::Wide(v) => write!(f, "fixture fault wide {v:#x}"),
            Self::Pair(a, b) => write!(f, "fixture fault pair {a} and {b}"),
            Self::Ratio(r) => write!(f, "fixture fault ratio {r:.3}"),
            Self::Flag(b) => write!(f, "fixture fault flag {b}"),
            Self::Letter(c) => write!(f, "fixture fault letter {c}"),
            Self::Signed(v) => write!(f, "fixture fault signed {v:+}"),
            Self::Triple(a, b, c) => write!(f, "fixture fault triple {a}/{b}/{c}"),
            Self::Short(v) => write!(f, "fixture fault short {v:>8}"),
            Self::Text(t) => write!(f, "fixture fault text <{t}>"),
        }
    }
}

#[no_mangle]
#[inline(never)]
pub fn fixture_limit(len: usize) -> bool {
    black_box(len) == 9
}

#[no_mangle]
#[inline(never)]
pub fn fixture_pick(values: &[u64], index: usize) -> u64 {
    values[index]
}

#[no_mangle]
#[inline(never)]
pub fn fixture_inline(index: usize) -> String {
    let mut text = String::from("token mismatch");
    if fixture_limit(index) || fixture_limit(7) {
        text.push('!');
    }
    text
}

fn main() {
    let faults = [
        Fault::Empty,
        Fault::Small(1),
        Fault::Wide(2),
        Fault::Pair(3, 4),
        Fault::Ratio(0.5),
        Fault::Flag(true),
        Fault::Letter('x'),
        Fault::Signed(-7),
        Fault::Triple(1, 2, 3),
        Fault::Short(-2),
        Fault::Text("t"),
    ];
    let index = black_box(std::env::args().count());
    println!("{}", faults[index % faults.len()]);
    println!("{}", fixture_limit(index));
    println!("{}", fixture_pick(&[1, 2, 3], index));
    println!("{}", fixture_inline(index));
}
