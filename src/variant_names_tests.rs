/*
 * xref — Ultra blazing fast cross-references of an x86-64 ELF binary
 * Copyright (c) 2026 Alexander Panasenko
 *
 * Contact: alex@prod.codes
 * Author: https://prod.codes/about/
 * Project: https://github.com/alex09x/xref
 * SPDX-License-Identifier: MIT OR Apache-2.0
 */

use iced_x86::Register;

use super::Names;
use crate::origin::dispatch::Tag;

fn tag(bias: u64, dataful: Option<u64>) -> Tag {
    Tag { width: 8, base: Register::RDI, displacement: 0, bias, dataful }
}

fn names(count: usize, tag: Option<Tag>) -> Names {
    Names { function: 0x2000, table: 0x3000, tag, names: (0..count).map(|i| vec![format!("v{i}")]).collect() }
}

#[test]
fn an_index_is_carried_over_through_the_tag_value() {
    // Both tables are niche-encoded the same way: the same index, the dataful variant to itself.
    let there = names(50, Some(tag(0x88, Some(20))));
    let same = tag(0x88, Some(20));
    assert_eq!(there.of(Some(&same), 50, 44), ["v44"]);
    assert_eq!(there.of(Some(&same), 50, 20), ["v20"]);
    // Here the tag is the plain index (no niche): tag 0x88 + 3 is index 3 there.
    let plain = tag(0, None);
    assert_eq!(there.of(Some(&plain), 200, 0x88 + 3), ["v3"]);
    assert_eq!(there.of(Some(&plain), 200, 5), Vec::<String>::new());
}

#[test]
fn without_tags_indices_match_only_between_equally_long_tables() {
    let there = names(10, None);
    assert_eq!(there.of(None, 10, 7), ["v7"]);
    assert_eq!(there.of(None, 12, 7), Vec::<String>::new());
}
