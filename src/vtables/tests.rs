/*
 * XRef — Tests for indirect calls through constant records
 * Copyright (c) 2026 Alexander Panasenko
 * Contact: alex@prod.codes
 * Author: https://prod.codes/about/
 * Project: https://github.com/alex09x/xref
 * SPDX-License-Identifier: MIT OR Apache-2.0
 */

use super::{Dispatch, Target, describe, dispatches, table};
use crate::image::{Image, Segment};

/// At 0xa000: `cmp edi, 1; je L1; cmp edi, 2; je L2; lea rax, [R0]; jmp J; L1: lea rax, [R1];
/// jmp J; L2: lea rax, [R2]; J: mov rcx, [rax+0x18]; call rcx; ret`, with three 32-byte records
/// at 0xa200 whose +0x18 slots are relocated to 0xa100, 0xa110 and 0xa120.
fn image() -> Image {
    let mut data = vec![0u8; 0x260];
    data[..42].copy_from_slice(&[
        0x83, 0xff, 0x01, 0x74, 0x0e, 0x83, 0xff, 0x02, 0x74, 0x12, 0x48, 0x8d, 0x05, 0xef, 0x01, 0, 0, 0xeb, 0x10,
        0x48, 0x8d, 0x05, 0x06, 0x02, 0, 0, 0xeb, 0x07, 0x48, 0x8d, 0x05, 0x1d, 0x02, 0, 0, 0x48, 0x8b, 0x48, 0x18,
        0xff, 0xd1, 0xc3,
    ]);
    for at in [0x100, 0x110, 0x120] {
        data[at] = 0xc3;
    }
    Image {
        segments: vec![Segment { va: 0xa000, offset: 0, size: data.len() }],
        data,
        functions: vec![0xa000..0xa02a, 0xa100..0xa101, 0xa110..0xa111, 0xa120..0xa121],
        pointers: vec![(0xa218, 0xa100), (0xa238, 0xa110), (0xa258, 0xa120)],
        imports: Vec::new(),
        symbols: Vec::new(),
        metadata: crate::image_format::Metadata::default(),
    }
}

#[test]
fn an_indirect_call_through_records_chosen_by_branch_lists_each_target_and_its_condition() {
    let found = dispatches(&image(), 0xa000);
    let target = |record, target, set_at, when: Option<&str>| Target {
        record,
        slot: record + 0x18,
        target,
        set_at,
        when: when.map(str::to_owned),
    };
    assert_eq!(
        found,
        vec![Dispatch {
            ip: 0xa027,
            offset: 0x18,
            targets: vec![
                // The default path falls through both compares: no single condition.
                target(0xa200, 0xa100, 0xa00a, None),
                target(0xa220, 0xa110, 0xa013, Some("edi == 1")),
                target(0xa240, 0xa120, 0xa01c, Some("edi == 2")),
            ],
        }]
    );
    assert_eq!(
        describe(&found[0]),
        "{0xa100, 0xa110 (when edi == 1), 0xa120 (when edi == 2)} via 3 records +0x18"
    );
}

#[test]
fn table_dumps_records_with_their_relocated_pointers() -> Result<(), Box<dyn std::error::Error>> {
    let mut out = Vec::new();
    table(&image(), 0xa200, 0x20, 2, &mut out)?;
    let text = String::from_utf8(out)?;
    assert!(text.starts_with("record 0 at 0xa200\n  +0x00  0x0\n"), "{text}");
    assert!(text.contains("  +0x18  -> 0xa100\nrecord 1 at 0xa220\n"), "{text}");
    assert!(text.contains("  +0x18  -> 0xa110\n"), "{text}");
    assert!(table(&image(), 0xa200, 12, 1, &mut Vec::new()).is_err(), "a stride that is not a multiple of 8");
    Ok(())
}
