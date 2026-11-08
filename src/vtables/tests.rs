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
        function: target,
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
    assert_eq!(describe(&found[0]), "{0xa100, 0xa110 (when edi == 1), 0xa120 (when edi == 2)} via 3 records +0x18");
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

/// At 0xb000: `test edi, edi; je L; lea rax, [R0]; L: call [rax+0x18]; ret`: on the `je` path rax
/// holds whatever the caller left, so the call is not resolved to R0's method.
#[test]
fn a_call_is_resolved_only_when_every_path_sets_the_record() {
    let mut data = vec![0u8; 0x220];
    data[..15].copy_from_slice(&[0x85, 0xff, 0x74, 0x07, 0x48, 0x8d, 0x05, 0xf5, 0x01, 0, 0, 0xff, 0x50, 0x18, 0xc3]);
    data[0x100] = 0xc3;
    let image = Image {
        segments: vec![Segment { va: 0xb000, offset: 0, size: data.len() }],
        data,
        functions: vec![0xb000..0xb00f, 0xb100..0xb101],
        pointers: vec![(0xb218, 0xb100)],
        imports: Vec::new(),
        symbols: Vec::new(),
        metadata: crate::image_format::Metadata::default(),
    };
    assert_eq!(dispatches(&image, 0xb000), Vec::new());
}

/// #172 review cases at 0xe000, with an executable segment 0xe000..0xe200 and a data segment
/// 0xe200..0xe240 holding two records (R0 at 0xe200, R1 at 0xe220):
/// - 0xe000 `lea rax, [R0]; jmp [rax+0x18]` — a tail jump through the record;
/// - 0xe020 `lea rax, [R0+0x20]; call [rax-8]; ret` — a negative offset from 0xe220 reaching R0+0x18;
/// - 0xe040 `cmp edi, 1; je L; add esi, 1; L: lea rax, [R0]; call [rax+0x18]; ret` — L is also
///   reached from above, so it has no single condition;
/// - 0xe080 `lea rax, [R1]; call [rax+0x18]; ret` — R1+0x18 is relocated to data, no call target.
fn review_image() -> Image {
    let mut data = vec![0u8; 0x240];
    let mut put = |at: usize, bytes: &[u8]| data[at..at + bytes.len()].copy_from_slice(bytes);
    put(0x00, &[0x48, 0x8d, 0x05, 0xf9, 0x01, 0, 0, 0xff, 0x60, 0x18]);
    put(0x20, &[0x48, 0x8d, 0x05, 0xf9, 0x01, 0, 0, 0xff, 0x50, 0xf8, 0xc3]);
    put(
        0x40,
        &[0x83, 0xff, 0x01, 0x74, 0x03, 0x83, 0xc6, 0x01, 0x48, 0x8d, 0x05, 0xb1, 0x01, 0, 0, 0xff, 0x50, 0x18, 0xc3],
    );
    put(0x80, &[0x48, 0x8d, 0x05, 0x99, 0x01, 0, 0, 0xff, 0x50, 0x18, 0xc3]);
    put(0x100, &[0xc3]);
    let segment = |va, file_size, executable| crate::image_format::LoadSegment {
        va,
        file_offset: va - 0xe000,
        file_size,
        mem_size: file_size,
        executable,
        writable: false,
    };
    Image {
        segments: vec![Segment { va: 0xe000, offset: 0, size: data.len() }],
        data,
        functions: vec![0xe000..0xe00a, 0xe020..0xe02b, 0xe040..0xe053, 0xe080..0xe08b, 0xe100..0xe101],
        pointers: vec![(0xe218, 0xe100), (0xe238, 0xe200)],
        imports: Vec::new(),
        symbols: Vec::new(),
        metadata: crate::image_format::Metadata {
            load_segments: vec![segment(0xe000, 0x200, true), segment(0xe200, 0x40, false)],
            ..crate::image_format::Metadata::default()
        },
    }
}

#[test]
fn tail_jumps_negative_offsets_shared_blocks_and_data_pointers() {
    let image = review_image();
    let one = |start| {
        dispatches(&image, start)
            .iter()
            .map(|d| (d.ip, d.offset, d.targets.iter().map(|t| (t.function, t.when.clone())).collect::<Vec<_>>()))
            .collect::<Vec<_>>()
    };
    assert_eq!(one(0xe000), vec![(0xe007, 0x18, vec![(0xe100, None)])], "a tail jump");
    assert_eq!(one(0xe020), vec![(0xe027, -8, vec![(0xe100, None)])], "a negative offset");
    assert_eq!(one(0xe040), vec![(0xe04f, 0x18, vec![(0xe100, None)])], "L is entered from above too");
    assert_eq!(one(0xe080), Vec::new(), "a pointer to data is no call target");
    assert_eq!(describe(&dispatches(&image, 0xe020)[0]), "{0xe100} via record 0xe220-0x8");
    assert!(table(&image, u64::MAX - 8, 32, 1, &mut Vec::new()).is_err(), "the record runs past the address space");
}
