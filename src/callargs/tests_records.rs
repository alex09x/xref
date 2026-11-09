/*
 * XRef — Tests for readers of a field of records consumed by value (#176)
 * Copyright (c) 2026 Alexander Panasenko
 * Contact: alex@prod.codes
 * Author: https://prod.codes/about/
 * Project: https://github.com/alex09x/xref
 * SPDX-License-Identifier: MIT OR Apache-2.0
 */

use crate::image::{Image, Segment};

/// A consumer of 0x200-byte records, as rustc emits `for r in v` (field +0x40, one byte):
/// - 0x1000 `push rbx; push r15; push r12; sub rsp, 0x400; mov rbx, rdi; add rbx, 0x200;
///   mov r15, [rip + memcpy@got]`, then the loop at 0x101d:
///   `movzx eax, byte [rbx-0x1c0]` (the field, read through the pointer stepped past it);
///   `cmp rax, 0xb; je done; lea rsi, [rbx-0x1f8]; lea rdi, [rsp+0x10]; mov edx, 0x1f8; call r15`
///   (the element from +8 on, copied through a register); `movzx ecx, byte [rsp+0x48]` (the field
///   in the copy); `lea rsi, [rsp+0x10]; lea rdi, [rsp+0x208]; mov edx, 0x1f8; call r15` (the copy
///   copied again, a record rebuilt at `rsp+0x200`); `lea rdi, [rsp+0x200]; call judge;
///   add rbx, 0x200; jmp loop`;
/// - 0x1100 `judge`: `movzx eax, byte [rdi+0x40]; ret`;
/// - 0x1200 the `memcpy` import slot.
fn consumer_image() -> Image {
    let consumer: &[u8] = &[
        0x53, 0x41, 0x57, 0x41, 0x54, 0x48, 0x81, 0xec, 0x00, 0x04, 0x00, 0x00, 0x48, 0x89, 0xfb, 0x48, 0x81, 0xc3,
        0x00, 0x02, 0x00, 0x00, 0x4c, 0x8b, 0x3d, 0xe3, 0x01, 0x00, 0x00, 0x0f, 0xb6, 0x83, 0x40, 0xfe, 0xff, 0xff,
        0x48, 0x83, 0xf8, 0x0b, 0x74, 0x44, 0x48, 0x8d, 0xb3, 0x08, 0xfe, 0xff, 0xff, 0x48, 0x8d, 0x7c, 0x24, 0x10,
        0xba, 0xf8, 0x01, 0x00, 0x00, 0x41, 0xff, 0xd7, 0x0f, 0xb6, 0x4c, 0x24, 0x48, 0x48, 0x8d, 0x74, 0x24, 0x10,
        0x48, 0x8d, 0xbc, 0x24, 0x08, 0x02, 0x00, 0x00, 0xba, 0xf8, 0x01, 0x00, 0x00, 0x41, 0xff, 0xd7, 0x48, 0x8d,
        0xbc, 0x24, 0x00, 0x02, 0x00, 0x00, 0xe8, 0x9b, 0x00, 0x00, 0x00, 0x48, 0x81, 0xc3, 0x00, 0x02, 0x00, 0x00,
        0xeb, 0xaf, 0x48, 0x81, 0xc4, 0x00, 0x04, 0x00, 0x00, 0x41, 0x5c, 0x41, 0x5f, 0x5b, 0xc3,
    ];
    let mut data = vec![0; 0x208];
    data[..consumer.len()].copy_from_slice(consumer);
    data[0x100..0x105].copy_from_slice(&[0x0f, 0xb6, 0x47, 0x40, 0xc3]);
    Image {
        segments: vec![Segment { va: 0x1000, offset: 0, size: data.len() }],
        data,
        functions: vec![0x1000..0x107b, 0x1100..0x1105],
        pointers: Vec::new(),
        imports: vec![(0x1200, "memcpy@GLIBC_2.14".to_owned())],
        symbols: Vec::new(),
        metadata: crate::image_format::Metadata::default(),
    }
}

#[test]
fn a_record_consumed_by_value_is_read_through_its_stepped_pointer_copies_and_a_rebuilt_record() {
    let image = consumer_image();
    let (f, code) = super::flow::function_code(&image, 0x1000).unwrap_or_default();
    let (readers, _) = super::records::in_function(&image, &f, &code, 0x200, 0x40, 1);
    let found: Vec<(u64, Option<&str>)> = readers.iter().map(|r| (r.ip, r.note.as_deref())).collect();
    assert!(found.contains(&(0x101d, None)), "the read one element behind the stepped pointer: {found:?}");
    assert!(
        found.contains(&(0x103e, Some("copy-in at 0x103b to [rsp+0x10], field +0x40"))),
        "the field in the part copied through r15: {found:?}"
    );
    let rebuilt = readers.iter().find(|r| r.ip == 0x1100).map(|r| (r.via.clone(), r.note.as_deref()));
    assert_eq!(
        rebuilt,
        Some((
            vec![(0x1100, super::scan::Slot::Reg(0))],
            Some("copy-in at 0x103b to [rsp+0x10], field +0x40, then copied at 0x1055 to [rsp+0x240]")
        )),
        "the callee handed the record rebuilt from the copy: {found:?}"
    );
    assert_eq!(readers.len(), 3, "{found:?}");
}

#[test]
fn a_slot_names_a_copy_routine_by_import_or_by_the_address_it_holds() {
    let mut image = consumer_image();
    assert_eq!(super::copy::copy_routine_at(&image, 0x1200), Some("memcpy"));
    // A non-PIE function-pointer variable holds the routine's address itself.
    image.imports.clear();
    image.data[0x200..0x208].copy_from_slice(&0x1100u64.to_le_bytes());
    assert_eq!(super::copy::copy_routine_at(&image, 0x1200), None, "judge is no copy routine");
    image.symbols.push((0x1100, "memmove".to_owned()));
    assert_eq!(super::copy::copy_routine_at(&image, 0x1200), Some("memmove"));
}
