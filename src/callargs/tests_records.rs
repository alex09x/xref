/*
 * XRef — Tests for readers of a field of records consumed by value (#176)
 * Copyright (c) 2026 Alexander Panasenko
 * Contact: alex@prod.codes
 * Author: https://prod.codes/about/
 * Project: https://github.com/alex09x/xref
 * SPDX-License-Identifier: MIT OR Apache-2.0
 */

use super::scan::Slot;
use crate::image::{Image, Segment};

/// A reader: where, through which calls, and its note.
type Seen<'a> = (u64, Vec<(u64, Slot)>, Option<&'a str>);

/// A consumer of 0x200-byte records, as rustc emits `for r in v` (field +0x40, one byte):
/// - 0x1000 `push rbx; push r15; push r12; push r13; sub rsp, 0x408; mov rbx, rdi; add rbx, 0x200;
///   mov r15, [rip + memcpy@got]`, then the loop at 0x101f:
///   `movzx eax, byte [rbx-0x1c0]` (the field, read through the pointer stepped past it);
///   `cmp rax, 0xb; je done; lea r13, [rbx-0x1f8]; jmp arm` (the element from +8, kept in `r13`
///   across a block start);
///   arm: `mov rsi, r13; lea rdi, [rsp+0x10]; mov edx, 0x1f8; call r15` (that part copied through a
///   register); `movzx ecx, byte [rsp+0x48]` (the field in the copy); `lea rsi, [rsp+0x10];
///   lea rdi, [rsp+0x208]; mov edx, 0x1f8; call r15` (the copy copied again: a record rebuilt at
///   `rsp+0x200`); `lea rdx, [rsp+0x208]; call peek` (the copy's first byte, +8 of the record);
///   `lea rdi, [rsp+0x200]; call judge; add rbx, 0x200; jmp loop`;
/// - 0x1100 `judge`: `movzx eax, byte [rdi+0x40]; ret`;
/// - 0x1120 `peek`: `movups xmm0, [rdx+0x30]; ret` (16 bytes holding +0x38 of what it is handed);
/// - 0x1200 the `memcpy` import slot.
fn consumer_image() -> Image {
    let consumer: &[u8] = &[
        0x53, 0x41, 0x57, 0x41, 0x54, 0x41, 0x55, 0x48, 0x81, 0xec, 0x08, 0x04, 0x00, 0x00, 0x48, 0x89, 0xfb, 0x48,
        0x81, 0xc3, 0x00, 0x02, 0x00, 0x00, 0x4c, 0x8b, 0x3d, 0xe1, 0x01, 0x00, 0x00, 0x0f, 0xb6, 0x83, 0x40, 0xfe,
        0xff, 0xff, 0x48, 0x83, 0xf8, 0x0b, 0x74, 0x56, 0x4c, 0x8d, 0xab, 0x08, 0xfe, 0xff, 0xff, 0xeb, 0x00, 0x4c,
        0x89, 0xee, 0x48, 0x8d, 0x7c, 0x24, 0x10, 0xba, 0xf8, 0x01, 0x00, 0x00, 0x41, 0xff, 0xd7, 0x0f, 0xb6, 0x4c,
        0x24, 0x48, 0x48, 0x8d, 0x74, 0x24, 0x10, 0x48, 0x8d, 0xbc, 0x24, 0x08, 0x02, 0x00, 0x00, 0xba, 0xf8, 0x01,
        0x00, 0x00, 0x41, 0xff, 0xd7, 0x48, 0x8d, 0x94, 0x24, 0x08, 0x02, 0x00, 0x00, 0xe8, 0xb4, 0x00, 0x00, 0x00,
        0x48, 0x8d, 0xbc, 0x24, 0x00, 0x02, 0x00, 0x00, 0xe8, 0x87, 0x00, 0x00, 0x00, 0x48, 0x81, 0xc3, 0x00, 0x02,
        0x00, 0x00, 0xeb, 0x9d, 0x48, 0x81, 0xc4, 0x08, 0x04, 0x00, 0x00, 0x41, 0x5d, 0x41, 0x5c, 0x41, 0x5f, 0x5b,
        0xc3,
    ];
    let mut data = vec![0; 0x208];
    data[..consumer.len()].copy_from_slice(consumer);
    data[0x100..0x105].copy_from_slice(&[0x0f, 0xb6, 0x47, 0x40, 0xc3]);
    data[0x120..0x125].copy_from_slice(&[0x0f, 0x10, 0x42, 0x30, 0xc3]);
    Image {
        segments: vec![Segment { va: 0x1000, offset: 0, size: data.len() }],
        data,
        functions: vec![0x1000..0x1091, 0x1100..0x1105, 0x1120..0x1125],
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
    let found: Vec<Seen<'_>> = readers.iter().map(|r| (r.ip, r.via.clone(), r.note.as_deref())).collect();
    let copied = "copy-in at 0x1042 to [rsp+0x10], field +0x40";
    let again = format!("{copied}, then copied at 0x105c to [rsp+0x208]");
    let covering = format!("{again}, then a 16-byte load that covers it");
    let expected = vec![
        // One element behind the stepped pointer.
        (0x101f, vec![], None),
        // In the part `r13` points at, copied through `r15`.
        (0x1045, vec![], Some(copied)),
        // In the record rebuilt from the copy, handed to `judge`.
        (0x1100, vec![(0x1100, Slot::Reg(0))], Some(again.as_str())),
        // Handed the copy's first byte, `peek` loads 16 bytes holding the field.
        (0x1120, vec![(0x1120, Slot::Reg(2))], Some(covering.as_str())),
    ];
    let mut sorted = found.clone();
    sorted.sort_by_key(|(ip, ..)| *ip);
    assert_eq!(sorted, expected);
}

/// #182 review cases, 0x200-byte records with a one-byte field at +0x40:
/// - 0x2000 `lea rbx, [rip + table]; L: movzx eax, byte [rbx+0x40]; add rbx, 0x200; cmp rbx, rdi;
///   jne L; ret` — a static array starts at an element, whatever its address;
/// - 0x2100 `imul rax, rsi, 0x200; add rax, [rdi]; movzx r8d, byte [rax+0x40];
///   movzx ecx, byte [rax+rdx*8+0x40]; add rax, rdx; movzx ecx, byte [rax+0x40]; ret` — the read off
///   the element, not the array inside it, nor an element moved by an unscaled offset;
/// - 0x2200 `push rbx; push r15; sub rsp, 0x218; mov rax, [rip + memcpy@got]; mov r15, rax;
///   imul rbx, rsi, 0x200; add rbx, [rdi]; lea rsi, [rbx+8]; lea rdi, [rsp+0x10]; mov edx, 0x1f8;
///   call r15; movzx ecx, byte [rax+0x38]; mov rsi, rbx; lea rdi, [rsp+8]; mov edx, 8;
///   call memcpy; ...` — the routine moved to `r15`, the partial copy read through the `rax` it
///   returns, and a local `memcpy` (its own unwind range) that is no reader;
/// - 0x2300 `memcpy`: `movups xmm0, [rsi+0x38]; ret`.
fn review_182_image() -> Image {
    let mut data = vec![0; 0x708];
    let mut put = |at: usize, bytes: &[u8]| data[at..at + bytes.len()].copy_from_slice(bytes);
    put(
        0x000,
        &[
            0x48, 0x8d, 0x1d, 0xf9, 0x06, 0x00, 0x00, 0x0f, 0xb6, 0x43, 0x40, 0x48, 0x81, 0xc3, 0x00, 0x02, 0x00, 0x00,
            0x48, 0x39, 0xfb, 0x75, 0xf0, 0xc3,
        ],
    );
    put(
        0x100,
        &[
            0x48, 0x69, 0xc6, 0x00, 0x02, 0x00, 0x00, 0x48, 0x03, 0x07, 0x44, 0x0f, 0xb6, 0x40, 0x40, 0x0f, 0xb6, 0x4c,
            0xd0, 0x40, 0x48, 0x01, 0xd0, 0x0f, 0xb6, 0x48, 0x40, 0xc3,
        ],
    );
    put(
        0x200,
        &[
            0x53, 0x41, 0x57, 0x48, 0x81, 0xec, 0x18, 0x02, 0x00, 0x00, 0x48, 0x8b, 0x05, 0xef, 0x01, 0x00, 0x00, 0x49,
            0x89, 0xc7, 0x48, 0x69, 0xde, 0x00, 0x02, 0x00, 0x00, 0x48, 0x03, 0x1f, 0x48, 0x8d, 0x73, 0x08, 0x48, 0x8d,
            0x7c, 0x24, 0x10, 0xba, 0xf8, 0x01, 0x00, 0x00, 0x41, 0xff, 0xd7, 0x0f, 0xb6, 0x48, 0x38, 0x48, 0x89, 0xde,
            0x48, 0x8d, 0x7c, 0x24, 0x08, 0xba, 0x08, 0x00, 0x00, 0x00, 0xe8, 0xbb, 0x00, 0x00, 0x00, 0x48, 0x81, 0xc4,
            0x18, 0x02, 0x00, 0x00, 0x41, 0x5f, 0x5b, 0xc3,
        ],
    );
    put(0x300, &[0x0f, 0x10, 0x46, 0x38, 0xc3]);
    Image {
        segments: vec![Segment { va: 0x2000, offset: 0, size: data.len() }],
        data,
        functions: vec![0x2000..0x2018, 0x2100..0x211c, 0x2200..0x2250, 0x2300..0x2305],
        pointers: Vec::new(),
        imports: vec![(0x2400, "memcpy".to_owned())],
        symbols: vec![(0x2300, "memcpy".to_owned())],
        metadata: crate::image_format::Metadata::default(),
    }
}

#[test]
fn element_phases_need_scaled_offsets_and_copy_routines_are_no_readers() {
    let image = review_182_image();
    let readers = |start: u64| {
        let (f, code) = super::flow::function_code(&image, start).unwrap_or_default();
        let (found, passed) = super::records::in_function(&image, &f, &code, 0x200, 0x40, 1);
        let found: Vec<(u64, Option<String>)> = found.into_iter().map(|r| (r.ip, r.note)).collect();
        (found, passed)
    };
    assert_eq!(readers(0x2000).0, vec![(0x2007, None)], "a static array's loop pointer is at phase 0");
    assert_eq!(readers(0x2100).0, vec![(0x210a, None)], "only the read off the element itself");
    let (found, passed) = readers(0x2200);
    assert_eq!(found, vec![(0x222f, Some("copy-in at 0x222c to [rsp+0x10], field +0x40".to_owned()))]);
    assert!(passed.is_empty(), "a copy routine is not handed the element as a reader: {passed:?}");
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
