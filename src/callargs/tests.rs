/*
 * XRef — Tests for constant call arguments
 * Copyright (c) 2026 Alexander Panasenko
 * Contact: alex@prod.codes
 * Author: https://prod.codes/about/
 * Project: https://github.com/alex09x/xref
 * SPDX-License-Identifier: MIT OR Apache-2.0
 */

use super::forward::arg_stores;
use super::scan::{Slot, calls};
use super::{CallArgsOptions, callargs};
use crate::image::{Image, Segment};

/// - 0x1000 `caller`: `mov r9d, 0x27; xor edi, edi; mov dword [rsp], 7; call 0x1100;
///   mov esi, 5; call 0x1100; ret` (the first call clobbers r9 and the stack slot);
/// - 0x1100 `callee`: `ret`;
/// - 0x1200 `store`: `mov byte [rdi], sil; ret`;
/// - 0x1300 `forward`: `mov esi, r9d; jmp 0x1200`.
fn image() -> Image {
    let mut data = vec![0xcc; 0x310];
    let caller: &[u8] = &[
        0x41, 0xb9, 0x27, 0x00, 0x00, 0x00, 0x31, 0xff, 0xc7, 0x04, 0x24, 0x07, 0x00, 0x00, 0x00, 0xe8, 0xec, 0x00,
        0x00, 0x00, 0xbe, 0x05, 0x00, 0x00, 0x00, 0xe8, 0xe2, 0x00, 0x00, 0x00, 0xc3,
    ];
    data[..caller.len()].copy_from_slice(caller);
    data[0x100] = 0xc3;
    data[0x200..0x204].copy_from_slice(&[0x40, 0x88, 0x37, 0xc3]);
    data[0x300..0x308].copy_from_slice(&[0x44, 0x89, 0xce, 0xe9, 0xf8, 0xfe, 0xff, 0xff]);
    Image {
        segments: vec![Segment { va: 0x1000, offset: 0, size: data.len() }],
        data,
        functions: vec![0x1000..0x101f, 0x1100..0x1101, 0x1200..0x1204, 0x1300..0x1308],
        pointers: Vec::new(),
        imports: Vec::new(),
        symbols: Vec::new(),
        metadata: crate::image_format::Metadata::default(),
    }
}

#[test]
fn slots_parse_and_print_as_abi_names() {
    assert_eq!(Slot::parse("r9"), Ok(Slot::Reg(5)));
    assert_eq!(Slot::parse("stack3"), Ok(Slot::Stack(3)));
    assert!(Slot::parse("stack8").is_err());
    assert!(Slot::parse("rax").is_err());
    assert_eq!(Slot::Reg(0).to_string(), "rdi");
    assert_eq!(Slot::Stack(1).to_string(), "stack1");
}

#[test]
fn constants_reach_the_call_until_a_call_clobbers_them() {
    let found = calls(&image(), &|callee, _| callee == 0x1100);
    let args: Vec<_> = found.iter().map(|call| (call.ip, call.args.clone())).collect();
    assert_eq!(
        args,
        vec![
            (0x100f, vec![(Slot::Reg(0), 0), (Slot::Reg(5), 0x27), (Slot::Stack(0), 7)]),
            (0x1019, vec![(Slot::Reg(1), 5)]),
        ]
    );
}

#[test]
fn callargs_lists_only_the_call_passing_the_value_and_names_the_callee() -> Result<(), Box<dyn std::error::Error>> {
    let mut out = Vec::new();
    let options = CallArgsOptions { value: 0x27, slot: Some(Slot::Reg(5)), callee: None, limit: 10 };
    callargs(&image(), &options, &mut out)?;
    let text = String::from_utf8(out)?;
    assert!(text.contains("callee 0x1100  r9: 1 of 2 call sites pass 0x27; constants there: 0x27 ×1"), "{text}");
    assert!(text.contains("  0x100f  in 0x1000..0x101f  call  rdi=0x0  r9=0x27  stack0=0x7"), "{text}");
    assert!(!text.contains("0x1019"), "{text}");
    Ok(())
}

#[test]
fn an_argument_is_followed_into_its_store_and_one_call_on() {
    let image = image();
    let direct = arg_stores(&image, 0x1200, Slot::Reg(1), 1, 0);
    assert_eq!(direct.len(), 1);
    assert!(direct[0].at_object_offset(0));
    let forwarded = arg_stores(&image, 0x1300, Slot::Reg(5), 1, 1);
    assert_eq!(
        forwarded.iter().map(|s| (s.ip, s.via.iter().map(|h| (h.function, h.slot)).collect::<Vec<_>>())).collect::<Vec<_>>(),
        vec![(0x1200, vec![(0x1200, Slot::Reg(1))])]
    );
    assert!(arg_stores(&image, 0x1300, Slot::Reg(5), 1, 0).is_empty(), "the store is only one call deeper");
}

/// Review cases for #152, at 0x2000 (`R` at 0x2300 is a bare `ret`):
/// - 0x2000 `mov esi, 1; lock xadd [rdi], rsi; call R` — xadd overwrites rsi;
/// - 0x2040 `mov ecx, 5; rep stosb; call R` — rep stosb drives rcx to 0;
/// - 0x2080 `push 7; mov [rsp], rax; call R` — the pushed slot is overwritten;
/// - 0x20c0 `mov dword [rsp+8], 0x27; jmp R` — a tail jump's stack0 is [rsp+8];
/// - 0x2100 `push 7; call R` — stack0 = 7;
/// - 0x2140 `test edi, edi; je L; mov edx, esi; ret; L: mov [rdi], dl; ret` — the copy is on the other path;
/// - 0x2180 `test edi, edi; je L; call R; ret; L: mov [rdi], sil; ret` — a guard's call does not hide the store;
/// - 0x21c0 `movzx eax, sil; mov [rdi], ax; ret` — the copy is narrower than the stored width;
/// - 0x2200 `mov edx, esi; mov [rdi], dh; ret` — dh is not the low byte.
fn review_image() -> Image {
    let mut data = vec![0xcc; 0x301];
    let mut put = |at: usize, bytes: &[u8]| data[at..at + bytes.len()].copy_from_slice(bytes);
    put(0x000, &[0xbe, 1, 0, 0, 0, 0xf0, 0x48, 0x0f, 0xc1, 0x37, 0xe8, 0xf1, 0x02, 0, 0, 0xc3]);
    put(0x040, &[0xb9, 5, 0, 0, 0, 0xf3, 0xaa, 0xe8, 0xb4, 0x02, 0, 0, 0xc3]);
    put(0x080, &[0x6a, 7, 0x48, 0x89, 0x04, 0x24, 0xe8, 0x75, 0x02, 0, 0, 0xc3]);
    put(0x0c0, &[0xc7, 0x44, 0x24, 0x08, 0x27, 0, 0, 0, 0xe9, 0x33, 0x02, 0, 0]);
    put(0x100, &[0x6a, 7, 0xe8, 0xf9, 0x01, 0, 0, 0xc3]);
    put(0x140, &[0x85, 0xff, 0x74, 0x03, 0x89, 0xf2, 0xc3, 0x88, 0x17, 0xc3]);
    put(0x180, &[0x85, 0xff, 0x74, 0x06, 0xe8, 0x77, 0x01, 0, 0, 0xc3, 0x40, 0x88, 0x37, 0xc3]);
    put(0x1c0, &[0x40, 0x0f, 0xb6, 0xc6, 0x66, 0x89, 0x07, 0xc3]);
    put(0x200, &[0x89, 0xf2, 0x88, 0x37, 0xc3]);
    put(0x300, &[0xc3]);
    Image {
        segments: vec![Segment { va: 0x2000, offset: 0, size: data.len() }],
        data,
        functions: vec![
            0x2000..0x2010,
            0x2040..0x204d,
            0x2080..0x208c,
            0x20c0..0x20cd,
            0x2100..0x2108,
            0x2140..0x214a,
            0x2180..0x218e,
            0x21c0..0x21c8,
            0x2200..0x2205,
            0x2300..0x2301,
        ],
        pointers: Vec::new(),
        imports: Vec::new(),
        symbols: Vec::new(),
        metadata: crate::image_format::Metadata::default(),
    }
}

#[test]
fn implicit_writes_overwritten_slots_and_tail_jumps_keep_constants_honest() {
    let found = calls(&review_image(), &|callee, _| callee == 0x2300);
    let args: Vec<_> = found.iter().map(|call| (call.ip, call.args.clone())).collect();
    assert_eq!(
        args,
        vec![
            (0x200a, vec![]),
            (0x2047, vec![]),
            (0x2086, vec![]),
            (0x20c8, vec![(Slot::Stack(0), 0x27)]),
            (0x2102, vec![(Slot::Stack(0), 7)]),
            (0x2184, vec![]),
        ]
    );
}

#[test]
fn argument_stores_follow_paths_and_widths() {
    let image = review_image();
    assert!(arg_stores(&image, 0x2140, Slot::Reg(1), 1, 0).is_empty(), "the copy is on a path that returned");
    let guarded = arg_stores(&image, 0x2180, Slot::Reg(1), 1, 0);
    assert_eq!(guarded.iter().map(|s| s.ip).collect::<Vec<_>>(), vec![0x218a]);
    assert!(arg_stores(&image, 0x21c0, Slot::Reg(1), 2, 0).is_empty(), "movzx from sil keeps one byte");
    assert!(arg_stores(&image, 0x2200, Slot::Reg(1), 1, 0).is_empty(), "dh is bits 8..15");
}

/// The #157 chain, at 0x3000 (`R` at 0x3200 is a bare `ret`):
/// - 0x3000 `P`: `mov r9d, 0x27; call F; ret`;
/// - 0x3040 `F`: `movzx r9d, r9b; call G; ret` — passes the value on unchanged;
/// - 0x3080 `G`: `push rbx; push rbp; sub rsp, 8; mov ebx, r9d; test rdi, rdi; je L;
///   movzx ebp, bl; mov [rsp+4], ebx; call R; mov r9d, ebp; xor edi, edi; call G;
///   mov r9d, ebp; call H; xor ebx, ebx; xor ebp, ebp; mov esi, [rsp+4]; call H2;
///   L: add rsp, 8; pop rbp; pop rbx; ret` — callee-saved copies, a spill, recursion;
/// - 0x3100 `H`: `mov [rdi], r9b; ret`;
/// - 0x3140 `H2`: `mov [rdi+8], sil; ret`.
fn chain_image() -> Image {
    let mut data = vec![0xcc; 0x201];
    let mut put = |at: usize, bytes: &[u8]| data[at..at + bytes.len()].copy_from_slice(bytes);
    put(0x000, &[0x41, 0xb9, 0x27, 0, 0, 0, 0xe8, 0x35, 0, 0, 0, 0xc3]);
    put(0x040, &[0x45, 0x0f, 0xb6, 0xc9, 0xe8, 0x37, 0, 0, 0, 0xc3]);
    put(
        0x080,
        &[
            0x53, 0x55, 0x48, 0x83, 0xec, 0x08, 0x44, 0x89, 0xcb, 0x48, 0x85, 0xff, 0x74, 0x2b, 0x0f, 0xb6, 0xeb, 0x89,
            0x5c, 0x24, 0x04, 0xe8, 0x66, 0x01, 0, 0, 0x41, 0x89, 0xe9, 0x31, 0xff, 0xe8, 0xdc, 0xff, 0xff, 0xff, 0x41,
            0x89, 0xe9, 0xe8, 0x54, 0, 0, 0, 0x31, 0xdb, 0x31, 0xed, 0x8b, 0x74, 0x24, 0x04, 0xe8, 0x87, 0, 0, 0, 0x48,
            0x83, 0xc4, 0x08, 0x5d, 0x5b, 0xc3,
        ],
    );
    put(0x100, &[0x44, 0x88, 0x0f, 0xc3]);
    put(0x140, &[0x40, 0x88, 0x77, 0x08, 0xc3]);
    put(0x200, &[0xc3]);
    Image {
        segments: vec![Segment { va: 0x3000, offset: 0, size: data.len() }],
        data,
        functions: vec![0x3000..0x300c, 0x3040..0x304a, 0x3080..0x30c0, 0x3100..0x3104, 0x3140..0x3145, 0x3200..0x3201],
        pointers: Vec::new(),
        imports: Vec::new(),
        symbols: Vec::new(),
        metadata: crate::image_format::Metadata::default(),
    }
}

#[test]
fn an_argument_is_followed_through_callee_saved_copies_spills_and_recursion() {
    let image = chain_image();
    let stores = |depth| {
        arg_stores(&image, 0x3040, Slot::Reg(5), 1, depth)
            .into_iter()
            .map(|s| (s.ip, s.displacement, s.via.iter().map(|h| (h.function, h.slot)).collect::<Vec<_>>()))
            .collect::<Vec<_>>()
    };
    assert!(stores(1).is_empty(), "G stores nothing itself; the stores are two calls past F");
    let g = (0x3080, Slot::Reg(5));
    assert_eq!(
        stores(2),
        vec![
            // ebx → ebp (`movzx ebp, bl`) survives `call R`, then `mov r9d, ebp; call H`.
            (0x3100, 0, vec![g, (0x3100, Slot::Reg(5))]),
            // The ebx spill at [rsp+4] survives `xor ebx, ebx`, then `mov esi, [rsp+4]; call H2`.
            (0x3140, 8, vec![g, (0x3140, Slot::Reg(1))]),
        ]
    );
    assert_eq!(stores(5), stores(2), "G calling G is walked once");
}

/// At 0x4000 (`R` at 0x4100 is a bare `ret`):
/// - 0x4000 `sub rsp, 0x18; mov [rsp+8], r9b; lea rdi, [rsp]; call R; add rsp, 0x18; ret` — a
///   field of an object built on the stack and passed by pointer;
/// - 0x4040 `sub rsp, 0x18; mov [rsp+8], r9b; call R; movzx eax, byte [rsp+8]; add rsp, 0x18; ret`
///   — a spill, read back after the call.
#[test]
fn a_frame_store_never_read_back_is_a_stack_object_not_a_spill() {
    let mut data = vec![0xcc; 0x101];
    data[..23].copy_from_slice(&[
        0x48, 0x83, 0xec, 0x18, 0x44, 0x88, 0x4c, 0x24, 0x08, 0x48, 0x8d, 0x3c, 0x24, 0xe8, 0xee, 0, 0, 0, 0x48, 0x83,
        0xc4, 0x18, 0xc3,
    ]);
    data[0x40..0x58].copy_from_slice(&[
        0x48, 0x83, 0xec, 0x18, 0x44, 0x88, 0x4c, 0x24, 0x08, 0xe8, 0xb2, 0, 0, 0, 0x0f, 0xb6, 0x44, 0x24, 0x08, 0x48,
        0x83, 0xc4, 0x18, 0xc3,
    ]);
    data[0x100] = 0xc3;
    let image = Image {
        segments: vec![Segment { va: 0x4000, offset: 0, size: data.len() }],
        data,
        functions: vec![0x4000..0x4017, 0x4040..0x4058, 0x4100..0x4101],
        pointers: Vec::new(),
        imports: Vec::new(),
        symbols: Vec::new(),
        metadata: crate::image_format::Metadata::default(),
    };
    let kinds = |callee| {
        arg_stores(&image, callee, Slot::Reg(5), 1, 0).iter().map(|s| (s.ip, s.stack_object())).collect::<Vec<_>>()
    };
    assert_eq!(kinds(0x4000), vec![(0x4004, true)]);
    assert_eq!(kinds(0x4040), vec![(0x4044, false)]);
}

/// #158 review cases at 0x5000 (`R` at 0x5200 is a bare `ret`, `H2` at 0x5240 stores `sil` at +8):
/// - 0x5000 `sub rsp, 0x18; xorps xmm0, xmm0; movups [rsp], xmm0; mov [rsp+8], r9b; lea rdi, [rsp];
///   call R; ...` — a write-only zeroing store is not a read back;
/// - 0x5040 `sub rsp, 0x18; mov [rsp], r9b; call R; ...` — an outgoing stack argument, no address taken;
/// - 0x5080 `push rax; mov [rsp], r9b; lea rdi, [rsp]; call R; pop rax; ret` — `pop` reads it back;
/// - 0x50c0 `sub rsp, 0x18; mov [rsp+8], r9; lea rdi, [rsp]; call R; mov eax, [rsp+12]; ...` — a
///   read of its upper half;
/// - 0x5100 `push r9; pop rax; call R; sub rsp, 8; mov rsi, [rsp]; call H2; ...` — the slot below
///   `rsp` does not survive the call.
fn frame_image() -> Image {
    let mut data = vec![0xcc; 0x245];
    let mut put = |at: usize, bytes: &[u8]| data[at..at + bytes.len()].copy_from_slice(bytes);
    put(
        0x000,
        &[
            0x48, 0x83, 0xec, 0x18, 0x0f, 0x57, 0xc0, 0x0f, 0x11, 0x04, 0x24, 0x44, 0x88, 0x4c, 0x24, 0x08, 0x48, 0x8d,
            0x3c, 0x24, 0xe8, 0xe7, 0x01, 0, 0, 0x48, 0x83, 0xc4, 0x18, 0xc3,
        ],
    );
    put(0x040, &[0x48, 0x83, 0xec, 0x18, 0x44, 0x88, 0x0c, 0x24, 0xe8, 0xb3, 0x01, 0, 0, 0x48, 0x83, 0xc4, 0x18, 0xc3]);
    put(0x080, &[0x50, 0x44, 0x88, 0x0c, 0x24, 0x48, 0x8d, 0x3c, 0x24, 0xe8, 0x72, 0x01, 0, 0, 0x58, 0xc3]);
    put(
        0x0c0,
        &[
            0x48, 0x83, 0xec, 0x18, 0x4c, 0x89, 0x4c, 0x24, 0x08, 0x48, 0x8d, 0x3c, 0x24, 0xe8, 0x2e, 0x01, 0, 0, 0x8b,
            0x44, 0x24, 0x0c, 0x48, 0x83, 0xc4, 0x18, 0xc3,
        ],
    );
    put(
        0x100,
        &[
            0x41, 0x51, 0x58, 0xe8, 0xf8, 0, 0, 0, 0x48, 0x83, 0xec, 0x08, 0x48, 0x8b, 0x34, 0x24, 0xe8, 0x2b, 0x01, 0,
            0, 0x48, 0x83, 0xc4, 0x08, 0xc3,
        ],
    );
    put(0x200, &[0xc3]);
    put(0x240, &[0x40, 0x88, 0x77, 0x08, 0xc3]);
    Image {
        segments: vec![Segment { va: 0x5000, offset: 0, size: data.len() }],
        data,
        functions: vec![
            0x5000..0x501e,
            0x5040..0x5052,
            0x5080..0x5090,
            0x50c0..0x50db,
            0x5100..0x511a,
            0x5200..0x5201,
            0x5240..0x5245,
        ],
        pointers: Vec::new(),
        imports: Vec::new(),
        symbols: Vec::new(),
        metadata: crate::image_format::Metadata::default(),
    }
}

#[test]
fn stack_objects_need_an_address_taken_and_no_read_back() {
    let image = frame_image();
    let kinds = |callee, width| {
        arg_stores(&image, callee, Slot::Reg(5), width, 0).iter().map(|s| (s.ip, s.stack_object())).collect::<Vec<_>>()
    };
    assert_eq!(kinds(0x5000, 1), vec![(0x500b, true)], "movups only writes");
    assert_eq!(kinds(0x5040, 1), vec![(0x5044, false)], "an outgoing stack argument");
    assert_eq!(kinds(0x5080, 1), vec![(0x5081, false)], "pop reads it back");
    assert_eq!(kinds(0x50c0, 8), vec![(0x50c4, false)], "its upper half is read back");
    let below = arg_stores(&image, 0x5100, Slot::Reg(5), 1, 1);
    assert_eq!(below.iter().map(|s| s.ip).collect::<Vec<_>>(), Vec::<u64>::new(), "the call clobbers [rsp-8]");
}
