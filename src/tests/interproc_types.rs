/*
 * xref — Ultra blazing fast cross-references of an x86-64 ELF binary
 * Copyright (c) 2026 Alexander Panasenko
 *
 * Contact: alex@prod.codes
 * Author: https://prod.codes/about/
 * Project: https://github.com/alex09x/xref
 * SPDX-License-Identifier: MIT OR Apache-2.0
 */

//! Unit tests for interprocedural & type recovery (`callee_meta`, `caller_ret`, `calls`, `sig`).

use iced_x86::{Decoder, DecoderOptions, Instruction, Register};

use crate::callee_meta::{
    describe_callee, import_sig, is_fn_noreturn, is_target_noreturn, sanitize_panic_path,
};
use crate::caller_ret::CallerIndex;
use crate::calls::call_expr;
use crate::expr::State;
use crate::image::{Image, Segment};
use crate::locations::Location;
use crate::runtime::{RuntimeFn, RuntimeMap};
use crate::sig::{call_reads_reg, fn_sig};

fn dec_ins(bytes: &[u8], ip: u64) -> Instruction {
    Decoder::with_ip(64, bytes, ip, DecoderOptions::NONE).decode()
}

fn minimal_elf_dynsym() -> Vec<u8> {
    let mut elf = vec![0u8; 0x100];
    elf[0..4].copy_from_slice(b"\x7fELF");
    elf[4] = 2;
    elf[5] = 1;
    elf[6] = 1;
    elf[16..18].copy_from_slice(&2u16.to_le_bytes());
    elf[18..20].copy_from_slice(&0x3eu16.to_le_bytes());
    elf[20..24].copy_from_slice(&1u32.to_le_bytes());
    elf[24..32].copy_from_slice(&0x1000u64.to_le_bytes());
    elf[40..48].copy_from_slice(&64u64.to_le_bytes());
    elf[52..54].copy_from_slice(&64u16.to_le_bytes());
    elf[58..60].copy_from_slice(&64u16.to_le_bytes());
    elf[60..62].copy_from_slice(&2u16.to_le_bytes());
    elf[132..136].copy_from_slice(&11u32.to_le_bytes());
    elf[136..144].copy_from_slice(&2u64.to_le_bytes());
    elf[152..160].copy_from_slice(&192u64.to_le_bytes());
    elf[160..168].copy_from_slice(&48u64.to_le_bytes());
    elf[172..176].copy_from_slice(&1u32.to_le_bytes());
    elf[176..184].copy_from_slice(&8u64.to_le_bytes());
    elf[184..192].copy_from_slice(&24u64.to_le_bytes());
    elf[220] = 0x12;
    elf[222..224].copy_from_slice(&1u16.to_le_bytes());
    elf[224..232].copy_from_slice(&0x1020u64.to_le_bytes());
    elf
}

#[test]
fn callee_meta_sanitization_and_signatures() {
    assert_eq!(
        sanitize_panic_path("/.cargo/registry/src/crates.io-1234/bitflags-1.3.2/src/lib.rs"),
        "bitflags-1.3.2/src/lib.rs"
    );
    assert_eq!(sanitize_panic_path("/.cargo/registry/src/crates.io-1234"), "crates.io-1234");
    assert_eq!(sanitize_panic_path("/home/user/single_file.rs"), "single_file.rs");

    assert!(import_sig("strcmp").is_some_and(|s| s.ret == "i32" && s.params.len() == 2));
    assert!(import_sig("strncmp").is_some_and(|s| s.params.len() == 3));
    assert!(import_sig("memcpy").is_some_and(|s| s.ret == "void *" && s.params.len() == 3));
    assert!(import_sig("memmove").is_some_and(|s| s.ret == "void *" && s.params.len() == 3));
    assert!(import_sig("memset").is_some_and(|s| s.params.len() == 3));
    assert!(import_sig("memchr").is_some_and(|s| s.ret == "const void *"));
    assert!(import_sig("read").is_some_and(|s| s.ret == "isize" && s.params.len() == 3));
    assert!(import_sig("write").is_some_and(|s| s.ret == "isize" && s.params.len() == 3));
    assert!(import_sig("mprotect").is_some_and(|s| s.params.len() == 3));
}

#[test]
fn callee_meta_runtime_and_locations() {
    let mut data = vec![0u8; 0x1800];
    data[0x800..0x821].copy_from_slice(b"\x20index out of bounds: the len is ");
    data[0x840..0x864].copy_from_slice(b"panic in a destructor during cleanup");
    data[0x880..0x8aa].copy_from_slice(b"Once instance has previously been poisoned");
    data[0x8c0..0x8d1].copy_from_slice(b"capacity overflow");
    data[0x8e0..0x8f5].copy_from_slice(b"slice index starts at");

    data[0x000..0x00e].copy_from_slice(&[
        0x48, 0x8d, 0x3d, 0xf9, 0x07, 0x00, 0x00, 0xe8, 0x34, 0x00, 0x00, 0x00, 0x0f, 0x0b,
    ]);
    data[0x040] = 0xc3;
    data[0x050..0x05a].copy_from_slice(&[0x4c, 0x89, 0xc2, 0xe8, 0xe8, 0xff, 0xff, 0xff, 0x0f, 0x0b]);
    data[0x060..0x06e].copy_from_slice(&[
        0x48, 0x8d, 0x3d, 0xd9, 0x07, 0x00, 0x00, 0xe8, 0x14, 0x00, 0x00, 0x00, 0x0f, 0x0b,
    ]);
    data[0x080] = 0xc3;
    data[0x090..0x098].copy_from_slice(&[0x48, 0x8d, 0x3d, 0xe9, 0x07, 0x00, 0x00, 0xc3]);
    data[0x0a0..0x0a8].copy_from_slice(&[0x48, 0x8d, 0x3d, 0x19, 0x08, 0x00, 0x00, 0xc3]);
    data[0x0b0..0x0b8].copy_from_slice(&[0x48, 0x8d, 0x3d, 0x29, 0x08, 0x00, 0x00, 0xc3]);
    let dealloc = [
        0x48, 0x81, 0xfe, 0x00, 0x10, 0x00, 0x00, 0x64, 0x48, 0x8b, 0x04, 0x25, 0x00, 0x00, 0x00, 0x00,
        0x48, 0x89, 0x38, 0xe9, 0xeb, 0x03, 0x00, 0x00,
    ];
    data[0x100..0x100 + dealloc.len()].copy_from_slice(&dealloc);
    let alloc = [
        0x48, 0x81, 0xff, 0x00, 0x10, 0x00, 0x00, 0x64, 0x48, 0x8b, 0x0c, 0x25, 0x00, 0x00, 0x00, 0x00,
        0x48, 0x8b, 0x01, 0xe9, 0x8b, 0x03, 0x00, 0x00,
    ];
    data[0x160..0x160 + alloc.len()].copy_from_slice(&alloc);
    let fmt_w = [0xf6, 0xc1, 0x01, 0x0f, 0xb6, 0x02, 0x48, 0x8b, 0x4e, 0x18, 0xc3];
    data[0x200..0x200 + fmt_w.len()].copy_from_slice(&fmt_w);
    data[0x400..0x406].copy_from_slice(&[0xff, 0x25, 0xfa, 0x04, 0x00, 0x00]);
    data[0x410..0x416].copy_from_slice(&[0xff, 0x25, 0xfa, 0x04, 0x00, 0x00]);
    data[0x500..0x502].copy_from_slice(&[0x0f, 0x0b]);
    data[0x520..0x528].copy_from_slice(&[0x48, 0x8d, 0x3d, 0x10, 0x00, 0x00, 0x00, 0xc3]);
    data[0x540..0x546].copy_from_slice(&[0xe8, 0xdb, 0xff, 0xff, 0xff, 0xc3]);

    let image = Image {
        data,
        segments: vec![Segment { va: 0x1000, offset: 0, size: 0x1800 }],
        functions: vec![
            0x1000..0x100e,
            0x1040..0x1041,
            0x1050..0x105a,
            0x1060..0x106e,
            0x1080..0x1081,
            0x1090..0x1098,
            0x10a0..0x10a8,
            0x10b0..0x10b8,
            0x1100..0x1150,
            0x1160..0x11b0,
            0x1200..0x1300,
            0x1500..0x1502,
            0x1520..0x1528,
            0x1540..0x1546,
        ],
        pointers: Vec::new(),
        imports: vec![(0x1900, "abort".to_owned()), (0x1910, "strcmp".to_owned())],
        symbols: Vec::new(),
    };
    let rt = RuntimeMap::detect(&image);
    assert_eq!(rt.get(0x1000), Some(RuntimeFn::PanicBoundsCheck));

    assert!(describe_callee(&image, &[], &rt, 0x1050)
        .unwrap_or_default()
        .contains("rust_unwrap_failed(msg_ptr, msg_len, val_ptr, vtable, loc) -> noreturn"));
    assert!(describe_callee(&image, &[], &rt, 0x10b0)
        .unwrap_or_default()
        .contains("rust_slice_index_fail(start, end, loc) -> noreturn"));
    assert!(describe_callee(&image, &[], &rt, 0x1060).unwrap_or_default().contains("() -> noreturn"));
    assert!(describe_callee(&image, &[], &rt, 0x1080).unwrap_or_default().contains("() -> noreturn"));
    assert!(describe_callee(&image, &[], &rt, 0x10a0).unwrap_or_default().contains("() -> noreturn"));
    assert!(describe_callee(&image, &[], &rt, 0x1090)
        .unwrap_or_default()
        .contains("rust_once_call(once_state, closure_ptr) -> void"));
    assert!(describe_callee(&image, &[], &rt, 0x1200)
        .unwrap_or_default()
        .contains("rust_fmt_write(out_ptr, vtable, pieces, count) -> u8"));
    assert!(describe_callee(&image, &[], &rt, 0x1160)
        .unwrap_or_default()
        .contains("rust_alloc(size, align) -> void *"));
    assert!(describe_callee(&image, &[], &rt, 0x1100)
        .unwrap_or_default()
        .contains("rust_dealloc(ptr, size, align) -> void"));

    assert!(is_fn_noreturn(&image, &(0x1400..0x1406)));
    assert!(is_target_noreturn(&image, &rt, 0x1000));
    assert!(is_target_noreturn(&image, &rt, 0x1400));

    assert!(describe_callee(&image, &[], &rt, 0x1400)
        .unwrap_or_default()
        .contains("[PLT] noreturn void abort() [noreturn]"));
    assert!(describe_callee(&image, &[], &rt, 0x1410)
        .unwrap_or_default()
        .contains("[PLT] i32 strcmp(const char * s1, const char * s2)"));

    let locs = [Location { place: 0x1537, file: "/Users/dev/proj/src/core.rs".to_owned(), line: 42, col: 1 }];
    assert_eq!(describe_callee(&image, &locs, &rt, 0x1500).unwrap_or_default(), "fn_1500: noreturn");
    assert_eq!(describe_callee(&image, &locs, &rt, 0x1520).unwrap_or_default(), "fn_1520: source src/core.rs:42");
    let desc_sub = describe_callee(&image, &locs, &rt, 0x1540).unwrap_or_default();
    assert!(desc_sub.contains("source src/core.rs:42") && desc_sub.contains("calls fn_1520"));
}

#[test]
fn caller_ret_uncovered_paths() {
    let elf = minimal_elf_dynsym();
    let mut data = vec![0u8; 0x1000];
    data[..elf.len()].copy_from_slice(&elf);

    // 0x1020: target function: mov eax, 1; ret
    data[0x20..0x26].copy_from_slice(&[0xb8, 0x01, 0x00, 0x00, 0x00, 0xc3]);

    // 0x1040: lea rax, [rip-0x27] (0x1020); jmp 0x1020 (tail call)
    data[0x40..0x47].copy_from_slice(&[0x48, 0x8d, 0x05, 0xd9, 0xff, 0xff, 0xff]);
    data[0x47..0x4c].copy_from_slice(&[0xe9, 0xd4, 0xff, 0xff, 0xff]);
    data[0x4c] = 0xc3;

    // 0x1060: call 0x1020; jmp 0x9000; ret
    data[0x60..0x65].copy_from_slice(&[0xe8, 0xbb, 0xff, 0xff, 0xff]);
    data[0x65..0x6a].copy_from_slice(&[0xe9, 0x96, 0x7f, 0x00, 0x00]);
    data[0x6a] = 0xc3;

    // 0x1080: call 0x1020; jz +2; jmp +0; xor eax, eax; ret
    data[0x80..0x85].copy_from_slice(&[0xe8, 0x9b, 0xff, 0xff, 0xff]);
    data[0x85..0x87].copy_from_slice(&[0x74, 0x02]);
    data[0x87..0x89].copy_from_slice(&[0xeb, 0x00]);
    data[0x89..0x8c].copy_from_slice(&[0x31, 0xc0, 0xc3]);

    // 0x10a0: call 0x1020; jz +2; jmp rbx; jmp 0x1000
    data[0xa0..0xa5].copy_from_slice(&[0xe8, 0x7b, 0xff, 0xff, 0xff]);
    data[0xa5..0xa7].copy_from_slice(&[0x74, 0x02]);
    data[0xa7..0xa9].copy_from_slice(&[0xff, 0xe3]);
    data[0xa9..0xae].copy_from_slice(&[0xe9, 0x52, 0xff, 0xff, 0xff]);

    // 0x10c0: call 0x1020; jmp 0x10d5
    data[0xc0..0xc5].copy_from_slice(&[0xe8, 0x5b, 0xff, 0xff, 0xff]);
    data[0xc5..0xca].copy_from_slice(&[0xe9, 0x0b, 0x00, 0x00, 0x00]);

    // 0x1100: call 0x1020; 33 nops; ret
    data[0x100..0x105].copy_from_slice(&[0xe8, 0x1b, 0xff, 0xff, 0xff]);
    data[0x105..0x126].fill(0x90);
    data[0x126] = 0xc3;

    // 0x1140: call 0x1020; nop; nop
    data[0x140..0x145].copy_from_slice(&[0xe8, 0xdb, 0xfe, 0xff, 0xff]);
    data[0x145..0x147].fill(0x90);

    let image = Image {
        data,
        segments: vec![
            Segment { va: 0x1000, offset: 0, size: 0xcc },
            Segment { va: 0x1100, offset: 0x100, size: 0x50 },
        ],
        functions: vec![
            0x1020..0x1026,
            0x1040..0x104d,
            0x1060..0x106b,
            0x1080..0x108c,
            0x10a0..0x10ae,
            0x10c0..0x10e0,
            0x1100..0x1127,
            0x1140..0x1147,
        ],
        pointers: vec![(0x2000, 0x1020)],
        imports: Vec::new(),
        symbols: Vec::new(),
    };

    let idx = CallerIndex::build(&image);
    let st = idx.get(0x1020);
    assert!(st.addr_taken && st.rax_may_escape);

    let demand = CallerIndex::for_target(&image, 0x1020);
    assert!(demand.addr_taken && demand.rax_may_escape);
}

#[test]
fn calls_and_sig_uncovered_paths() {
    let mut data = vec![0u8; 0x1000];
    data[0x00..0x03].copy_from_slice(&[0x89, 0xf8, 0xc3]);
    data[0x10..0x14].copy_from_slice(&[0x89, 0xff, 0xff, 0xe0]);
    data[0x20..0x26].copy_from_slice(&[0xe8, 0xfb, 0xff, 0xff, 0xff, 0xc3]);
    data[0x40..0x4a].copy_from_slice(&[0x55, 0x48, 0x89, 0xe5, 0x48, 0x89, 0x7d, 0x10, 0x5d, 0xc3]);
    data[0x60..0x66].copy_from_slice(&[0xba, 0x01, 0x00, 0x00, 0x00, 0xc3]);
    data[0x400..0x406].copy_from_slice(&[0xff, 0x25, 0xfa, 0x04, 0x00, 0x00]);

    let image = Image {
        data,
        segments: vec![Segment { va: 0x1000, offset: 0, size: 0x1000 }],
        functions: vec![
            0x1000..0x1003,
            0x1010..0x1014,
            0x1020..0x1026,
            0x1040..0x104a,
            0x1060..0x1066,
        ],
        pointers: Vec::new(),
        imports: vec![(0x1900, "memcpy".to_owned())],
        symbols: Vec::new(),
    };
    let rt = RuntimeMap::detect(&image);

    let ins_memcpy = dec_ins(&[0xe8, 0xfb, 0x03, 0x00, 0x00], 0x1000);
    let mut st1 = State::default();
    st1.regs.insert(Register::RDI, "d".to_owned());
    st1.regs.insert(Register::RSI, "s".to_owned());
    st1.regs.insert(Register::RDX, "n".to_owned());
    let (_, call_m) = call_expr(&image, &[], &rt, &mut st1, &ins_memcpy, None);
    assert_eq!(call_m, "memcpy(d, s, n)");

    let ins_exact = dec_ins(&[0xe8, 0xeb, 0xff, 0xff, 0xff], 0x1010);
    let mut st2 = State::default();
    st2.regs.insert(Register::RDI, "x".to_owned());
    let (_, call_e) = call_expr(&image, &[], &rt, &mut st2, &ins_exact, None);
    assert_eq!(call_e, "fn_1000(x)");

    let ins_inexact = dec_ins(&[0xe8, 0x0b, 0x00, 0x00, 0x00], 0x1000);
    let mut st3 = State::default();
    st3.regs.insert(Register::RSI, "y".to_owned());
    let (_, call_inexact) = call_expr(&image, &[], &rt, &mut st3, &ins_inexact, None);
    assert_eq!(call_inexact, "fn_1010(rdi, y)");

    let ins_indirect = dec_ins(&[0xff, 0xd0], 0x1000);
    let mut st4 = State::default();
    st4.regs.insert(Register::RDX, "z".to_owned());
    let (_, call_ind) = call_expr(&image, &[], &rt, &mut st4, &ins_indirect, None);
    assert_eq!(call_ind, "rax(z)");

    let sig_rec = fn_sig(&image, &(0x1020..0x1026));
    assert!(sig_rec.exact);

    let sig_stk = fn_sig(&image, &(0x1040..0x104a));
    assert!(sig_stk.uses_fp && !sig_stk.stack_args.contains(&0));

    assert!(!call_reads_reg(&image, &(0x1060..0x1066), 0x1060, Register::RDX));
}
