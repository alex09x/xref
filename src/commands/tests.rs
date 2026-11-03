/*
 * XRef Code — Command dispatch tests
 * Copyright (c) 2026 Alexander Panasenko
 * Contact: alex@prod.codes
 * Author: https://prod.codes/about/
 * Project: https://github.com/alex09x/xref
 * SPDX-License-Identifier: MIT OR Apache-2.0
 */

use super::{closest_arm, run};
use crate::cli::Command;
use crate::image::{Image, Segment};
use crate::tables::Table;

#[test]
fn the_closest_arm_across_tables_wins() {
    let far = Table { dispatch: 0x10, base: 0x900, arms: vec![0x100, 0x200] };
    let near = Table { dispatch: 0x20, base: 0xa00, arms: vec![0x2f0, 0x300] };
    let tables = [far, near];
    assert_eq!(closest_arm(&tables, 0x2f8).map(|(d, t, i, a)| (d, t.base, i, a)), Some((8, 0xa00, vec![0], 0x2f0)));
    let mut data = vec![0u8; 0x200];
    // 0x1000: lea rcx, [rip + 0xf9] (0x1100); movsxd rax, [rcx + rcx*4]; jmp rax
    // 0x100d (arm 0): lea rax, [rip + 0x1c] (0x1030 "hello"); lea rdx, [rip + 0x25] (0x1040 Location); ret
    let code: &[u8] = &[
        0x48, 0x8d, 0x0d, 0xf9, 0x00, 0x00, 0x00, // 0x1000: lea rcx, [0x1100]
        0x48, 0x63, 0x04, 0x89, // 0x1007: movsxd rax, [rcx + rcx*4]
        0xff, 0xe0, // 0x100b: jmp rax
        0x48, 0x8d, 0x05, 0x1c, 0x00, 0x00, 0x00, // 0x100d: lea rax, [0x1030]
        0xc3, // 0x1014: ret
    ];
    data[..code.len()].copy_from_slice(code);
    // 0x1020 (no jump table): lea rdx, [0x1040]; ret
    data[0x20..0x28].copy_from_slice(&[0x48, 0x8d, 0x15, 0x19, 0x00, 0x00, 0x00, 0xc3]);
    data[0x30..0x35].copy_from_slice(b"hello");
    data[0x35..0x3b].copy_from_slice(b"lib.rs");
    // Location at 0x1040: ptr -> 0x1035 ("lib.rs"), len = 6, line = 1, col = 1
    data[0x48..0x50].copy_from_slice(&6u64.to_le_bytes());
    data[0x50..0x54].copy_from_slice(&1u32.to_le_bytes());
    data[0x54..0x58].copy_from_slice(&1u32.to_le_bytes());
    // Jump table at 0x1100: arm 0 -> 0x100d (offset -0xf3)
    data[0x100..0x104].copy_from_slice(&(-0xf3i32).to_le_bytes());
    let image = Image {
        data,
        segments: vec![Segment { va: 0x1000, offset: 0, size: 0x200 }],
        functions: vec![0x1000..0x1015, 0x1020..0x1028],
        pointers: vec![(0x1040, 0x1035), (0x1060, 0x1030)],
        imports: Vec::new(),
        symbols: vec![(0x1000, "main_fn".to_owned())],
        metadata: crate::image_format::Metadata::default(),
    };
    let empty = Image {
        data: Vec::new(),
        segments: Vec::new(),
        functions: Vec::new(),
        pointers: Vec::new(),
        imports: Vec::new(),
        symbols: Vec::new(),
        metadata: crate::image_format::Metadata::default(),
    };
    let mut out = Vec::new();
    assert!(run(&empty, Command::Stats, &mut out).is_ok());
    for cmd in [
        Command::Stats,
        Command::Sym { pattern: "main".to_owned() },
        Command::Func { addrs: vec![0x1000, 0x9999] },
        Command::Refs {
            targets: vec!["0x1030".to_owned(), "hello".to_owned(), "missing".to_owned()],
            back: 1,
            inline: false,
        },
        Command::Refs { targets: vec!["missing".to_owned()], back: 1, inline: true },
        Command::Istr { targets: vec!["missing".to_owned()] },
        Command::Imm { value: 0, store: false, cmp: false, within: Some(0x1000) },
        Command::Imm { value: 0, store: false, cmp: false, within: None },
        Command::Disp {
            values: vec![0],
            write: false,
            lea: false,
            all: false,
            stride: None,
            stack: false,
            within: Some(0x1000),
        },
        Command::Disp {
            values: vec![0],
            write: false,
            lea: false,
            all: true,
            stride: None,
            stack: false,
            within: None,
        },
        Command::Layout { addr: "0x1000".to_owned(), reg: "rdi".to_owned(), callees: false },
        Command::Callers { addr: 0x1030 },
        Command::Calls { addr: 0x1000 },
        Command::Path { from: "0x1000".to_owned(), to: "0x1020".to_owned(), depth: 2 },
        Command::Tree { addr: "0x1000".to_owned(), callers: false, callees: true, depth: 1 },
        Command::Asm { addr: 0x1000, from: Some(0x1000), to: Some(0x1007) },
        Command::C { addrs: vec![0x1000], from: None, to: None, out: None, fields: true, keep_gotos: false },
        Command::Slice { addr: "0x1000".to_owned(), to: "hello".to_owned(), fields: false, keep_gotos: false },
        Command::Error { text: "hello".to_owned(), back: 1 },
        Command::Error { text: "lib.rs".to_owned(), back: 1 },
        Command::Variant { addr: 0x1000, indices: vec![0, 9] },
        Command::Arm { addrs: vec![0x100d, 0x1020] },
        Command::Src { addr: 0x1020 },
        Command::Where { pattern: "lib.rs".to_owned(), line: Some(1) },
        Command::Files { pattern: Some("lib.rs".to_owned()) },
    ] {
        assert!(run(&image, cmd, &mut out).is_ok());
    }
    assert!(
        crate::scan::search_in(&image, std::slice::from_ref(&(0x9000..0x9004)), &crate::scan::Query::Branch(0))
            .is_empty()
    );
    assert!(run(&image, Command::Error { text: "missing".to_owned(), back: 1 }, &mut out).is_err());
    assert!(run(&image, Command::Variant { addr: 0x1020, indices: vec![0] }, &mut out).is_err());
}
