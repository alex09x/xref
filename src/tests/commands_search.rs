/*
 * xref — Ultra blazing fast cross-references of an x86-64 ELF binary
 * Copyright (c) 2026 Alexander Panasenko
 *
 * Contact: alex@prod.codes
 * Author: https://prod.codes/about/
 * Project: https://github.com/alex09x/xref
 * SPDX-License-Identifier: MIT OR Apache-2.0
 */

//! Unit tests covering CLI commands, cross-build matching, ELF image, layout formatting,
//! runtime detection with callers, and jump-table variant resolution.

use std::collections::{BTreeMap, BTreeSet};
use std::path::PathBuf;

use iced_x86::Register;

use crate::cli::Command;
use crate::commands::run;
use crate::image::{Image, Segment};
use crate::layout::{FieldInfo, layout, parse_reg, scan_fn};
use crate::layout_fmt::render_layout;
use crate::matching::best_matches;
use crate::runtime::RuntimeMap;
use crate::variant::{arms, variants};

fn build_test_image() -> Image {
    let mut data = vec![0u8; 0x400];
    let code: &[u8] = &[
        0x48, 0x8d, 0x0d, 0xf9, 0x00, 0x00, 0x00, // 0x1000: lea rcx, [rip + 0xf9] (0x1100)
        0x48, 0x63, 0x04, 0x89, // 0x1007: movsxd rax, [rcx + rcx*4]
        0xff, 0xe0, // 0x100b: jmp rax
        0x48, 0x8d, 0x05, 0x2c, 0x00, 0x00, 0x00, // 0x100d: lea rax, [rip + 0x2c] (0x1040)
        0xc3, // 0x1014: ret
    ];
    data[..code.len()].copy_from_slice(code);
    data[0x40..0x4a].copy_from_slice(b"target_err");
    data[0x100..0x104].copy_from_slice(&(-0xf3i32).to_le_bytes());
    data[0x104..0x108].copy_from_slice(&(-0xeci32).to_le_bytes());
    data[0x108..0x10c].copy_from_slice(&0i32.to_le_bytes());

    Image {
        data,
        segments: vec![Segment { va: 0x1000, offset: 0, size: 0x400 }],
        functions: vec![0x1000..0x1020, 0x1020..0x1030],
        pointers: vec![(0x1060, 0x1040)],
        imports: vec![(0x1070, "test_import".to_owned())],
        symbols: vec![(0x1000, "main_func".to_owned())],
        metadata: crate::image_format::Metadata::default(),
    }
}

fn build_matching_image(shift: u32, line_shift: u32) -> Image {
    let mut data = vec![0xc3u8; 0x500];
    let offset1 = usize::try_from(shift).unwrap_or_default();
    let entry_addr = 0x1000 + u64::from(shift);
    let second_addr = 0x1100 + u64::from(shift);
    let rel_call = 0xfbi32;
    data[offset1] = 0xe8;
    data[offset1 + 1..offset1 + 5].copy_from_slice(&rel_call.to_le_bytes());
    data[offset1 + 5..offset1 + 12].copy_from_slice(&[0x48, 0x8b, 0x85, 0xd0, 0x06, 0x00, 0x00]);
    let caller_loc = 0x300i32 - i32::try_from(shift).unwrap_or_default() - 19;
    data[offset1 + 12..offset1 + 15].copy_from_slice(&[0x48, 0x8d, 0x3d]);
    data[offset1 + 15..offset1 + 19].copy_from_slice(&caller_loc.to_le_bytes());
    data[offset1 + 19] = 0xc3;

    let offset2 = 0x100 + offset1;
    data[offset2..offset2 + 2].copy_from_slice(&[0x48, 0xb9]);
    data[offset2 + 2..offset2 + 10].copy_from_slice(b"token mi");
    let loc_rel = 0x200i32 - i32::try_from(shift).unwrap_or_default() - 17;
    data[offset2 + 10..offset2 + 13].copy_from_slice(&[0x48, 0x8d, 0x3d]);
    data[offset2 + 13..offset2 + 17].copy_from_slice(&loc_rel.to_le_bytes());
    let str_rel = 0x240i32 - i32::try_from(shift).unwrap_or_default() - 24;
    data[offset2 + 17..offset2 + 20].copy_from_slice(&[0x48, 0x8d, 0x35]);
    data[offset2 + 20..offset2 + 24].copy_from_slice(&str_rel.to_le_bytes());
    data[offset2 + 24..offset2 + 31].copy_from_slice(&[0x48, 0x81, 0xfe, 0x99, 0x01, 0x00, 0x00]);
    data[offset2 + 31] = 0xc3;

    data[0x308..0x310].copy_from_slice(&11u64.to_le_bytes());
    data[0x310..0x314].copy_from_slice(&(100 + line_shift).to_le_bytes());
    data[0x314..0x318].copy_from_slice(&1u32.to_le_bytes());
    data[0x320..0x32b].copy_from_slice(b"src/core.rs");
    data[0x340..0x350].copy_from_slice(b"unique error msg");

    Image {
        data,
        segments: vec![Segment { va: 0x1000, offset: 0, size: 0x500 }],
        functions: vec![entry_addr..entry_addr + 20, second_addr..second_addr + 32],
        pointers: vec![(0x1300, 0x1320)],
        imports: Vec::new(),
        symbols: Vec::new(),
        metadata: crate::image_format::Metadata::default(),
    }
}

fn build_layout_image() -> Image {
    let mut data = vec![0x90u8; 0x100];
    let code: &[u8] = &[
        0x48, 0x8d, 0x77, 0x10, // 0x1000: lea rsi, [rdi + 0x10]
        0x48, 0x83, 0xc7, 0x20, // 0x1004: add rdi, 0x20
        0x48, 0x8b, 0x77, 0x08, // 0x1008: mov rsi, [rdi + 0x08]
        0xe8, 0x0f, 0x00, 0x00, 0x00, // 0x100c: call 0x1020
        0xc3, // 0x1011: ret
    ];
    data[..code.len()].copy_from_slice(code);

    Image {
        data,
        segments: vec![Segment { va: 0x1000, offset: 0, size: 0x100 }],
        functions: vec![0x1000..0x1020, 0x1020..0x1030],
        pointers: Vec::new(),
        imports: Vec::new(),
        symbols: Vec::new(),
        metadata: crate::image_format::Metadata::default(),
    }
}

#[test]
fn commands_diffc_dump_stats_func_error_and_variants() {
    let img = build_test_image();
    let mut out = Vec::new();

    assert!(run(&img, Command::Stats, &mut out).is_ok());
    assert!(run(&img, Command::Func { addrs: vec![0x1005] }, &mut out).is_ok());
    assert!(run(&img, Command::Error { text: "target_err".to_owned(), back: 1 }, &mut out).is_ok());
    assert!(
        run(
            &img,
            Command::Variant { addr: 0x1000, indices: vec!["0".to_owned(), "99".to_owned()], table: None },
            &mut out
        )
        .is_ok()
    );
    assert!(run(&img, Command::Arm { addrs: vec![0x100d] }, &mut out).is_ok());

    let temp_dump = std::env::temp_dir().join("xref_cmd_search_dump");
    drop(run(&img, Command::Dump { out: temp_dump.clone(), src: None, fields: false, keep_gotos: false }, &mut out));
    drop(std::fs::remove_dir_all(temp_dump));

    drop(run(
        &img,
        Command::DiffC {
            other: PathBuf::from("nonexistent_test_bin.elf"),
            addrs: vec!["0x1000".to_owned()],
            target: None,
            fields: false,
        },
        &mut out,
    ));

    if let Ok(exe) = std::env::current_exe() {
        drop(run(
            &img,
            Command::DiffC { other: exe, addrs: vec!["0x1000".to_owned()], target: None, fields: false },
            &mut out,
        ));
    }
}

#[test]
fn matching_best_matches_finds_shifted_pair() {
    let img_a = build_matching_image(0, 0);
    let img_b = build_matching_image(0x20, 5);
    let res = best_matches(&img_a, &img_b, &[format!("{:#x}", 0x1100)]).unwrap_or_default();
    assert_eq!(res.len(), 1);
    assert!(res[0].1.is_some());
}

#[test]
fn image_function_or_span_and_load_paths() {
    let img = Image {
        data: vec![0x90; 0x200],
        segments: vec![Segment { va: 0x1000, offset: 0, size: 0x200 }],
        functions: vec![0x1050..0x1070, 0x1070..0x1080],
        pointers: Vec::new(),
        imports: Vec::new(),
        symbols: Vec::new(),
        metadata: crate::image_format::Metadata::default(),
    };

    assert_eq!(img.function_or_span(0x1010, None), Some(0x1010..0x1050));
    assert_eq!(img.function_or_span(0x1010, Some(0x1030)), Some(0x1010..0x1030));
    assert_eq!(img.function_or_span(0x1080, None), Some(0x1080..0x1200));

    if let Ok(exe) = std::env::current_exe() {
        drop(Image::load(&exe));
    }
}

#[test]
fn layout_scan_fn_and_render_layout_formatting() {
    let img = build_layout_image();
    let mut fields = BTreeMap::new();
    let mut forwarded = Vec::new();
    scan_fn(&img, &(0x1000..0x1020), Register::RDI, 0, Some((0x3000, "via_callee")), &mut fields, &mut forwarded);

    let f_info = FieldInfo {
        width: 8,
        ty: "",
        reads: 1,
        writes: 1,
        leas: 1,
        stride: Some(8),
        ptr_callees: BTreeSet::from([(0x1020, "rdi")]),
        val_callees: BTreeSet::from([(0x1020, "rsi")]),
        via_callees: BTreeSet::from([(0x1020, "rdx")]),
    };
    let fields_map = BTreeMap::from([(0x10, f_info)]);

    let mut hops = BTreeSet::new();
    hops.insert((0i64, 0x1020u64, "rdi"));
    hops.insert((8i64, 0x1020u64, "rsi"));

    let mut out = Vec::new();
    assert!(render_layout(&img, &(0x1000..0x1020), Register::RDI, "rdi", &fields_map, &hops, &mut out).is_ok());

    assert!(parse_reg("rdi").is_ok());
    assert!(parse_reg("invalid_reg_name").is_err());
    drop(layout(&img, "0x1000", "rdi", true, &mut out));
    drop(layout(&img, "0x1000", "rdi", false, &mut out));
}

#[test]
fn variant_arms_and_variants_resolution() {
    let img = build_test_image();
    let mut out = Vec::new();

    assert!(arms(&img, &[0x100d], &mut out).is_ok());
    assert!(variants(&img, 0x1000, &[0, 99], None, &mut out).is_ok());
}

#[test]
fn runtime_detect_with_callers_exercises_stats() {
    let img = build_test_image();
    let rt = RuntimeMap::detect_with_callers(&img);
    let _stats = rt.caller_stats(&img, 0x1000);
    let _label = rt.label(&img, 0x1000);
}
