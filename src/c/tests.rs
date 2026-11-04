/*
 * XRef Code — Pseudo-C rendering tests
 * Copyright (c) 2026 Alexander Panasenko
 * Contact: alex@prod.codes
 * Author: https://prod.codes/about/
 * Project: https://github.com/alex09x/xref
 * SPDX-License-Identifier: MIT OR Apache-2.0
 */

use super::c_one;
use crate::image::{Image, Segment};
use crate::runtime::RuntimeMap;
use clap::Parser;

#[test]
fn output_modes_cli_flags_are_opt_in() {
    use crate::cli::Cli;
    for command in [
        vec!["xref", "-b", "fixture.elf", "c", "0x1000", "--goto"],
        vec!["xref", "-b", "fixture.elf", "decomp", "0x1000", "--goto", "--fields"],
        vec!["xref", "-b", "fixture.elf", "slice", "0x1000", "--to", "0x1010", "--goto"],
        vec!["xref", "-b", "fixture.elf", "dump", "--out", "out", "--goto"],
        vec!["xref", "-b", "fixture.elf", "disp", "0x20", "--stack", "--all", "--write"],
    ] {
        assert!(Cli::try_parse_from(&command).is_ok(), "{command:?}");
    }
    assert!(Cli::try_parse_from(["xref", "-b", "fixture.elf", "stats", "--goto"]).is_err());
    assert!(Cli::try_parse_from(["xref", "-b", "fixture.elf", "disp", "0x20", "--goto"]).is_err());
    assert!(Cli::try_parse_from(["xref", "-b", "fixture.elf", "find", "--disp", "0x20", "--stack"]).is_err());
}

fn output_modes_image() -> Image {
    // An inner-loop error skips the store and advances the outer loop.
    let code = vec![
        0x31, 0xc0, 0x31, 0xc9, 0xff, 0xc1, 0x39, 0xd1, 0x7d, 0x09, 0x85, 0xf6, 0x75, 0x07, 0x83, 0xf9, 0x0a, 0x7c,
        0xf1, 0x89, 0x0f, 0xff, 0xc0, 0x39, 0xd0, 0x7c, 0xe7, 0xc3,
    ];
    let end = 0x1000 + code.len() as u64;
    Image {
        segments: vec![Segment { va: 0x1000, offset: 0, size: code.len() }],
        data: code,
        functions: std::iter::once(0x1000..end).collect(),
        pointers: Vec::new(),
        imports: Vec::new(),
        symbols: vec![(0x1000, "output_modes_fixture".to_owned())],
        metadata: crate::image_format::Metadata::default(),
    }
}

fn assert_resolved_gotos(text: &str) {
    for tail in text.split("goto L_").skip(1) {
        let address: String = tail.chars().take_while(char::is_ascii_hexdigit).collect();
        assert!(text.contains(&format!("L_{address}:")), "unresolved L_{address}:\n{text}");
    }
    assert_eq!(text.matches('{').count(), text.matches('}').count(), "{text}");
}

#[test]
fn output_modes_c_slice_and_dump_keep_residual_gotos() -> Result<(), Box<dyn std::error::Error>> {
    use crate::{
        c::{COptions, c_one_options},
        cli::Cli,
        commands::run,
    };
    let image = output_modes_image();
    let rt = RuntimeMap::default();
    let normal = c_one(&image, &[], &rt, 0x1000, None, None)?.1;
    let raw = c_one_options(&image, &[], &rt, 0x1000, COptions { keep_gotos: true, ..Default::default() })?.1;
    assert!(normal.contains("skip_"), "{normal}");
    assert!(raw.contains("goto L_") && !raw.contains("skip_"), "{raw}");
    assert!(raw.contains("while (") || raw.contains("do {"), "{raw}");
    assert_resolved_gotos(&raw);
    for flags in [vec![], vec!["--fields"]] {
        for args in [
            vec!["xref", "-b", "fixture.elf", "c", "0x1000", "--goto"],
            vec!["xref", "-b", "fixture.elf", "slice", "0x1000", "--to", "0x1013", "--goto"],
        ] {
            let command = Cli::try_parse_from(args.into_iter().chain(flags.iter().copied()))?.command;
            let mut out = Vec::new();
            run(&image, command, &mut out)?;
            let text = String::from_utf8(out)?;
            assert!(!text.contains("skip_"), "{text}");
            assert_resolved_gotos(&text);
            if text.starts_with("/* slice") {
                assert!(text.contains("goto L_1015;"), "slice lost the store-bypassing exit:\n{text}");
            }
        }
    }
    let nonce = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH)?.as_nanos();
    let dir = std::env::temp_dir().join(format!("xref-output-modes-{}-{nonce}", std::process::id()));
    for args in [
        vec!["xref", "-b", "fixture.elf", "c", "0x1000", "--goto", "--out"],
        vec!["xref", "-b", "fixture.elf", "dump", "--goto", "--out"],
    ] {
        let command =
            Cli::try_parse_from(args.into_iter().chain([dir.to_str().ok_or("temporary path is not UTF-8")?]))?.command;
        run(&image, command, &mut Vec::new())?;
    }
    assert_eq!(std::fs::read_to_string(dir.join("0x1000.c"))?, raw);
    assert_eq!(std::fs::read_to_string(dir.join("unmapped/bucket_0000.c"))?, format!("{raw}\n"));
    std::fs::remove_dir_all(dir)?;
    Ok(())
}

#[test]
fn output_modes_stack_disp_cli_filters_and_literal_offsets() -> Result<(), Box<dyn std::error::Error>> {
    use crate::{cli::Cli, commands::run};
    let code = vec![
        0x55, 0x48, 0x89, 0xe5, // frame pointer
        0x89, 0x44, 0x24, 0x20, // store [rsp+0x20]
        0x83, 0x7c, 0x24, 0x20, 0x01, // cmp [rsp+0x20],1 (read)
        0x48, 0x8d, 0x7c, 0x24, 0x28, // lea rdi,[rsp+0x28]
        0x8b, 0x45, 0xe0, // read [rbp-0x20]
        0xc3,
    ];
    let image = Image {
        segments: vec![Segment { va: 0x1000, offset: 0, size: code.len() }],
        functions: std::iter::once(0x1000..0x1000 + code.len() as u64).collect(),
        data: code,
        pointers: Vec::new(),
        imports: Vec::new(),
        symbols: Vec::new(),
        metadata: crate::image_format::Metadata::default(),
    };
    let render = |image: &Image, arguments: &[&str]| -> Result<String, Box<dyn std::error::Error>> {
        let command =
            Cli::try_parse_from(["xref", "-b", "fixture.elf", "disp"].into_iter().chain(arguments.iter().copied()))?
                .command;
        let mut out = Vec::new();
        run(image, command, &mut out)?;
        Ok(String::from_utf8(out)?)
    };
    assert_eq!(render(&image, &["0x20"])?, "0 hits\n");
    let writes = render(&image, &["0x20", "--stack", "--write", "--in", "0x1000"])?;
    assert!(writes.contains("1 hits") && writes.contains("; stack") && !writes.contains("cmp"), "{writes}");
    let all = render(&image, &["0x20", "0x28", "--stack", "--all"])?;
    assert!(all.contains("3 hits") && all.contains("3 stack hits") && all.contains("1 functions"), "{all}");
    let lea = render(&image, &["0x28", "--stack", "--lea"])?;
    assert!(lea.contains("lea") && lea.contains("; stack") && lea.contains("1 hits"), "{lea}");
    let negative = render(&image, &["0xffffffffffffffe0", "--stack"])?;
    assert!(negative.contains("rbp-0x20") && negative.contains("1 hits"), "{negative}");
    let code = vec![0x48, 0x8d, 0x7c, 0x24, 0x30, 0x8b, 0x44, 0x24, 0x50, 0xc3];
    let image = Image {
        segments: vec![Segment { va: 0x1000, offset: 0, size: code.len() }],
        functions: std::iter::once(0x1000..0x1000 + code.len() as u64).collect(),
        data: code,
        pointers: Vec::new(),
        imports: Vec::new(),
        symbols: Vec::new(),
        metadata: crate::image_format::Metadata::default(),
    };
    assert_eq!(render(&image, &["0x20"])?, "0 hits\n");
    let field = render(&image, &["0x20", "--stack"])?;
    assert!(field.contains("1 hits") && field.contains("anchor@"), "{field}");
    assert!(render(&image, &["0x50", "--stack"])?.contains("1 hits"));
    Ok(())
}

#[test]
fn decompiles_branches_calls_tables_ops_runtime_and_tuples() {
    let mut data = vec![0u8; 0x500];
    data[0x200..0x206].copy_from_slice(&[0xff, 0x25, 0x00, 0x01, 0x00, 0x00]);
    data[0x220..0x224].copy_from_slice(&[0x48, 0x89, 0xf8, 0xc3]);
    data[0x300..0x304].copy_from_slice(&(-0x1f3i32).to_le_bytes());
    data[0x320..0x329].copy_from_slice(b"hello txt");
    data[0x340..0x361].copy_from_slice(b"\x20index out of bounds: the len is ");
    let code: &[u8] = &[
        0x55, 0x48, 0x89, 0xe5, 0x48, 0x83, 0xec, 0x10, 0x49, 0x89, 0xfe, 0x48, 0x89, 0x74, 0x24, 0x08, 0x48, 0x8d,
        0x44, 0x24, 0x08, 0x48, 0x89, 0x07, 0x48, 0x83, 0xff, 0x09, 0x0f, 0x94, 0xc0, 0x48, 0x0f, 0x45, 0xc6, 0x48,
        0x85, 0xc0, 0x48, 0xf7, 0xc6, 0x01, 0x00, 0x00, 0x00, 0x31, 0xc9, 0x48, 0x6b, 0xd7, 0x05, 0x48, 0x83, 0xc2,
        0x01, 0x48, 0xff, 0xc2, 0x0f, 0x31, 0x6a, 0x07, 0xe8, 0xbd, 0x01, 0x00, 0x00, 0x58, 0xe8, 0xd7, 0x01, 0x00,
        0x00, 0xff, 0xd6, 0x66, 0x0f, 0x2e, 0xc0, 0x70, 0x05, 0x75, 0x05, 0xeb, 0x00, 0xc3, 0x0f, 0x0b, 0x78, 0x05,
        0xe9, 0xc1, 0x01, 0x00, 0x00, 0xff, 0xe6, 0x0f, 0x0b,
    ];
    data[..code.len()].copy_from_slice(code);
    let jt_fn: &[u8] = &[
        0x48, 0x8d, 0x0d, 0xf9, 0x01, 0x00, 0x00, 0x48, 0x63, 0x04, 0x89, 0xff, 0xe0, 0x48, 0x8b, 0x06, 0xb9, 0x01,
        0x00, 0x00, 0x00, 0x48, 0x8d, 0x35, 0x04, 0x02, 0x00, 0x00, 0xba, 0x05, 0x00, 0x00, 0x00, 0x49, 0x83, 0xc6,
        0xff, 0xff, 0x15, 0xdf, 0x01, 0x00, 0x00, 0xff, 0x15, 0xe1, 0x01, 0x00, 0x00, 0x0f, 0x57, 0xc0, 0xf3, 0x48,
        0x0f, 0xbc, 0xc7, 0xc3,
    ];
    data[0x100..0x100 + jt_fn.len()].copy_from_slice(jt_fn);
    let (end1, end2) = (0x1000 + code.len() as u64, 0x1100 + jt_fn.len() as u64);
    let image = Image {
        data,
        segments: vec![Segment { va: 0x1000, offset: 0, size: 0x500 }],
        functions: vec![0x1000..end1, 0x1100..end2, 0x1200..0x1206, 0x1220..0x1224],
        pointers: vec![(0x1312, 0x1220)],
        imports: vec![(0x1306, "puts".to_owned()), (0x130a, "puts".to_owned())],
        symbols: Vec::new(),
        metadata: crate::image_format::Metadata::default(),
    };
    let rt = RuntimeMap::default();
    let (_, text) = c_one(&image, &[], &rt, 0x1000, None, None).unwrap_or_default();
    assert!(text.contains("fn_1000(") && text.contains("&slot_8") && text.contains(", 7)"), "{text}");
    assert!(text.contains("fn_1220(") && text.contains("isnan(zmm0)") && text.contains("return rsi("), "{text}");
    let ucomisd_clears_overflow = !text.contains("overflow(");
    assert!(ucomisd_clears_overflow, "{text}");
    assert!(text.contains("rdtsc"), "{text}");
    let (_, t2) = c_one(&image, &[], &rt, 0x1100, None, None).unwrap_or_default();
    assert!(t2.contains("switch (") && t2.contains("case 0 (0x0):") && t2.contains("puts(\"hello\", 5, 1)"));
    assert!(t2.contains("zmm0 = 0;") && t2.contains("return __builtin_ctzll(rdi);"), "{t2}");
    assert!(c_one(&image, &[], &rt, 0x9999, None, None).is_err());
    let (_, sliced) = c_one(&image, &[], &rt, 0x1000, Some(0x1004), Some(0x1010)).unwrap_or_default();
    assert!(sliced.contains("slice from 0x1004") && sliced.contains("truncated at 0x1010"), "{sliced}");
}

#[test]
fn only_paths_to_addr_fixture_omits_unrelated_branch_and_keeps_target() -> Result<(), Box<dyn std::error::Error>> {
    use crate::c::{COptions, c_one_options};
    use crate::cli::{Cli, Command};

    // Instruction sequence:
    // 0x1000: cmp edi, 0 (83 ff 00)
    // 0x1003: jne 0x101a (75 15)
    // Unrelated branch:
    // 0x1005: mov eax, 0x11111111 (b8 11 11 11 11)
    // 0x100a: add eax, 0x22222222 (05 22 22 22 22)
    // 0x100f: mov ecx, 0x33333333 (b9 33 33 33 33)
    // 0x1014: add eax, ecx (01 c8)
    // 0x1016: mov [rsi], eax (89 06)
    // 0x1018: ret (c3)
    // 0x1019: nop (90)
    // Target branch:
    // 0x101a: mov eax, 0x42 (b8 42 00 00 00)
    // 0x101f: mov [rdx], eax (89 02) <- target at 0x101f
    // 0x1021: ret (c3)
    let code: Vec<u8> = vec![
        0x83, 0xff, 0x00, 0x75, 0x15, 0xb8, 0x11, 0x11, 0x11, 0x11, 0x05, 0x22, 0x22, 0x22, 0x22, 0xb9, 0x33, 0x33,
        0x33, 0x33, 0x01, 0xc8, 0x89, 0x06, 0xc3, 0x90, 0xb8, 0x42, 0x00, 0x00, 0x00, 0x89, 0x02, 0xc3,
    ];
    let len = u64::try_from(code.len())?;
    let end = 0x1000 + len;
    let image = Image {
        segments: vec![Segment { va: 0x1000, offset: 0, size: code.len() }],
        data: code,
        functions: std::iter::once(0x1000..end).collect(),
        pointers: Vec::new(),
        imports: Vec::new(),
        symbols: vec![(0x1000, "only_paths_test_fn".to_owned())],
        metadata: crate::image_format::Metadata::default(),
    };
    let rt = RuntimeMap::default();

    // 1. Without flag: normal output contains both branches
    let (_, normal) = c_one_options(&image, &[], &rt, 0x1000, COptions::default())?;
    assert!(normal.contains("0x66666666") && normal.contains("arg_1"), "{normal}");
    assert!(normal.contains("66") && normal.contains("arg_2"), "{normal}");

    // 2. With --only-paths-to 0x101f: omits unrelated branch, keeps target statement, marks elided
    let (_, pruned) =
        c_one_options(&image, &[], &rt, 0x1000, COptions { only_paths_to: Some(0x101f), ..Default::default() })?;
    assert!(!pruned.contains("0x66666666") && !pruned.contains("*(u32 *)(arg_1)"), "{pruned}");
    assert!(pruned.contains("*(u32 *)(arg_2) = v_2;"), "{pruned}");
    assert!(pruned.contains("/* ... */"), "{pruned}");

    // 3. With --only-paths-to and --goto: residual gotos are consistent
    let (_, goto_pruned) = c_one_options(
        &image,
        &[],
        &rt,
        0x1000,
        COptions { keep_gotos: true, only_paths_to: Some(0x101f), ..Default::default() },
    )?;
    assert_resolved_gotos(&goto_pruned);
    assert!(goto_pruned.contains("0x42") || goto_pruned.contains("66"), "{goto_pruned}");
    assert!(goto_pruned.contains("/* ... */"), "{goto_pruned}");

    // 4. Outside function address errors clearly
    let Err(err_outside) =
        c_one_options(&image, &[], &rt, 0x1000, COptions { only_paths_to: Some(0x2000), ..Default::default() })
    else {
        panic!("expected err for outside addr");
    };
    assert!(err_outside.contains("outside function"), "{err_outside}");

    // 5. Non-instruction boundary errors clearly
    let Err(err_boundary) =
        c_one_options(&image, &[], &rt, 0x1000, COptions { only_paths_to: Some(0x1001), ..Default::default() })
    else {
        panic!("expected err for non-boundary addr");
    };
    assert!(err_boundary.contains("outside function instructions"), "{err_boundary}");

    // 6. CLI flag parses properly
    let parsed = Cli::try_parse_from(["xref", "-b", "fixture.elf", "c", "0x1000", "--only-paths-to", "0x101f"])?;
    match parsed.command {
        Command::C { only_paths_to, .. } => assert_eq!(only_paths_to, Some(0x101f)),
        _ => panic!("expected Command::C"),
    }
    Ok(())
}

#[test]
fn only_paths_unreachable_instruction_errors_clearly() -> Result<(), Box<dyn std::error::Error>> {
    use crate::c::{COptions, c_one_options};

    // 0x1000: mov eax, 1 (b8 01 00 00 00)
    // 0x1005: ret (c3)
    // Dead block:
    // 0x1006: mov edx, 42 (ba 2a 00 00 00)
    // 0x100b: ret (c3)
    let code: Vec<u8> = vec![0xb8, 0x01, 0x00, 0x00, 0x00, 0xc3, 0xba, 0x2a, 0x00, 0x00, 0x00, 0xc3];
    let len = u64::try_from(code.len())?;
    let end = 0x1000 + len;
    let image = Image {
        segments: vec![Segment { va: 0x1000, offset: 0, size: code.len() }],
        data: code,
        functions: std::iter::once(0x1000..end).collect(),
        pointers: Vec::new(),
        imports: Vec::new(),
        symbols: vec![(0x1000, "unreachable_test_fn".to_owned())],
        metadata: crate::image_format::Metadata::default(),
    };
    let rt = RuntimeMap::default();

    let Err(err) =
        c_one_options(&image, &[], &rt, 0x1000, COptions { only_paths_to: Some(0x1006), ..Default::default() })
    else {
        panic!("expected err for unreachable addr");
    };
    assert!(err.contains("unreachable in function"), "{err}");
    Ok(())
}
