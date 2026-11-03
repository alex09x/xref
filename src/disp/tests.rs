/*
 * XRef Code — Explicit stack-anchor query tests
 * Copyright (c) 2026 Alexander Panasenko
 * Contact: alex@prod.codes
 * Author: https://prod.codes/about/
 * Project: https://github.com/alex09x/xref
 * SPDX-License-Identifier: MIT OR Apache-2.0
 */

use crate::{
    cli::Cli,
    commands::run,
    image::{Image, Segment},
};
use clap::Parser;

fn image(code: &[u8]) -> Image {
    Image {
        data: code.to_vec(),
        segments: vec![Segment { va: 0x1000, offset: 0, size: code.len() }],
        functions: std::iter::once(0x1000..0x1000 + code.len() as u64).collect(),
        pointers: Vec::new(),
        imports: Vec::new(),
        symbols: Vec::new(),
        metadata: crate::image_format::Metadata::default(),
    }
}

fn query(image: &Image, arguments: &[&str]) -> Result<String, Box<dyn std::error::Error>> {
    let command =
        Cli::try_parse_from(["xref", "-b", "fixture.elf", "disp"].into_iter().chain(arguments.iter().copied()))?
            .command;
    let mut out = Vec::new();
    run(image, command, &mut out)?;
    Ok(String::from_utf8(out)?)
}

#[test]
fn stack_anchor_fields_raw_offsets_and_zero_lea() -> Result<(), Box<dyn std::error::Error>> {
    let data = image(&[
        0x48, 0x8d, 0x7c, 0x24, 0x40, // lea rdi,[rsp+0x40]
        0xe8, 0xf6, 0x00, 0x00, 0x00, // call outside this function
        0x48, 0x8b, 0x44, 0x24, 0x58, // field +0x18
        0x48, 0x8b, 0x4c, 0x24, 0x68, // field +0x28
        0xc3,
    ]);
    assert_eq!(query(&data, &["0x18", "0x28", "--all"])?, "0 functions\n");
    let all = query(&data, &["0x18", "0x28", "--all", "--stack"])?;
    assert!(all.contains("2 hits (0x18: 1, 0x28: 1)") && all.contains("1 functions"), "{all}");
    assert!(all.contains("anchors (entry rsp): 0x40"), "{all}");
    let field = query(&data, &["0x18", "--stack"])?;
    assert!(
        field.contains("[rsp+0x40]+0x18") && field.contains("anchor@0x1000") && field.contains("1 hits"),
        "{field}"
    );
    assert!(query(&data, &["0x58", "--stack"])?.contains("1 hits"));
    let zero = query(&data, &["0", "--lea", "--stack"])?;
    assert!(zero.contains("lea") && zero.contains("+0x0") && zero.contains("1 hits"), "{zero}");
    assert_eq!(query(&data, &["0", "--write", "--stack"])?, "0 hits\n");
    Ok(())
}

#[test]
fn stack_anchor_intersection_never_combines_different_buffers() -> Result<(), Box<dyn std::error::Error>> {
    let data = image(&[
        0x48, 0x8d, 0x7c, 0x24, 0x40, // anchor +0x40
        0x48, 0x8d, 0xb4, 0x24, 0x80, 0x00, 0x00, 0x00, // anchor +0x80
        0x48, 0x8b, 0x44, 0x24, 0x58, // first anchor +0x18
        0x48, 0x8b, 0x8c, 0x24, 0xa8, 0x00, 0x00, 0x00, // second anchor +0x28
        0xc3,
    ]);
    assert!(query(&data, &["0x18", "0x28", "--stack"])?.contains("2 hits"));
    assert_eq!(query(&data, &["0x18", "0x28", "--stack", "--all"])?, "0 functions\n");
    let shared = image(&[
        0x48, 0x8d, 0x7c, 0x24, 0x40, 0x48, 0x8d, 0x74, 0x24, 0x30, 0x48, 0x8b, 0x44, 0x24,
        0x58, // +0x18 and +0x28, with different anchors
        0xc3,
    ]);
    assert!(query(&shared, &["0x18", "0x28", "--stack"])?.contains("1 hits"));
    assert_eq!(query(&shared, &["0x18", "0x28", "--stack", "--all"])?, "0 functions\n");
    Ok(())
}

#[test]
fn stack_anchor_normalizes_pushes_and_ignores_future_anchors() -> Result<(), Box<dyn std::error::Error>> {
    let adjusted = image(&[
        0x48, 0x8d, 0x7c, 0x24, 0x40, 0x50, // push rax: rsp -= 8
        0x48, 0x8b, 0x44, 0x24, 0x60, // same anchor +0x18
        0x48, 0x8b, 0x4c, 0x24, 0x70, // same anchor +0x28
        0x58, 0xc3,
    ]);
    let all = query(&adjusted, &["0x18", "0x28", "--stack", "--all"])?;
    assert!(all.contains("2 hits") && all.contains("1 functions"), "{all}");
    let pop_memory = image(&[
        0x48, 0x8d, 0x7c, 0x24, 0x40, 0x50, // push rax
        0x8f, 0x44, 0x24, 0x58, // pop [rsp+0x58]: destination uses post-increment RSP
        0x48, 0x8b, 0x4c, 0x24, 0x68, 0xc3,
    ]);
    let popped = query(&pop_memory, &["0x18", "0x28", "--stack", "--all"])?;
    assert!(popped.contains("2 hits") && popped.contains("1 functions"), "{popped}");
    let future = image(&[
        0x48, 0x8b, 0x44, 0x24, 0x58, 0x48, 0x8b, 0x4c, 0x24, 0x68, 0x48, 0x8d, 0x7c, 0x24,
        0x40, // address taken after the accesses
        0xc3,
    ]);
    assert_eq!(query(&future, &["0x18", "0x28", "--stack", "--all"])?, "0 functions\n");
    Ok(())
}

#[test]
fn stack_anchor_rejects_truncated_addresses_and_unknown_sp() -> Result<(), Box<dyn std::error::Error>> {
    let narrow_anchor = image(&[
        0x67, 0x48, 0x8d, 0x7c, 0x24, 0x40, // lea rdi,[esp+0x40], truncates the base
        0x48, 0x8b, 0x44, 0x24, 0x58, 0x48, 0x8b, 0x4c, 0x24, 0x68, 0xc3,
    ]);
    assert_eq!(query(&narrow_anchor, &["0x18", "0x28", "--stack", "--all"])?, "0 functions\n");
    let narrow_access = image(&[
        0x48, 0x8d, 0x7c, 0x24, 0x40, 0x67, 0x48, 0x8b, 0x44, 0x24, 0x58, 0x67, 0x48, 0x8b, 0x4c, 0x24, 0x68, 0xc3,
    ]);
    assert_eq!(query(&narrow_access, &["0x18", "0x28", "--stack", "--all"])?, "0 functions\n");
    let unknown_sp = image(&[
        0x48, 0x8d, 0x7c, 0x24, 0x40, 0x5c, // pop rsp: new stack pointer is an unknown loaded value
        0x48, 0x8b, 0x44, 0x24, 0x58, 0x48, 0x8b, 0x4c, 0x24, 0x68, 0xc3,
    ]);
    assert_eq!(query(&unknown_sp, &["0x18", "0x28", "--stack", "--all"])?, "0 functions\n");
    assert!(query(&unknown_sp, &["0x58", "--stack"])?.contains("1 hits"));
    Ok(())
}

#[test]
fn stack_anchor_groups_rsp_and_rbp_accesses_to_the_same_address() -> Result<(), Box<dyn std::error::Error>> {
    let mixed = image(&[
        0x55, 0x48, 0x89, 0xe5, 0x48, 0x81, 0xec, 0x80, 0x00, 0x00, 0x00, // frame rsp = entry-0x88
        0x48, 0x8d, 0x7c, 0x24, 0x40, // anchor = entry-0x48
        0x48, 0x8b, 0x45, 0xd8, // [rbp-0x28] = anchor+0x18
        0x48, 0x8b, 0x4c, 0x24, 0x68, // [rsp+0x68] = anchor+0x28
        0xc9, 0xc3,
    ]);
    let all = query(&mixed, &["0x18", "0x28", "--stack", "--all"])?;
    assert!(all.contains("2 hits") && all.contains("1 functions") && all.contains("entry rsp): -0x48"), "{all}");
    Ok(())
}
