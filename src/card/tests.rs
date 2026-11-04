/*
 * XRef — Tests for function card analysis and rendering
 * Copyright (c) 2026 Alexander Panasenko
 * Contact: alex@prod.codes
 * Author: https://prod.codes/about/
 * Project: https://github.com/alex09x/xref
 * SPDX-License-Identifier: MIT OR Apache-2.0
 */

use std::ops::Range;

use super::analyze_card;
use super::render::render_card;
use crate::image::{Image, Segment};

fn make_img(code: &[u8], f_range: Range<u64>, extra_fn: Option<(&[u8], Range<u64>)>) -> Image {
    let mut data = vec![0x90u8; 0x4000];
    let offset = usize::try_from(f_range.start.saturating_sub(0x1000)).unwrap_or_default();
    let len = code.len();
    if offset + len <= data.len() {
        data[offset..offset + len].copy_from_slice(code);
    }
    let mut functions = vec![f_range];
    if let Some((extra_code, extra_range)) = extra_fn {
        let e_offset = usize::try_from(extra_range.start.saturating_sub(0x1000)).unwrap_or_default();
        let e_len = extra_code.len();
        if e_offset + e_len <= data.len() {
            data[e_offset..e_offset + e_len].copy_from_slice(extra_code);
        }
        functions.push(extra_range);
    }
    Image {
        data,
        segments: vec![Segment { va: 0x1000, offset: 0, size: 0x4000 }],
        functions,
        pointers: Vec::new(),
        imports: Vec::new(),
        symbols: Vec::new(),
        metadata: crate::image_format::Metadata::default(),
    }
}

#[test]
fn card_extracts_field_stores_callee_args_and_exits() {
    let sink_bytes = &[0x48, 0x83, 0x07, 0x01, 0xc3];
    let sink_range = 0x1100..0x1105;

    let entry_bytes = &[
        0x53,                               // 0x1000: push rbx
        0x48, 0x89, 0xfb,                   // 0x1001: mov rbx, rdi
        0x48, 0xc7, 0x47, 0x18, 0x2a, 0x00, 0x00, 0x00, // 0x1004: mov qword ptr [rdi+0x18], 42
        0x48, 0xc7, 0x44, 0x24, 0x08, 0x64, 0x00, 0x00, 0x00, // 0x100c: mov qword ptr [rsp+8], 100
        0xbf, 0x01, 0x00, 0x00, 0x00,       // 0x1015: mov edi, 1
        0xbe, 0x02, 0x00, 0x00, 0x00,       // 0x101a: mov esi, 2
        0xe8, 0xdc, 0x00, 0x00, 0x00,       // 0x101f: call 0x1100 (next ip 0x1024, delta 0xdc)
        0x85, 0xc0,                         // 0x1024: test eax, eax
        0x75, 0x04,                         // 0x1026: jnz 0x102c
        0x31, 0xc0,                         // 0x1028: xor eax, eax
        0x5b,                               // 0x102a: pop rbx
        0xc3,                               // 0x102b: ret
        0xb8, 0xff, 0xff, 0xff, 0xff,       // 0x102c: mov eax, -1
        0x5b,                               // 0x1031: pop rbx
        0xc3,                               // 0x1032: ret
    ];
    let entry_range = 0x1000..0x1033;

    let mut img = make_img(entry_bytes, entry_range.clone(), Some((sink_bytes, sink_range)));
    img.symbols.push((0x1000, "sample_fn".to_owned()));
    img.symbols.push((0x1100, "target_sink".to_owned()));

    let card = analyze_card(&img, &entry_range);

    assert_eq!(card.function.start, 0x1000);
    assert_eq!(card.function.end, 0x1033);
    assert_eq!(card.function.name.as_deref(), Some("sample_fn"));

    assert!(card.inputs.registers.contains(&"rdi".to_owned()));
    assert!(card.return_registers.contains(&"rax".to_owned()));

    // Stores check
    assert!(card.stores.contains_key("arg0"), "expected arg0 stores: {:?}", card.stores);
    let arg0_stores = &card.stores["arg0"];
    assert_eq!(arg0_stores.len(), 1);
    assert_eq!(arg0_stores[0].offset, 0x18);
    assert_eq!(arg0_stores[0].widths, vec![8]);

    assert!(card.stores.contains_key("stack"), "expected stack stores: {:?}", card.stores);
    let stack_stores = &card.stores["stack"];
    assert_eq!(stack_stores.len(), 1);
    assert_eq!(stack_stores[0].offset, 8);
    assert_eq!(stack_stores[0].widths, vec![8]);

    // Callees check
    assert_eq!(card.callees.len(), 1);
    assert_eq!(card.callees[0].ip, 0x101f);
    assert_eq!(card.callees[0].target, 0x1100);
    assert_eq!(card.callees[0].name, "target_sink");
    assert!(
        card.callees[0].args.contains(&"rdi=1".to_owned()) || card.callees[0].args.contains(&"rdi=0x1".to_owned()),
        "expected rdi=1 in callee args: {:?}",
        card.callees[0].args
    );

    // Exits check
    assert_eq!(card.exits.len(), 2);
    let Some(ok_exit) = card.exits.iter().find(|e| e.ip == 0x102b) else {
        panic!("missing ok exit");
    };
    assert_eq!(ok_exit.constant_code, Some(0));
    assert!(!ok_exit.is_error);

    let Some(err_exit) = card.exits.iter().find(|e| e.ip == 0x1032) else {
        panic!("missing err exit");
    };
    assert_eq!(err_exit.constant_code, Some(-1));
    assert!(err_exit.is_error);

    // Rendering test
    let mut text_out = Vec::new();
    let Ok(()) = render_card(&card, false, &mut text_out) else {
        panic!("failed to render text card");
    };
    let Ok(text) = String::from_utf8(text_out) else {
        panic!("invalid utf-8 text");
    };
    assert!(text.contains("sample_fn"));
    assert!(text.contains("arg0:"));
    assert!(text.contains("+0x18: 8"));
    assert!(text.contains("target_sink"));
    assert!(text.contains("ret (rax = 0)"));
    assert!(text.contains("ret (rax = -1) [error]"));

    let mut json_out = Vec::new();
    let Ok(()) = render_card(&card, true, &mut json_out) else {
        panic!("failed to render json card");
    };
    let Ok(json_str) = String::from_utf8(json_out) else {
        panic!("invalid utf-8 json");
    };
    let Ok(parsed) = serde_json::from_str::<serde_json::Value>(&json_str) else {
        panic!("failed to parse json");
    };
    assert_eq!(parsed["function"]["name"], "sample_fn");
    assert_eq!(parsed["stores"]["arg0"][0]["offset"], 24);
}

#[test]
fn card_handles_indirect_calls_panics_and_globals() {
    let code = &[
        0x48, 0xc7, 0x05, 0x00, 0x01, 0x00, 0x00, 0x07, 0x00, 0x00, 0x00, // 0x1000: mov qword ptr [rip+0x100], 7 (next ip 0x100b, addr 0x110b)
        0xff, 0xd0,                         // 0x100b: call rax
        0xe8, 0x10, 0x00, 0x00, 0x00,       // 0x100d: call 0x1022 (abort)
        0x0f, 0x0b,                         // 0x1012: ud2
        0x31, 0xc0,                         // 0x1014: xor eax, eax
        0xc3,                               // 0x1016: ret
    ];
    let range = 0x1000..0x1017;
    let mut img = make_img(code, range.clone(), None);
    img.symbols.push((0x1022, "abort".to_owned()));

    let card = analyze_card(&img, &range);

    assert!(card.stores.contains_key("global"), "expected global stores: {:?}", card.stores);
    assert_eq!(card.indirect_calls.len(), 1);
    assert_eq!(card.indirect_calls[0].ip, 0x100b);

    assert_eq!(card.panic_callees.len(), 1);
    assert_eq!(card.panic_callees[0].ip, 0x100d);
    assert_eq!(card.panic_callees[0].name, "abort");
}
