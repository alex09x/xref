/*
 * XRef Code — Structured query regressions
 * Copyright (c) 2026 Alexander Panasenko
 * Contact: alex@prod.codes
 * Author: https://prod.codes/about/
 * Project: https://github.com/alex09x/xref
 * SPDX-License-Identifier: MIT OR Apache-2.0
 */

use super::{Analysis, Cancellation, types::*};
use crate::image::{Image, Segment};

pub fn fixture() -> Analysis {
    let mut data = vec![0; 0x300];
    data[..13].copy_from_slice(&[0x48, 0x8d, 0x3d, 0xf9, 0x01, 0x00, 0x00, 0xe8, 0xf4, 0x00, 0x00, 0x00, 0xc3]);
    data[0x100..0x104].copy_from_slice(&[0x48, 0x89, 0xf8, 0xc3]);
    data[0x200..0x20a].copy_from_slice(b"MCP_NEEDLE");
    let identity = ImageIdentity {
        sha256: "fixture".into(),
        bytes: data.len(),
        format: "elf",
        architecture: "x86_64",
        base_address: "0x1000".into(),
        rva_basis: "lowest_load_segment_va",
    };
    let image = Image {
        data,
        segments: vec![Segment { va: 0x1000, offset: 0, size: 0x300 }],
        functions: vec![0x1000..0x100d, 0x1100..0x1104],
        pointers: vec![],
        imports: vec![],
        symbols: vec![],
    };
    Analysis { image, identity, base: 0x1000 }
}

fn query(analysis: &Analysis, json: &str) -> Result<serde_json::Value, Box<dyn std::error::Error>> {
    let request = serde_json::from_str(json)?;
    Ok(analysis.query(&request, &Cancellation::default()).json())
}

#[test]
fn api_string_reference_function_calls_and_slice_chain() -> Result<(), Box<dyn std::error::Error>> {
    let a = fixture();
    let strings = query(&a, r#"{"operation":"strings","text":"MCP_NEEDLE"}"#)?;
    assert_eq!(strings["data"]["locations"][0], "0x1200");
    let refs = query(&a, r#"{"operation":"refs","address":"0x1200"}"#)?;
    assert_eq!(refs["data"]["references"][0]["address"], "0x1000");
    assert_eq!(refs["data"]["references"][0]["function"]["range_origin"], "eh_frame_fde");
    let function = query(&a, r#"{"operation":"function","address":"0x1007"}"#)?;
    assert_eq!(function["data"]["function"]["start"], "0x1000");
    let calls = query(&a, r#"{"operation":"calls","address":"0x1000"}"#)?;
    assert_eq!(calls["data"]["calls"][0]["target"], "0x1100");
    let asm = query(&a, r#"{"operation":"asm","address":"0x1000","page":{"limit":1}}"#)?;
    assert_eq!(asm["data"]["instructions"][0]["bytes"], "488d3df9010000");
    assert_eq!(asm["page"]["next_offset"], 1);
    for operation in ["c", "slice"] {
        let request = if operation == "c" {
            r#"{"operation":"c","address":"0x1000"}"#
        } else {
            r#"{"operation":"slice","address":"0x1000","to":"0x1007"}"#
        };
        let result = query(&a, request)?;
        assert!(result["error"].is_null(), "{result}");
        assert!(result["data"]["text"].as_str().is_some_and(|s| s.contains("fn_1100")), "{result}");
    }
    Ok(())
}

#[test]
fn api_budgets_errors_cancellation_and_utf8() -> Result<(), Box<dyn std::error::Error>> {
    let a = fixture();
    for request in [
        r#"{"operation":"info","unknown":1}"#,
        r#"{"operation":"unknown"}"#,
        r#"{"operation":"function","address":4096}"#,
    ] {
        assert!(serde_json::from_str::<Query>(request).is_err(), "{request}");
    }
    for (request, code) in [
        (r#"{"operation":"function","address":"4096"}"#, "invalid_address"),
        (r#"{"operation":"function","address":"0xdead"}"#, "no_function"),
        (r#"{"operation":"strings","text":""}"#, "invalid_text"),
        (r#"{"operation":"strings","text":"x","page":{"limit":0}}"#, "invalid_page"),
        (r#"{"operation":"strings","text":"x","page":{"offset":1}}"#, "invalid_offset"),
        (r#"{"operation":"refs","address":"0x1200","back":65}"#, "invalid_window"),
    ] {
        assert_eq!(query(&a, request)?["error"]["code"], code);
    }
    let token = Cancellation::default();
    token.cancel();
    assert_eq!(a.query(&Query::Info {}, &token).json()["error"]["code"], "cancelled");
    assert_eq!(super::clipped("αβγ", 3), ("α".into(), true));
    let page = query(&a, r#"{"operation":"c","address":"0x1000","page":{"limit":4}}"#)?;
    assert_eq!(page["data"]["fragment"], true);
    assert_eq!(page["page"]["next_offset"], 4);
    assert_eq!(page["data"]["text"].as_str().map(str::len), Some(4));
    Ok(())
}

#[test]
fn api_string_chunk_boundary_and_ordered_pagination() -> Result<(), Box<dyn std::error::Error>> {
    let mut a = fixture();
    a.image.data.resize(70000, 0);
    a.image.segments[0].size = 70000;
    a.image.data[65535..65541].copy_from_slice(b"needle");
    a.image.data[65550..65556].copy_from_slice(b"needle");
    let first = query(&a, r#"{"operation":"strings","text":"needle","page":{"limit":1}}"#)?;
    assert_eq!(first["data"]["locations"][0], format!("{:#x}", 0x1000 + 65535));
    assert_eq!(first["page"]["next_offset"], 1);
    let second = query(&a, r#"{"operation":"strings","text":"needle","page":{"limit":1,"offset":1}}"#)?;
    assert_eq!(second["data"]["locations"][0], format!("{:#x}", 0x1000 + 65550));
    assert_eq!(second["page"]["complete"], true);
    a.image.data.fill(b'x');
    let capped = query(&a, r#"{"operation":"strings","text":"x","page":{"offset":10000,"limit":100}}"#)?;
    assert_eq!(capped["page"]["complete"], false);
    assert!(capped["page"]["next_offset"].is_null());
    assert!(
        capped["warnings"].as_array().is_some_and(|w| w.contains(&serde_json::json!("pagination_window_exhausted")))
    );
    Ok(())
}

#[test]
fn api_response_budget_and_invalid_unwind_range_are_explicit() -> Result<(), Box<dyn std::error::Error>> {
    let mut a = fixture();
    let mut response = a.query(&Query::Info {}, &Cancellation::default());
    response.data = Some(Data::Text {
        format: "pseudo_c",
        function: a.function_info(&(0x1000..0x100d)),
        text: "x".repeat(70000),
        total_bytes: 70000,
        fragment: false,
    });
    assert_eq!(response.json()["error"]["code"], "response_too_large");
    a.image.functions = std::iter::once(0x2000..0x3000).collect();
    assert_eq!(query(&a, r#"{"operation":"function","address":"0x2000"}"#)?["error"]["code"], "invalid_function_range");
    Ok(())
}
