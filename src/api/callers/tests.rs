/*
 * XRef Code — Structured reverse call regressions
 * Copyright (c) 2026 Alexander Panasenko
 * Contact: alex@prod.codes
 * Author: https://prod.codes/about/
 * Project: https://github.com/alex09x/xref
 * SPDX-License-Identifier: MIT OR Apache-2.0
 */

use super::super::{Analysis, Cancellation, types::*};
use crate::image::{Image, Segment};

fn make_analysis(data: Vec<u8>, functions: Vec<std::ops::Range<u64>>) -> Analysis {
    let len = data.len();
    let identity = ImageIdentity {
        sha256: "synthetic_fixture".into(),
        bytes: len,
        format: "elf",
        architecture: "x86_64",
        base_address: "0x1000".into(),
        rva_basis: "lowest_load_segment_va",
    };
    let image = Image {
        data,
        segments: vec![Segment { va: 0x1000, offset: 0, size: len }],
        functions,
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
fn callers_two_calls_to_same_callee() -> Result<(), Box<dyn std::error::Error>> {
    let mut data = vec![0; 0x200];
    data[..14].copy_from_slice(&[0xe8, 0xfb, 0x00, 0x00, 0x00, 0x90, 0x90, 0x90, 0xe8, 0xf3, 0x00, 0x00, 0x00, 0xc3]);
    data[0x100..0x104].copy_from_slice(&[0x48, 0x89, 0xf8, 0xc3]);

    let a = make_analysis(data, vec![0x1000..0x100e, 0x1100..0x1104]);
    let result = query(&a, r#"{"operation":"callers","address":"0x1100"}"#)?;
    assert!(result["error"].is_null(), "{result}");

    let Some(callers) = result["data"]["callers"].as_array() else {
        panic!("expected callers array: {result}");
    };
    assert_eq!(callers.len(), 2);

    assert_eq!(callers[0]["call"]["address"], "0x1000");
    assert_eq!(callers[0]["call"]["target"], "0x1100");
    assert_eq!(callers[0]["call"]["kind"], "direct_call");
    assert_eq!(callers[0]["caller"]["start"], "0x1000");

    assert_eq!(callers[1]["call"]["address"], "0x1008");
    assert_eq!(callers[1]["call"]["target"], "0x1100");
    assert_eq!(callers[1]["call"]["kind"], "direct_call");
    assert_eq!(callers[1]["caller"]["start"], "0x1000");

    assert_eq!(result["data"]["unresolved_indirect_edges"], 0);
    Ok(())
}

#[test]
fn callers_tail_jump() -> Result<(), Box<dyn std::error::Error>> {
    let mut data = vec![0; 0x200];
    data[..5].copy_from_slice(&[0xe9, 0xfb, 0x00, 0x00, 0x00]);
    data[0x100..0x104].copy_from_slice(&[0x48, 0x89, 0xf8, 0xc3]);

    let a = make_analysis(data, vec![0x1000..0x1005, 0x1100..0x1104]);
    let result = query(&a, r#"{"operation":"callers","address":"0x1100"}"#)?;
    assert!(result["error"].is_null(), "{result}");

    let Some(callers) = result["data"]["callers"].as_array() else {
        panic!("expected callers array: {result}");
    };
    assert_eq!(callers.len(), 1);
    assert_eq!(callers[0]["call"]["address"], "0x1000");
    assert_eq!(callers[0]["call"]["kind"], "tail_jump");
    assert_eq!(callers[0]["call"]["target"], "0x1100");
    assert_eq!(callers[0]["caller"]["start"], "0x1000");
    Ok(())
}

#[test]
fn callers_unresolved_indirect() -> Result<(), Box<dyn std::error::Error>> {
    let mut data = vec![0; 0x200];
    data[..5].copy_from_slice(&[0xff, 0xd0, 0xff, 0xe0, 0xc3]);
    data[0x100..0x104].copy_from_slice(&[0x48, 0x89, 0xf8, 0xc3]);

    let a = make_analysis(data, vec![0x1000..0x1005, 0x1100..0x1104]);
    let result = query(&a, r#"{"operation":"callers","address":"0x1100"}"#)?;
    assert!(result["error"].is_null(), "{result}");

    let Some(callers) = result["data"]["callers"].as_array() else {
        panic!("expected callers array: {result}");
    };
    assert_eq!(callers.len(), 0);
    assert_eq!(result["data"]["unresolved_indirect_edges"], 2);

    let Some(warnings) = result["warnings"].as_array() else {
        panic!("expected warnings array: {result}");
    };
    assert!(warnings.contains(&serde_json::json!("indirect_branches_not_resolved_as_calls")));
    assert!(warnings.contains(&serde_json::json!("not_found_under_model_never_absence")));
    Ok(())
}

#[test]
fn callers_target_validation() -> Result<(), Box<dyn std::error::Error>> {
    let mut data = vec![0; 0x300];
    data[..6].copy_from_slice(&[0xe8, 0xfd, 0x00, 0x00, 0x00, 0xc3]);
    data[0x100..0x104].copy_from_slice(&[0x48, 0x89, 0xf8, 0xc3]);
    data[0x200..0x204].copy_from_slice(&[0x48, 0x89, 0xc0, 0xc3]);

    let a = make_analysis(data, vec![0x1000..0x1006, 0x1100..0x1104, 0x1200..0x1204]);

    let bad_addr = query(&a, r#"{"operation":"callers","address":"4096"}"#)?;
    assert_eq!(bad_addr["error"]["code"], "invalid_address");

    let no_fn = query(&a, r#"{"operation":"callers","address":"0xdead"}"#)?;
    assert_eq!(no_fn["error"]["code"], "no_function");

    let mid_fn = query(&a, r#"{"operation":"callers","address":"0x1102"}"#)?;
    assert_eq!(mid_fn["data"]["function"]["start"], "0x1100");
    let Some(callers) = mid_fn["data"]["callers"].as_array() else {
        panic!("expected callers array: {mid_fn}");
    };
    assert_eq!(callers.len(), 1);
    assert_eq!(callers[0]["call"]["address"], "0x1000");
    assert_eq!(callers[0]["call"]["target"], "0x1102");

    let other_fn = query(&a, r#"{"operation":"callers","address":"0x1200"}"#)?;
    assert_eq!(other_fn["data"]["callers"].as_array().map(Vec::len), Some(0));

    Ok(())
}

#[test]
fn callers_pagination_and_cancellation() -> Result<(), Box<dyn std::error::Error>> {
    let mut data = vec![0; 0x200];
    data[..14].copy_from_slice(&[0xe8, 0xfb, 0x00, 0x00, 0x00, 0x90, 0x90, 0x90, 0xe8, 0xf3, 0x00, 0x00, 0x00, 0xc3]);
    data[0x100..0x104].copy_from_slice(&[0x48, 0x89, 0xf8, 0xc3]);

    let a = make_analysis(data, vec![0x1000..0x100e, 0x1100..0x1104]);

    let p1 = query(&a, r#"{"operation":"callers","address":"0x1100","page":{"limit":1,"offset":0}}"#)?;
    let Some(c1) = p1["data"]["callers"].as_array() else {
        panic!("expected callers array: {p1}");
    };
    assert_eq!(c1.len(), 1);
    assert_eq!(c1[0]["call"]["address"], "0x1000");
    assert_eq!(p1["page"]["returned"], 1);
    assert_eq!(p1["page"]["next_offset"], 1);
    assert_eq!(p1["page"]["complete"], false);

    let p2 = query(&a, r#"{"operation":"callers","address":"0x1100","page":{"limit":1,"offset":1}}"#)?;
    let Some(c2) = p2["data"]["callers"].as_array() else {
        panic!("expected callers array: {p2}");
    };
    assert_eq!(c2.len(), 1);
    assert_eq!(c2[0]["call"]["address"], "0x1008");
    assert_eq!(p2["page"]["returned"], 1);
    assert!(p2["page"]["next_offset"].is_null());
    assert_eq!(p2["page"]["complete"], true);

    let p_err = query(&a, r#"{"operation":"callers","address":"0x1100","page":{"limit":1,"offset":10}}"#)?;
    assert_eq!(p_err["error"]["code"], "invalid_offset");

    let p_bad = query(&a, r#"{"operation":"callers","address":"0x1100","page":{"limit":0}}"#)?;
    assert_eq!(p_bad["error"]["code"], "invalid_page");

    let token = Cancellation::default();
    token.cancel();
    let res = a.callers("0x1100", &Page::default(), &token);
    assert_eq!(res.err().map(|e| e.code), Some("cancelled"));

    Ok(())
}

#[test]
fn callers_scan_budget_warning() -> Result<(), Box<dyn std::error::Error>> {
    let mut data = vec![0; 0x200];
    data[..5].copy_from_slice(&[0xe8, 0xfb, 0x00, 0x00, 0x00]);
    data[0x100..0x104].copy_from_slice(&[0x48, 0x89, 0xf8, 0xc3]);

    let mut a = make_analysis(data, vec![0x1000..0x1005, 0x1100..0x1104]);
    let big_len = 65 * 1024 * 1024;
    a.image.data.resize(0x2000 + big_len, 0x90);
    a.image.segments[0].size = a.image.data.len();
    a.image.functions.insert(0, 0x2000..0x2000 + big_len as u64);

    let res = query(&a, r#"{"operation":"callers","address":"0x1100"}"#)?;
    assert!(res["error"].is_null(), "{res}");
    let Some(warnings) = res["warnings"].as_array() else {
        panic!("expected warnings array: {res}");
    };
    assert!(warnings.contains(&serde_json::json!("scan_budget_exceeded_functions_skipped")));

    Ok(())
}
