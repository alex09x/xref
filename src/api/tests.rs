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
        metadata: crate::image_format::Metadata::default(),
    };
    Analysis { image, identity, base: 0x1000, field_digest: std::sync::Mutex::new(None) }
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

#[test]
fn field_api_rejects_conflicting_and_dependent_options() -> Result<(), Box<dyn std::error::Error>> {
    let a = fixture();
    for request in [
        r#"{"operation":"field","request":{"keys":["c","m"],"layout_only":true,"write":true}}"#,
        r#"{"operation":"field","request":{"keys":["c","m"],"layout_only":true,"writes_all_of":["m"]}}"#,
        r#"{"operation":"field","request":{"keys":["c","m"],"layout_only":true,"writer_root":"returned"}}"#,
        r#"{"operation":"field","request":{"keys":["c","m"],"writer_root":"returned"}}"#,
        r#"{"operation":"field","request":{"keys":["c","m"],"write":true,"writer_root":"elsewhere"}}"#,
        r#"{"operation":"field","request":{"keys":[]}}"#,
    ] {
        assert_eq!(query(&a, request)?["error"]["code"], "invalid_request", "{request}");
    }
    let ok = query(&a, r#"{"operation":"field","request":{"keys":["c","m"],"write":true,"writer_root":"returned"}}"#)?;
    assert!(ok["error"].is_null(), "{ok}");
    assert_eq!(ok["data"]["kind"], "field_search");
    Ok(())
}

/// The image digest never makes another thread wait for hashing: while one thread hashes a large
/// image (e.g. the MCP warm-up), the digest cell stays free and holds no value until it is done.
#[test]
fn field_digest_lock_is_not_held_while_hashing() {
    use std::sync::Arc;
    let mut a = fixture();
    a.image.data = vec![0x5a; 256 << 20];
    let a = Arc::new(a);
    let hasher = {
        let a = Arc::clone(&a);
        std::thread::spawn(move || a.image_digest())
    };
    let mut free_while_hashing = false;
    while !hasher.is_finished() {
        if let Ok(cell) = a.field_digest.try_lock()
            && cell.is_none()
        {
            free_while_hashing = true;
        }
        std::thread::yield_now();
    }
    let digest = hasher.join().unwrap_or_default();
    assert!(free_while_hashing, "the digest lock must be free while another thread hashes");
    assert_eq!(digest, <[u8; 32]>::from(<sha2::Sha256 as sha2::Digest>::digest(&a.image.data)));
    assert_eq!(a.image_digest(), digest);
}

#[test]
fn api_triage_confidence_evidence_id_and_extended_operations() -> Result<(), Box<dyn std::error::Error>> {
    let mut a = fixture();
    // Add a synthetic Rust `core::panic::Location` at 0x1240 -> string "src/demo.rs" at 0x1260,
    // plus an IP-relative reference from function 0x1100.
    a.image.data[0x260..0x26b].copy_from_slice(b"src/demo.rs");
    a.image.data[0x240..0x248].copy_from_slice(&0x1260u64.to_le_bytes());
    a.image.data[0x248..0x250].copy_from_slice(&11u64.to_le_bytes());
    a.image.data[0x250..0x254].copy_from_slice(&42u32.to_le_bytes());
    a.image.data[0x254..0x258].copy_from_slice(&7u32.to_le_bytes());
    a.image.pointers.push((0x1240, 0x1260));
    a.image.pointers.sort_unstable();
    // Rewrite 0x1100..0x110c: `mov rax, [rdi+0x18]; lea rsi, [rip+0x135] (-> 0x1240); ret`
    a.image.data[0x100..0x10c].copy_from_slice(&[
        0x48, 0x8b, 0x47, 0x18, // mov rax, [rdi+0x18]
        0x48, 0x8d, 0x35, 0x35, 0x01, 0x00, 0x00, // lea rsi, [rip+0x135] -> 0x1240
        0xc3, // ret
    ]);
    a.image.functions[1] = 0x1100..0x110c;
    a.image.metadata.build_id = Some(vec![0xca, 0xfe, 0xba, 0xbe]);

    let info1 = query(&a, r#"{"operation":"info"}"#)?;
    let info2 = query(&a, r#"{"operation":"info"}"#)?;
    assert_eq!(info1["confidence"], "observed");
    assert_eq!(info1["untrusted_binary_content"], true);
    let ev = info1["evidence_id"].as_str().ok_or("missing evidence_id")?;
    assert!(ev.starts_with("ev_") && ev.len() == 19, "{ev}");
    assert_eq!(info1["evidence_id"], info2["evidence_id"]);
    assert_eq!(info1["data"]["triage"]["language"], "rust");
    assert_eq!(info1["data"]["triage"]["stripped"], true);
    assert_eq!(info1["data"]["triage"]["panic_locations"], 1);
    assert_eq!(info1["data"]["triage"]["source_files"], 1);
    assert_eq!(info1["data"]["triage"]["build_id"], "cafebabe");
    assert!(!info1["data"]["triage"]["recommended_queries"].as_array().is_none_or(Vec::is_empty));

    let card = query(&a, r#"{"operation":"card","address":"0x1000"}"#)?;
    assert_eq!(card["confidence"], "inferred");
    assert_eq!(card["data"]["function"]["start"], "0x1000");
    assert_eq!(card["data"]["card"]["function"]["start"], "0x1000");
    assert_eq!(card["data"]["card"]["callees"][0]["ip"], "0x1007");
    assert_eq!(card["data"]["card"]["callees"][0]["target"], "0x1100");
    assert_eq!(card["data"]["card"]["totals"]["callees"], 1);
    assert_eq!(card["data"]["card"]["truncated"], false);

    // `imm` / `disp` as numbers or as decimal / hex strings, as `xref find --disp 0x18` takes them.
    for disp in ["24", r#""24""#, r#""0x18""#] {
        let found = query(&a, &format!(r#"{{"operation":"find","disp":[{disp}]}}"#))?;
        assert_eq!(found["data"]["matches"][0]["function"]["start"], "0x1100", "disp {disp}: {found}");
    }
    let high = query(&a, r#"{"operation":"find","imm":["0xcbf29ce484222325"]}"#)?;
    assert_eq!(high["data"]["total_matches"], 0, "{high}");
    assert_eq!(query(&a, r#"{"operation":"find","imm":["0xzz"]}"#)?["error"]["code"], "invalid_number");

    let found = query(&a, r#"{"operation":"find","refs":["MCP_NEEDLE"],"calls":["0x1100"]}"#)?;
    assert_eq!(found["confidence"], "derived");
    assert_eq!(found["data"]["total_matches"], 1);
    assert_eq!(found["data"]["matches"][0]["function"]["start"], "0x1000");
    assert_eq!(found["data"]["matches"][0]["satisfied"], 2);

    let layout = query(&a, r#"{"operation":"layout","address":"0x1100","reg":"rdi"}"#)?;
    assert_eq!(layout["confidence"], "inferred");
    assert_eq!(layout["data"]["fields"][0]["offset"], "+0x18");
    assert_eq!(layout["data"]["fields"][0]["reads"], 1);

    let files = query(&a, r#"{"operation":"files","pattern":"demo"}"#)?;
    assert_eq!(files["confidence"], "observed");
    assert_eq!(files["data"]["total_files"], 1);
    assert_eq!(files["data"]["files"][0]["file"], "src/demo.rs");

    let wh = query(&a, r#"{"operation":"where","pattern":"demo.rs","line":42}"#)?;
    assert_eq!(wh["confidence"], "derived");
    assert_eq!(wh["data"]["matched_locations"], 1);
    assert_eq!(wh["data"]["functions"][0]["function"]["start"], "0x1100");

    let deps = query(&a, r#"{"operation":"dependencies"}"#)?;
    assert_eq!(deps["confidence"], "observed");
    assert_eq!(deps["data"]["total_packages"], 0);
    Ok(())
}

/// `origin`, `callargs` and `data` answer with the CLI's report, paged like pseudo-C.
#[test]
fn api_whole_binary_reports_page_the_cli_text() -> Result<(), Box<dyn std::error::Error>> {
    let mut a = fixture();
    a.image.metadata.load_segments = vec![crate::image_format::LoadSegment {
        va: 0x1000,
        file_offset: 0,
        file_size: 0x300,
        mem_size: 0x300,
        executable: true,
        writable: false,
    }];
    let data = query(&a, r#"{"operation":"data","request":{"address":"0x1200","as":"str"}}"#)?;
    assert_eq!(data["confidence"], "observed", "{data}");
    assert_eq!(data["data"]["command"], "data");
    assert!(data["data"]["text"].as_str().is_some_and(|t| t.contains("MCP_NEEDLE")), "{data}");
    let paged =
        query(&a, r#"{"operation":"data","request":{"address":"0x1200","as":"bytes","count":32},"page":{"limit":8}}"#)?;
    assert_eq!(paged["data"]["fragment"], true, "{paged}");
    assert_eq!(paged["page"]["next_offset"], 8);
    let callargs = query(&a, r#"{"operation":"callargs","request":{"value":"0x27","arg":"r9"}}"#)?;
    assert_eq!(callargs["confidence"], "derived", "{callargs}");
    assert_eq!(callargs["data"]["command"], "callargs");
    for (request, code) in [
        (r#"{"operation":"data","request":{"address":"0x1200","as":"f128"}}"#, "invalid_type"),
        (r#"{"operation":"callargs","request":{"value":"0xzz"}}"#, "invalid_number"),
        (r#"{"operation":"callargs","request":{"value":1,"arg":"rax"}}"#, "invalid_argument"),
        (r#"{"operation":"origin","request":{"target":""}}"#, "invalid_text"),
        (r#"{"operation":"origin","request":{"target":"no such message anywhere"}}"#, "report_failed"),
    ] {
        assert_eq!(query(&a, request)?["error"]["code"], code, "{request}");
    }
    Ok(())
}

/// #170 review: `find` texts are bounded and counted before the image is scanned for them, and a
/// `refs` string with too many occurrences is refused instead of widened into windows.
#[test]
fn api_find_bounds_predicates_before_scanning() -> Result<(), Box<dyn std::error::Error>> {
    let mut a = fixture();
    let many: Vec<String> = (0..33).map(|i| format!("\"needle{i}\"")).collect();
    let request = format!(r#"{{"operation":"find","refs":[{}]}}"#, many.join(","));
    let refused = query(&a, &request)?;
    assert_eq!(refused["error"]["code"], "invalid_request");
    assert!(refused["error"]["message"].as_str().is_some_and(|m| m.contains("at most 32")), "{refused}");
    for request in [
        r#"{"operation":"find","refs":[""]}"#,
        r#"{"operation":"find","src":[""]}"#,
        r#"{"operation":"find","calls":[""]}"#,
    ] {
        assert_eq!(query(&a, request)?["error"]["code"], "invalid_text", "{request}");
    }
    let long = format!(r#"{{"operation":"find","refs":["{}"]}}"#, "a".repeat(513));
    assert_eq!(query(&a, &long)?["error"]["code"], "invalid_text");

    // A byte found more often than the cap.
    let bytes = crate::find::structured::MAX_REF_HITS + 1;
    a.image.data.resize(0x300 + bytes, b'Q');
    a.image.segments[0].size = a.image.data.len();
    let flooded = query(&a, r#"{"operation":"find","refs":["Q"]}"#)?;
    assert_eq!(flooded["error"]["code"], "invalid_request", "{flooded}");
    assert!(flooded["error"]["message"].as_str().is_some_and(|m| m.contains("more than 4096")), "{flooded}");
    Ok(())
}
