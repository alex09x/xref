/*
 * XRef Code — evidence-producing binary analysis
 * Copyright (c) 2026 Alexander Panasenko
 * Contact: alex@prod.codes
 * Author: https://prod.codes/about/
 * Project: https://github.com/alex09x/xref
 * SPDX-License-Identifier: MIT OR Apache-2.0
 */
use super::*;
use crate::api::{
    field_types::{FieldLimits, FieldRequest},
    tests::fixture,
    types::Query,
};
use serde_json::Value;
type Error = Box<dyn std::error::Error>;

fn sample() -> Analysis {
    let mut a = fixture();
    let root = [
        0x49, 0x89, 0xfc, 0x48, 0x8b, 0x47, 0x18, 0x48, 0x8d, 0x77, 0x18, 0x48, 0x89, 0xc2, 0xe8, 0xed, 0, 0, 0, 0x4c,
        0x89, 0xe7, 0x48, 0x8b, 0x47, 0x20, 0x48, 0x8d, 0x77, 0x10, 0xe8, 0x1d, 1, 0, 0, 0xc3,
    ];
    let first =
        [0x48, 0x83, 0x7f, 0x18, 0, 0x48, 0x83, 0x06, 1, 0x48, 0x89, 0x57, 0x20, 0x66, 0x0f, 0x10, 0x47, 0x28, 0xc3];
    let second = [0x48, 0x8b, 0x46, 8, 0xc3];
    a.image.data[..root.len()].copy_from_slice(&root);
    a.image.data[0x100..0x100 + first.len()].copy_from_slice(&first);
    a.image.data[0x140..0x145].copy_from_slice(&second);
    a.image.functions = vec![0x1000..0x1024, 0x1100..0x1113, 0x1140..0x1145];
    a
}
fn request() -> FieldRequest {
    FieldRequest {
        address: "0x1000".into(),
        register: "rdi".into(),
        offsets: vec![],
        callees: true,
        selection: None,
        limits: FieldLimits::default(),
    }
}
fn run(a: &Analysis, r: FieldRequest) -> Result<Value, Error> {
    let response = a.query(&Query::FieldOrigin { request: r }, &Cancellation::default());
    if let Some(error) = response.error {
        return Err(error.into());
    }
    Ok(serde_json::to_value(response.data)?["report"].clone())
}
fn rows<'a>(v: &'a Value, key: &str) -> Result<&'a Vec<Value>, Error> {
    v[key].as_array().ok_or_else(|| format!("missing {key}").into())
}

#[test]
fn field_origin_api_address_loaded_value_and_callee_provenance() -> Result<(), Error> {
    let a = sample();
    let result = run(&a, request())?;
    let calls = rows(&result, "calls")?;
    let first = calls.iter().find(|c| c["selection"]["call_site"] == "0x100e").ok_or("missing first call")?;
    let args = rows(first, "arguments")?;
    assert!(
        args.iter()
            .any(|arg| arg["register"] == "rdi" && arg["relation"] == "base_address" && arg["displacement"] == "0x0")
    );
    assert!(
        args.iter()
            .any(|arg| arg["register"] == "rsi" && arg["relation"] == "field_address" && arg["displacement"] == "0x18")
    );
    let loaded = args.iter().find(|arg| arg["register"] == "rdx").ok_or("missing loaded argument")?;
    assert_eq!(loaded["relation"], "loaded_value");
    assert_eq!(loaded["load_address"], "0x1003");
    assert_eq!(loaded["load_width_bytes"], 8);
    assert!(
        rows(loaded, "definitions")?
            .iter()
            .any(|i| i["address"] == "0x1003" && !i["bytes"].as_str().unwrap_or("").is_empty())
    );
    assert!(rows(&result, "callee_scopes")?.iter().all(|h| h["argument_register"] != "rdx"));
    let accesses = rows(&result, "accesses")?;
    let read = accesses.iter().find(|v| v["instruction"]["address"] == "0x1100").ok_or("callee cmp missing")?;
    assert_eq!(read["access"], "read");
    let update = accesses.iter().find(|v| v["instruction"]["address"] == "0x1105").ok_or("callee RMW missing")?;
    assert_eq!(update["access"], "read_write");
    assert_eq!(update["displacement"], "0x18");
    assert_eq!(update["via"]["argument_register"], "rsi");
    assert!(accesses.iter().any(|v| v["instruction"]["address"] == "0x110d" && v["width_bytes"] == 16));
    assert!(
        rows(&result, "layout_hints")?
            .iter()
            .all(|h| h["status"] == "heuristic_path_insensitive_not_a_type_or_forwarding_proof")
    );
    Ok(())
}
#[test]
fn field_origin_api_filtered_field_reached_through_subobject_base() -> Result<(), Error> {
    let a = sample();
    let mut r = request();
    r.offsets = vec!["0x18".into()];
    let result = run(&a, r)?;
    let access = rows(&result, "accesses")?
        .iter()
        .find(|v| v["instruction"]["address"] == "0x1140" && v["via"]["argument_register"] == "rsi")
        .ok_or("subobject field missing")?;
    assert_eq!(access["displacement"], "0x18");
    assert_eq!(access["via"]["base_displacement"], "0x10");
    let call = rows(&result, "calls")?
        .iter()
        .find(|v| v["selection"]["call_site"] == "0x101e")
        .ok_or("subobject call missing")?;
    let arg = rows(call, "arguments")?.iter().find(|v| v["register"] == "rsi").ok_or("subobject address missing")?;
    assert_eq!(arg["relation"], "field_address");
    assert_eq!(arg["requested_offset_match"], false);
    assert_eq!(arg["displacement"], "0x10");
    assert!(rows(&result, "accesses")?.iter().all(|v| v["displacement"] == "0x18"));
    Ok(())
}
#[test]
fn field_origin_api_selection_slice_and_limits_are_explicit() -> Result<(), Error> {
    let a = sample();
    let result = run(&a, request())?;
    assert!(result["slice"].is_null());
    let token = rows(&result, "calls")?[0]["selection"].clone();
    let mut r = request();
    r.selection = Some(serde_json::from_value(token)?);
    let selected = run(&a, r.clone())?;
    assert_eq!(selected["slice"]["target"], selected["selected"]["call_site"]);
    let standalone = a.query(
        &Query::Slice {
            address: r.selection.as_ref().ok_or("selection")?.function.clone(),
            to: r.selection.as_ref().ok_or("selection")?.call_site.clone(),
            fields: false,
            keep_gotos: false,
            page: TextPage { offset: 0, limit: 4096 },
        },
        &Cancellation::default(),
    );
    assert_eq!(selected["slice"]["data"], serde_json::to_value(standalone.data)?);
    r.selection.as_mut().ok_or("selection")?.image_sha256 = "different".into();
    let failure = a.query(&Query::FieldOrigin { request: r }, &Cancellation::default());
    assert_eq!(failure.error.as_ref().map(|e| e.code), Some("image_mismatch"));
    let mut r = request();
    r.limits.rows = 1;
    r.limits.callees = 0;
    r.limits.output_bytes = 4096;
    let result = run(&a, r)?;
    assert!(!result["complete_under_model"].as_bool().unwrap_or(true));
    assert!(serde_json::to_vec(&result)?.len() <= 4096);
    assert_ne!(rows(&result, "stops")?, &Vec::<Value>::new());
    Ok(())
}
#[test]
fn field_origin_api_unknown_cfg_and_mixed_join_do_not_invent_forwarding() -> Result<(), Error> {
    let mut a = sample();
    a.image.data[..2].copy_from_slice(&[0xff, 0xe0]);
    let report = run(&a, request())?;
    assert_eq!(rows(&report, "accesses")?.len(), 0);
    assert_eq!(rows(&report, "calls")?.len(), 0);
    assert_ne!(rows(&report, "layout_hints")?, &Vec::<Value>::new());
    let mut a = sample();
    let code =
        [0x85, 0xc9, 0x74, 6, 0x48, 0x8d, 0x77, 0x18, 0xeb, 4, 0x48, 0x8b, 0x77, 0x18, 0xe8, 0xed, 0, 0, 0, 0xc3];
    a.image.data[..code.len()].copy_from_slice(&code);
    a.image.functions[0] = 0x1000..0x1014;
    let report = run(&a, request())?;
    assert!(
        rows(&report, "calls")?
            .iter()
            .all(|c| c["arguments"].as_array().is_some_and(|args| args.iter().all(|arg| arg["register"] != "rsi")))
    );
    let cancel = Cancellation::default();
    cancel.cancel();
    let response = a.query(&Query::FieldOrigin { request: request() }, &cancel);
    assert_eq!(response.error.as_ref().map(|e| e.code), Some("cancelled"));
    Ok(())
}
#[test]
fn field_origin_api_loaded_pointer_does_not_become_original_base() -> Result<(), Error> {
    let mut a = sample();
    let code = [0x48, 0x8b, 0x77, 0x18, 0x48, 0x8b, 0x46, 8, 0xe8, 0xf3, 0, 0, 0, 0xc3];
    a.image.data[..code.len()].copy_from_slice(&code);
    a.image.functions[0] = 0x1000..0x100e;
    let mut r = request();
    r.callees = false;
    let report = run(&a, r)?;
    assert!(rows(&report, "accesses")?.iter().all(|v| v["instruction"]["address"] != "0x1004"));
    assert!(report["unresolved_memory_operands"].as_u64().is_some_and(|n| n > 0));
    let code = [0x48, 0x8b, 0x7f, 0x18, 0xe8, 0xf7, 0, 0, 0, 0xc3];
    a.image.data[..code.len()].copy_from_slice(&code);
    a.image.functions[0] = 0x1000..0x100a;
    let report = run(&a, request())?;
    assert_eq!(rows(&report, "callee_scopes")?.len(), 0);
    assert!(rows(&report, "stops")?.iter().any(|s| s == "loaded_value_pointee_not_followed"));
    Ok(())
}
#[test]
fn field_origin_api_capped_definition_union_converges_on_loop_diamond() -> Result<(), Error> {
    let mut a = sample();
    let mut code = vec![0x48, 0x89, 0xf8, 0x85, 0xc9, 0x75, 29];
    for _ in 0..9 {
        code.extend_from_slice(&[0x48, 0x89, 0xc0]);
    }
    code.extend_from_slice(&[0xeb, 27]);
    for _ in 0..9 {
        code.extend_from_slice(&[0x48, 0x89, 0xc0]);
    }
    code.extend_from_slice(&[0x85, 0xd2, 0x75, 0xc0, 0x48, 0x89, 0xc6, 0xe8, 0xb5, 0, 0, 0, 0xc3]);
    a.image.data[..code.len()].copy_from_slice(&code);
    a.image.functions[0] = 0x1000..0x1000 + code.len() as u64;
    let mut r = request();
    r.callees = false;
    let report = run(&a, r)?;
    let call = rows(&report, "calls")?.first().ok_or("dataflow did not converge")?;
    let arg = rows(call, "arguments")?.iter().find(|arg| arg["register"] == "rsi").ok_or("lost loop origin")?;
    assert_eq!(arg["relation"], "base_address");
    assert_eq!(arg["definitions_truncated"], true);
    Ok(())
}

#[test]
fn field_origin_api_conditional_memory_and_invalid_requests() -> Result<(), Error> {
    let mut a = sample();
    let code = [0x48, 0x0f, 0xb1, 0x57, 0x18, 0xc3]; // cmpxchg [rdi+24], rdx
    a.image.data[..code.len()].copy_from_slice(&code);
    a.image.functions[0] = 0x1000..0x1006;
    let result = run(&a, request())?;
    let access = rows(&result, "accesses")?.first().ok_or("conditional access")?;
    assert_eq!(access["access"], "read_write");
    assert_eq!(access["conditional_access"], true);
    a.image.data[..3].copy_from_slice(&[0xf3, 0xa4, 0xc3]); // rep movsb has implicit memory operands.
    a.image.functions[0] = 0x1000..0x1003;
    let implicit = run(&a, request())?;
    assert_eq!(rows(&implicit, "accesses")?.len(), 0);
    assert!(implicit["unresolved_memory_operands"].as_u64().is_some_and(|n| n > 0));
    for bad in [
        r#"{"operation":"field_origin","request":{"address":"0x1000","register":"eax"}}"#,
        r#"{"operation":"field_origin","request":{"address":"0x1000","offsets":["-0x18"]}}"#,
        r#"{"operation":"field_origin","request":{"address":"0x1000","limits":{"rows":0}}}"#,
    ] {
        let query: Query = serde_json::from_str(bad)?;
        assert!(a.query(&query, &Cancellation::default()).error.is_some());
    }
    assert!(
        serde_json::from_str::<Query>(r#"{"operation":"field_origin","request":{"address":"0x1000","execute":true}}"#)
            .is_err()
    );
    Ok(())
}
