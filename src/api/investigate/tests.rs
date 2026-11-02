/*
 * XRef Code — evidence-producing binary analysis
 * Copyright (c) 2026 Alexander Panasenko
 * Contact: alex@prod.codes
 * Author: https://prod.codes/about/
 * Project: https://github.com/alex09x/xref
 * SPDX-License-Identifier: MIT OR Apache-2.0
 */
use super::*;
use crate::api::tests::fixture;
use crate::api::types::{Query, TextPage};

pub fn branch_fixture() -> Analysis {
    let mut a = fixture();
    let code = [
        0x48, 0x8d, 0x15, 0xf9, 1, 0, 0, // lea rdx, [0x1200]
        0x85, 0xff, 0x74, 0x0d, // test edi,edi; je 0x1018
        0x41, 0xb8, 1, 0, 0, 0, 0xe8, 0xea, 0, 0, 0, 0xeb, 0x0b, 0x41, 0xb8, 0, 0, 0, 0, 0xe8, 0xdd, 0, 0, 0, 0xc3,
    ];
    a.image.data[..code.len()].copy_from_slice(&code);
    a.image.functions[0] = 0x1000..0x1024;
    a
}
fn request() -> Request {
    Request {
        seed: types::Seed::Text { text: "MCP_NEEDLE".into() },
        direction: types::Direction::Callees,
        callee: Some("0x1100".into()),
        selection: None,
        limits: types::Limits::default(),
    }
}
fn run(a: &Analysis, r: Request) -> Result<types::Investigation, Box<dyn std::error::Error>> {
    let response = a.query(&Query::Investigate { request: r }, &Cancellation::default());
    assert!(response.error.is_none(), "{:?}", response.error);
    match response.data.ok_or("missing data")? {
        Data::Investigation { investigation } => Ok(*investigation),
        other => panic!("{other:?}"),
    }
}
#[test]
fn investigate_lists_alternatives_and_only_renders_an_explicit_image_bound_selection()
-> Result<(), Box<dyn std::error::Error>> {
    let a = branch_fixture();
    let first = run(&a, request())?;
    assert_eq!(first.call_sites.len(), 2);
    assert_eq!(first.call_sites[0].selection.call_site, "0x1011");
    assert_eq!(first.call_sites[1].selection.call_site, "0x101e");
    assert!(first.stops.contains(&"selection_required"));
    assert!(first.evidence.iter().all(|s| s.operation != "slice" && s.operation != "c"));
    assert!(first.evidence.iter().any(|s| s.operation == "refs" && s.parent == Some(0)));
    let choice = first.call_sites[1].selection.clone();
    let mut r = request();
    r.selection = Some(choice.clone());
    let second = run(&a, r)?;
    assert_eq!(second.selected.as_ref().ok_or("missing selection")?.call_site, "0x101e");
    let slice_step = second.evidence.iter().find(|s| s.operation == "slice").ok_or("missing slice")?;
    let standalone = a.query(
        &Query::Slice {
            address: "0x1000".into(),
            to: "0x101e".into(),
            fields: false,
            keep_gotos: false,
            page: TextPage { offset: 0, limit: 4096 },
        },
        &Cancellation::default(),
    );
    assert_eq!(serde_json::to_value(&slice_step.data)?, serde_json::to_value(&standalone.data)?);
    let mut r = request();
    r.selection = Some(types::Selection { image_sha256: "other".into(), ..choice });
    let failure = a.query(&Query::Investigate { request: r }, &Cancellation::default());
    assert_eq!(failure.error.as_ref().map(|e| e.code), Some("image_mismatch"));
    Ok(())
}
#[test]
fn investigate_limits_preserve_partial_evidence_and_never_claim_absence() -> Result<(), Box<dyn std::error::Error>> {
    let a = branch_fixture();
    let mut r = request();
    r.limits.steps = 2;
    r.limits.rows = 1;
    r.limits.output_bytes = 4096;
    let value = run(&a, r)?;
    assert!(value.evidence.len() <= 2);
    assert!(value.stops.contains(&"step_limit"));
    assert!(serde_json::to_vec(&value)?.len() <= 4096);
    let mut r = request();
    r.callee = None;
    r.seed = types::Seed::Text { text: "NOT_HERE".into() };
    let value = run(&a, r)?;
    assert!(value.stops.contains(&"not_found_under_limits"));
    let cancel = Cancellation::default();
    cancel.cancel();
    let response = a.query(&Query::Investigate { request: request() }, &cancel);
    assert_eq!(response.error.as_ref().map(|e| e.code), Some("cancelled"));
    Ok(())
}
#[test]
fn investigate_rejects_limits_and_unknown_json_fields() {
    let a = branch_fixture();
    let mut r = request();
    r.limits.functions = 100;
    let response = a.query(&Query::Investigate { request: r }, &Cancellation::default());
    assert_eq!(response.error.as_ref().map(|e| e.code), Some("invalid_limits"));
    assert!(
        serde_json::from_str::<Query>(
            r#"{"operation":"investigate","request":{"seed":{"kind":"function","address":"0x1000"},"execute":true}}"#
        )
        .is_err()
    );
}

#[test]
fn investigate_reverse_traversal_cycles_and_multiple_string_ranges_are_explicit()
-> Result<(), Box<dyn std::error::Error>> {
    let mut a = branch_fixture();
    a.image.data[0x220..0x22a].copy_from_slice(b"MCP_NEEDLE");
    let value = run(&a, request())?;
    assert_eq!(value.string_matches.len(), 2);
    assert_eq!(value.string_matches[0].start, "0x1200");
    assert_eq!(value.string_matches[0].end_exclusive, "0x120a");
    assert!(value.ambiguities.contains(&"multiple_string_matches"));
    assert!(value.ambiguities.contains(&"multiple_call_sites"));
    // A call cycle must not duplicate FDEs or select one of the two reverse edges.
    a.image.data[0x100..0x106].copy_from_slice(&[0xe8, 0xfb, 0xfe, 0xff, 0xff, 0xc3]);
    a.image.functions[1] = 0x1100..0x1106;
    let mut r = request();
    r.seed = types::Seed::Function { address: "0x1100".into() };
    r.callee = None;
    r.direction = types::Direction::Both;
    let value = run(&a, r)?;
    assert_eq!(value.functions.len(), 2);
    assert_eq!(value.call_sites.len(), 3);
    assert!(value.evidence.iter().any(|s| s.operation == "callers"));
    assert!(value.stops.contains(&"depth_limit"));
    for step in &value.evidence {
        assert!(step.parent.is_none_or(|parent| parent < step.id));
    }
    Ok(())
}

#[test]
fn investigate_output_cap_retains_admitted_evidence() -> Result<(), Box<dyn std::error::Error>> {
    let a = branch_fixture();
    let mut r = request();
    r.limits.output_bytes = 4096;
    let result = run(&a, r)?;
    assert!(result.stops.contains(&"output_limit"));
    assert!(!result.evidence.is_empty());
    assert!(serde_json::to_vec(&result)?.len() <= 4096);
    assert!(result.evidence.iter().all(|s| s.parent.is_none_or(|parent| parent < s.id)));
    Ok(())
}
