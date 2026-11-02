/*
 * XRef Code — evidence-producing binary analysis
 * Copyright (c) 2026 Alexander Panasenko
 * Contact: alex@prod.codes
 * Author: https://prod.codes/about/
 * Project: https://github.com/alex09x/xref
 * SPDX-License-Identifier: MIT OR Apache-2.0
 */
use super::*;
fn install(a: &mut Analysis, code: &[u8]) {
    a.image.data[..code.len()].copy_from_slice(code);
    a.image.functions[0] = 0x1000..0x1000 + code.len() as u64;
}
#[test]
fn field_origin_review_cyclic_cap_keeps_unmodified_entry_facts() -> Result<(), Error> {
    let mut a = sample();
    let mut code = vec![];
    for _ in 0..5 {
        code.extend_from_slice(&[0x48, 0x89, 0xc0]);
    }
    code.extend_from_slice(&[
        0x75, 0x0b, 0x48, 0x89, 0xc0, 0x75, 0xf3, 0x48, 0x89, 0xc0, 0x48, 0x89, 0xc0, 0x75, 0xe8, 0x48, 0x89, 0xc0,
        0x75, 0xee, 0xe8, 0xd8, 0, 0, 0, 0xc3,
    ]);
    install(&mut a, &code);
    let context = a.context("0x1000", "0x1023", &Cancellation::default())?;
    assert!(context.complete_under_model);
    assert_eq!(context.arguments[0].value, crate::api::context::types::Value::EntryRegister { register: "rdi" });
    let mut r = request();
    r.callees = false;
    let report = run(&a, r)?;
    assert_eq!(rows(&report, "calls")?.len(), 1);
    assert_eq!(report["calls"][0]["selection"]["call_site"], "0x1023");
    assert!(rows(&report, "stops")?.iter().all(|s| s != "incomplete_cfg_or_dataflow_budget"));
    Ok(())
}
#[test]
fn field_origin_review_unrelated_call_does_not_trigger_row_limit() -> Result<(), Error> {
    let mut a = sample();
    install(&mut a, &[0xe8, 0xfb, 0, 0, 0, 0xe8, 0x36, 1, 0, 0, 0xc3]);
    let mut r = request();
    r.callees = false;
    r.limits.rows = 1;
    let report = run(&a, r.clone())?;
    assert_eq!(rows(&report, "calls")?.len(), 1);
    assert_eq!(report["calls_examined"], 2);
    assert!(rows(&report, "stops")?.iter().all(|s| s != "call_row_limit"));
    assert_eq!(report["complete_under_model"], true);
    // A second actually matching call still exceeds the one-row limit.
    install(&mut a, &[0x49, 0x89, 0xfc, 0xe8, 0xf8, 0, 0, 0, 0x4c, 0x89, 0xe7, 0xe8, 0x30, 1, 0, 0, 0xc3]);
    let report = run(&a, r)?;
    assert!(rows(&report, "stops")?.iter().any(|s| s == "call_row_limit"));
    assert_eq!(rows(&report, "calls")?.len(), 1);
    Ok(())
}
#[test]
fn field_origin_review_second_hop_boundary_is_reported() -> Result<(), Error> {
    let mut a = sample();
    install(&mut a, &[0xe8, 0xfb, 0, 0, 0, 0xc3]);
    a.image.data[0x100..0x106].copy_from_slice(&[0xe8, 0x3b, 0, 0, 0, 0xc3]);
    a.image.functions[1] = 0x1100..0x1106;
    a.image.data[0x140..0x145].copy_from_slice(&[0x48, 0x8b, 0x47, 0x18, 0xc3]);
    let report = run(&a, request())?;
    assert_eq!(rows(&report, "accesses")?.len(), 0);
    assert_eq!(rows(&report, "callee_scopes")?.len(), 1);
    assert!(rows(&report, "stops")?.iter().any(|s| s == "callee_depth_limit"));
    assert_eq!(report["complete_under_model"], false);
    // A nested loaded value has its own explicit pointee boundary.
    a.image.data[0x100..0x10a].copy_from_slice(&[0x48, 0x8b, 0x7f, 0x18, 0xe8, 0x37, 0, 0, 0, 0xc3]);
    a.image.functions[1] = 0x1100..0x110a;
    let report = run(&a, request())?;
    assert!(rows(&report, "stops")?.iter().any(|s| s == "loaded_value_pointee_not_followed"));
    assert!(rows(&report, "accesses")?.iter().all(|v| v["instruction"]["address"] != "0x1140"));
    Ok(())
}
#[test]
fn field_origin_review_unreachable_memory_and_calls_do_not_pollute_counts() -> Result<(), Error> {
    for terminal in [&[0xc3][..], &[0x0f, 0x0b][..], &[0xeb, 7][..]] {
        let mut a = sample();
        let mut code = vec![0x48, 0x8b, 0x47, 0x18];
        code.extend_from_slice(terminal);
        code.extend_from_slice(&[0, 0]); // Decodes as a dead add [rax],al.
        let next = i64::try_from(0x1000 + code.len() + 5)?;
        let delta = i32::try_from(0x1100i64 - next)?;
        code.push(0xe8);
        code.extend_from_slice(&delta.to_le_bytes());
        code.push(0xc3);
        install(&mut a, &code);
        let mut r = request();
        r.callees = false;
        let report = run(&a, r)?;
        assert_eq!(rows(&report, "accesses")?.len(), 1);
        assert_eq!(report["unresolved_memory_operands"], 0);
        assert_eq!(report["calls_examined"], 0);
        assert_eq!(report["complete_under_model"], true);
        assert!(rows(&report, "stops")?.iter().all(|s| s != "unresolved_memory_origins"));
    }
    // Unknown dispatch can reach those instructions: do not prune them using an incomplete CFG.
    let mut a = sample();
    install(&mut a, &[0xff, 0xe0, 0xc3, 0, 0, 0xe8, 0xf6, 0, 0, 0, 0xc3]);
    let mut r = request();
    r.callees = false;
    let report = run(&a, r)?;
    assert!(report["unresolved_memory_operands"].as_u64().is_some_and(|n| n > 0));
    assert_eq!(report["calls_examined"], 1);
    Ok(())
}
