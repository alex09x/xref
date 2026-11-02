/*
 * XRef Code — evidence-producing binary analysis
 * Copyright (c) 2026 Alexander Panasenko
 * Contact: alex@prod.codes
 * Author: https://prod.codes/about/
 * Project: https://github.com/alex09x/xref
 * SPDX-License-Identifier: MIT OR Apache-2.0
 */
use super::*;
use crate::api::context::types::Value;
use crate::api::tests::fixture;

#[test]
fn context_retains_both_callsite_argument_values_and_guard_edges() -> Result<(), Box<dyn std::error::Error>> {
    let a = crate::api::investigate::tests::branch_fixture();
    let cancel = Cancellation::default();
    for (site, bits, edge) in [("0x1011", "0x1", "fallthrough"), ("0x101e", "0x0", "taken")] {
        let result = a.context("0x1000", site, &cancel)?;
        assert!(result.complete_under_model);
        assert_eq!(result.arguments[4].register, "r8");
        assert_eq!(result.arguments[4].value, Value::Constant { bits: bits.into() });
        assert_eq!(result.guards.len(), 1);
        assert_eq!(result.guards[0].branch_address, "0x1009");
        assert_eq!(result.guards[0].required_edge, edge);
        assert_eq!(result.guards[0].flag_definition_addresses, vec!["0x1007"]);
        assert_eq!(result.call.address, site);
        assert!(result.instructions.iter().any(|i| i.address == "0x1007" && !i.bytes.is_empty()));
    }
    Ok(())
}
#[test]
fn context_merges_paths_and_preserves_unknowns_partial_writes_and_cancellation()
-> Result<(), Box<dyn std::error::Error>> {
    let mut a = fixture();
    // test edi,edi; je join; mov r8d,1; join: call; ret
    let code = [0x85, 0xff, 0x74, 0x06, 0x41, 0xb8, 1, 0, 0, 0, 0xe8, 0xf1, 0, 0, 0, 0xc3];
    a.image.data[..code.len()].copy_from_slice(&code);
    a.image.functions[0] = 0x1000..0x1010;
    let c = a.context("0x1000", "0x100a", &Cancellation::default())?;
    assert_eq!(c.arguments[4].value, Value::Unknown);
    assert_eq!(c.guards.len(), 0);
    // A full-width constant followed by a subword write cannot remain the same constant.
    let code = [0x41, 0xb8, 1, 0, 0, 0, 0x41, 0xb0, 2, 0xe8, 0xf2, 0, 0, 0, 0xc3];
    a.image.data[..code.len()].copy_from_slice(&code);
    a.image.functions[0] = 0x1000..0x100f;
    let c = a.context("0x1000", "0x1009", &Cancellation::default())?;
    assert_eq!(c.arguments[4].value, Value::Unknown);
    assert_eq!(
        a.context("0x1000", "0x1001", &Cancellation::default()).err().map(|e| e.code),
        Some("invalid_call_site")
    );
    let cancel = Cancellation::default();
    cancel.cancel();
    assert_eq!(a.context("0x1000", "0x1009", &cancel).err().map(|e| e.code), Some("cancelled"));
    Ok(())
}
#[test]
fn context_suppresses_values_when_control_flow_has_unknown_edges() -> Result<(), Box<dyn std::error::Error>> {
    let mut a = fixture();
    // An indirect jump on another branch could target any instruction in the range.
    let code = [0x85, 0xff, 0x74, 2, 0xff, 0xe0, 0x41, 0xb8, 1, 0, 0, 0, 0xe8, 0xef, 0, 0, 0, 0xc3];
    a.image.data[..code.len()].copy_from_slice(&code);
    a.image.functions[0] = 0x1000..0x1012;
    let c = a.context("0x1000", "0x100c", &Cancellation::default())?;
    assert!(!c.complete_under_model);
    assert!(c.arguments.iter().all(|arg| arg.value == Value::Unknown));
    assert_eq!(c.guards.len(), 0);
    Ok(())
}

#[test]
fn context_review_traps_do_not_hide_hot_path_values() -> Result<(), Box<dyn std::error::Error>> {
    for trap in [&[0x0f, 0x0b][..], &[0x0f, 0xb9, 0xc0][..], &[0x0f, 0xff, 0xc0][..]] {
        let mut a = fixture();
        let mut code = vec![0x41, 0xb8, 1, 0, 0, 0, 0xe8, 0xf5, 0, 0, 0, 0xc3];
        code.extend_from_slice(trap);
        a.image.data[..code.len()].copy_from_slice(&code);
        a.image.functions[0] = 0x1000..0x1000 + code.len() as u64;
        let c = a.context("0x1000", "0x1006", &Cancellation::default())?;
        assert!(c.complete_under_model, "trap: {trap:?}");
        assert_eq!(c.arguments[4].value, Value::Constant { bits: "0x1".into() });
    }
    Ok(())
}

#[test]
fn context_review_resolved_tail_jumps_and_internal_slot_edges() -> Result<(), Box<dyn std::error::Error>> {
    for imported in [false, true] {
        let mut a = fixture();
        let code = [0x41, 0xb8, 1, 0, 0, 0, 0xff, 0x25, 0xf4, 1, 0, 0];
        a.image.data[..code.len()].copy_from_slice(&code);
        a.image.functions[0] = 0x1000..0x100c;
        if imported {
            a.image.imports.push((0x1200, "external".into()));
        } else {
            a.image.pointers.push((0x1200, 0x1100));
        }
        let c = a.context("0x1000", "0x1006", &Cancellation::default())?;
        assert!(c.complete_under_model);
        assert_eq!(c.arguments[4].value, Value::Constant { bits: "0x1".into() });
    }
    // A relocated intra-FDE branch must propagate state to its exact decoded destination.
    let mut a = fixture();
    let code = [0xff, 0x25, 0xfa, 1, 0, 0, 0x0f, 0x0b, 0x41, 0xb8, 1, 0, 0, 0, 0xe8, 0xed, 0, 0, 0, 0xc3];
    a.image.data[..code.len()].copy_from_slice(&code);
    a.image.functions[0] = 0x1000..0x1014;
    a.image.pointers.push((0x1200, 0x1008));
    let c = a.context("0x1000", "0x100e", &Cancellation::default())?;
    assert!(c.complete_under_model);
    assert_eq!(c.arguments[4].value, Value::Constant { bits: "0x1".into() });
    a.image.pointers[0].1 = 0x1009; // A non-boundary target cannot be silently ignored.
    let c = a.context("0x1000", "0x100e", &Cancellation::default())?;
    assert!(!c.complete_under_model);
    assert_eq!(c.arguments[4].value, Value::Unknown);
    Ok(())
}

#[test]
fn context_review_mid_instruction_direct_jump_marks_cfg_unknown() -> Result<(), Box<dyn std::error::Error>> {
    let mut a = fixture();
    let code = [0xeb, 1, 0x41, 0xb8, 1, 0, 0, 0, 0xe8, 0xf3, 0, 0, 0, 0xc3];
    a.image.data[..code.len()].copy_from_slice(&code);
    a.image.functions[0] = 0x1000..0x100e;
    let c = a.context("0x1000", "0x1008", &Cancellation::default())?;
    assert!(c.warnings.contains(&"unresolved_control_flow_values_suppressed"));
    assert_eq!(c.guards.len(), 0);
    Ok(())
}

#[test]
fn context_review_unreachable_call_has_no_vacuous_required_guard() -> Result<(), Box<dyn std::error::Error>> {
    let mut a = fixture();
    let code = [0xeb, 4, 0x74, 3, 0xeb, 0, 0xc3, 0xe8, 0xf4, 0, 0, 0, 0xc3];
    a.image.data[..code.len()].copy_from_slice(&code);
    a.image.functions[0] = 0x1000..0x100d;
    let c = a.context("0x1000", "0x1007", &Cancellation::default())?;
    assert!(!c.complete_under_model);
    assert_eq!(c.guards.len(), 0);
    assert!(c.warnings.contains(&"unreachable_or_dataflow_budget_exhausted"));
    Ok(())
}
