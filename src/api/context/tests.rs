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
    Ok(())
}
