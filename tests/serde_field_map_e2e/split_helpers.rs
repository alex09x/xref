/*
 * XRef — executable analysis
 * Copyright (c) 2026 Alexander Panasenko
 * Contact: alex@prod.codes
 * Author: https://prod.codes/about/
 * Project: https://github.com/alex09x/xref
 * SPDX-License-Identifier: MIT OR Apache-2.0
 */
use super::*;

#[test]
fn distinct_key_helpers_retain_their_shared_caller_in_a_stripped_elf() {
    let fixture = Fixture::build("release");
    let binary = fixture.stripped();
    let report = fixture.query_keys(&binary, &["x", "y", "z"], "", &["--layout-only"]);
    let expected: std::collections::BTreeSet<_> =
        ["x", "y", "z"].iter().map(|name| fixture.offsets[&format!("SplitRecord.{name}")]).collect();
    let candidates = report["candidates"].as_array().unwrap();
    assert!(
        candidates.iter().any(|candidate| {
            let offsets: std::collections::BTreeSet<_> = candidate["offsets"]
                .as_array()
                .unwrap()
                .iter()
                .filter_map(|offset| offset["offset"].as_u64())
                .collect();
            offsets == expected && candidate["matched_keys"] == serde_json::json!(["x", "y", "z"])
        }),
        "split helper emissions should form one layout: {report}"
    );
    for (index, suffix) in ["emit_x", "emit_y", "emit_z"].iter().enumerate() {
        let helper = fixture
            .symbols
            .iter()
            .find(|(name, _)| name.contains(suffix))
            .map_or_else(|| panic!("missing compiled helper {suffix}"), |(_, address)| format!("{address:#x}"));
        let references = report["key_diagnostics"]["keys"][index]["code_reference_functions"].as_array().unwrap();
        assert!(references.iter().any(|address| address == &helper), "missing direct helper reference: {report}");
    }
    let exhaustive = fixture.query_keys(&binary, &["x", "y", "z"], "", &["--layout-only", "--exhaustive-key-seeds"]);
    assert_eq!(exhaustive["coverage"]["key_seed_filter_excluded"], 0);
    assert!(
        exhaustive["candidates"].as_array().unwrap().iter().any(|candidate| {
            let offsets: std::collections::BTreeSet<_> = candidate["offsets"]
                .as_array()
                .unwrap()
                .iter()
                .filter_map(|offset| offset["offset"].as_u64())
                .collect();
            offsets == expected
        }),
        "exhaustive seed mode must retain the layout: {exhaustive}"
    );
}
