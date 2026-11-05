/*
 * XRef — exact key sets whose values serialize nested structs, in compiled ELFs
 * Copyright (c) 2026 Alexander Panasenko
 * Contact: alex@prod.codes
 * Author: https://prod.codes/about/
 * Project: https://github.com/alex09x/xref
 * SPDX-License-Identifier: MIT OR Apache-2.0
 */
use super::*;

/// `Timed { tally, period: Span { secs, nanos } }`: the release build follows `period` into the
/// out-of-line `Span` serializer, so its layout also lists `secs` and `nanos`. The exact set
/// `[tally, period]` must still form that layout, while the nested keys stay in the output.
#[test]
fn exact_key_sets_tolerate_keys_of_nested_values_in_compiled_elfs() {
    for profile in ["debug", "release"] {
        let fixture = Fixture::build(profile);
        let binary = fixture.stripped();
        let report = fixture.query_keys(&binary, &["tally", "period"], "", &["--layout-only"]);
        let expected: std::collections::BTreeSet<_> =
            ["tally", "period"].iter().map(|name| fixture.offsets[&format!("Timed.{name}")]).collect();
        let layout = report["candidates"].as_array().unwrap().iter().find(|candidate| {
            let offsets: std::collections::BTreeSet<_> = candidate["offsets"]
                .as_array()
                .unwrap()
                .iter()
                .filter_map(|offset| offset["offset"].as_u64())
                .collect();
            offsets == expected && candidate["matched_keys"] == serde_json::json!(["tally", "period"])
        });
        let layout =
            layout.unwrap_or_else(|| panic!("{profile}: exact set with a nested value must form a layout: {report}"));
        if profile == "release" {
            let keeps_nested = layout["fields"].as_array().unwrap().iter().any(|field| field["name"] == "nanos");
            assert!(keeps_nested, "release layout keeps the nested keys: {layout}");
        }
    }
}
