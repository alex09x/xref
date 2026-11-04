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
fn related_writer_beats_many_unrelated_writers_before_limit() {
    let fixture = Fixture::build("release");
    let decoys: std::collections::BTreeSet<_> =
        fixture.symbols.iter().filter(|(name, _)| name.starts_with("decoy")).map(|(_, address)| *address).collect();
    assert!(decoys.len() >= 65, "the fixture must retain enough distinct writer functions");
    let binary = fixture.stripped();
    let report =
        fixture.query_keys(&binary, &["c", "m", "e"], "process_short", &["--writes-all-of", "m,e", "--limit", "1"]);
    let row = &report["accessor_candidates"][0];
    let function = row["function"].as_str().unwrap();
    let related = ["update_short_stage", "related_short_writer"]
        .iter()
        .any(|name| function.starts_with(&format!("{:#x}..", fixture.symbols[*name])));
    assert!(related, "an actual callgraph neighbor should outrank unrelated stores: {report}");
    assert_eq!(row["callgraph_distance"], 1);
    assert_eq!(row["colocated_written_fields"], 2);
    assert!(report["coverage"]["accessor_prefiltered_functions"].as_u64().unwrap() > 0);
    for offset in [fixture.offsets["ShortRecord.m"], fixture.offsets["ShortRecord.e"]] {
        assert!(
            row["queried_field_accesses"]
                .as_array()
                .unwrap()
                .iter()
                .any(|access| { access["offset"] == offset && access["access"].as_str().unwrap().contains("write") }),
            "missing required write: {report}"
        );
    }
    let missing = fixture.query_keys(&binary, &["c", "m", "e"], "process_short", &["--writes-all-of", "m,missing"]);
    assert!(
        missing["accessor_candidates"].as_array().unwrap().is_empty(),
        "unknown required field must not match: {missing}"
    );
}
