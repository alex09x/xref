/*
 * XRef — Real derive(Serialize) field offsets and accessor integration
 * Copyright (c) 2026 Alexander Panasenko
 * Contact: alex@prod.codes
 * Author: https://prod.codes/about/
 * Project: https://github.com/alex09x/xref
 * SPDX-License-Identifier: MIT OR Apache-2.0
 */
#![cfg(target_os = "linux")]
#![allow(clippy::unwrap_used, clippy::expect_used)] // Independent compiler/runtime oracle assertions.
use object::{Object, ObjectSection, ObjectSymbol};
use serde_json::Value;
use std::{
    cell::RefCell,
    collections::BTreeMap,
    fs,
    path::{Path, PathBuf},
    process::{Command, Output},
    sync::atomic::{AtomicU64, Ordering},
};

fn run(command: &mut Command) -> Output {
    let output = command.output().expect("spawn field fixture command");
    assert!(output.status.success(), "{command:?}: {}", String::from_utf8_lossy(&output.stderr));
    output
}

struct Fixture {
    bin: PathBuf,
    offsets: BTreeMap<String, u64>,
    symbols: BTreeMap<String, u64>,
    copies: RefCell<Vec<PathBuf>>,
}
impl Drop for Fixture {
    fn drop(&mut self) {
        for path in self.copies.get_mut() {
            let _ = fs::remove_file(path);
        }
    }
}
impl Fixture {
    fn build(mode: &str) -> Self {
        let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        let target = root.join("target/tests/serde-field-fixture");
        let builder = std::env::var("XREF_TEST_RUST_BUILDER").unwrap_or_else(|_| "cargo".to_owned());
        assert!(builder == "cargo" || builder == "mitts", "unknown explicit fixture builder");
        let fixture_manifest = root.join("tests/fixtures/serde_field_map/Cargo.toml");
        let fixture_lock = fixture_manifest.with_file_name("Cargo.lock");
        let inputs = (fs::read(&fixture_manifest).unwrap(), fs::read(&fixture_lock).unwrap());
        let mut command = Command::new(&builder);
        command
            .args(["build", "--manifest-path", "tests/fixtures/serde_field_map/Cargo.toml", "--target-dir"])
            .arg(&target);
        if mode == "release" {
            command.arg("--release");
        }
        if builder == "mitts" {
            command.arg("--native");
        } else {
            command.args(["--locked", "--offline"]);
        }
        eprintln!("Serde fixture builder={builder} profile={mode}");
        let built = command.output().expect("spawn the explicit Rust fixture builder");
        assert_eq!(
            inputs,
            (fs::read(&fixture_manifest).unwrap(), fs::read(&fixture_lock).unwrap()),
            "the builder must preserve fixture manifest and lock bytes"
        );
        assert!(built.status.success(), "{command:?}: {}", String::from_utf8_lossy(&built.stderr));
        let bin = target.join(mode).join("serde_field_map_fixture");
        let bytes = fs::read(&bin).unwrap();
        let object = object::File::parse(bytes.as_slice()).unwrap();
        assert!(object.section_by_name(".eh_frame").is_some());
        let symbols =
            object.symbols().filter_map(|symbol| Some((symbol.name().ok()?.to_owned(), symbol.address()))).collect();
        let output = run(&mut Command::new(&bin));
        let offsets = String::from_utf8(output.stdout)
            .unwrap()
            .lines()
            .filter_map(|line| {
                let (name, number) = line.split_once('=')?;
                Some((name.to_owned(), number.parse().ok()?))
            })
            .collect();
        Self { bin, offsets, symbols, copies: RefCell::new(vec![]) }
    }
    fn stripped(&self) -> PathBuf {
        static NEXT: AtomicU64 = AtomicU64::new(0);
        let path = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join(format!(
            "serde-fields-stripped-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        run(Command::new("objcopy").args(["--strip-all", "--keep-section=.eh_frame"]).arg(&self.bin).arg(&path));
        let bytes = fs::read(&path).unwrap();
        let object = object::File::parse(bytes.as_slice()).unwrap();
        assert_eq!(object.symbols().count(), 0);
        assert!(object.sections().all(|section| !section.name().unwrap_or("").starts_with(".debug_")));
        self.copies.borrow_mut().push(path.clone());
        path
    }
    fn query(&self, bin: &Path, name: &str, entry: &str, layout_only: bool) -> Value {
        let mut command = Command::new(env!("CARGO_BIN_EXE_xref"));
        command.arg("-b").arg(bin).args(["field", name, "--json"]);
        if !entry.is_empty() {
            command.args(["--within", &format!("{:#x}", self.symbols[entry])]);
        }
        if layout_only {
            command.arg("--layout-only");
        } else {
            command.args(["--write", "--min-offsets", "2", "--limit", "128"]);
        }
        serde_json::from_slice(&run(&mut command).stdout).expect("field JSON report")
    }

    fn query_keys(&self, bin: &Path, keys: &[&str], entry: &str, extra: &[&str]) -> Value {
        let mut command = Command::new(env!("CARGO_BIN_EXE_xref"));
        command.arg("-b").arg(bin).args(["field", "--keys", &keys.join(","), "--json"]);
        if !entry.is_empty() {
            command.args(["--within", &format!("{:#x}", self.symbols[entry])]);
        }
        command.args(["--write", "--min-offsets", "2"]);
        if !extra.contains(&"--limit") {
            command.args(["--limit", "128"]);
        }
        command.args(extra);
        serde_json::from_slice(&run(&mut command).stdout).expect("field key-set JSON report")
    }
}

fn validate(report: &Value, fixture: &Fixture, kind: &str, entry: &str, name: &str) {
    let expected = fixture.offsets[&format!("{kind}.{name}")];
    let candidates = report["candidates"].as_array().unwrap();
    assert!(!candidates.is_empty(), "{} {kind}.{name}: {report}", fixture.bin.display());
    for layout in candidates {
        assert!(layout["function"].as_str().unwrap().starts_with(&format!("{:#x}..", fixture.symbols[entry])));
        assert_eq!(layout["base_argument"], "rdi", "value pointer is explicitly the first C ABI argument: {report}");
        let offsets = layout["offsets"].as_array().unwrap();
        assert!(!offsets.is_empty(), "layout must contain field offsets: {layout}");
        for offset in offsets {
            assert_eq!(offset["offset"], expected, "field-specific oracle, not any offset of the struct: {report}");
        }
        for field in layout["fields"].as_array().unwrap() {
            let key = format!("{kind}.{}", field["name"].as_str().unwrap());
            if let Some(oracle) = fixture.offsets.get(&key) {
                assert_eq!(field["offset"], *oracle, "{key}: {report}");
            }
            for witness in field["emissions"].as_array().unwrap() {
                let steps = witness["evidence_steps"].as_array().unwrap();
                assert!(!steps.is_empty(), "emission must carry instruction witnesses: {witness}");
                assert!(steps.iter().all(|step| step["assembly"].as_str().is_some_and(|text| !text.is_empty())));
                if witness["state_identity"].as_str().unwrap().starts_with("unverified") {
                    assert_eq!(layout["association_uncertain"], true);
                    assert_eq!(report["ambiguous"], true, "uncertain writer continuation must remain explicit");
                }
            }
        }
        assert_eq!(layout["size_bytes"], Value::Null);
        assert_eq!(layout["exact_size_unknown"], true);
        assert_eq!(layout["field_order_evidence"], "lexical_call_site_order_not_source_declaration_or_runtime_order");
        if kind == "Payload" {
            assert!(layout["minimum_observed_extent"].as_u64().unwrap() <= fixture.offsets["Payload.size"]);
        }
    }
}

#[test]
fn logging_literal_next_to_a_real_field_read_is_not_a_serialized_field() {
    for mode in ["debug", "release"] {
        let fixture = Fixture::build(mode);
        let binary = fixture.stripped();
        for entry in ["log_only_entry", ""] {
            let report = fixture.query(&binary, "log_only_name", entry, true);
            assert!(
                report["candidates"].as_array().unwrap().is_empty(),
                "{mode} log source must not become a layout: {report}"
            );
        }
    }
}

#[test]
fn natural_serde_derives_map_exact_offsets_in_unoptimized_optimized_and_stripped_elf() {
    for mode in ["debug", "release"] {
        let fixture = Fixture::build(mode);
        assert_ne!(
            fixture.offsets["Payload.payload"], fixture.offsets["Other.payload"],
            "duplicate names must have distinct type-scoped oracles"
        );
        for binary in [&fixture.bin, &fixture.stripped()] {
            for (kind, entry, names) in [
                ("Payload", "serialize_payload_entry", &["payload", "narrow", "flag", "nested"][..]),
                ("Nested", "serialize_nested_entry", &["child", "trailing"][..]),
                ("Other", "serialize_other_entry", &["payload", "stamp"][..]),
            ] {
                for name in names {
                    validate(&fixture.query(binary, name, entry, true), &fixture, kind, entry, name);
                }
            }
            for negative in ["omitted", "log_only_name", "nonexistent_field"] {
                let report = fixture.query(binary, negative, "serialize_payload_entry", true);
                assert!(report["candidates"].as_array().unwrap().is_empty(), "{mode} {negative}: {report}");
            }
        }
    }
}

#[test]
fn constellation_writers_include_real_mutator_and_exclude_single_offset_coincidence() {
    let fixture = Fixture::build("release");
    let binary = fixture.stripped();
    let report = fixture.query(&binary, "payload", "serialize_payload_entry", false);
    validate(&report, &fixture, "Payload", "serialize_payload_entry", "payload");
    let rows = report["accessor_candidates"].as_array().unwrap();
    let stage = format!("{:#x}..", fixture.symbols["update_payload_stage"]);
    let unrelated = format!("{:#x}..", fixture.symbols["update_unrelated"]);
    assert!(
        rows.iter().any(|row| row["function"].as_str().unwrap().starts_with(&stage)
            && row["base_argument"] == "rdi"
            && row["matched_offsets"].as_array().unwrap().len() >= 2),
        "real writer missing: {report}"
    );
    assert!(
        !rows.iter().any(|row| row["function"].as_str().unwrap().starts_with(&unrelated)),
        "same queried displacement alone is not a common-root constellation: {report}"
    );
}

#[test]
fn sibling_key_set_finds_short_fields_and_lists_real_writers_in_compiled_elfs() {
    for mode in ["debug", "release"] {
        let fixture = Fixture::build(mode);
        for binary in [&fixture.bin, &fixture.stripped()] {
            let report = fixture.query_keys(binary, &["c", "m", "e"], "update_short_stage", &[]);
            assert_eq!(report["queried_keys"], serde_json::json!(["c", "m", "e"]));
            let candidates = report["candidates"].as_array().expect("layout candidates");
            assert_eq!(candidates.len(), 1, "expected one exact sibling-key layout: {report}");
            let candidate = &candidates[0];
            let update = format!("{:#x}..", fixture.symbols["update_short_stage"]);
            assert!(candidate["function"].as_str().unwrap().starts_with(&update), "wrong key-set source: {report}");
            let fields = candidate["fields"].as_array().expect("field evidence");
            for name in ["c", "m", "e"] {
                assert!(fields.iter().any(|field| field["name"] == name), "missing key {name}: {report}");
            }
            let mut offsets = candidate["offsets"]
                .as_array()
                .unwrap()
                .iter()
                .filter_map(|offset| offset["offset"].as_u64())
                .collect::<Vec<_>>();
            offsets.sort_unstable();
            assert_eq!(
                offsets,
                [fixture.offsets["ShortRecord.c"], fixture.offsets["ShortRecord.m"], fixture.offsets["ShortRecord.e"]]
                    .into_iter()
                    .collect::<std::collections::BTreeSet<_>>()
                    .into_iter()
                    .collect::<Vec<_>>()
            );
            let rows = report["accessor_candidates"].as_array().unwrap();
            let writes = rows
                .iter()
                .flat_map(|row| row["queried_field_accesses"].as_array().unwrap())
                .filter(|access| access["access"] == "write")
                .collect::<Vec<_>>();
            for offset in [fixture.offsets["ShortRecord.m"], fixture.offsets["ShortRecord.e"]] {
                assert!(
                    writes.iter().any(|access| access["offset"] == offset),
                    "missing writer for {offset:#x}: {report}"
                );
            }
            let packed = fixture.query_keys(binary, &["c", "m", "e"], "", &["--layout-only"]);
            assert!(
                packed["candidates"].as_array().unwrap().iter().any(|candidate| {
                    candidate["matched_keys"] == serde_json::json!(["c", "m", "e"])
                        && candidate["offsets"]
                            == serde_json::json!([
                                {"offset": 0, "offset_hex": "0x0"},
                                {"offset": 8, "offset_hex": "0x8"},
                                {"offset": 16, "offset_hex": "0x10"}
                            ])
                }),
                "shared literal table should yield the three expected offsets: {packed}"
            );
            let keys = packed["key_diagnostics"]["keys"].as_array().unwrap();
            let shared_reference = keys[0]["code_reference_functions"].as_array().unwrap().iter().any(|function| {
                keys[1]["code_reference_functions"].as_array().unwrap().contains(function)
                    && keys[2]["code_reference_functions"].as_array().unwrap().contains(function)
            });
            assert!(shared_reference, "merged key literal should be attributed to one function: {packed}");
        }
    }
}

#[test]
fn key_set_partial_matches_and_budget_diagnostics_are_explicit() {
    let fixture = Fixture::build("release");
    let binary = fixture.stripped();
    let partial = fixture.query_keys(
        &binary,
        &["c", "m", "missing"],
        "update_short_stage",
        &["--min-keys", "2", "--max-functions", "1024", "--layout-only"],
    );
    assert_eq!(partial["candidates"].as_array().unwrap().len(), 1, "partial key match: {partial}");
    assert_eq!(partial["candidates"][0]["matched_keys"], serde_json::json!(["c", "m"]));
    assert_eq!(partial["candidates"][0]["missing_keys"], serde_json::json!(["missing"]));
    assert_eq!(partial["key_diagnostics"]["minimum_matched_keys"], 2);
    assert_eq!(partial["key_diagnostics"]["max_functions"], 1024);

    let limited = fixture.query_keys(&binary, &["c", "m", "e"], "", &["--max-functions", "128", "--layout-only"]);
    assert!(limited["key_diagnostics"]["selected_functions"].as_u64().unwrap() <= 128);

    let expanded = fixture.query_keys(&binary, &["c", "m", "e"], "", &["--max-functions", "1024", "--layout-only"]);
    assert_eq!(expanded["key_diagnostics"]["max_functions"], 1024);
    assert!(
        expanded["key_diagnostics"]["selected_functions"].as_u64().unwrap()
            >= limited["key_diagnostics"]["selected_functions"].as_u64().unwrap(),
        "increased function budget should expand the selected discovery context: {expanded}"
    );

    let exact = fixture.query_keys(&binary, &["c", "m", "missing"], "update_short_stage", &["--layout-only"]);
    assert!(exact["candidates"].as_array().unwrap().is_empty(), "default key-set matching remains exact: {exact}");
    assert_eq!(exact["key_diagnostics"]["missing_emission_keys"], serde_json::json!(["missing"]));

    let budget = fixture.query_keys(
        &binary,
        &["c", "m", "e"],
        "update_short_stage",
        &["--max-instructions", "1", "--layout-only"],
    );
    assert!(budget["key_diagnostics"]["instruction_budget_exhausted_functions"].as_u64().unwrap() > 0, "{budget}");
    assert!(budget["key_diagnostics"]["discovery_budget_exhausted"].as_bool().unwrap(), "{budget}");
    let evidence = budget["key_diagnostics"]["keys"].as_array().unwrap();
    for key in ["c", "m", "e"] {
        assert!(evidence.iter().any(|item| item["key"] == key), "missing per-key diagnostics for {key}: {budget}");
    }
}
#[path = "serde_field_map_e2e/cache_index.rs"]
mod cache_index;
#[path = "serde_field_map_e2e/mcp_session.rs"]
mod mcp_session;
#[path = "serde_field_map_e2e/nested_values.rs"]
mod nested_values;
#[path = "serde_field_map_e2e/rank_callgraph.rs"]
mod rank_callgraph;
#[path = "serde_field_map_e2e/split_helpers.rs"]
mod split_helpers;
#[path = "serde_field_map_e2e/within_keys.rs"]
mod within_keys;
