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
}

fn validate(report: &Value, fixture: &Fixture, kind: &str, entry: &str, name: &str) {
    let expected = fixture.offsets[&format!("{kind}.{name}")];
    let candidates = report["candidates"].as_array().unwrap();
    assert!(!candidates.is_empty(), "{} {kind}.{name}: {report}", fixture.bin.display());
    for layout in candidates {
        assert!(layout["function"].as_str().unwrap().starts_with(&format!("{:#x}..", fixture.symbols[entry])));
        assert_eq!(layout["base_argument"], "rdi", "value pointer is explicitly the first C ABI argument: {report}");
        let offsets = layout["offsets"].as_array().unwrap();
        assert!(!offsets.is_empty());
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
                assert!(!steps.is_empty());
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
