/*
 * xref — Ultra blazing fast cross-references of an x86-64 ELF binary
 * Copyright (c) 2026 Alexander Panasenko
 *
 * Contact: alex@prod.codes
 * Author: https://prod.codes/about/
 * SPDX-License-Identifier: MIT OR Apache-2.0
 */

//! End-to-end tests: build `tests/fixtures/sample.rs` with the toolchain's `rustc` (optimized,
//! position independent, symbols kept) and query it with the `xref` binary.

use std::path::PathBuf;
use std::process::Command;
use std::sync::OnceLock;

const SOURCE: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures/sample.rs");

fn fixture() -> &'static PathBuf {
    static BUILT: OnceLock<PathBuf> = OnceLock::new();
    BUILT.get_or_init(|| {
        let out = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join("xref-sample");
        let rustc = std::env::var("RUSTC").unwrap_or_else(|_| "rustc".to_owned());
        let status = Command::new(rustc)
            .args(["--edition", "2021", "-C", "opt-level=2", "-o"])
            .arg(&out)
            .arg(SOURCE)
            .status()
            .unwrap_or_else(|error| panic!("rustc did not start: {error}"));
        assert!(status.success(), "fixture build failed");
        out
    })
}

fn xref(args: &[&str]) -> String {
    let output = Command::new(env!("CARGO_BIN_EXE_xref"))
        .arg("--bin")
        .arg(fixture())
        .args(args)
        .output()
        .unwrap_or_else(|error| panic!("xref did not start: {error}"));
    assert!(output.status.success(), "xref {args:?} failed: {}", String::from_utf8_lossy(&output.stderr));
    String::from_utf8_lossy(&output.stdout).into_owned()
}

/// Address of a fixture function symbol.
fn symbol(name: &str) -> String {
    let out = xref(&["sym", name]);
    let line = out.lines().find(|line| line.ends_with(&format!("  {name}"))).unwrap_or_else(|| panic!("{out}"));
    line.split_whitespace().next().unwrap_or_default().to_owned()
}

/// Function start of the first hit line (`IP  in START  TEXT`).
fn first_hit_function(out: &str) -> String {
    let line = out.lines().find(|line| line.contains("  in ")).unwrap_or_else(|| panic!("{out}"));
    line.split_whitespace().nth(2).unwrap_or_default().to_owned()
}

#[test]
fn a_display_arm_resolves_to_its_enum_variant() {
    let pair = xref(&["error", "fixture fault pair"]);
    assert!(pair.contains("variant 3 (0x3)"), "{pair}");
    let text = xref(&["error", "fixture fault text"]);
    assert!(text.contains("variant 10 (0xa)"), "{text}");
}

#[test]
fn a_variant_index_shows_the_text_of_its_arm() {
    let out = xref(&["error", "fixture fault pair"]);
    let display = first_hit_function(&out);
    let arms = xref(&["variant", &display, "3", "10"]);
    assert!(arms.contains("variant 3 (0x3)") && arms.contains("fixture fault pair"), "{arms}");
    assert!(arms.contains("variant 10 (0xa)") && arms.contains("fixture fault text"), "{arms}");
    assert!(!arms.contains("fixture fault triple"), "{arms}");
}

#[test]
fn an_address_inside_an_arm_gives_its_variant_index() {
    let refs = xref(&["refs", "fixture fault letter"]);
    let line = refs.lines().find(|line| line.contains("  in ")).unwrap_or_else(|| panic!("{refs}"));
    let ip = line.split_whitespace().next().unwrap_or_default();
    let out = xref(&["arm", ip]);
    let best = out.lines().next().unwrap_or_default();
    assert!(best.contains("variant 6 (0x6)"), "{out}");
}

#[test]
fn a_text_is_found_with_the_code_naming_it_and_shown_in_the_listing() {
    let out = xref(&["refs", "fixture fault triple"]);
    assert!(out.contains("text 0x"), "{out}");
    assert!(out.contains("lea "), "{out}");
    let listing = xref(&["asm", &first_hit_function(&out)]);
    assert!(listing.contains("fixture fault triple"), "{listing}");
}

#[test]
fn a_compare_constant_is_found_inside_one_function() {
    let limit = symbol("fixture_limit");
    let out = xref(&["imm", "9", "--cmp", "--in", &limit]);
    assert!(out.contains(&format!("  in {limit}  cmp ")), "{out}");
    assert!(out.contains("1 hits"), "{out}");
}

#[test]
fn a_function_range_starts_at_its_symbol() {
    let limit = symbol("fixture_limit");
    let out = xref(&["func", &limit]);
    assert!(out.contains(&format!("in {limit}..")) && out.contains("offset 0x0"), "{out}");
}

#[test]
fn callers_and_calls_see_the_direct_call() {
    let limit = symbol("fixture_limit");
    let callers = xref(&["callers", &limit]);
    assert!(callers.contains(&format!("call {limit}")), "{callers}");
    let calls = xref(&["calls", &first_hit_function(&callers)]);
    assert!(calls.contains(&format!("call {limit}")), "{calls}");
}

#[test]
fn panic_locations_map_code_to_its_source_line() {
    let line = std::fs::read_to_string(SOURCE)
        .unwrap_or_default()
        .lines()
        .position(|text| text.trim() == "values[index]")
        .map(|index| index + 1)
        .unwrap_or_default();
    let pick = symbol("fixture_pick");
    let src = xref(&["src", &pick]);
    assert!(src.contains(&format!("sample.rs:{line}:")), "{src}");
    let places = xref(&["where", "sample.rs", "--line", &line.to_string()]);
    assert!(places.contains(&format!("{pick}..")), "{places}");
    let files = xref(&["files", "sample.rs"]);
    assert!(files.contains("tests/fixtures/sample.rs"), "{files}");
}
