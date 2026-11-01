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

#[test]
fn pseudo_c_decompiles_comparisons_bounds_checks_and_jump_tables() {
    let limit = symbol("fixture_limit");
    let limit_c = xref(&["c", &limit]);
    assert!(limit_c.contains(&format!("function {limit}..")) && limit_c.contains("== 9"), "{limit_c}");

    let pick = symbol("fixture_pick");
    let pick_c = xref(&["c", &pick]);
    assert!(pick_c.contains("((u64 *)") && pick_c.contains("sample.rs:"), "{pick_c}");

    let err = xref(&["error", "fixture fault pair"]);
    let display = first_hit_function(&err);
    let display_c = xref(&["c", &display]);
    assert!(display_c.contains("switch (") && display_c.contains("case 3 (0x3):"), "{display_c}");
    assert!(display_c.contains("fixture fault pair"), "{display_c}");

    let stats = xref(&["stats"]);
    assert!(stats.contains("functions ") && stats.contains("panic locations "), "{stats}");
    let funcs = xref(&["func", &limit, "0x1"]);
    assert!(funcs.contains("0x1  no function"), "{funcs}");
    let imm_all = xref(&["imm", "9", "--cmp"]);
    assert!(imm_all.contains(&format!("in {limit}")), "{imm_all}");
    let disp_out = xref(&["disp", "8", "--write", "--in", &display]);
    assert!(disp_out.contains("hits"), "{disp_out}");
    let disp_all = xref(&["disp", "8", "16", "--all"]);
    assert!(disp_all.contains("functions") && disp_all.contains("0x8:"), "{disp_all}");
    let refs_more = xref(&["refs", &display, "missing_fixture_string"]);
    assert!(refs_more.contains("not found") && refs_more.contains("1 hits"), "{refs_more}");
    let arm_no_jt = xref(&["arm", &limit]);
    assert!(arm_no_jt.contains("no jump-table arm"), "{arm_no_jt}");
    let var_out = xref(&["variant", &display, "999"]);
    assert!(var_out.contains("outside "), "{var_out}");
    let bad = Command::new(env!("CARGO_BIN_EXE_xref")).args(["--bin", "/nonexistent", "stats"]).output();
    assert!(bad.is_ok_and(|o| !o.status.success()));

    let out_dir = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join("xref-c-out");
    let decomp_out = xref(&["decomp", &limit, &pick, "--out", out_dir.to_str().unwrap_or_default()]);
    assert!(decomp_out.contains(&format!("{limit}.c")) && decomp_out.contains("bytes"), "{decomp_out}");
}

#[test]
fn call_paths_trees_inline_strings_and_cross_build_matching_work() {
    let limit = symbol("fixture_limit");
    let inline_fn = symbol("fixture_inline");
    let pick = symbol("fixture_pick");

    let paths = xref(&["path", "4main", "fixture_limit"]);
    assert!(paths.contains(&format!("-> {limit}")) && paths.contains(&format!("-> {inline_fn} -> {limit}")), "{paths}");
    let paths_d1 = xref(&["path", "4main", "fixture_limit", "--depth", "1"]);
    assert!(paths_d1.contains("1 paths") && !paths_d1.contains(&inline_fn), "{paths_d1}");

    let tree_out = xref(&["tree", "fixture_inline", "--callees", "--depth", "2"]);
    assert!(tree_out.contains(&format!("{limit}..")), "{tree_out}");

    let istr_out = xref(&["refs", "--inline", "token mismatch"]);
    assert!(istr_out.contains(&format!("in {inline_fn}..")), "{istr_out}");
    let istr_alias = xref(&["istr", "token mismatch"]);
    assert!(istr_alias.contains(&format!("in {inline_fn}..")), "{istr_alias}");

    let args_out = xref(&["args", "fixture_limit"]);
    assert!(args_out.contains("rdi=7") && args_out.contains("call sites"), "{args_out}");

    let find_refs = xref(&["find", "--refs", "fixture fault pair", "--refs", "fixture fault text"]);
    assert!(find_refs.contains("1 functions") && find_refs.contains("(2/2:"), "{find_refs}");
    let find_calls = xref(&["find", "--calls", "fixture_limit", "--calls", "fixture_pick"]);
    assert!(find_calls.contains("1 functions") && find_calls.contains("(2/2:"), "{find_calls}");
    let find_none = xref(&["find", "--calls", "fixture_limit", "--imm", "0xdeadbeef"]);
    assert!(find_none.contains("0 functions"), "{find_none}");

    let shifted_src = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join("sample_shifted.rs");
    let shifted_bin = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join("xref-sample-shifted");
    let orig = std::fs::read_to_string(SOURCE).unwrap_or_default();
    let modified = orig.replace(
        "#[no_mangle]\n#[inline(never)]\npub fn fixture_limit",
        "#[no_mangle]\n#[inline(never)]\npub fn extra_pad(x: u64) -> u64 { black_box(x) + 0x1234 }\n\n#[no_mangle]\n#[inline(never)]\npub fn fixture_limit",
    );
    std::fs::write(&shifted_src, modified).unwrap_or_else(|e| panic!("{e}"));
    let rustc = std::env::var("RUSTC").unwrap_or_else(|_| "rustc".to_owned());
    let status = Command::new(rustc)
        .args(["--edition", "2021", "-C", "opt-level=2", "-o"])
        .arg(&shifted_bin)
        .arg(&shifted_src)
        .status()
        .unwrap_or_else(|e| panic!("{e}"));
    assert!(status.success());

    let matched = xref(&["match", "--other", shifted_bin.to_str().unwrap_or_default(), &pick, &inline_fn]);
    assert!(matched.contains(&format!("query {pick}..")) && matched.contains("score "), "{matched}");
}
