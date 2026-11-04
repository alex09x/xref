/*
 * XRef — Compiled instruction search and cross-build matching CLI integration
 * Copyright (c) 2026 Alexander Panasenko
 * Contact: alex@prod.codes
 * Author: https://prod.codes/about/
 * Project: https://github.com/alex09x/xref
 * SPDX-License-Identifier: MIT OR Apache-2.0
 */
#![cfg(target_os = "linux")]
#![allow(clippy::unwrap_used, clippy::expect_used)] // Failures are test-oracle assertions.
use object::{Object, ObjectSymbol};
use serde_json::Value;
use std::{
    collections::BTreeMap,
    fs,
    path::{Path, PathBuf},
    process::{Command, Output},
};

struct Files(PathBuf);
impl Drop for Files {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}
fn run(command: &mut Command) -> Output {
    let output = command.output().expect("spawn CLI fixture command");
    assert!(output.status.success(), "{command:?}: {}", String::from_utf8_lossy(&output.stderr));
    output
}
fn symbols(path: &Path) -> BTreeMap<String, u64> {
    let bytes = fs::read(path).unwrap();
    let image = object::File::parse(bytes.as_slice()).unwrap();
    image.symbols().filter_map(|symbol| Some((symbol.name().ok()?.to_owned(), symbol.address()))).collect()
}
fn cli(path: &Path, args: &[&str]) -> Output {
    run(Command::new(env!("CARGO_BIN_EXE_xref")).arg("-b").arg(path).args(args))
}
fn fixture(root: &Path, source: &str) -> (PathBuf, BTreeMap<String, u64>) {
    let path = root.join(source);
    run(Command::new("cc")
        .args(["-O0", "-fno-inline", "-fno-toplevel-reorder", "-fno-pie", "-no-pie"])
        .arg(Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures").join(format!("{source}.c")))
        .arg("-o")
        .arg(&path));
    let oracle = symbols(&path);
    let stripped = root.join(format!("{source}-stripped"));
    run(Command::new("objcopy").arg("--strip-all").arg(&path).arg(&stripped));
    (stripped, oracle)
}

#[test]
fn cli_instruction_globs_and_ambiguity_options_reach_real_binary_backends() {
    let nonce = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos();
    let files = Files(
        PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join(format!("analysis-workflows-{}-{nonce}", std::process::id())),
    );
    fs::create_dir_all(&files.0).unwrap();
    let asm = files.0.join("instructions");
    run(Command::new("cc")
        .args(["-nostdlib", "-no-pie", "-Wl,--build-id=none,-e,insn_div"])
        .arg(Path::new(env!("CARGO_MANIFEST_DIR")).join("src/find/fixtures/insn_find.S"))
        .arg("-o")
        .arg(&asm));
    let oracle = symbols(&asm);
    let found =
        String::from_utf8(cli(&asm, &["find", "--insn", "DIVSD XMM*", "--class", "float", "--any", "1"]).stdout)
            .unwrap();
    assert!(found.contains(&format!("insn:divsd xmm*=[{:#x}]", oracle["insn_div_site"])), "{found}");
    assert!(!found.contains(&format!("{:#x}..", oracle["insn_integer"])));
    assert!(!found.contains(&format!("{:#x}..", oracle["insn_avx_integer"])));
    let rejected = Command::new(env!("CARGO_BIN_EXE_xref"))
        .arg("-b")
        .arg(&asm)
        .args(["find", "--insn", "not_an_opcode"])
        .output()
        .unwrap();
    assert!(!rejected.status.success());

    let (a, sa) = fixture(&files.0, "matching_ambiguity_a");
    let (b, sb) = fixture(&files.0, "matching_ambiguity_b");
    let query = format!("{:#x}", sa["target"]);
    let caller = format!("{:#x}", sa["caller"]);
    let anchor = format!("{:#x}", sb["other_caller"]);
    let plain: Value = serde_json::from_slice(
        &cli(&a, &["match", "--other", b.to_str().unwrap(), &query, "--json", "--top", "1"]).stdout,
    )
    .unwrap();
    assert_eq!(plain["reports"][0]["ambiguous"], true);
    assert!(plain["reports"][0]["selected"].is_null());
    assert_eq!(
        plain["reports"][0]["candidates"].as_array().unwrap().len(),
        1,
        "display limit must not erase ambiguity"
    );
    assert_eq!(plain["query_image_sha256"].as_str().unwrap().len(), 64);
    let candidate = &plain["reports"][0]["candidates"][0];
    assert!(candidate["range"]["start"].as_str().unwrap().starts_with("0x"));
    assert!(candidate["features"].as_array().unwrap().iter().any(|feature| feature["kind"] == "immediates"));
    let compared: Value =
        serde_json::from_slice(&cli(&a, &["match", "--other", b.to_str().unwrap(), &query, "--json", "--diff"]).stdout)
            .unwrap();
    assert_eq!(compared["reports"][0]["ambiguous"], true, "identical normalized twins still need explicit selection");
    let anchored: Value = serde_json::from_slice(
        &cli(&a, &["match", "--other", b.to_str().unwrap(), &query, "--context", &caller, &anchor, "--json"]).stdout,
    )
    .unwrap();
    assert_eq!(anchored["reports"][0]["ambiguous"], false);
    assert_eq!(anchored["reports"][0]["selected"]["range"]["start"], format!("{:#x}", sb["twin_one"]));
    let invalid = Command::new(env!("CARGO_BIN_EXE_xref"))
        .arg("-b")
        .arg(&a)
        .args(["match", "--other", b.to_str().unwrap(), &query, "--ambiguity-ratio", "NaN"])
        .output()
        .unwrap();
    assert!(!invalid.status.success());
}
