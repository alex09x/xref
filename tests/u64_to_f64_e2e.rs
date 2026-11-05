/*
 * XRef — x86-64 binary analysis and cross-reference tooling
 * Copyright (c) 2026 Alexander Panasenko
 *
 * Contact: alex@prod.codes
 * Author: https://prod.codes/about/
 * Project: https://github.com/alex09x/xref
 * SPDX-License-Identifier: MIT OR Apache-2.0
 */

#![cfg(all(target_os = "linux", target_arch = "x86_64"))]

use object::{Object, ObjectSymbol};
use std::{
    collections::BTreeMap,
    error::Error,
    fs,
    path::{Path, PathBuf},
    process::{Command, Output},
    time::{SystemTime, UNIX_EPOCH},
};

struct Fixture(PathBuf);

impl Fixture {
    fn new() -> Result<Self, Box<dyn Error>> {
        let nonce = SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos();
        let path = std::env::temp_dir().join(format!("xref-u64-{}-{nonce}", std::process::id()));
        fs::create_dir_all(&path)?;
        let binary = path.join("u64-fixture");
        let compile = Command::new("rustc")
            .args(["-C", "opt-level=3"])
            .arg(Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/u64_to_f64.rs"))
            .arg("-o")
            .arg(&binary)
            .output()?;
        assert!(compile.status.success(), "{}", String::from_utf8_lossy(&compile.stderr));
        let stripped = path.join("u64-fixture-stripped");
        let strip = Command::new("objcopy")
            .args(["--strip-all", "--keep-section=.eh_frame"])
            .arg(&binary)
            .arg(&stripped)
            .output()?;
        assert!(strip.status.success(), "{}", String::from_utf8_lossy(&strip.stderr));
        Ok(Self(binary))
    }

    fn symbols(&self) -> Result<BTreeMap<String, u64>, Box<dyn Error>> {
        let bytes = fs::read(&self.0)?;
        let object = object::File::parse(bytes.as_slice())?;
        Ok(object.symbols().filter_map(|s| Some((s.name().ok()?.to_owned(), s.address()))).collect())
    }

    fn stripped(&self) -> PathBuf {
        self.0.with_file_name("u64-fixture-stripped")
    }

    fn c(binary: &Path, address: u64) -> Result<Output, std::io::Error> {
        Command::new(env!("CARGO_BIN_EXE_xref")).arg("-b").arg(binary).args(["c", &format!("{address:#x}")]).output()
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        if let Some(parent) = self.0.parent() {
            let _ = fs::remove_dir_all(parent);
        }
    }
}

fn text(output: Output) -> Result<String, Box<dyn Error>> {
    if !output.status.success() {
        return Err(String::from_utf8_lossy(&output.stderr).into_owned().into());
    }
    Ok(String::from_utf8(output.stdout)?)
}

#[test]
fn u64_to_f64_compiled_and_stripped_rustc_release_lifts_conversion_div_and_store() -> Result<(), Box<dyn Error>> {
    let fixture = Fixture::new()?;
    let symbols = fixture.symbols()?;
    let conv_div = symbols["conv_div"];
    let conv_div_store = symbols["conv_div_store"];

    let report_div = text(Fixture::c(&fixture.stripped(), conv_div)?)?;
    assert!(
        report_div.contains("(f64)(u64)arg_0") || report_div.contains("(f64)(u64)(arg_0)"),
        "expected conversion of arg_0 in:\n{report_div}"
    );
    assert!(
        report_div.contains(" / zmm0") || report_div.contains(" / arg_1") || report_div.contains(" / xmm0"),
        "expected division by f64 argument in:\n{report_div}"
    );
    assert!(
        !report_div.contains("unpcklps") && !report_div.contains("punpckldq") && !report_div.contains("subpd"),
        "leftover SIMD comments in conv_div:\n{report_div}"
    );

    let report_store = text(Fixture::c(&fixture.stripped(), conv_div_store)?)?;
    assert!(
        report_store.contains("(f64)(u64)arg_0") || report_store.contains("(f64)(u64)(arg_0)"),
        "expected conversion of arg_0 in:\n{report_store}"
    );
    assert!(
        report_store.contains(" / zmm0") || report_store.contains(" / arg_1") || report_store.contains(" / xmm0"),
        "expected division by f64 argument in:\n{report_store}"
    );
    assert!(
        report_store.contains("*(u64 *)") || report_store.contains("*(f64 *)") || report_store.contains("->value"),
        "expected store of converted and divided value in:\n{report_store}"
    );
    let div_var = report_store
        .lines()
        .find(|l| l.contains(" / ") && l.contains("f64 fp_"))
        .and_then(|l| l.split_whitespace().nth(1))
        .ok_or_else(|| std::io::Error::other("division variable not found in decompilation"))?;
    assert!(
        report_store
            .lines()
            .any(|l| (l.contains("*(u64 *)") || l.contains("*(f64 *)") || l.contains("->value")) && l.contains(div_var)),
        "store must store the division result variable {div_var}:\n{report_store}"
    );
    assert!(
        !report_store.contains("unpcklps") && !report_store.contains("punpckldq") && !report_store.contains("subpd"),
        "leftover SIMD comments in conv_div_store:\n{report_store}"
    );

    Ok(())
}
