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
#![allow(clippy::unwrap_used, clippy::expect_used)]

use object::{Object, ObjectSymbol};
use std::{
    collections::BTreeMap,
    error::Error,
    fs,
    path::{Path, PathBuf},
    process::{Command, Output},
    time::{SystemTime, UNIX_EPOCH},
};

const POWERS_EXPECTED: [&str; 20] = [
    "1.0",
    "10.0",
    "100.0",
    "1000.0",
    "10000.0",
    "100000.0",
    "1000000.0",
    "10000000.0",
    "100000000.0",
    "1000000000.0",
    "10000000000.0",
    "100000000000.0",
    "1000000000000.0",
    "10000000000000.0",
    "100000000000000.0",
    "1000000000000000.0",
    "1e16",
    "1e17",
    "1e18",
    "1e19",
];

struct Fixture(PathBuf);

impl Fixture {
    fn new() -> Result<Self, Box<dyn Error>> {
        let nonce = SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos();
        let path = std::env::temp_dir().join(format!("xref-data-{}-{nonce}", std::process::id()));
        fs::create_dir_all(&path)?;
        let binary = path.join("data-read-fixture");
        let compile = Command::new("cc")
            .args(["-O2", "-no-pie"])
            .arg(Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/data_read.c"))
            .arg("-o")
            .arg(&binary)
            .output()?;
        assert!(compile.status.success(), "cc failed: {}", String::from_utf8_lossy(&compile.stderr));
        let stripped = path.join("data-read-fixture-stripped");
        let strip = Command::new("objcopy")
            .args(["--strip-all", "--keep-section=.eh_frame"])
            .arg(&binary)
            .arg(&stripped)
            .output()?;
        assert!(strip.status.success(), "objcopy failed: {}", String::from_utf8_lossy(&strip.stderr));
        Ok(Self(binary))
    }

    fn symbols(&self) -> Result<BTreeMap<String, u64>, Box<dyn Error>> {
        let bytes = fs::read(&self.0)?;
        let object = object::File::parse(bytes.as_slice())?;
        Ok(object.symbols().filter_map(|s| Some((s.name().ok()?.to_owned(), s.address()))).collect())
    }

    fn stripped(&self) -> PathBuf {
        self.0.with_file_name("data-read-fixture-stripped")
    }

    fn run(&self, args: &[&str]) -> Result<Output, std::io::Error> {
        Command::new(env!("CARGO_BIN_EXE_xref")).arg("-b").arg(self.stripped()).args(args).output()
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        if let Some(parent) = self.0.parent() {
            let _ = fs::remove_dir_all(parent);
        }
    }
}

#[test]
fn data_read_e2e_f64_powers() -> Result<(), Box<dyn Error>> {
    let fixture = Fixture::new()?;
    let symbols = fixture.symbols()?;
    let powers_va = symbols["powers"];
    let output = fixture.run(&["data", &format!("{powers_va:#x}"), "--as", "f64", "--count", "20"])?;
    assert!(output.status.success(), "stderr: {}", String::from_utf8_lossy(&output.stderr));
    let stdout = String::from_utf8(output.stdout)?;
    let lines: Vec<&str> = stdout.lines().collect();
    assert_eq!(lines.len(), 20, "expected 20 lines, got {}:\n{stdout}", lines.len());
    for (i, line) in lines.iter().enumerate().take(20) {
        let expected_addr = format!("{:#x}", powers_va + (i as u64) * 8);
        let expected_val = POWERS_EXPECTED[i];
        assert!(line.contains(&expected_addr), "line {i} missing addr {expected_addr}: {line}");
        assert!(line.contains("f64"), "line {i} missing f64: {line}");
        assert!(line.contains(expected_val), "line {i} missing val {expected_val}: {line}");
    }
    Ok(())
}

#[test]
fn data_read_e2e_str() -> Result<(), Box<dyn Error>> {
    let fixture = Fixture::new()?;
    let symbols = fixture.symbols()?;
    let string_va = symbols["test_string"];
    let output = fixture.run(&["data", &format!("{string_va:#x}"), "--as", "str"])?;
    assert!(output.status.success(), "stderr: {}", String::from_utf8_lossy(&output.stderr));
    let stdout = String::from_utf8(output.stdout)?;
    assert!(stdout.contains("Hello, xref data reading!"), "missing string in:\n{stdout}");
    assert!(stdout.contains(&format!("{string_va:#x}")), "missing addr in:\n{stdout}");
    assert!(stdout.contains("str"), "missing str in:\n{stdout}");
    Ok(())
}

#[test]
fn data_read_e2e_bytes() -> Result<(), Box<dyn Error>> {
    let fixture = Fixture::new()?;
    let symbols = fixture.symbols()?;
    let string_va = symbols["test_string"];
    let output = fixture.run(&["data", &format!("{string_va:#x}"), "--as", "bytes", "--count", "32"])?;
    assert!(output.status.success(), "stderr: {}", String::from_utf8_lossy(&output.stderr));
    let stdout = String::from_utf8(output.stdout)?;
    let lines: Vec<&str> = stdout.lines().collect();
    assert_eq!(lines.len(), 2, "expected 2 lines for 32 bytes hex dump:\n{stdout}");
    assert!(lines[0].starts_with(&format!("{string_va:#x}")), "line 0 addr mismatch: {}", lines[0]);
    assert!(lines[1].starts_with(&format!("{:#x}", string_va + 16)), "line 1 addr mismatch: {}", lines[1]);
    assert!(lines[0].contains("48 65 6c 6c 6f"), "hex bytes mismatch: {}", lines[0]);
    Ok(())
}

#[test]
fn data_read_e2e_bss() -> Result<(), Box<dyn Error>> {
    let fixture = Fixture::new()?;
    let symbols = fixture.symbols()?;
    let bss_va = symbols["bss_array"];
    let output = fixture.run(&["data", &format!("{bss_va:#x}"), "--as", "u64", "--count", "4"])?;
    assert!(output.status.success(), "stderr: {}", String::from_utf8_lossy(&output.stderr));
    let stdout = String::from_utf8(output.stdout)?;
    let lines: Vec<&str> = stdout.lines().collect();
    assert_eq!(lines.len(), 4, "expected 4 lines:\n{stdout}");
    for (i, line) in lines.iter().enumerate() {
        let expected_addr = format!("{:#x}", bss_va + (i as u64) * 8);
        assert!(line.contains(&expected_addr), "line missing addr: {line}");
        assert!(line.contains("u64"), "line missing type: {line}");
        assert!(line.contains(" 0"), "line missing value 0: {line}");
        assert!(line.contains("(bss)"), "line missing (bss) mark: {line}");
    }
    Ok(())
}

#[test]
fn data_read_e2e_unmapped_va() -> Result<(), Box<dyn Error>> {
    let fixture = Fixture::new()?;
    let output = fixture.run(&["data", "0x10", "--as", "f64"])?;
    assert!(!output.status.success(), "expected failure for unmapped VA");
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("nearest segment") || stderr.contains("permissions"),
        "stderr should name nearest segment: {stderr}"
    );
    Ok(())
}
