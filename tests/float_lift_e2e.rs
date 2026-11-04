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
        let path = std::env::temp_dir().join(format!("xref-f64-{}-{nonce}", std::process::id()));
        fs::create_dir_all(&path)?;
        let binary = path.join("float-fixture");
        let compile = Command::new("cc")
            .args(["-nostdlib", "-no-pie", "-Wl,--build-id=none,-e,float_formula"])
            .arg(Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/float_lift.S"))
            .arg("-o")
            .arg(&binary)
            .output()?;
        assert!(compile.status.success(), "{}", String::from_utf8_lossy(&compile.stderr));
        let stripped = path.join("float-fixture-stripped");
        let strip = Command::new("objcopy")
            .args(["--strip-all", "--keep-section=.eh_frame"])
            .arg(&binary)
            .arg(&stripped)
            .output()?;
        assert!(strip.status.success(), "{}", String::from_utf8_lossy(&strip.stderr));
        Ok(Self(path.join("float-fixture")))
    }

    fn symbols(&self) -> Result<BTreeMap<String, u64>, Box<dyn Error>> {
        let bytes = fs::read(&self.0)?;
        let object = object::File::parse(bytes.as_slice())?;
        Ok(object.symbols().filter_map(|s| Some((s.name().ok()?.to_owned(), s.address()))).collect())
    }

    fn stripped(&self) -> PathBuf {
        self.0.with_file_name("float-fixture-stripped")
    }

    fn c(binary: &Path, address: u64) -> Result<Output, std::io::Error> {
        Command::new(env!("CARGO_BIN_EXE_xref"))
            .arg("-b")
            .arg(binary)
            .args(["c", &format!("{address:#x}")])
            .output()
    }

    fn slice(binary: &Path, address: u64, target: u64) -> Result<Output, std::io::Error> {
        Command::new(env!("CARGO_BIN_EXE_xref"))
            .arg("-b")
            .arg(binary)
            .args(["slice", &format!("{address:#x}"), "--to"])
            .arg(format!("{target:#x}"))
            .output()
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
fn compiled_and_stripped_elf_lifts_sse2_doubles_constants_and_slice_dependencies() -> Result<(), Box<dyn Error>> {
    let fixture = Fixture::new()?;
    let symbols = fixture.symbols()?;
    let formula = symbols["float_formula"];
    let signed = symbols["convert_signed_double"];
    let integer_rodata = symbols["convert_integer_rodata"];
    let unsigned = symbols["convert_u64_double"];
    let near_miss = symbols["near_miss_u64_double"];
    let slice_site = symbols["convert_u64_double_add_site"];
    for binary in [&fixture.0, &fixture.stripped()] {
        let report = text(Fixture::c(binary, formula)?)?;
        for literal in ["0.015", "1000.0", "31557600.0", "-0.5", "10.0", "INFINITY"] {
            assert!(report.contains(literal), "missing read-only double {literal} in:\n{report}");
        }
        for operation in ["sqrt(", " > ", " < ", "isnan(", "f64 zmm"] {
            assert!(report.contains(operation), "missing scalar double operation {operation} in:\n{report}");
        }
        for register in ["zmm0", "zmm1", "zmm2", "zmm3", "zmm4", "zmm5"] {
            assert_eq!(report.matches(&format!("f64 {register};")).count(), 1, "one declaration for {register}:\n{report}");
        }
        assert!(!report.contains("*(u64 *)"), "read-only scalar constants should be rendered as double literals:\n{report}");
        let converted = text(Fixture::c(binary, signed)?)?;
        assert!(converted.contains("(f64)(i64)"), "signed integer-to-double conversion:\n{converted}");
        assert!(converted.contains("(i64)("), "double-to-signed-integer truncation:\n{converted}");

        let converted_integer = text(Fixture::c(binary, integer_rodata)?)?;
        assert!(converted_integer.contains("*(u64 *)"), "integer memory operand must remain integer-valued:\n{converted_integer}");
        assert!(!converted_integer.contains("1000.0"), "cvtsi2sd must not reinterpret an integer constant as an f64:\n{converted_integer}");

        let converted_u64 = text(Fixture::c(binary, unsigned)?)?;
        assert!(converted_u64.contains("(f64)(u64)(arg_0)"), "recognized exact uint64 conversion idiom:\n{converted_u64}");
        assert!(!converted_u64.contains("punpckldq"), "the recognized conversion is lifted instead of left as SIMD comments:\n{converted_u64}");
        let slice = text(Fixture::slice(binary, unsigned, slice_site)?)?;
        assert!(slice.contains(&format!("fp_{slice_site:x} =")), "slice retains a value at the requested addsd site:\n{slice}");
        assert!(slice.contains("(f64)(u64)(arg_0)"), "slice follows the xmm conversion dependency to its integer source:\n{slice}");
        assert!(!slice.contains("punpckldq"), "slice omits unrelated implementation instructions once their dataflow is lifted:\n{slice}");

        let near_miss_text = text(Fixture::c(binary, near_miss)?)?;
        assert!(near_miss_text.contains("punpckldq"), "a changed magic constant must remain visible as unsupported SIMD:\n{near_miss_text}");
        assert!(!near_miss_text.contains("(f64)(u64)(arg_0)"), "near-miss constants must not be claimed as a conversion:\n{near_miss_text}");
    }
    Ok(())
}
