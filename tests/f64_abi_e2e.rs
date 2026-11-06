/*
 * XRef — x86-64 binary analysis and cross-reference tooling
 * Copyright (c) 2026 Alexander Panasenko
 *
 * Contact: alex@prod.codes
 * Author: https://prod.codes/about/
 * Project: https://github.com/alex09x/xref
 * SPDX-License-Identifier: MIT OR Apache-2.0
 */

//! System V SSE calling convention in `xref c`: float parameters in xmm0..xmm7, scalar float
//! returns in xmm0, and f64 call results used as values, on rustc and `cc -O2` binaries.

#![cfg(all(target_os = "linux", target_arch = "x86_64"))]

use object::{Object, ObjectSymbol};
use std::{
    collections::BTreeMap,
    error::Error,
    fs,
    path::{Path, PathBuf},
    process::Command,
    time::{SystemTime, UNIX_EPOCH},
};

struct Build(PathBuf);

impl Build {
    fn new(tag: &str) -> Result<Self, Box<dyn Error>> {
        let nonce = SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos();
        let dir = std::env::temp_dir().join(format!("xref-f64-abi-{tag}-{}-{nonce}", std::process::id()));
        fs::create_dir_all(&dir)?;
        Ok(Self(dir))
    }

    fn compile(&self, command: &mut Command, source: &str, out: &str) -> Result<PathBuf, Box<dyn Error>> {
        let binary = self.0.join(out);
        let output = command.arg(Path::new(env!("CARGO_MANIFEST_DIR")).join(source)).arg("-o").arg(&binary).output()?;
        assert!(output.status.success(), "{}", String::from_utf8_lossy(&output.stderr));
        Ok(binary)
    }

    fn strip(&self, binary: &Path) -> Result<PathBuf, Box<dyn Error>> {
        let stripped = self.0.join("stripped");
        let output = Command::new("objcopy")
            .args(["--strip-all", "--keep-section=.eh_frame"])
            .arg(binary)
            .arg(&stripped)
            .output()?;
        assert!(output.status.success(), "{}", String::from_utf8_lossy(&output.stderr));
        Ok(stripped)
    }
}

impl Drop for Build {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn symbols(binary: &Path) -> Result<BTreeMap<String, u64>, Box<dyn Error>> {
    let bytes = fs::read(binary)?;
    let object = object::File::parse(bytes.as_slice())?;
    Ok(object.symbols().filter_map(|s| Some((s.name().ok()?.to_owned(), s.address()))).collect())
}

fn c(binary: &Path, address: u64) -> Result<String, Box<dyn Error>> {
    let output = Command::new(env!("CARGO_BIN_EXE_xref"))
        .arg("-b")
        .arg(binary)
        .args(["c", &format!("{address:#x}")])
        .output()?;
    if !output.status.success() {
        return Err(String::from_utf8_lossy(&output.stderr).into_owned().into());
    }
    Ok(String::from_utf8(output.stdout)?)
}

fn signature<'a>(report: &'a str, name: &str) -> &'a str {
    report.lines().find(|l| l.contains(&format!(" {name}(")) && l.ends_with('{')).unwrap_or_default()
}

fn returns(report: &str) -> Vec<&str> {
    report.lines().map(str::trim).filter(|l| l.starts_with("return")).collect()
}

const U64_CONVERSION: [&str; 2] = ["(f64)(u64)(arg_0)", "(f64)(u64)arg_0"];

#[test]
fn f64_abi_rustc_float_param_return_store_and_call_site() -> Result<(), Box<dyn Error>> {
    let build = Build::new("rustc")?;
    let mut rustc = Command::new("rustc");
    rustc.args(["-C", "opt-level=3"]);
    let binary = build.compile(&mut rustc, "tests/fixtures/u64_to_f64.rs", "u64-fixture")?;
    let stripped = build.strip(&binary)?;
    let syms = symbols(&binary)?;
    let (div, store, caller) = (syms["conv_div"], syms["conv_div_store"], syms["scaled_quotient"]);

    let report = c(&stripped, div)?;
    let sig = signature(&report, &format!("fn_{div:x}"));
    assert!(sig.starts_with("f64 fn_"), "conv_div returns f64:\n{report}");
    assert!(sig.contains(" arg_0, f64 arg_f0)") && !sig.contains("f64 arg_0"), "integer then float param:\n{report}");
    assert!(report.contains("arg_f0 (xmm0): f64"), "docblock lists the xmm0 parameter:\n{report}");
    let rets = returns(&report);
    assert_eq!(rets.len(), 1, "a single return:\n{report}");
    assert!(
        U64_CONVERSION.iter().any(|conv| rets[0].contains(&format!("{conv} / arg_f0"))),
        "the return divides the u64 conversion of arg_0 by arg_f0:\n{report}"
    );
    assert!(!report.contains("zmm0") && !report.contains("callers ignore rax"), "{report}");

    let report = c(&stripped, store)?;
    let sig = signature(&report, &format!("fn_{store:x}"));
    assert!(sig.starts_with("void fn_") && sig.contains("f64 arg_f0)"), "{report}");
    assert!(
        report.lines().any(|l| l.contains("*(f64 *)")
            && l.contains(" / arg_f0")
            && U64_CONVERSION.iter().any(|conv| l.contains(conv))),
        "the quotient is stored through an f64 pointer:\n{report}"
    );
    assert!(!report.contains("*(u64 *)"), "{report}");

    let report = c(&stripped, caller)?;
    let sig = signature(&report, &format!("fn_{caller:x}"));
    assert!(sig.starts_with("f64 fn_") && sig.contains("f64 arg_f0)"), "{report}");
    let call = format!("fn_{div:x}(arg_0, arg_f0)");
    let call_line = report.lines().find(|l| l.contains(&call)).ok_or_else(|| format!("no call {call}:\n{report}"))?;
    // Either `f64 fp_N = call;` whose name feeds arithmetic, or the call folded into the returned arithmetic.
    let arithmetic = |l: &str| l.contains(" * ") || l.contains(" + ");
    let used_as_value = call_line
        .trim()
        .strip_prefix("f64 ")
        .and_then(|rest| rest.split_once(" = "))
        .map(|(name, _)| name)
        .map_or_else(
            || call_line.trim().starts_with("return") && arithmetic(call_line),
            |name| report.lines().any(|l| l.contains(name) && !l.contains(&call) && arithmetic(l)),
        );
    assert!(used_as_value, "the f64 call result feeds further arithmetic:\n{report}");
    Ok(())
}

#[test]
fn f64_abi_cc_o2_double_and_float_params_and_returns() -> Result<(), Box<dyn Error>> {
    let build = Build::new("cc")?;
    let mut cc = Command::new("cc");
    cc.arg("-O2");
    let binary = build.compile(&mut cc, "tests/fixtures/f64_abi.c", "f64-abi")?;
    let syms = symbols(&binary)?;

    let report = c(&binary, syms["scale"])?;
    let sig = signature(&report, "scale");
    assert!(sig.starts_with("f64 scale("), "double return:\n{report}");
    assert!(sig.contains(" arg_0, f64 arg_f0, f32 arg_f1)"), "long, then double and float params:\n{report}");
    let rets = returns(&report);
    assert_eq!(rets.len(), 1, "{report}");
    for operand in ["arg_0", "arg_f0", "arg_f1"] {
        assert!(rets[0].contains(operand), "return uses {operand}:\n{report}");
    }

    let report = c(&binary, syms["halve"])?;
    let sig = signature(&report, "halve");
    assert!(sig.starts_with("f32 halve(f32 arg_f0)"), "float return and param:\n{report}");
    let rets = returns(&report);
    assert!(rets.len() == 1 && rets[0].contains("arg_f0") && rets[0].contains("0.5f"), "{report}");

    // The variadic prologue's xmm0..xmm7 spills are not parameters, in the callee or its caller.
    let report = c(&binary, syms["log_msg"])?;
    assert!(!signature(&report, "log_msg").is_empty(), "{report}");
    assert!(!report.contains("arg_f"), "variadic register-save spills are not float params:\n{report}");
    let report = c(&binary, syms["call_log"])?;
    assert!(!signature(&report, "call_log").is_empty(), "{report}");
    assert!(!report.contains("arg_f"), "the caller passes no float values:\n{report}");
    Ok(())
}
