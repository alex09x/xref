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

/// Runs `check` on `tests/fixtures/f64_abi.c` built with `cc -O2`, then with `-march=x86-64-v3`
/// (VEX three-operand scalar forms: `vmulsd xmm0, xmm0, xmm1`, `vcvtss2sd`, `vcvtsi2sd`).
fn for_each_march(tag: &str, check: fn(&Path) -> Result<(), Box<dyn Error>>) -> Result<(), Box<dyn Error>> {
    for march in [None, Some("-march=x86-64-v3")] {
        let build = Build::new(tag)?;
        let mut cc = Command::new("cc");
        cc.arg("-O2").args(march);
        let binary = build.compile(&mut cc, "tests/fixtures/f64_abi.c", "f64-abi")?;
        eprintln!("cc -O2 {}", march.unwrap_or_default());
        check(&binary)?;
    }
    Ok(())
}

#[test]
fn f64_abi_cc_o2_double_and_float_params_and_returns() -> Result<(), Box<dyn Error>> {
    for_each_march("cc", check_params_and_returns)
}

fn check_params_and_returns(binary: &Path) -> Result<(), Box<dyn Error>> {
    let syms = symbols(binary)?;

    let report = c(binary, syms["scale"])?;
    let sig = signature(&report, "scale");
    assert!(sig.starts_with("f64 scale("), "double return:\n{report}");
    assert!(sig.contains(" arg_0, f64 arg_f0, f32 arg_f1)"), "long, then double and float params:\n{report}");
    let rets = returns(&report);
    assert_eq!(rets.len(), 1, "{report}");
    for operand in ["arg_0", "arg_f0", "arg_f1"] {
        assert!(rets[0].contains(operand), "return uses {operand}:\n{report}");
    }

    let report = c(binary, syms["halve"])?;
    let sig = signature(&report, "halve");
    assert!(sig.starts_with("f32 halve(f32 arg_f0)"), "float return and param:\n{report}");
    let rets = returns(&report);
    assert!(rets.len() == 1 && rets[0].contains("arg_f0") && rets[0].contains("0.5f"), "{report}");

    // The variadic prologue's xmm0..xmm7 spills are not parameters, in the callee or its caller.
    let report = c(binary, syms["log_msg"])?;
    assert!(!signature(&report, "log_msg").is_empty(), "{report}");
    assert!(!report.contains("arg_f"), "variadic register-save spills are not float params:\n{report}");
    let report = c(binary, syms["call_log"])?;
    assert!(!signature(&report, "call_log").is_empty(), "{report}");
    assert!(!report.contains("arg_f"), "the caller passes no float values:\n{report}");
    Ok(())
}

#[test]
fn f64_abi_cc_o2_void_store_keeps_void_despite_xmm0_leftover() -> Result<(), Box<dyn Error>> {
    for_each_march("cc-void", check_void_store)
}

fn check_void_store(binary: &Path) -> Result<(), Box<dyn Error>> {
    let syms = symbols(binary)?;

    // *p = x * y; ret: xmm0 still holds the product, but main never reads it after the call.
    for (name, ty) in [("store2", "f64"), ("store_f32", "f32")] {
        let report = c(binary, syms[name])?;
        let sig = signature(&report, name);
        assert!(sig.starts_with(&format!("void {name}(")), "{name} stays void:\n{report}");
        assert!(sig.contains(&format!("{ty} arg_f0, {ty} arg_f1)")), "{name} float params:\n{report}");
        assert!(report.contains(&format!("*({ty} *)")), "{name} stores through a {ty} pointer:\n{report}");
        assert!(!returns(&report).iter().any(|r| r.contains("fp_") || r.contains("arg_f")), "{report}");
    }

    // At the call sites in main the calls are statements, not f64/f32 values.
    let report = c(binary, syms["main"])?;
    for name in ["store2", "store_f32"] {
        // Call sites name the callee by its symbol or by its address.
        let callee = [format!("{name}("), format!("fn_{:x}(", syms[name])];
        let call = report
            .lines()
            .map(str::trim)
            .find(|l| callee.iter().any(|c| l.contains(c.as_str())))
            .ok_or_else(|| format!("no call to {name}:\n{report}"))?;
        assert!(callee.iter().any(|c| call.starts_with(c.as_str())), "the call to {name} is a statement:\n{report}");
    }

    // triple's result goes straight into `call rax`: an indirect callee may read it, so it stays f64.
    let report = c(binary, syms["triple"])?;
    assert!(signature(&report, "triple").starts_with("f64 triple("), "{report}");
    Ok(())
}

/// Trimmed statement lines of the body, without comments and declarations of locals.
fn statements(report: &str) -> Vec<&str> {
    report
        .lines()
        .map(str::trim)
        .filter(|l| {
            (!l.is_empty() && !l.starts_with("/*") && !l.starts_with('*') && !l.ends_with('{')) || l.starts_with("if (")
        })
        .collect()
}

/// Where `x` lives across the call to `scale` in `after_call`: a copy made before the call (`f64
/// fp_K = arg_f0;`) that reaches the product directly or through the register carried into the
/// branch (`zmmN = fp_K;`, GCC's IPA-RA keeps it in an xmm register the callee never writes), or a
/// stack slot stored from `arg_f0` before the call.
fn saved_before_call(lines: &[&str], call: usize, branch: usize, operand: &str) -> bool {
    let copy_of_x = |name: &str| lines[..call].iter().any(|l| *l == format!("f64 {name} = arg_f0;"));
    if operand.starts_with("fp_") {
        return copy_of_x(operand);
    }
    if operand.starts_with("slot_") {
        return lines[..call].iter().any(|l| *l == format!("{operand} = arg_f0;"));
    }
    operand.starts_with("zmm")
        && lines[call..branch]
            .iter()
            .any(|l| l.strip_prefix(&format!("{operand} = ")).and_then(|v| v.strip_suffix(';')).is_some_and(copy_of_x))
}

#[test]
fn f64_abi_cc_o2_float_values_cross_branches_and_calls() -> Result<(), Box<dyn Error>> {
    for_each_march("cc-flow", check_values_cross_branches_and_calls)
}

fn check_values_cross_branches_and_calls(binary: &Path) -> Result<(), Box<dyn Error>> {
    let syms = symbols(binary)?;

    // x = x * x; if (n) x += 3.0; return x;
    let report = c(binary, syms["branchy"])?;
    assert!(signature(&report, "branchy").starts_with("f64 branchy("), "{report}");
    let lines = statements(&report);
    let pos = |pred: &dyn Fn(&str) -> bool| lines.iter().position(|l| pred(l));
    let square = pos(&|l| l == "arg_f0 = (arg_f0 * arg_f0);");
    let branch = pos(&|l| l.starts_with("if ("));
    let add = pos(&|l| l.starts_with("arg_f0 = (arg_f0 + 3.0)"));
    assert!(square.is_some() && square < branch && branch < add, "x*x reaches the add:\n{report}");
    assert_eq!(returns(&report), vec!["return arg_f0;"], "returns the carried value:\n{report}");

    // y = scale(x, 2.0f, n); if (n > 1) y = y * x; return y;
    let report = c(binary, syms["after_call"])?;
    assert!(signature(&report, "after_call").starts_with("f64 after_call("), "{report}");
    let lines = statements(&report);
    // `scale` or its GCC clone, called with n, x and the 2.0f constant; its result becomes y.
    let call = lines.iter().position(|l| l.starts_with("arg_f0 = ") && l.ends_with("(arg_0, arg_f0, 2.0f);"));
    let branch = lines.iter().position(|l| l.starts_with("if ("));
    let (Some(call), Some(branch)) = (call, branch) else { panic!("the call result is carried:\n{report}") };
    assert!(call < branch, "{report}");
    let product = lines[branch..].iter().find_map(|l| l.strip_prefix("arg_f0 = (arg_f0 * ")?.strip_suffix(");"));
    let operand = product.unwrap_or_else(|| panic!("y * x reads the call result:\n{report}"));
    assert!(saved_before_call(&lines, call, branch, operand), "x is the value saved before the call:\n{report}");
    assert_eq!(returns(&report), vec!["return arg_f0;"], "{report}");
    Ok(())
}

#[test]
fn f64_abi_cc_o2_fma_rounding_float_compares_and_zeroing() -> Result<(), Box<dyn Error>> {
    for_each_march("cc-v3", check_v3_shapes)
}

/// `fused` is `vfmadd132sd` at x86-64-v3 (`mulsd; addsd` otherwise), `floor_of` is `vroundsd` (only
/// built with SSE4.1), `smaller` compares floats with `(v)comiss`, and `zero_unless` zeroes xmm0
/// with `(v)xorpd` between the `test` and the branch it decides.
fn check_v3_shapes(binary: &Path) -> Result<(), Box<dyn Error>> {
    let syms = symbols(binary)?;

    let report = c(binary, syms["fused"])?;
    let rets = returns(&report);
    assert_eq!(rets.len(), 1, "{report}");
    for operand in ["arg_f0", "arg_f1", "arg_f2"] {
        assert!(rets[0].contains(operand), "a * b + c uses {operand}:\n{report}");
    }
    assert!(!report.contains("/* vf"), "the FMA is lifted:\n{report}");

    if let Some(&floor_of) = syms.get("floor_of") {
        let report = c(binary, floor_of)?;
        assert_eq!(returns(&report), vec!["return floor(arg_f0);"], "{report}");
    }

    let report = c(binary, syms["smaller"])?;
    assert!(report.contains("isnan(arg_f1) || isnan(arg_f0)"), "a float compare with NaN cases:\n{report}");
    assert!(!report.contains("isnan(arg_f1, ") && !report.contains("comiss"), "{report}");
    // #161: the taken path returns `arg_f0` untouched in xmm0, so both paths return a value.
    assert!(report.lines().any(|l| l.starts_with("f32 smaller(f32 arg_f0, f32 arg_f1)")), "{report}");
    let values = returns(&report);
    assert!(!values.is_empty() && values.iter().all(|r| !r.starts_with("return;")), "{report}");
    for void in ["store2", "store_f32"] {
        let report = c(binary, syms[void])?;
        assert!(report.lines().any(|l| l.starts_with(&format!("void {void}("))), "{report}");
    }

    let report = c(binary, syms["zero_unless"])?;
    assert!(
        report.contains("if (arg_0 != 0)") || report.contains("if (arg_0 == 0)"),
        "the test survives the xor:\n{report}"
    );
    assert!(!report.contains("if (0"), "{report}");
    Ok(())
}
