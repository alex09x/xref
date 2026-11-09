/*
 * XRef — Live Linux procfs inspection and xref-aware memory scanning
 * Copyright (c) 2026 Alexander Panasenko
 * Contact: alex@prod.codes
 * Author: https://prod.codes/about/
 * Project: https://github.com/alex09x/xref
 * SPDX-License-Identifier: MIT OR Apache-2.0
 */

//! Subprocess CLI integration tests for `xref [--bin BIN] live {maps, resolve, memscan}`.

use std::error::Error;
use std::path::PathBuf;
use std::process::{Command, Output};

type TestResult = Result<(), Box<dyn Error>>;

const fn xref_bin() -> &'static str {
    env!("CARGO_BIN_EXE_xref")
}

fn macho_fixture(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(format!("tests/fixtures/macho/{name}.macho"))
}

fn run_xref(args: &[&str]) -> Result<Output, Box<dyn Error>> {
    Ok(Command::new(xref_bin()).args(args).output()?)
}

#[test]
fn static_cli_still_requires_bin_argument() -> TestResult {
    let out = run_xref(&["stats"])?;
    assert!(!out.status.success(), "expected non-zero exit when static command omits --bin");
    assert_eq!(out.status.code(), Some(2));
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(stderr.contains("--bin <BIN>"), "expected clap missing --bin error, got: {stderr}");
    Ok(())
}

#[test]
fn live_cli_help_lists_subcommands_and_flags() -> TestResult {
    let top = run_xref(&["live", "--help"])?;
    assert!(top.status.success(), "live --help failed: {}", String::from_utf8_lossy(&top.stderr));
    let top_stdout = String::from_utf8(top.stdout)?;
    assert!(top_stdout.contains("maps"), "{top_stdout}");
    assert!(top_stdout.contains("resolve"), "{top_stdout}");
    assert!(top_stdout.contains("memscan"), "{top_stdout}");

    let maps_help = run_xref(&["live", "maps", "--help"])?;
    assert!(maps_help.status.success());
    let maps_out = String::from_utf8(maps_help.stdout)?;
    assert!(maps_out.contains("--pid"), "{maps_out}");
    assert!(maps_out.contains("--force-bin"), "{maps_out}");
    assert!(maps_out.contains("--json"), "{maps_out}");

    let resolve_help = run_xref(&["live", "resolve", "--help"])?;
    assert!(resolve_help.status.success());
    let resolve_out = String::from_utf8(resolve_help.stdout)?;
    assert!(resolve_out.contains("--pid"), "{resolve_out}");
    assert!(resolve_out.contains("<ADDR>..."), "{resolve_out}");

    let scan_help = run_xref(&["live", "memscan", "--help"])?;
    assert!(scan_help.status.success());
    let scan_out = String::from_utf8(scan_help.stdout)?;
    for flag in [
        "--pid",
        "--align",
        "--before-words",
        "--after-words",
        "--max-hits",
        "--max-bytes",
        "--timeout-ms",
        "--force-bin",
        "--json",
        "--range",
        "--width",
        "[VALUES]...",
    ] {
        assert!(scan_out.contains(flag), "missing {flag} in:\n{scan_out}");
    }
    Ok(())
}

#[test]
fn live_cli_maps_without_bin_uses_proc_exe_auto_on_linux() -> TestResult {
    let pid_str = std::process::id().to_string();
    let out = run_xref(&["live", "maps", "--pid", &pid_str, "--json"])?;

    #[cfg(target_os = "linux")]
    {
        assert!(
            out.status.success(),
            "expected live maps without --bin to succeed on Linux: {}",
            String::from_utf8_lossy(&out.stderr)
        );
        let payload: serde_json::Value = serde_json::from_slice(&out.stdout)?;
        assert_eq!(payload["schema_version"], 1);
        assert_eq!(payload["process"]["binary_match"], "proc_exe_auto");
        assert!(payload["process"]["exe_sha256"].as_str().is_some_and(|h| h.len() == 64));
    }

    #[cfg(not(target_os = "linux"))]
    {
        assert!(!out.status.success(), "expected non-zero exit on non-Linux");
        let stderr = String::from_utf8_lossy(&out.stderr);
        assert!(stderr.contains("unsupported_platform"), "unexpected non-Linux stderr: {stderr}");
    }

    Ok(())
}

#[test]
fn live_cli_rejects_invalid_align_three() -> TestResult {
    let out = run_xref(&["--bin", xref_bin(), "live", "memscan", "--pid", "1", "--align", "3", "0xdeadbeef"])?;
    assert!(!out.status.success(), "expected non-zero exit for --align 3");
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(stderr.contains("--align") && stderr.contains("1, 2, 4, or 8"), "unexpected stderr: {stderr}");
    Ok(())
}

#[test]
fn live_cli_rejects_macho_binary_input() -> TestResult {
    let macho = macho_fixture("basic");
    let macho_str = macho.to_str().ok_or("non-utf8 macho fixture path")?;
    let out = run_xref(&["--bin", macho_str, "live", "maps", "--pid", "1"])?;
    assert!(!out.status.success(), "expected non-zero exit for Mach-O --bin");
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("live Linux procfs inspection requires an x86-64 ELF binary")
            || stderr.contains("unsupported_platform"),
        "unexpected stderr: {stderr}"
    );
    Ok(())
}

#[test]
fn live_cli_rejects_binary_mismatch_without_force_bin() -> TestResult {
    let pid_str = std::process::id().to_string();
    let out = run_xref(&["--bin", xref_bin(), "live", "maps", "--pid", &pid_str])?;
    assert!(!out.status.success(), "expected non-zero exit when --bin mismatches /proc/<pid>/exe");
    let stderr = String::from_utf8_lossy(&out.stderr);

    #[cfg(target_os = "linux")]
    {
        assert!(
            stderr.contains("binary mismatch") || stderr.contains("--force-bin"),
            "expected binary mismatch error on Linux, got: {stderr}"
        );
        let forced = run_xref(&["--bin", xref_bin(), "live", "maps", "--pid", &pid_str, "--force-bin", "--json"])?;
        assert!(
            forced.status.success(),
            "expected --force-bin to succeed on Linux: {}",
            String::from_utf8_lossy(&forced.stderr)
        );
        let payload: serde_json::Value = serde_json::from_slice(&forced.stdout)?;
        assert_eq!(payload["schema_version"], 1);
        assert_eq!(payload["process"]["binary_match"], "forced_mismatch");

        let tabular = run_xref(&["--bin", xref_bin(), "live", "maps", "--pid", &pid_str, "--force-bin"])?;
        assert!(tabular.status.success());
        let tab_out = String::from_utf8(tabular.stdout)?;
        assert!(tab_out.contains("match forced_mismatch") && tab_out.contains("regions ("), "{tab_out}");
    }

    #[cfg(not(target_os = "linux"))]
    {
        assert!(
            stderr.contains("unsupported_platform") || stderr.contains("requires an x86-64 ELF binary"),
            "unexpected non-Linux stderr: {stderr}"
        );
    }

    Ok(())
}

#[test]
fn live_cli_reports_nonexistent_pid_error() -> TestResult {
    let missing_pid = u32::MAX.to_string();
    let out = run_xref(&["--bin", xref_bin(), "live", "maps", "--pid", &missing_pid, "--force-bin"])?;
    assert!(!out.status.success(), "expected non-zero exit for nonexistent PID");
    let stderr = String::from_utf8_lossy(&out.stderr);

    #[cfg(target_os = "linux")]
    assert!(
        stderr.contains(&missing_pid) && stderr.contains("/proc/"),
        "expected procfs PID error in stderr, got: {stderr}"
    );

    #[cfg(not(target_os = "linux"))]
    assert!(
        stderr.contains("unsupported_platform") || stderr.contains("requires an x86-64 ELF binary"),
        "unexpected non-Linux stderr: {stderr}"
    );

    Ok(())
}
