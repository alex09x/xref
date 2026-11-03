/*
 * XRef — Stage L2 CLI validation, watchdog pipe-EOF cleanup, and Linux live_target_app probe tests
 * Copyright (c) 2026 Alexander Panasenko
 * Contact: alex@prod.codes
 * Author: https://prod.codes/about/
 * Project: https://github.com/alex09x/xref
 * SPDX-License-Identifier: MIT OR Apache-2.0
 */

use std::error::Error;
#[cfg(target_os = "linux")]
use std::path::PathBuf;
use std::process::Command;
#[cfg(target_os = "linux")]
use std::process::Stdio;
#[cfg(target_os = "linux")]
use std::time::{SystemTime, UNIX_EPOCH};

type TestResult = Result<(), Box<dyn Error>>;

const fn xref_bin() -> &'static str {
    env!("CARGO_BIN_EXE_xref")
}

#[cfg(target_os = "linux")]
fn temp_cli_dir(tag: &str) -> Result<PathBuf, Box<dyn Error>> {
    let nanos = SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos();
    let dir = std::env::temp_dir().join(format!("xref-probe-cli-{tag}-{}-{nanos}", std::process::id()));
    std::fs::create_dir_all(&dir)?;
    Ok(dir)
}

#[test]
fn cli_probe_rejects_invalid_pid_and_out_of_range_duration() -> TestResult {
    let zero_pid = Command::new(xref_bin()).args(["live", "probe", "--pid", "0", "0x401000"]).output()?;
    assert!(!zero_pid.status.success());
    let stderr = String::from_utf8_lossy(&zero_pid.stderr);
    assert!(stderr.contains("invalid --pid 0"), "stderr: {stderr}");

    let bad_dur =
        Command::new(xref_bin()).args(["live", "probe", "--pid", "1", "--duration-ms", "0", "0x401000"]).output()?;
    assert!(!bad_dur.status.success());
    let stderr2 = String::from_utf8_lossy(&bad_dur.stderr);
    assert!(stderr2.contains("--duration-ms 0"), "stderr: {stderr2}");
    Ok(())
}

#[cfg(not(target_os = "linux"))]
#[test]
fn cli_probe_reports_unsupported_platform_on_non_linux() -> TestResult {
    let out = Command::new(xref_bin()).args(["live", "probe", "--pid", "1", "0x401000"]).output()?;
    assert!(!out.status.success());
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(stderr.contains("unsupported_platform"), "stderr: {stderr}");
    Ok(())
}

#[cfg(target_os = "linux")]
#[test]
fn tracefs_watchdog_cleans_up_instance_and_events_on_parent_pipe_eof() -> TestResult {
    let root = temp_cli_dir("watchdog")?;
    let uprobe_events = root.join("uprobe_events");
    std::fs::write(&uprobe_events, "p:foreign/keep_me /bin/ls:0x200\n")?;
    let inst = root.join("instances/xref_777_feedface");
    std::fs::create_dir_all(&inst)?;

    let mut child = Command::new(xref_bin())
        .args([
            "live",
            "tracefs-watchdog",
            "--tracefs-root",
            &root.to_string_lossy(),
            "--instance",
            "xref_777_feedface",
            "--event",
            "xp_feedface/xp_feedface_0",
            "--event",
            "xp_feedface/xp_feedface_1",
        ])
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()?;

    // Simulate abrupt parent termination (closing write end of pipe -> EOF in watchdog).
    drop(child.stdin.take());
    let status = child.wait()?;
    assert!(status.success(), "watchdog exited with {status}");

    assert!(!inst.exists(), "watchdog must remove instance dir on parent pipe EOF");
    let events_after = std::fs::read_to_string(&uprobe_events)?;
    assert!(events_after.starts_with("p:foreign/keep_me /bin/ls:0x200\n"));
    assert!(events_after.contains("-:xp_feedface/xp_feedface_1\n"));
    assert!(events_after.contains("-:xp_feedface/xp_feedface_0\n"));

    let _ = std::fs::remove_dir_all(&root);
    Ok(())
}

#[cfg(target_os = "linux")]
#[test]
fn live_rust_fixture_probe_validates_target_and_reports_honest_tracefs_status() -> TestResult {
    use std::collections::BTreeMap;
    use std::io::{BufRead, BufReader};

    let dir = temp_cli_dir("live-app")?;
    let bin_path = dir.join("live_target_app");
    let fixture = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/live_target_app.rs");
    let rustc = std::env::var("RUSTC").unwrap_or_else(|_| "rustc".to_owned());
    let build = Command::new(rustc)
        .args(["--edition=2021", "-C", "opt-level=2", "-C", "strip=symbols"])
        .arg(&fixture)
        .arg("-o")
        .arg(&bin_path)
        .status()?;
    assert!(build.success(), "failed to compile live_target_app");

    let mut target = Command::new(&bin_path)
        .arg("123456")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()?;
    let stdout = target.stdout.take().ok_or("missing stdout")?;
    let mut reader = BufReader::new(stdout);
    let mut meta = BTreeMap::new();
    let mut line = String::new();
    let n = reader.read_line(&mut line)?;
    assert!(n > 0, "live_target_app exited before READY line");
    let trimmed = line.trim();
    assert!(trimmed.starts_with("READY "), "unexpected banner: {trimmed}");
    for token in trimmed.split_whitespace().skip(1) {
        if let Some((k, v)) = token.split_once('=') {
            meta.insert(k.to_owned(), v.to_owned());
        }
    }
    let pid = target.id().to_string();
    let fn_ptr = meta.get("fn_va").ok_or("missing fn_va")?;

    // 1. Non-executable address (`heap_va` in heap) must fail target validation BEFORE tracefs!
    let heap_addr = meta.get("heap_va").ok_or("missing heap_va")?;
    let bad_target = Command::new(xref_bin())
        .args(["live", "probe", "--pid", &pid, "--duration-ms", "50", "--json", heap_addr])
        .output()?;
    assert!(!bad_target.status.success());
    let bad_err = String::from_utf8_lossy(&bad_target.stderr);
    assert!(
        bad_err.contains("outside the target ELF executable") || bad_err.contains("executable"),
        "expected non-code target rejection before tracefs, got: {bad_err}"
    );

    // 2. Valid stripped Rust function entry (`FN_PTR`) passes ELF/maps/iced-x86/gimli validation and reaches tracefs:
    //    - Under root/tracefs write access: succeeds and emits valid `live_probe` JSON!
    //    - Under unprivileged user (`EACCES`): fails honestly with `permission_denied:` naming tracefs path & errno!
    let probe_out = Command::new(xref_bin())
        .args(["live", "probe", "--pid", &pid, "--callers", "--regs", "--duration-ms", "60", "--json", fn_ptr])
        .output()?;
    if probe_out.status.success() {
        let parsed: serde_json::Value = serde_json::from_slice(&probe_out.stdout)?;
        assert_eq!(parsed["operation"], "live_probe");
        assert_eq!(parsed["backend"], "tracefs");
        assert_eq!(parsed["probes"].as_array().map(Vec::len), Some(1));
    } else {
        let stderr = String::from_utf8_lossy(&probe_out.stderr);
        assert!(
            stderr.contains("permission_denied: tracefs") && stderr.contains("uprobe_events"),
            "expected honest tracefs permission_denied diagnostic on unprivileged host, got: {stderr}"
        );
    }

    drop(target.stdin.take());
    let _ = target.kill();
    let _ = target.wait();
    let _ = std::fs::remove_dir_all(&dir);
    Ok(())
}
