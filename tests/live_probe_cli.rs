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
fn tracefs_watchdog_survives_foreground_process_group_sigint_and_cleans_up() -> TestResult {
    use std::io::{BufRead, BufReader};
    use std::os::unix::process::{CommandExt, ExitStatusExt};
    use std::time::{Duration, Instant};

    let root = temp_cli_dir("watchdog-pgrp-sigint")?;
    let uprobe_events = root.join("uprobe_events");
    std::fs::write(&uprobe_events, "p:foreign/keep_me /bin/ls:0x200\np:xp_sig/xp_sig_0 /bin/true:0x100\n")?;
    let inst = root.join("instances/xref_888_sigint");

    let mut parent_cmd = Command::new(xref_bin());
    parent_cmd
        .args([
            "live",
            "tracefs-watchdog",
            "--parent-test-hold",
            "--tracefs-root",
            &root.to_string_lossy(),
            "--instance",
            "xref_888_sigint",
            "--event",
            "xp_sig/xp_sig_0",
        ])
        .process_group(0)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null());
    let mut parent = parent_cmd.spawn()?;

    let stdout = parent.stdout.take().ok_or("missing parent stdout")?;
    let mut reader = BufReader::new(stdout);
    let mut ready_line = String::new();
    let n = reader.read_line(&mut ready_line)?;
    assert!(n > 0 && ready_line.starts_with("ARMED pid="), "unexpected readiness line: {ready_line}");
    assert!(inst.exists(), "instance directory must exist while parent holds session");

    // Deliver SIGINT to the entire foreground process group (-pgid == -parent.id()).
    // Because CleanupSupervisor isolates the watchdog via process_group(0), only the parent dies on SIGINT;
    // the parent's open instance FD closes on exit and pipe EOF wakes the watchdog to clean up!
    let neg_pgid = format!("-{}", parent.id());
    let kill_out = Command::new("kill").args(["-s", "INT", "--", &neg_pgid]).output()?;
    assert!(kill_out.status.success(), "kill -INT {neg_pgid} failed: {}", String::from_utf8_lossy(&kill_out.stderr));

    let parent_status = parent.wait()?;
    assert_eq!(parent_status.signal(), Some(2), "expected parent termination by SIGINT (2), got {parent_status}");

    let deadline = Instant::now() + Duration::from_secs(2);
    while inst.exists() && Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(20));
    }
    assert!(!inst.exists(), "isolated watchdog must remove instance dir after foreground process-group SIGINT");

    // Wait briefly in case the append to uprobe_events happens right after rmdir.
    let mut events_after = String::new();
    while Instant::now() < deadline {
        events_after = std::fs::read_to_string(&uprobe_events)?;
        if events_after.contains("-:xp_sig/xp_sig_0\n") {
            break;
        }
        std::thread::sleep(Duration::from_millis(20));
    }
    assert!(events_after.starts_with("p:foreign/keep_me /bin/ls:0x200\n"), "events_after: {events_after}");
    assert!(events_after.contains("-:xp_sig/xp_sig_0\n"), "events_after: {events_after}");

    let _ = std::fs::remove_dir_all(&root);
    Ok(())
}

#[cfg(target_os = "linux")]
fn spawn_live_target_app(
    dir: &std::path::Path,
) -> Result<(std::process::Child, std::collections::BTreeMap<String, String>), Box<dyn Error>> {
    use std::collections::BTreeMap;
    use std::io::{BufRead, BufReader};

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
    Ok((target, meta))
}

#[cfg(target_os = "linux")]
#[test]
fn live_rust_fixture_probe_validates_target_and_reports_honest_backend_status() -> TestResult {
    use std::path::Path;

    let dir = temp_cli_dir("live-app")?;
    let (mut target, meta) = spawn_live_target_app(&dir)?;
    let pid = target.id().to_string();
    let fn_ptr = meta.get("fn_va").ok_or("missing fn_va")?;

    // 1. Non-executable address (`heap_va` in heap) must fail target validation BEFORE kernel attachment!
    let heap_addr = meta.get("heap_va").ok_or("missing heap_va")?;
    let bad_target = Command::new(xref_bin())
        .args(["live", "probe", "--pid", &pid, "--duration-ms", "50", "--json", heap_addr])
        .output()?;
    assert!(!bad_target.status.success());
    let bad_err = String::from_utf8_lossy(&bad_target.stderr);
    assert!(
        bad_err.contains("outside the target ELF executable") || bad_err.contains("executable"),
        "expected non-code target rejection before backend attach, got: {bad_err}"
    );

    // 2. Default `--backend perf`: validates ELF/maps/iced-x86/gimli and reaches perf_event_open
    //    with zero silent fallback to tracefs on EACCES/EPERM.
    let perf_out = Command::new(xref_bin())
        .args(["live", "probe", "--pid", &pid, "--callers", "--regs", "--duration-ms", "60", "--json", fn_ptr])
        .output()?;
    if perf_out.status.success() {
        let parsed: serde_json::Value = serde_json::from_slice(&perf_out.stdout)?;
        assert_eq!(parsed["operation"], "live_probe");
        assert_eq!(parsed["backend"], "perf");
        assert_eq!(parsed["backend_selection"], "perf");
        assert_eq!(parsed["capabilities"]["pid_isolated_breakpoint"]["collected"], true);
        assert_eq!(parsed["capabilities"]["silent_fallback_permitted"], false);
        assert_eq!(parsed["probes"].as_array().map(Vec::len), Some(1));
    } else {
        let stderr = String::from_utf8_lossy(&perf_out.stderr);
        if Path::new("/sys/bus/event_source/devices/uprobe/type").exists() {
            assert!(
                stderr.contains("permission_denied: perf_event_open")
                    && stderr.contains("perf_event_paranoid=")
                    && stderr.contains("refusing silent fallback to tracefs"),
                "expected honest perf_event_open permission_denied diagnostic without fallback, got: {stderr}"
            );
        } else {
            assert!(stderr.contains("unsupported_uprobe_pmu:"), "unexpected perf error: {stderr}");
        }
    }

    // 3. Explicit `--backend tracefs`: reaches tracefs directly and reports its own capability/permission boundary.
    let tracefs_out = Command::new(xref_bin())
        .args([
            "live",
            "probe",
            "--backend",
            "tracefs",
            "--pid",
            &pid,
            "--callers",
            "--regs",
            "--duration-ms",
            "60",
            "--json",
            fn_ptr,
        ])
        .output()?;
    if tracefs_out.status.success() {
        let parsed: serde_json::Value = serde_json::from_slice(&tracefs_out.stdout)?;
        assert_eq!(parsed["operation"], "live_probe");
        assert_eq!(parsed["backend"], "tracefs");
        assert_eq!(parsed["backend_selection"], "tracefs");
        assert_eq!(parsed["capabilities"]["pid_isolated_breakpoint"]["collected"], false);
        assert_eq!(parsed["capabilities"]["silent_fallback_permitted"], false);
        assert_eq!(parsed["probes"].as_array().map(Vec::len), Some(1));
    } else {
        let stderr = String::from_utf8_lossy(&tracefs_out.stderr);
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
