/*
 * XRef — Controlled privileged kernel uprobe E2E verification (perf & tracefs)
 * Copyright (c) 2026 Alexander Panasenko
 * Contact: alex@prod.codes
 * Author: https://prod.codes/about/
 * Project: https://github.com/alex09x/xref
 * SPDX-License-Identifier: MIT OR Apache-2.0
 */

//! Verifies real Linux kernel uprobes (`--backend perf` and `--backend tracefs`) against the live
//! stripped daemon (`tests/fixtures/live_daemon_app.rs`) when `sudo -n true` is available:
//! - Exact 6-probe dispatch table (`execute_deposit=2`, `execute_rotate=1`, `fast_seal_hook=1`,
//!   `strict_seal_hook=2`, `SipAuditEngine::compute_mac=3`, `xref_abi_anchor=3`) with `--callers`
//!   and `--regs` verified against the compiled stripped binary.
//! - Multi-thread & process isolation (`WORKER_PREPARE`/`WORKER_RUN`, post-arm worker,
//!   `WORKER_SHORT`, `FORK_CHILD`).
//! - Session-owned cleanup receipts (`tracefs_instance` and `uprobe_events` from `probe_ready`).

#[path = "fixtures/live_daemon_harness.rs"]
mod live_daemon_harness;

use std::collections::BTreeSet;
use std::error::Error;
use std::io::{BufRead, BufReader, Read};
use std::path::Path;
use std::process::{Child, ChildStderr, Command, Stdio};

use live_daemon_harness::{LiveDaemon, TestResult, discover_six_probe_targets, run_xref, xref_bin};

fn sudo_nopasswd_available() -> bool {
    Command::new("sudo").args(["-n", "true"]).status().is_ok_and(|s| s.success())
}

fn sudo_cmd_checked(args: &[&str]) -> Result<String, Box<dyn Error>> {
    let out = Command::new("sudo").arg("-n").args(args).output()?;
    if !out.status.success() {
        return Err(format!("sudo -n {:?} failed: {}", args, String::from_utf8_lossy(&out.stderr)).into());
    }
    Ok(String::from_utf8_lossy(&out.stdout).into_owned())
}

fn verify_session_owned_cleanup(receipt: &serde_json::Value, daemon_pid: u32) -> TestResult {
    let inst_raw = sudo_cmd_checked(&["ls", "/sys/kernel/tracing/instances"])?;
    let up_raw = sudo_cmd_checked(&["cat", "/sys/kernel/tracing/uprobe_events"])?;
    let inst_set: BTreeSet<&str> = inst_raw.lines().map(str::trim).filter(|s| !s.is_empty()).collect();
    let up_lines: Vec<&str> = up_raw.lines().collect();

    let pid_prefix = format!("xref_{daemon_pid}_");
    assert!(
        !inst_set.iter().any(|i| i.starts_with(&pid_prefix)),
        "leftover instance for pid {daemon_pid}: {inst_set:?}"
    );

    if let Some(inst) = receipt["tracefs_instance"].as_str() {
        assert!(!inst.is_empty(), "tracefs receipt must record non-empty tracefs_instance");
        assert!(!inst_set.contains(inst), "session tracefs_instance {inst} was not removed");
    }
    if let Some(events) = receipt["uprobe_events"].as_array() {
        assert!(!events.is_empty(), "tracefs receipt must record non-empty uprobe_events");
        for ev_val in events {
            let ev = ev_val.as_str().ok_or("non-str event in receipt")?;
            assert!(
                !up_lines.iter().any(|line| line.contains(ev)),
                "session uprobe_event {ev} still present in uprobe_events: {up_lines:?}"
            );
        }
    }
    Ok(())
}

struct ArmedProbe {
    child: Child,
    stderr: BufReader<ChildStderr>,
}

impl ArmedProbe {
    fn spawn(dpid: &str, backend: &str, dur_ms: &str, extra: &[&str]) -> Result<Self, Box<dyn Error>> {
        let base = ["-n", xref_bin(), "live", "probe", "--pid", dpid, "--backend", backend];
        let opts = ["--duration-ms", dur_ms, "--max-events", "256", "--json"];
        let mut child = Command::new("sudo")
            .args(base)
            .args(opts)
            .args(extra)
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()?;
        let stderr = BufReader::new(child.stderr.take().ok_or("missing probe stderr")?);
        Ok(Self { child, stderr })
    }

    fn wait_ready(
        &mut self,
        backend: &str,
        pid: u32,
        expected_tids: usize,
        expected_probes: &[&str],
    ) -> Result<serde_json::Value, Box<dyn Error>> {
        let mut line = String::new();
        loop {
            line.clear();
            let n = self.stderr.read_line(&mut line)?;
            if n == 0 {
                return Err(format!("observer exited before emitting probe_ready for {backend} pid={pid}").into());
            }
            if let Some(json_str) = line.trim().strip_prefix("xref: probe_ready ") {
                let rec: serde_json::Value = serde_json::from_str(json_str)?;
                assert_eq!(rec["backend"].as_str(), Some(backend));
                assert_eq!(rec["pid"].as_u64(), Some(u64::from(pid)));
                let probes: Vec<&str> =
                    rec["probes"].as_array().ok_or("no probes")?.iter().filter_map(|v| v.as_str()).collect();
                assert_eq!(probes, expected_probes, "probe_ready target list mismatch");
                let tids = rec["attached_tids"].as_array().ok_or("no attached_tids")?;
                if tids.len() >= expected_tids {
                    return Ok(rec);
                }
            }
        }
    }

    fn finish(mut self, backend: &str) -> Result<serde_json::Value, Box<dyn Error>> {
        let mut rem_err = String::new();
        let _ = self.stderr.read_to_string(&mut rem_err);
        let mut out_bytes = Vec::new();
        if let Some(mut stdout) = self.child.stdout.take() {
            stdout.read_to_end(&mut out_bytes)?;
        }
        let status = self.child.wait()?;
        assert!(status.success(), "{backend} probe failed ({status}): {rem_err}");
        Ok(serde_json::from_slice(&out_bytes)?)
    }
}

fn assert_caller_row(probe: &serde_json::Value, caller_fn: &str, expected_hits: u64, asm_text: &str) -> TestResult {
    assert_eq!(probe["unwind_entry_abi"]["kind"], "standard_rsp8_ra_minus8");
    let callers = probe["callers"].as_array().ok_or("missing callers array")?;
    let row = callers
        .iter()
        .find(|c| c["caller_function"].as_str() == Some(caller_fn))
        .ok_or_else(|| format!("missing caller {caller_fn} in {callers:?}"))?;
    assert_eq!(row["hits"].as_u64(), Some(expected_hits));
    assert_eq!(row["call_verified"].as_bool(), Some(true));
    assert!(row["return_static_va"].as_str().is_some());
    assert!(row["caveat"].as_str().is_some_and(|s| s.contains("tail_call")));
    let site_hex = row["call_site_static_va"].as_str().ok_or("missing call_site_static_va")?;
    let site_no_prefix = site_hex.trim_start_matches("0x");
    assert!(
        asm_text.lines().any(|l| l.contains(site_no_prefix) && l.to_ascii_lowercase().contains("call")),
        "call_site_static_va {site_hex} not found as CALL in asm of {caller_fn}:\n{asm_text}"
    );
    Ok(())
}

fn verify_callers_against_asm(bin_path: &Path, targets: &[String; 6], probes: &[serde_json::Value]) -> TestResult {
    let bin_str = bin_path.to_str().ok_or("non-utf8 path")?;
    let dep_asm = String::from_utf8_lossy(&run_xref(&["--bin", bin_str, "asm", &targets[0]])?.stdout).into_owned();
    let rot_asm = String::from_utf8_lossy(&run_xref(&["--bin", bin_str, "asm", &targets[1]])?.stdout).into_owned();

    assert_eq!(probes[2]["callers"].as_array().map(Vec::len), Some(1));
    assert_caller_row(&probes[2], &targets[0], 1, &dep_asm)?;

    assert_eq!(probes[3]["callers"].as_array().map(Vec::len), Some(2));
    assert_caller_row(&probes[3], &targets[1], 1, &rot_asm)?;
    assert_caller_row(&probes[3], &targets[0], 1, &dep_asm)?;

    assert_eq!(probes[4]["callers"].as_array().map(Vec::len), Some(2));
    assert_caller_row(&probes[4], &targets[0], 2, &dep_asm)?;
    assert_caller_row(&probes[4], &targets[1], 1, &rot_asm)?;

    assert_eq!(probes[5]["callers"].as_array().map(Vec::len), Some(2));
    assert_caller_row(&probes[5], &targets[0], 2, &dep_asm)?;
    assert_caller_row(&probes[5], &targets[1], 1, &rot_asm)?;
    Ok(())
}

#[test]
fn live_daemon_privileged_kernel_uprobe_perf_and_tracefs_e2e() -> TestResult {
    if !cfg!(target_os = "linux") || !sudo_nopasswd_available() {
        return Ok(());
    }

    let mut disc = LiveDaemon::compile_and_start()?;
    let bin_path = disc.bin_path.clone();
    let targets = discover_six_probe_targets(&mut disc)?;
    disc.shutdown()?;
    let target_refs: Vec<&str> = targets.iter().map(String::as_str).collect();

    for backend in ["perf", "tracefs"] {
        let sub_dir = std::env::temp_dir().join(format!("xref-live-run-{backend}-{}", std::process::id()));
        std::fs::create_dir_all(&sub_dir)?;
        let mut d = LiveDaemon::start_from_existing_bin(sub_dir, bin_path.clone())?;
        let dpid = d.pid.to_string();
        let mut args = vec!["--callers", "--regs"];
        args.extend(&target_refs);

        let mut probe = ArmedProbe::spawn(&dpid, backend, "1400", &args)?;
        let receipt = probe.wait_ready(backend, d.pid, 1, &target_refs)?;

        assert_eq!(d.send_cmd("DEPOSIT 777 500000")?, "ACK op=DEPOSIT seq=1");
        assert_eq!(d.send_cmd("ROTATE 0x99")?, "ACK op=ROTATE seq=2");
        assert_eq!(d.send_cmd("DEPOSIT 777 250000")?, "ACK op=DEPOSIT seq=3");

        let rep = probe.finish(backend)?;
        assert_eq!(d.send_cmd("PING")?, "PONG seq=3");
        d.shutdown()?;

        verify_session_owned_cleanup(&receipt, d.pid)?;

        assert_eq!(rep["observation"]["stop_reason"], "duration_elapsed");
        assert_eq!(rep["observation"]["lost_events"]["total"], 0);
        assert_eq!(rep["observation"]["counts_are_lower_bound"], false);

        let probes = rep["probes"].as_array().ok_or("missing probes")?;
        let hits: Vec<u64> = probes.iter().map(|p| p["accepted_hits"].as_u64().unwrap_or(0)).collect();
        assert_eq!(hits, vec![2, 1, 1, 2, 3, 3], "{backend} expected [2, 1, 1, 2, 3, 3] hits");
        verify_callers_against_asm(&bin_path, &targets, probes)?;

        let anchor_regs = probes[5]["register_samples"].as_array().ok_or("missing anchor regs")?;
        assert_eq!(anchor_regs[0]["rdi"], "0x309");
        assert_eq!(anchor_regs[0]["rsi"], "0x7a120");
        assert_eq!(anchor_regs[0]["rdx"], "0x1");
        assert_eq!(anchor_regs[1]["rdi"], "0x0");
        assert_eq!(anchor_regs[1]["rsi"], "0x99");
        assert_eq!(anchor_regs[1]["rdx"], "0x2");
        assert_eq!(anchor_regs[2]["rdi"], "0x309");
        assert_eq!(anchor_regs[2]["rsi"], "0x3d090");
        assert_eq!(anchor_regs[2]["rdx"], "0x3");

        verify_worker_and_fork_isolation(&bin_path, &targets[5], backend)?;
        verify_post_arm_worker_and_short_thread(&bin_path, &targets[5], backend)?;
    }

    let _ = std::fs::remove_file(&bin_path);
    Ok(())
}

fn verify_worker_and_fork_isolation(bin_path: &Path, anchor_va: &str, backend: &str) -> TestResult {
    let sub_dir = std::env::temp_dir().join(format!("xref-live-wf-{backend}-{}", std::process::id()));
    std::fs::create_dir_all(&sub_dir)?;
    let mut d = LiveDaemon::start_from_existing_bin(sub_dir, bin_path.to_path_buf())?;
    assert_eq!(d.send_cmd("WORKER_PREPARE")?, "ACK op=WORKER_PREPARE");

    let dpid = d.pid.to_string();
    let mut probe = ArmedProbe::spawn(&dpid, backend, "1200", &["--regs", anchor_va])?;
    let receipt = probe.wait_ready(backend, d.pid, 2, &[anchor_va])?;

    assert_eq!(d.send_cmd("WORKER_RUN 4")?, "ACK op=WORKER_RUN count=4");
    assert!(d.send_cmd("FORK_CHILD 5")?.starts_with("ACK op=FORK_CHILD"));

    let rep = probe.finish(backend)?;
    d.shutdown()?;
    verify_session_owned_cleanup(&receipt, d.pid)?;

    assert_eq!(rep["observation"]["thread_coverage"]["seeded_tids"], 2);
    assert_eq!(rep["probes"][0]["accepted_hits"], 4);
    Ok(())
}

fn verify_post_arm_worker_and_short_thread(bin_path: &Path, anchor_va: &str, backend: &str) -> TestResult {
    let sub_dir = std::env::temp_dir().join(format!("xref-live-dyn-{backend}-{}", std::process::id()));
    std::fs::create_dir_all(&sub_dir)?;
    let mut d = LiveDaemon::start_from_existing_bin(sub_dir, bin_path.to_path_buf())?;
    let dpid = d.pid.to_string();
    let mut probe = ArmedProbe::spawn(&dpid, backend, "1200", &[anchor_va])?;
    let receipt = probe.wait_ready(backend, d.pid, 1, &[anchor_va])?;

    assert_eq!(d.send_cmd("WORKER_PREPARE")?, "ACK op=WORKER_PREPARE");
    if backend == "perf" {
        let _ = probe.wait_ready(backend, d.pid, 2, &[anchor_va])?;
    }
    assert_eq!(d.send_cmd("WORKER_RUN 3")?, "ACK op=WORKER_RUN count=3");
    assert_eq!(d.send_cmd("WORKER_SHORT 2")?, "ACK op=WORKER_SHORT count=2");

    let rep = probe.finish(backend)?;
    d.shutdown()?;
    verify_session_owned_cleanup(&receipt, d.pid)?;

    let hits = rep["probes"][0]["accepted_hits"].as_u64().unwrap_or(0);
    if backend == "tracefs" {
        assert_eq!(hits, 5, "tracefs event-fork must capture all 3 + 2 post-arm thread hits");
    } else {
        assert!(hits >= 3, "perf must capture at least the 3 attached post-arm worker hits, got {hits}");
        assert_eq!(rep["observation"]["thread_coverage"]["partial_coverage"], true);
        assert_eq!(rep["observation"]["counts_are_lower_bound"], true);
    }
    Ok(())
}
