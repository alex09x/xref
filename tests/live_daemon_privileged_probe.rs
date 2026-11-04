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
use std::path::Path;
use std::process::Command;

use live_daemon_harness::{ArmedProbe, LiveDaemon, TestResult, discover_six_probe_targets, run_xref};

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

fn check_cleanup_against_sets(receipt: &serde_json::Value, inst_set: &BTreeSet<&str>, up_lines: &[&str]) -> TestResult {
    if let Some(inst) = receipt["tracefs_instance"].as_str() {
        if inst.is_empty() {
            return Err("tracefs receipt must record non-empty tracefs_instance".into());
        }
        if inst_set.contains(inst) {
            return Err(format!("session tracefs_instance {inst} was not removed").into());
        }
    }
    if let Some(events) = receipt["uprobe_events"].as_array() {
        if events.is_empty() {
            return Err("tracefs receipt must record non-empty uprobe_events".into());
        }
        for ev_val in events {
            let ev = ev_val.as_str().ok_or("non-str event in receipt")?;
            if up_lines.iter().any(|line| line.contains(ev)) {
                return Err(format!("session uprobe_event {ev} still present in uprobe_events").into());
            }
        }
    }
    Ok(())
}

fn verify_session_owned_cleanup(receipt: &serde_json::Value) -> TestResult {
    let inst_raw = sudo_cmd_checked(&["ls", "/sys/kernel/tracing/instances"])?;
    let up_raw = sudo_cmd_checked(&["cat", "/sys/kernel/tracing/uprobe_events"])?;
    let inst_set: BTreeSet<&str> = inst_raw.lines().map(str::trim).filter(|s| !s.is_empty()).collect();
    let up_lines: Vec<&str> = up_raw.lines().collect();
    check_cleanup_against_sets(receipt, &inst_set, &up_lines)
}

fn parse_hex_u64(s: &str) -> Result<u64, Box<dyn Error>> {
    Ok(u64::from_str_radix(s.trim().trim_start_matches("0x").trim_start_matches("0X"), 16)?)
}

fn parse_asm_listing(asm_text: &str) -> (Option<u64>, Vec<(u64, String)>) {
    let mut fn_end = None;
    let mut insns = Vec::new();
    for line in asm_text.lines() {
        let trimmed = line.trim();
        if let Some(range) = trimmed.strip_prefix("function ") {
            if let Some((_, end_hex)) = range.split_once("..") {
                fn_end = parse_hex_u64(end_hex).ok();
            }
            continue;
        }
        let mut toks = trimmed.split_whitespace();
        let Some(addr_tok) = toks.next() else { continue };
        let Some(mnem_tok) = toks.next() else { continue };
        if let Ok(va) = parse_hex_u64(addr_tok.trim_end_matches(':')) {
            insns.push((va, mnem_tok.to_ascii_lowercase()));
        }
    }
    (fn_end, insns)
}

fn assert_caller_row(probe: &serde_json::Value, caller_fn: &str, expected_hits: u64, asm_text: &str) -> TestResult {
    if probe["unwind_entry_abi"]["kind"] != "standard_rsp8_ra_minus8" {
        return Err("unexpected unwind_entry_abi kind".into());
    }
    let callers = probe["callers"].as_array().ok_or("missing callers array")?;
    let row = callers
        .iter()
        .find(|c| c["caller_function"].as_str() == Some(caller_fn))
        .ok_or_else(|| format!("missing caller {caller_fn} in {callers:?}"))?;
    if row["hits"].as_u64() != Some(expected_hits) || row["call_verified"].as_bool() != Some(true) {
        return Err(format!("caller row mismatch for {caller_fn}: {row}").into());
    }
    if !row["caveat"].as_str().is_some_and(|s| s.contains("tail_call")) {
        return Err("missing tail_call caveat on caller row".into());
    }
    let site_va = parse_hex_u64(row["call_site_static_va"].as_str().ok_or("missing call_site_static_va")?)?;
    let ret_va = parse_hex_u64(row["return_static_va"].as_str().ok_or("missing return_static_va")?)?;
    let (fn_end, insns) = parse_asm_listing(asm_text);
    let idx = insns
        .iter()
        .position(|(va, _)| *va == site_va)
        .ok_or_else(|| format!("call_site_static_va 0x{site_va:x} is not an instruction start in {caller_fn}"))?;
    if insns[idx].1 != "call" {
        return Err(format!("instruction at 0x{site_va:x} is '{}', expected 'call'", insns[idx].1).into());
    }
    let expected_ret = insns.get(idx + 1).map(|(va, _)| *va).or(fn_end);
    if expected_ret != Some(ret_va) {
        return Err(format!("return_static_va 0x{ret_va:x} != end of CALL 0x{site_va:x} ({expected_ret:x?})").into());
    }
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
fn unit_gate_helpers_reject_operand_addr_and_allow_foreign_same_pid_session() -> TestResult {
    let fake_probe = serde_json::json!({
        "unwind_entry_abi": { "kind": "standard_rsp8_ra_minus8" },
        "callers": [{
            "caller_function": "0x1000",
            "call_site_static_va": "0x2000",
            "return_static_va": "0x1005",
            "call_verified": true,
            "hits": 1,
            "caveat": "caller_attributed_from_stack_return_address_subject_to_tail_call_or_inlining"
        }]
    });
    let asm = "function 0x1000..0x1006\n0x1000  call 0x2000\n0x1005  ret\n";
    assert!(assert_caller_row(&fake_probe, "0x1000", 1, asm).is_err(), "must reject operand address 0x2000");

    let valid_probe = serde_json::json!({
        "unwind_entry_abi": { "kind": "standard_rsp8_ra_minus8" },
        "callers": [{
            "caller_function": "0x1000",
            "call_site_static_va": "0x1000",
            "return_static_va": "0x1005",
            "call_verified": true,
            "hits": 1,
            "caveat": "caller_attributed_from_stack_return_address_subject_to_tail_call_or_inlining"
        }]
    });
    assert_caller_row(&valid_probe, "0x1000", 1, asm)?;

    let receipt = serde_json::json!({
        "tracefs_instance": "xref_123_OWN",
        "uprobe_events": ["xp_OWN/event_0"]
    });
    let foreign_inst = BTreeSet::from(["xref_123_FOREIGN"]);
    let foreign_up = ["p:other/keep /bin/true:0x100"];
    check_cleanup_against_sets(&receipt, &foreign_inst, &foreign_up)?;

    let leaked_inst = BTreeSet::from(["xref_123_OWN"]);
    assert!(check_cleanup_against_sets(&receipt, &leaked_inst, &foreign_up).is_err());
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

        let probe = ArmedProbe::spawn(&dpid, backend, "1400", &args)?;
        let receipt = probe.wait_ready(backend, d.pid, 1, &target_refs)?;

        assert_eq!(d.send_cmd("DEPOSIT 777 500000")?, "ACK op=DEPOSIT seq=1");
        assert_eq!(d.send_cmd("ROTATE 0x99")?, "ACK op=ROTATE seq=2");
        assert_eq!(d.send_cmd("DEPOSIT 777 250000")?, "ACK op=DEPOSIT seq=3");

        let rep = probe.finish(backend)?;
        assert_eq!(d.send_cmd("PING")?, "PONG seq=3");
        d.shutdown()?;

        verify_session_owned_cleanup(&receipt)?;

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
    let probe = ArmedProbe::spawn(&dpid, backend, "1200", &["--regs", anchor_va])?;
    let receipt = probe.wait_ready(backend, d.pid, 2, &[anchor_va])?;

    assert_eq!(d.send_cmd("WORKER_RUN 4")?, "ACK op=WORKER_RUN count=4");
    assert!(d.send_cmd("FORK_CHILD 5")?.starts_with("ACK op=FORK_CHILD"));

    let rep = probe.finish(backend)?;
    d.shutdown()?;
    verify_session_owned_cleanup(&receipt)?;

    assert_eq!(rep["observation"]["thread_coverage"]["seeded_tids"], 2);
    assert_eq!(rep["probes"][0]["accepted_hits"], 4);
    Ok(())
}

fn verify_post_arm_worker_and_short_thread(bin_path: &Path, anchor_va: &str, backend: &str) -> TestResult {
    let sub_dir = std::env::temp_dir().join(format!("xref-live-dyn-{backend}-{}", std::process::id()));
    std::fs::create_dir_all(&sub_dir)?;
    let mut d = LiveDaemon::start_from_existing_bin(sub_dir, bin_path.to_path_buf())?;
    let dpid = d.pid.to_string();
    let probe = ArmedProbe::spawn(&dpid, backend, "1200", &[anchor_va])?;
    let receipt = probe.wait_ready(backend, d.pid, 1, &[anchor_va])?;

    assert_eq!(d.send_cmd("WORKER_PREPARE")?, "ACK op=WORKER_PREPARE");
    if backend == "perf" {
        let attached_tid = probe.wait_tid_attached(backend, d.pid)?;
        assert_ne!(attached_tid, d.pid, "dynamic TID delta must identify the spawned worker");
    }
    assert_eq!(d.send_cmd("WORKER_RUN 3")?, "ACK op=WORKER_RUN count=3");
    assert_eq!(d.send_cmd("WORKER_SHORT 2")?, "ACK op=WORKER_SHORT count=2");

    let rep = probe.finish(backend)?;
    d.shutdown()?;
    verify_session_owned_cleanup(&receipt)?;

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
