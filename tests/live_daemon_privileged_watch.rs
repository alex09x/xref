/*
 * XRef — Stage L3 privileged hardware data watchpoint (`DR0`–`DR3`) E2E verification
 * Copyright (c) 2026 Alexander Panasenko
 * Contact: alex@prod.codes
 * Author: https://prod.codes/about/
 * Project: https://github.com/alex09x/xref
 * SPDX-License-Identifier: MIT OR Apache-2.0
 */

//! Verifies real Linux `PERF_TYPE_BREAKPOINT` hardware write watchpoints (`DR0`–`DR3`) against
//! the live stripped daemon (`tests/fixtures/live_daemon_app.rs`) when `sudo -n true` is available:
//! - Discovers `DaemonVault` on the heap via `xref live memscan` without DWARF/symbols.
//! - Arms 4 simultaneous 8-byte hardware write watchpoints (`DR0`–`DR3`) on:
//!   `tx_seq` (+16), `raw_balance` (+32), `sealed_balance` (+40), and `epoch_key` (+48).
//! - Drives `DEPOSIT 777 500000`, `ROTATE 0x99`, `DEPOSIT 777 250000` after `watch_ready`.
//! - Asserts exact store counts (`[3, 2, 3, 1]`), post-execution `trap_ip` attribution to the
//!   preceding store instruction in `execute_deposit` / `execute_rotate`, proven register store
//!   value recovery (`PERF_SAMPLE_REGS_INTR`), and before/after `/proc/<pid>/mem` snapshots.
//! - Verifies CLI preflight rejections (`>4` watchpoints, unaligned addresses, non-writable region).

#[path = "fixtures/live_daemon_harness.rs"]
mod live_daemon_harness;

use std::error::Error;
use std::process::Command;

use live_daemon_harness::{
    ArmedProbe, LiveDaemon, TestResult, discover_six_probe_targets, memscan_vault_json, run_xref,
};

fn sudo_nopasswd_available() -> bool {
    Command::new("sudo").args(["-n", "true"]).status().is_ok_and(|s| s.success())
}

fn parse_hex_u64(s: &str) -> Result<u64, Box<dyn Error>> {
    Ok(u64::from_str_radix(s.trim().trim_start_matches("0x").trim_start_matches("0X"), 16)?)
}

fn find_word_va(ctx: &[serde_json::Value], rel_off: i64) -> Result<String, Box<dyn Error>> {
    Ok(ctx
        .iter()
        .find(|w| w["relative_offset"].as_i64() == Some(rel_off))
        .ok_or_else(|| format!("missing context word at offset {rel_off}"))?["runtime_va"]
        .as_str()
        .ok_or("missing runtime_va")?
        .to_owned())
}

fn verify_watch_preflight_errors(dpid: &str, base_rw_va: u64, ro_va: &str) -> TestResult {
    let unaligned = format!("0x{:x}", base_rw_va + 4);
    let out_unaligned = run_xref(&["live", "watch", "--pid", dpid, "--len", "8", "--json", &unaligned])?;
    assert!(!out_unaligned.status.success(), "unaligned 8B watch must fail");
    let err_u = String::from_utf8_lossy(&out_unaligned.stderr);
    assert!(err_u.contains("unaligned_watch_address"), "unexpected stderr: {err_u}");

    let out_ro = run_xref(&["live", "watch", "--pid", dpid, "--len", "8", "--access", "write", "--json", ro_va])?;
    assert!(!out_ro.status.success(), "write watch on non-writable code/rodata must fail");
    let err_ro = String::from_utf8_lossy(&out_ro.stderr);
    assert!(err_ro.contains("non_writable_watch_region"), "unexpected stderr: {err_ro}");

    let a0 = format!("0x{base_rw_va:x}");
    let a1 = format!("0x{:x}", base_rw_va + 8);
    let a2 = format!("0x{:x}", base_rw_va + 16);
    let a3 = format!("0x{:x}", base_rw_va + 24);
    let a4 = format!("0x{:x}", base_rw_va + 32);
    let out_cap = run_xref(&["live", "watch", "--pid", dpid, "--json", &a0, &a1, &a2, &a3, &a4])?;
    assert!(!out_cap.status.success(), ">4 watchpoints must fail preflight");
    let err_cap = String::from_utf8_lossy(&out_cap.stderr);
    assert!(err_cap.contains("DR0..DR3"), "unexpected stderr: {err_cap}");
    Ok(())
}

fn parse_asm_insns(asm_text: &str) -> (Option<u64>, Vec<(u64, String)>) {
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

fn assert_writer_site_in_asm(site: &serde_json::Value, asm_text: &str) -> TestResult {
    let writer_s = parse_hex_u64(site["candidate_writer_static_ip"].as_str().ok_or("no writer_static_ip")?)?;
    let trap_s = parse_hex_u64(site["trap_static_ip"].as_str().ok_or("no trap_static_ip")?)?;
    let mnem = site["candidate_writer_mnemonic"].as_str().ok_or("no writer mnemonic")?;
    let (fn_end, insns) = parse_asm_insns(asm_text);
    let idx = insns
        .iter()
        .position(|(va, _)| *va == writer_s)
        .ok_or_else(|| format!("candidate_writer_static_ip 0x{writer_s:x} is not an instruction start in asm"))?;
    if insns[idx].1 != mnem {
        return Err(format!("asm mnemonic '{}' != site mnemonic '{mnem}' at 0x{writer_s:x}", insns[idx].1).into());
    }
    let next_va = insns.get(idx + 1).map(|(va, _)| *va).or(fn_end);
    if next_va != Some(trap_s) {
        return Err(
            format!("trap_static_ip 0x{trap_s:x} != next instruction after 0x{writer_s:x} ({next_va:x?})").into()
        );
    }
    Ok(())
}

#[test]
fn live_daemon_privileged_hardware_watchpoints_dr0_dr3_e2e() -> TestResult {
    if !cfg!(all(target_os = "linux", target_arch = "x86_64")) || !sudo_nopasswd_available() {
        return Ok(());
    }

    let mut daemon = LiveDaemon::compile_and_start()?;
    let targets = discover_six_probe_targets(&mut daemon)?;
    let dep_fn_va = &targets[0];
    let rot_fn_va = &targets[1];
    let dpid_str = daemon.pid.to_string();

    // Discover heap DaemonVault after initial DEPOSIT + ROTATE from discover_six_probe_targets
    // (at this point: tx_seq=2, raw_balance=500000, epoch_key=0x99).
    let scan = memscan_vault_json(&dpid_str)?;
    let hits = scan["hits"].as_array().ok_or("missing hits")?;
    let heap_hit = hits
        .iter()
        .find(|h| {
            h["context"]
                .as_array()
                .is_some_and(|c| c.iter().any(|w| w["relative_offset"] == 56 && w["kind"] == "code_ptr"))
        })
        .ok_or("missing heap DaemonVault hit")?;
    let ctx = heap_hit["context"].as_array().ok_or("missing context")?;

    let va_tx_seq = find_word_va(ctx, 16)?;
    let va_raw_bal = find_word_va(ctx, 32)?;
    let va_sealed_bal = find_word_va(ctx, 40)?;
    let va_epoch_key = find_word_va(ctx, 48)?;
    let watch_addrs = [va_tx_seq.as_str(), va_raw_bal.as_str(), va_sealed_bal.as_str(), va_epoch_key.as_str()];

    // Verify unprivileged preflight validations before arming hardware breakpoints.
    verify_watch_preflight_errors(&dpid_str, parse_hex_u64(&va_tx_seq)?, dep_fn_va)?;

    // Arm all 4 hardware write watchpoints (DR0..DR3) with --regs.
    let extra = ["--regs", watch_addrs[0], watch_addrs[1], watch_addrs[2], watch_addrs[3]];
    let armed = ArmedProbe::spawn_watch(&dpid_str, "1200", &extra)?;
    let receipt = armed.wait_watch_ready(daemon.pid, 1, &watch_addrs)?;
    assert_eq!(receipt["access"].as_str(), Some("write"));
    assert_eq!(receipt["len_bytes"].as_u64(), Some(8));

    // Drive 3 mutations after watch_ready:
    // 1. DEPOSIT 777 100000 -> writes tx_seq (3), raw_balance (600000), sealed_balance
    // 2. ROTATE 0xaa        -> writes tx_seq (4), epoch_key (0xaa), sealed_balance
    // 3. DEPOSIT 777 50000  -> writes tx_seq (5), raw_balance (650000), sealed_balance
    daemon.send_cmd("DEPOSIT 777 100000")?;
    daemon.send_cmd("ROTATE 0xaa")?;
    daemon.send_cmd("DEPOSIT 777 50000")?;

    let report = armed.finish("perf_breakpoint")?;
    assert_eq!(report["operation"].as_str(), Some("live_watch"));
    assert_eq!(report["backend"].as_str(), Some("perf_breakpoint"));
    assert_eq!(report["capabilities"]["pid_isolated_watchpoint"]["collected"].as_bool(), Some(true));
    assert_eq!(report["observation"]["lost_events"]["total"].as_u64(), Some(0));
    assert_eq!(report["observation"]["counts_are_lower_bound"].as_bool(), Some(false));

    let watches = report["watches"].as_array().ok_or("missing watches array")?;
    assert_eq!(watches.len(), 4);

    // Expected hits across the 3 operations:
    // tx_seq (+16): 3 writes (2 deposits + 1 rotate)
    // raw_balance (+32): 2 writes (2 deposits)
    // sealed_balance (+40): 3 writes (2 deposits + 1 rotate)
    // epoch_key (+48): 1 write (1 rotate)
    let actual_hits: Vec<u64> = watches.iter().filter_map(|w| w["accepted_hits"].as_u64()).collect();
    assert_eq!(actual_hits, vec![3, 2, 3, 1], "unexpected DR0..DR3 watch hit counts: {watches:#?}");

    // Verify before/after snapshots on tx_seq (2 -> 5), raw_balance (500000 -> 650000), epoch_key (0x99 -> 0xaa)
    assert_eq!(watches[0]["initial_snapshot"].as_str(), Some("0x2"));
    assert_eq!(watches[0]["latest_snapshot"].as_str(), Some("0x5"));
    assert_eq!(watches[0]["snapshot_changed"].as_bool(), Some(true));

    assert_eq!(watches[1]["initial_snapshot"].as_str(), Some("0x7a120")); // 500_000
    assert_eq!(watches[1]["latest_snapshot"].as_str(), Some("0x9eb10")); // 650_000
    assert_eq!(watches[1]["snapshot_changed"].as_bool(), Some(true));

    assert_eq!(watches[3]["initial_snapshot"].as_str(), Some("0x99"));
    assert_eq!(watches[3]["latest_snapshot"].as_str(), Some("0xaa"));
    assert_eq!(watches[3]["snapshot_changed"].as_bool(), Some(true));

    let bin_str = daemon.bin_path.to_str().ok_or("non-utf8 path")?;
    let dep_asm = String::from_utf8_lossy(&run_xref(&["--bin", bin_str, "asm", dep_fn_va])?.stdout).into_owned();
    let rot_asm = String::from_utf8_lossy(&run_xref(&["--bin", bin_str, "asm", rot_fn_va])?.stdout).into_owned();

    // Verify writer attribution:
    // tx_seq (watches[0]) is written by execute_deposit (2 hits) and execute_rotate (1 hit).
    let tx_sites = watches[0]["writer_sites"].as_array().ok_or("missing tx_seq writer_sites")?;
    assert_eq!(tx_sites.len(), 2);
    assert!(tx_sites.iter().any(|s| s["writer_function"].as_str() == Some(dep_fn_va) && s["hits"].as_u64() == Some(2)));
    assert!(tx_sites.iter().any(|s| s["writer_function"].as_str() == Some(rot_fn_va) && s["hits"].as_u64() == Some(1)));
    for site in tx_sites {
        assert_eq!(site["confidence"].as_str(), Some("verified_linear_predecessor_store"));
        if site["writer_function"].as_str() == Some(dep_fn_va) {
            assert_writer_site_in_asm(site, &dep_asm)?;
        } else {
            assert_writer_site_in_asm(site, &rot_asm)?;
        }
    }

    // Verify epoch_key (watches[3]) is written exclusively by execute_rotate (1 hit) with proven value 0xaa.
    let ek_sites = watches[3]["writer_sites"].as_array().ok_or("missing epoch_key writer_sites")?;
    assert_eq!(ek_sites.len(), 1);
    assert_eq!(ek_sites[0]["writer_function"].as_str(), Some(rot_fn_va.as_str()));
    assert_eq!(ek_sites[0]["hits"].as_u64(), Some(1));
    assert_writer_site_in_asm(&ek_sites[0], &rot_asm)?;
    let ek_sample = &watches[3]["samples"][0];
    assert_eq!(ek_sample["written_value"]["status"].as_str(), Some("proven_register_store"));
    assert_eq!(ek_sample["written_value"]["value"].as_str(), Some("0xaa"));
    assert!(ek_sample["regs"].is_object(), "expected --regs 16-GPR snapshot on watch sample");

    daemon.shutdown()?;
    Ok(())
}
