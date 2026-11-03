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
//! - Session-owned cleanup receipts (`instances/xref_*` and `uprobe_events` before/after).

use std::collections::BTreeSet;
use std::error::Error;
use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};
use std::process::{Child, ChildStdin, ChildStdout, Command, Output, Stdio};
use std::time::Duration;

type TestResult = Result<(), Box<dyn Error>>;

const fn xref_bin() -> &'static str {
    env!("CARGO_BIN_EXE_xref")
}

fn daemon_fixture_src() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/live_daemon_app.rs")
}

struct LiveDaemon {
    dir: PathBuf,
    bin_path: PathBuf,
    pid: u32,
    stdin: Option<ChildStdin>,
    reader: Option<BufReader<ChildStdout>>,
    child: Option<Child>,
}

impl LiveDaemon {
    fn compile_and_start() -> Result<Self, Box<dyn Error>> {
        let nonce = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH)?.as_nanos();
        let dir = std::env::temp_dir().join(format!("xref-live-pprobe-{}-{nonce}", std::process::id()));
        std::fs::create_dir_all(&dir)?;
        let bin_path = dir.join("live_daemon_app");
        let rustc = std::env::var("RUSTC").unwrap_or_else(|_| "rustc".to_owned());

        let compile = Command::new(rustc)
            .args(["--edition=2021", "-O", "-C", "strip=symbols"])
            .arg(daemon_fixture_src())
            .arg("-o")
            .arg(&bin_path)
            .output()?;
        if !compile.status.success() {
            let _ = std::fs::remove_dir_all(&dir);
            return Err(format!("rustc daemon build failed: {}", String::from_utf8_lossy(&compile.stderr)).into());
        }
        Self::start_from_existing_bin(dir, bin_path)
    }

    fn start_from_existing_bin(dir: PathBuf, bin_path: PathBuf) -> Result<Self, Box<dyn Error>> {
        let mut child =
            Command::new(&bin_path).stdin(Stdio::piped()).stdout(Stdio::piped()).stderr(Stdio::piped()).spawn()?;
        let stdin = child.stdin.take().ok_or("missing daemon stdin")?;
        let stdout = child.stdout.take().ok_or("missing daemon stdout")?;
        let mut reader = BufReader::new(stdout);
        let mut banner = String::new();
        reader.read_line(&mut banner)?;
        let pid: u32 = banner
            .trim()
            .strip_prefix("DAEMON_READY pid=")
            .ok_or_else(|| format!("unexpected daemon banner: {banner}"))?
            .parse()?;
        Ok(Self { dir, bin_path, pid, stdin: Some(stdin), reader: Some(reader), child: Some(child) })
    }

    fn send_cmd(&mut self, cmd: &str) -> Result<String, Box<dyn Error>> {
        let stdin = self.stdin.as_mut().ok_or("daemon stdin closed")?;
        writeln!(stdin, "{cmd}")?;
        stdin.flush()?;
        let reader = self.reader.as_mut().ok_or("daemon stdout closed")?;
        let mut reply = String::new();
        reader.read_line(&mut reply)?;
        Ok(reply.trim().to_owned())
    }

    fn shutdown(&mut self) -> TestResult {
        if self.stdin.is_some() {
            let reply = self.send_cmd("QUIT")?;
            assert!(reply.starts_with("BYE "), "unexpected QUIT reply: {reply}");
            self.stdin = None;
        }
        if let Some(mut child) = self.child.take() {
            let _ = child.wait()?;
        }
        Ok(())
    }
}

impl Drop for LiveDaemon {
    fn drop(&mut self) {
        if let Some(mut child) = self.child.take() {
            let _ = child.kill();
            let _ = child.wait();
        }
        if self.dir.exists() {
            let _ = std::fs::remove_dir_all(&self.dir);
        }
    }
}

fn run_xref(args: &[&str]) -> Result<Output, Box<dyn Error>> {
    Ok(Command::new(xref_bin()).args(args).output()?)
}

fn sudo_nopasswd_available() -> bool {
    Command::new("sudo").args(["-n", "true"]).status().is_ok_and(|s| s.success())
}

fn sudo_cmd_out(args: &[&str]) -> String {
    Command::new("sudo")
        .arg("-n")
        .args(args)
        .output()
        .map(|o| String::from_utf8_lossy(&o.stdout).into_owned())
        .unwrap_or_default()
}

fn snapshot_tracefs_state() -> (BTreeSet<String>, BTreeSet<String>) {
    let inst = sudo_cmd_out(&["ls", "/sys/kernel/tracing/instances"]).lines().map(str::to_owned).collect();
    let up = sudo_cmd_out(&["cat", "/sys/kernel/tracing/uprobe_events"]).lines().map(str::to_owned).collect();
    (inst, up)
}

fn wait_until_probe_armed(sudo_child_pid: u32, daemon_pid: u32, backend: &str, expected_fds: usize) {
    for _ in 0..200 {
        if backend == "tracefs" {
            let ls = sudo_cmd_out(&["ls", "/sys/kernel/tracing/instances"]);
            if ls.lines().any(|inst| {
                inst.starts_with(&format!("xref_{daemon_pid}_"))
                    && sudo_cmd_out(&["cat", &format!("/sys/kernel/tracing/instances/{inst}/tracing_on")]).trim() == "1"
            }) {
                return;
            }
        } else {
            let pgrep = Command::new("pgrep")
                .args(["-P", &sudo_child_pid.to_string()])
                .output()
                .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_owned())
                .unwrap_or_default();
            let xpid = pgrep.lines().next().unwrap_or("");
            if !xpid.is_empty()
                && sudo_cmd_out(&["ls", "-l", &format!("/proc/{xpid}/fd")]).matches("perf_event").count()
                    >= expected_fds
            {
                std::thread::sleep(Duration::from_millis(40));
                return;
            }
        }
        std::thread::sleep(Duration::from_millis(20));
    }
    panic!("timed out waiting for {backend} probes to arm on pid {daemon_pid}");
}

fn first_va_from_output(out: &[u8]) -> Result<String, Box<dyn Error>> {
    let text = String::from_utf8_lossy(out);
    let tok = text.split_whitespace().next().ok_or("empty output")?;
    Ok(tok.trim_end_matches(':').split("..").next().ok_or("empty range")?.to_owned())
}

fn memscan_vault_json(dpid: &str) -> Result<serde_json::Value, Box<dyn Error>> {
    let args = ["live", "memscan", "--pid", dpid, "--after-words", "10", "--json"];
    let sigs = ["0x4441454d4f4e5632", "0x778899aabbccddee"];
    let out = Command::new(xref_bin()).args(args).args(sigs).output()?;
    Ok(serde_json::from_slice(&out.stdout)?)
}

fn spawn_sudo_probe(dpid: &str, backend: &str, dur_ms: &str, extra: &[&str]) -> std::io::Result<Child> {
    let base = ["-n", xref_bin(), "live", "probe", "--pid", dpid, "--backend", backend];
    let opts = ["--duration-ms", dur_ms, "--max-events", "256", "--json"];
    Command::new("sudo").args(base).args(opts).args(extra).stdout(Stdio::piped()).stderr(Stdio::piped()).spawn()
}

fn discover_six_probe_targets(disc: &mut LiveDaemon) -> Result<[String; 6], Box<dyn Error>> {
    let bin_str = disc.bin_path.to_str().ok_or("non-utf8 path")?.to_owned();
    let dpid_str = disc.pid.to_string();

    let dep_va =
        first_va_from_output(&run_xref(&["--bin", &bin_str, "find", "--refs", "DAEMON_OP_DEPOSIT_V2"])?.stdout)?;
    let rot_va =
        first_va_from_output(&run_xref(&["--bin", &bin_str, "find", "--refs", "DAEMON_OP_ROTATE_V2"])?.stdout)?;

    disc.send_cmd("DEPOSIT 777 500000")?;
    let scan1 = memscan_vault_json(&dpid_str)?;
    let hits1 = scan1["hits"].as_array().ok_or("missing hits1")?;
    let heap1 = hits1
        .iter()
        .find(|h| {
            h["context"]
                .as_array()
                .is_some_and(|c| c.iter().any(|w| w["relative_offset"] == 56 && w["kind"] == "code_ptr"))
        })
        .ok_or("missing heap1")?;
    let ctx1 = heap1["context"].as_array().ok_or("missing ctx1")?;
    let fast_va = ctx1.iter().find(|w| w["relative_offset"] == 56).ok_or("no +56")?["target_function"]
        .as_str()
        .ok_or("no target_function")?
        .to_owned();
    let vtable_cands = ctx1
        .iter()
        .find(|w| (w["relative_offset"] == 72 || w["relative_offset"] == 80) && w["kind"] == "relro_ptr_candidate")
        .ok_or("no vtable")?["candidate_targets"]
        .as_array()
        .ok_or("no candidate_targets")?;
    let mut mac_va = String::new();
    for cand in vtable_cands {
        let va = cand.as_str().ok_or("non-str cand")?;
        let c_res = run_xref(&["--bin", &bin_str, "c", va])?;
        let c_out = String::from_utf8_lossy(&c_res.stdout).to_ascii_lowercase();
        if c_out.contains("55aa77cc") || c_out.contains("1437235148") {
            va.clone_into(&mut mac_va);
            break;
        }
    }
    disc.send_cmd("ROTATE 0x99")?;
    let scan2 = memscan_vault_json(&dpid_str)?;
    let hits2 = scan2["hits"].as_array().ok_or("missing hits2")?;
    let heap2 = hits2.iter().find(|h| h["runtime_va"] == heap1["runtime_va"]).ok_or("missing heap2")?;
    let strict_va = heap2["context"]
        .as_array()
        .ok_or("missing ctx2")?
        .iter()
        .find(|w| w["relative_offset"] == 56)
        .ok_or("no +56")?["target_function"]
        .as_str()
        .ok_or("no strict target_function")?
        .to_owned();

    let dep_c_out = run_xref(&["--bin", &bin_str, "c", &dep_va])?;
    let dep_c = String::from_utf8_lossy(&dep_c_out.stdout);
    let anchor_hex = dep_c
        .lines()
        .skip(1)
        .find_map(|line| {
            let rest = line.trim().strip_prefix("fn_")?;
            Some(format!("0x{}", rest.split_once('(')?.0))
        })
        .ok_or_else(|| format!("could not find direct call fn_<hex>(...) in decompiled execute_deposit:\n{dep_c}"))?;

    Ok([dep_va, rot_va, fast_va, strict_va, mac_va, anchor_hex])
}

#[test]
fn live_daemon_privileged_kernel_uprobe_perf_and_tracefs_e2e() -> TestResult {
    use serde_json::Value;
    if !cfg!(target_os = "linux") || !sudo_nopasswd_available() {
        return Ok(());
    }

    let mut disc = LiveDaemon::compile_and_start()?;
    let bin_path = disc.bin_path.clone();
    let targets = discover_six_probe_targets(&mut disc)?;
    disc.shutdown()?;

    for backend in ["perf", "tracefs"] {
        let (base_inst, base_up) = snapshot_tracefs_state();
        let sub_dir = std::env::temp_dir().join(format!("xref-live-run-{backend}-{}", std::process::id()));
        std::fs::create_dir_all(&sub_dir)?;
        let mut d = LiveDaemon::start_from_existing_bin(sub_dir, bin_path.clone())?;
        let dpid = d.pid.to_string();
        let mut args = vec!["--callers", "--regs"];
        args.extend(targets.iter().map(String::as_str));

        let child = spawn_sudo_probe(&dpid, backend, "1400", &args)?;
        wait_until_probe_armed(child.id(), d.pid, backend, targets.len());

        assert_eq!(d.send_cmd("DEPOSIT 777 500000")?, "ACK op=DEPOSIT seq=1");
        assert_eq!(d.send_cmd("ROTATE 0x99")?, "ACK op=ROTATE seq=2");
        assert_eq!(d.send_cmd("DEPOSIT 777 250000")?, "ACK op=DEPOSIT seq=3");

        let out = child.wait_with_output()?;
        assert!(out.status.success(), "{backend} probe failed: {}", String::from_utf8_lossy(&out.stderr));
        assert_eq!(d.send_cmd("PING")?, "PONG seq=3");
        d.shutdown()?;

        let (after_inst, after_up) = snapshot_tracefs_state();
        assert_eq!(after_inst, base_inst, "{backend} left tracefs instances behind");
        assert_eq!(after_up, base_up, "{backend} left uprobe_events behind");

        let rep: Value = serde_json::from_slice(&out.stdout)?;
        assert_eq!(rep["observation"]["stop_reason"], "duration_elapsed");
        assert_eq!(rep["observation"]["lost_events"]["total"], 0);
        assert_eq!(rep["observation"]["counts_are_lower_bound"], false);

        let probes = rep["probes"].as_array().ok_or("missing probes")?;
        let hits: Vec<u64> = probes.iter().map(|p| p["accepted_hits"].as_u64().unwrap_or(0)).collect();
        assert_eq!(hits, vec![2, 1, 1, 2, 3, 3], "{backend} expected [2, 1, 1, 2, 3, 3] hits");

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
    use serde_json::Value;

    let sub_dir = std::env::temp_dir().join(format!("xref-live-wf-{backend}-{}", std::process::id()));
    std::fs::create_dir_all(&sub_dir)?;
    let mut d = LiveDaemon::start_from_existing_bin(sub_dir, bin_path.to_path_buf())?;
    assert_eq!(d.send_cmd("WORKER_PREPARE")?, "ACK op=WORKER_PREPARE");

    let dpid = d.pid.to_string();
    let child = spawn_sudo_probe(&dpid, backend, "1200", &["--regs", anchor_va])?;
    wait_until_probe_armed(child.id(), d.pid, backend, 2);

    assert_eq!(d.send_cmd("WORKER_RUN 4")?, "ACK op=WORKER_RUN count=4");
    let fork_reply = d.send_cmd("FORK_CHILD 5")?;
    assert!(fork_reply.starts_with("ACK op=FORK_CHILD"));

    let out = child.wait_with_output()?;
    assert!(out.status.success());
    d.shutdown()?;

    let rep: Value = serde_json::from_slice(&out.stdout)?;
    assert_eq!(rep["observation"]["thread_coverage"]["seeded_tids"], 2);
    assert_eq!(rep["probes"][0]["accepted_hits"], 4);
    Ok(())
}

fn verify_post_arm_worker_and_short_thread(bin_path: &Path, anchor_va: &str, backend: &str) -> TestResult {
    use serde_json::Value;

    let sub_dir = std::env::temp_dir().join(format!("xref-live-dyn-{backend}-{}", std::process::id()));
    std::fs::create_dir_all(&sub_dir)?;
    let mut d = LiveDaemon::start_from_existing_bin(sub_dir, bin_path.to_path_buf())?;
    let dpid = d.pid.to_string();
    let child = spawn_sudo_probe(&dpid, backend, "1200", &[anchor_va])?;
    wait_until_probe_armed(child.id(), d.pid, backend, 1);

    assert_eq!(d.send_cmd("WORKER_PREPARE")?, "ACK op=WORKER_PREPARE");
    if backend == "perf" {
        wait_until_probe_armed(child.id(), d.pid, backend, 2);
    }
    assert_eq!(d.send_cmd("WORKER_RUN 3")?, "ACK op=WORKER_RUN count=3");
    assert_eq!(d.send_cmd("WORKER_SHORT 2")?, "ACK op=WORKER_SHORT count=2");

    let out = child.wait_with_output()?;
    assert!(out.status.success());
    d.shutdown()?;

    let rep: Value = serde_json::from_slice(&out.stdout)?;
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
