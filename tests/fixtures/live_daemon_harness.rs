/*
 * XRef — Shared test harness for compiling, running, and inspecting live_daemon_app
 * Copyright (c) 2026 Alexander Panasenko
 * Contact: alex@prod.codes
 * Author: https://prod.codes/about/
 * Project: https://github.com/alex09x/xref
 * SPDX-License-Identifier: MIT OR Apache-2.0
 */

use std::error::Error;
use std::io::{BufRead, BufReader, Write};
use std::path::PathBuf;
use std::process::{Child, ChildStdin, ChildStdout, Command, Output, Stdio};

pub type TestResult = Result<(), Box<dyn Error>>;

pub const fn xref_bin() -> &'static str {
    env!("CARGO_BIN_EXE_xref")
}

pub fn daemon_fixture_src() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/live_daemon_app.rs")
}

pub struct LiveDaemon {
    pub dir: PathBuf,
    pub bin_path: PathBuf,
    pub pid: u32,
    stdin: Option<ChildStdin>,
    reader: Option<BufReader<ChildStdout>>,
    child: Option<Child>,
}

impl LiveDaemon {
    pub fn compile_and_start() -> Result<Self, Box<dyn Error>> {
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

    pub fn start_from_existing_bin(dir: PathBuf, bin_path: PathBuf) -> Result<Self, Box<dyn Error>> {
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

    pub fn send_cmd(&mut self, cmd: &str) -> Result<String, Box<dyn Error>> {
        let stdin = self.stdin.as_mut().ok_or("daemon stdin closed")?;
        writeln!(stdin, "{cmd}")?;
        stdin.flush()?;
        let reader = self.reader.as_mut().ok_or("daemon stdout closed")?;
        let mut reply = String::new();
        reader.read_line(&mut reply)?;
        Ok(reply.trim().to_owned())
    }

    pub fn shutdown(&mut self) -> TestResult {
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

pub fn run_xref(args: &[&str]) -> Result<Output, Box<dyn Error>> {
    Ok(Command::new(xref_bin()).args(args).output()?)
}

pub fn first_va_from_output(out: &[u8]) -> Result<String, Box<dyn Error>> {
    let text = String::from_utf8_lossy(out);
    let tok = text.split_whitespace().next().ok_or("empty output")?;
    Ok(tok.trim_end_matches(':').split("..").next().ok_or("empty range")?.to_owned())
}

pub fn memscan_vault_json(dpid: &str) -> Result<serde_json::Value, Box<dyn Error>> {
    let args = ["live", "memscan", "--pid", dpid, "--after-words", "10", "--json"];
    let sigs = ["0x4441454d4f4e5632", "0x778899aabbccddee"];
    let out = Command::new(xref_bin()).args(args).args(sigs).output()?;
    Ok(serde_json::from_slice(&out.stdout)?)
}

pub fn discover_six_probe_targets(disc: &mut LiveDaemon) -> Result<[String; 6], Box<dyn Error>> {
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
