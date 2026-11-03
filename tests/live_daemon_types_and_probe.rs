/*
 * XRef — Rich Rust types live RAM verification E2E tests
 * Copyright (c) 2026 Alexander Panasenko
 * Contact: alex@prod.codes
 * Author: https://prod.codes/about/
 * Project: https://github.com/alex09x/xref
 * SPDX-License-Identifier: MIT OR Apache-2.0
 */

//! Verifies diverse Rust data types in a running stripped daemon's live RAM:
//! - `#[repr(C, u64)]` tagged enum (`VaultCommandEnum`: `Idle -> Deposit -> Rotate`),
//! - packed primitive struct (`FeePolicy`: `u32`, `u16`, `u8`, negative `i64`, `f32`/`f64` bit patterns),
//! - `Vec<u64>` (`empty -> nonempty -> growth`) + following `vec_ptr` into the heap buffer,
//! - `&[u8]` slice with embedded NUL + UTF-8 (`b"XREF\0UTF8_\xF0\x9F\x94\xA5_END!"`).

use std::error::Error;
use std::io::{BufRead, BufReader, Write};
use std::path::PathBuf;
use std::process::{Child, ChildStdin, ChildStdout, Command, Output, Stdio};

type TestResult = Result<(), Box<dyn Error>>;

const fn xref_bin() -> &'static str {
    env!("CARGO_BIN_EXE_xref")
}

fn daemon_fixture_src() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/live_daemon_app.rs")
}

struct LiveDaemon {
    dir: PathBuf,
    pid: u32,
    stdin: Option<ChildStdin>,
    reader: Option<BufReader<ChildStdout>>,
    child: Option<Child>,
}

impl LiveDaemon {
    fn compile_and_start() -> Result<Self, Box<dyn Error>> {
        let nonce = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH)?.as_nanos();
        let dir = std::env::temp_dir().join(format!("xref-live-types-{}-{nonce}", std::process::id()));
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
        Ok(Self { dir, pid, stdin: Some(stdin), reader: Some(reader), child: Some(child) })
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

fn parse_hex_u64(s: &str) -> Result<u64, Box<dyn Error>> {
    let trimmed = s.trim();
    let hex = trimmed.strip_prefix("0x").or_else(|| trimmed.strip_prefix("0X")).unwrap_or(trimmed);
    Ok(u64::from_str_radix(hex, 16)?)
}

fn ctx_u64(ctx: &[serde_json::Value], rel_offset: i64) -> Result<u64, Box<dyn Error>> {
    let word = ctx
        .iter()
        .find(|w| w["relative_offset"].as_i64() == Some(rel_offset))
        .ok_or_else(|| format!("missing relative_offset={rel_offset}"))?;
    parse_hex_u64(word["value"].as_str().ok_or("missing word value")?)
}

#[test]
fn live_daemon_rich_rust_types_enum_primitives_floats_vec_and_slice_e2e() -> TestResult {
    use serde_json::Value;
    if !cfg!(target_os = "linux") {
        return Ok(());
    }

    let mut daemon = LiveDaemon::compile_and_start()?;
    let pid_str = daemon.pid.to_string();
    let ext_hi = "0x5852454654595045";
    let ext_lo = "0x1122334455667788";

    let scan0: Value = serde_json::from_slice(
        &run_xref(&["live", "memscan", "--pid", &pid_str, "--after-words", "13", "--json", ext_hi, ext_lo])?.stdout,
    )?;
    let ctx0 = scan0["hits"][0]["context"].as_array().ok_or("missing ctx0")?;
    assert_eq!(ctx_u64(ctx0, 16)?, 0, "VaultCommandEnum::Idle discriminant must be 0");
    assert_eq!(ctx_u64(ctx0, 48)?, 0, "initial packed u32/u16/u8/u8 word must be 0");
    assert_eq!(ctx_u64(ctx0, 56)?.cast_signed(), -1_i64, "initial multiplier_i64 must be -1");
    assert_eq!(u32::try_from(ctx_u64(ctx0, 64)? & 0xffff_ffff)?, 0.25_f32.to_bits());
    assert_eq!(ctx_u64(ctx0, 72)?, (-123.875_f64).to_bits());
    assert_eq!(ctx_u64(ctx0, 80)?, 0, "empty Vec ptr snapshot must be null");
    assert_eq!(ctx_u64(ctx0, 88)?, 0, "empty Vec cap must be 0");
    assert_eq!(ctx_u64(ctx0, 96)?, 0, "empty Vec len must be 0");
    assert_eq!(ctx_u64(ctx0, 112)?, 19, "&[u8] slice_len with embedded NUL + UTF-8 must be 19");

    assert_eq!(daemon.send_cmd("DEPOSIT 777 500000")?, "ACK op=DEPOSIT seq=1");
    let scan1: Value = serde_json::from_slice(
        &run_xref(&["live", "memscan", "--pid", &pid_str, "--after-words", "13", "--json", ext_hi, ext_lo])?.stdout,
    )?;
    let ctx1 = scan1["hits"][0]["context"].as_array().ok_or("missing ctx1")?;
    assert_eq!(ctx_u64(ctx1, 16)?, 1, "VaultCommandEnum::Deposit discriminant must be 1");
    assert_eq!(ctx_u64(ctx1, 24)?, 777, "Deposit.acct must be 777");
    assert_eq!(ctx_u64(ctx1, 32)?, 500_000, "Deposit.amount must be 500_000");
    let packed_dep_flags = ctx_u64(ctx1, 40)?;
    assert_eq!(u32::try_from(packed_dep_flags & 0xffff_ffff)?, 25);
    assert_eq!(u32::try_from(packed_dep_flags >> 32)?, 0x8000_0001);

    let packed_prim1 = ctx_u64(ctx1, 48)?.to_le_bytes();
    assert_eq!(u32::from_le_bytes(packed_prim1[0..4].try_into()?), u32::MAX);
    assert_eq!(u16::from_le_bytes(packed_prim1[4..6].try_into()?), 0x1234);
    assert_eq!(packed_prim1[6], 1);
    assert_eq!(packed_prim1[7], 0xff);
    assert_eq!(ctx_u64(ctx1, 56)?.cast_signed(), -42_000_000_000_i64);
    assert_eq!(u32::try_from(ctx_u64(ctx1, 64)? & 0xffff_ffff)?, 1.5_f32.to_bits());
    assert_eq!(ctx_u64(ctx1, 72)?, 3.125_f64.to_bits());
    assert_eq!(ctx_u64(ctx1, 96)?, 1);
    assert!(ctx_u64(ctx1, 88)? >= 1);

    verify_rotated_rich_types_and_buffers(&mut daemon, &pid_str, ext_hi, ext_lo)?;
    daemon.shutdown()?;
    Ok(())
}

fn verify_rotated_rich_types_and_buffers(
    daemon: &mut LiveDaemon,
    pid_str: &str,
    ext_hi: &str,
    ext_lo: &str,
) -> TestResult {
    use serde_json::Value;

    assert_eq!(daemon.send_cmd("ROTATE 0x99")?, "ACK op=ROTATE seq=2");
    let scan_rot: Value = serde_json::from_slice(
        &run_xref(&["live", "memscan", "--pid", pid_str, "--after-words", "13", "--json", ext_hi, ext_lo])?.stdout,
    )?;
    let ctx_rot = scan_rot["hits"][0]["context"].as_array().ok_or("missing ctx_rot")?;
    assert_eq!(ctx_u64(ctx_rot, 16)?, 2, "VaultCommandEnum::Rotate discriminant must be 2");
    assert_eq!(ctx_u64(ctx_rot, 24)?, 0x0042_0042);
    assert_eq!(ctx_u64(ctx_rot, 32)?, 0x99);
    assert_eq!(ctx_u64(ctx_rot, 40)?, 0x0102_0304_0506_0708);
    assert_eq!(ctx_u64(ctx_rot, 56)?.cast_signed(), i64::MIN);
    assert_eq!(u32::try_from(ctx_u64(ctx_rot, 64)? & 0xffff_ffff)?, (-0.75_f32).to_bits());
    assert_eq!(ctx_u64(ctx_rot, 72)?, (-9999.0625_f64).to_bits());

    assert_eq!(daemon.send_cmd("DEPOSIT 777 250000")?, "ACK op=DEPOSIT seq=3");
    let scan2: Value = serde_json::from_slice(
        &run_xref(&["live", "memscan", "--pid", pid_str, "--after-words", "13", "--json", ext_hi, ext_lo])?.stdout,
    )?;
    let ctx2 = scan2["hits"][0]["context"].as_array().ok_or("missing ctx2")?;
    let vec_ptr = ctx_u64(ctx2, 80)?;
    let vec_cap = ctx_u64(ctx2, 88)?;
    let vec_len = ctx_u64(ctx2, 96)?;
    assert_eq!(vec_len, 3);
    assert!(vec_cap >= 3);

    let elem0 = (1_u64 << 48) | 0x0007_a120_u64;
    let elem1 = (2_u64 << 48) | 0x99_u64;
    let elem2 = (3_u64 << 48) | 0x0003_d090_u64;
    let vec_scan: Value = serde_json::from_slice(
        &run_xref(&[
            "live",
            "memscan",
            "--pid",
            pid_str,
            "--after-words",
            "2",
            "--json",
            &format!("{elem0:#x}"),
            &format!("{elem1:#x}"),
        ])?
        .stdout,
    )?;
    let vec_hits = vec_scan["hits"].as_array().ok_or("missing vec_hits")?;
    let vec_hit = vec_hits
        .iter()
        .find(|h| parse_hex_u64(h["runtime_va"].as_str().unwrap_or("0x0")).ok() == Some(vec_ptr))
        .ok_or_else(|| format!("expected Vec buffer at runtime_va={vec_ptr:#x}"))?;
    assert_eq!(ctx_u64(vec_hit["context"].as_array().ok_or("missing vctx")?, 16)?, elem2);

    let slice_ptr = ctx_u64(ctx2, 104)?;
    let slice_word0 = u64::from_le_bytes(*b"XREF\0UTF");
    let slice_word1 = u64::from_le_bytes(*b"8_\xF0\x9F\x94\xA5_E");
    let slice_scan: Value = serde_json::from_slice(
        &run_xref(&[
            "live",
            "memscan",
            "--pid",
            pid_str,
            "--after-words",
            "1",
            "--json",
            &format!("{slice_word0:#x}"),
            &format!("{slice_word1:#x}"),
        ])?
        .stdout,
    )?;
    let slice_hits = slice_scan["hits"].as_array().ok_or("missing slice_hits")?;
    assert!(
        slice_hits.iter().any(|h| parse_hex_u64(h["runtime_va"].as_str().unwrap_or("0x0")).ok() == Some(slice_ptr)),
        "expected &[u8] slice with embedded NUL + UTF-8 at slice_ptr={slice_ptr:#x}"
    );
    Ok(())
}
