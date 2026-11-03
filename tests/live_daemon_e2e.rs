/*
 * XRef — Blind reverse-engineering + interactive live daemon memory mutation E2E test
 * Copyright (c) 2026 Alexander Panasenko
 * Contact: alex@prod.codes
 * Author: https://prod.codes/about/
 * Project: https://github.com/alex09x/xref
 * SPDX-License-Identifier: MIT OR Apache-2.0
 */

//! End-to-end test demonstrating a real blind reverse-engineering + live daemon workflow:
//! 1. Compiles `tests/fixtures/live_daemon_app.rs` with `-O -C strip=symbols` (`0` `.symtab` symbols)
//!    and starts it as a background daemon that prints ONLY `DAEMON_READY pid=<pid>`.
//! 2. Uses static `xref` (`find --refs`, `layout`, `c --fields`) on the stripped daemon binary to
//!    discover the command handler functions, reconstruct the `DaemonVault` struct layout, and
//!    extract the 64-bit vault signature constants directly from decompiled pseudo-C.
//! 3. Verifies via `xref live memscan` that the vault signature is absent from RAM before commands.
//! 4. Sends live `DEPOSIT` and `ROTATE` commands over stdin to the running daemon, re-scans live
//!    RAM after each command, verifies in-place field mutations (`tx_seq`, `raw_balance`,
//!    `sealed_balance`, `epoch_key`, `last_mac`), and decompiles the dynamically swapped callback
//!    function pointers (`fast_seal_hook` -> `strict_seal_hook`) discovered in live RAM.

use std::error::Error;
use std::io::{BufRead, BufReader, Write};
use std::path::PathBuf;
#[cfg(target_os = "linux")]
use std::process::Output;
use std::process::{Child, ChildStdin, ChildStdout, Command, Stdio};

type TestResult = Result<(), Box<dyn Error>>;

#[cfg(target_os = "linux")]
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
        let dir = std::env::temp_dir().join(format!("xref-live-daemon-{}-{nonce}", std::process::id()));
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
        let trimmed = banner.trim();
        let pid_str =
            trimmed.strip_prefix("DAEMON_READY pid=").ok_or_else(|| format!("unexpected daemon banner: {trimmed}"))?;
        let pid: u32 = pid_str.parse()?;

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
            let status = child.wait()?;
            assert!(status.success(), "daemon exited with {status}");
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
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

#[cfg(target_os = "linux")]
fn run_xref(args: &[&str]) -> Result<Output, Box<dyn Error>> {
    Ok(Command::new(xref_bin()).args(args).output()?)
}

#[cfg(target_os = "linux")]
fn first_hex_token_on_first_line(stdout: &[u8]) -> Result<String, Box<dyn Error>> {
    let text = String::from_utf8_lossy(stdout);
    for line in text.lines() {
        for tok in line.split_whitespace() {
            let clean = tok.trim_end_matches(':').split("..").next().unwrap_or(tok);
            if clean.starts_with("0x") && u64::from_str_radix(&clean[2..], 16).is_ok() {
                return Ok(clean.to_owned());
            }
        }
    }
    Err(format!("no 0x... address found in output:\n{text}").into())
}

#[cfg(target_os = "linux")]
fn extract_64bit_hex_constants_from_pseudo_c(pseudo_c: &str) -> Vec<String> {
    let mut out = Vec::new();
    for raw in pseudo_c.split(|c: char| !c.is_ascii_hexdigit() && c != 'x' && c != 'X') {
        if let Some(hex) = raw.strip_prefix("0x").or_else(|| raw.strip_prefix("0X"))
            && hex.len() == 16
            && u64::from_str_radix(hex, 16).is_ok()
        {
            let norm = format!("0x{}", hex.to_ascii_lowercase());
            if !out.contains(&norm) {
                out.push(norm);
            }
        }
    }
    out
}

#[cfg(target_os = "linux")]
fn discover_daemon_handlers_and_signatures(bin_str: &str) -> Result<(String, String, String, String), Box<dyn Error>> {
    // 1. Locate stripped `execute_deposit` and `execute_rotate` via their protocol strings!
    let find_dep = run_xref(&["--bin", bin_str, "find", "--refs", "DAEMON_OP_DEPOSIT_V2"])?;
    assert!(find_dep.status.success(), "find deposit failed: {}", String::from_utf8_lossy(&find_dep.stderr));
    let deposit_fn_va = first_hex_token_on_first_line(&find_dep.stdout)?;

    let find_rot = run_xref(&["--bin", bin_str, "find", "--refs", "DAEMON_OP_ROTATE_V2"])?;
    assert!(find_rot.status.success(), "find rotate failed: {}", String::from_utf8_lossy(&find_rot.stderr));
    let rotate_fn_va = first_hex_token_on_first_line(&find_rot.stdout)?;
    assert_ne!(deposit_fn_va, rotate_fn_va, "deposit and rotate handlers must be distinct stripped functions");

    // 2. Recover struct field layout of `DaemonVault` (`rdi`) from `execute_deposit`.
    let layout_out = run_xref(&["--bin", bin_str, "layout", &deposit_fn_va, "--reg", "rdi"])?;
    assert!(layout_out.status.success(), "layout failed: {}", String::from_utf8_lossy(&layout_out.stderr));
    let layout_text = String::from_utf8_lossy(&layout_out.stdout);
    for expected_off in ["+0 ", "+8 ", "+10 ", "+18 ", "+20 ", "+28 ", "+30 ", "+48 ", "+50 ", "min span 0x68"] {
        assert!(
            layout_text.contains(expected_off),
            "expected DaemonVault field {expected_off} in xref layout:\n{layout_text}"
        );
    }

    // 3. Decompile `execute_deposit` with `--fields` and extract the 64-bit vault header signatures!
    let decomp_dep = run_xref(&["--bin", bin_str, "c", "--fields", &deposit_fn_va])?;
    assert!(decomp_dep.status.success(), "xref c failed: {}", String::from_utf8_lossy(&decomp_dep.stderr));
    let dep_c = String::from_utf8_lossy(&decomp_dep.stdout);
    let consts = extract_64bit_hex_constants_from_pseudo_c(&dep_c);
    let sig_hi = consts
        .iter()
        .find(|c| *c == "0x4441454d4f4e5632")
        .cloned()
        .ok_or_else(|| format!("expected SIG_HI 0x4441454d4f4e5632 in decompiled execute_deposit:\n{dep_c}"))?;
    let sig_lo = consts
        .iter()
        .find(|c| *c == "0x778899aabbccddee")
        .cloned()
        .ok_or_else(|| format!("expected SIG_LO 0x778899aabbccddee in decompiled execute_deposit:\n{dep_c}"))?;

    Ok((deposit_fn_va, rotate_fn_va, sig_hi, sig_lo))
}

#[cfg(target_os = "linux")]
fn ctx_word(ctx: &[serde_json::Value], rel_offset: i64) -> Result<&serde_json::Value, Box<dyn Error>> {
    ctx.iter()
        .find(|w| w["relative_offset"].as_i64() == Some(rel_offset))
        .ok_or_else(|| format!("missing context word at relative_offset={rel_offset} in {ctx:?}").into())
}

#[test]
fn live_daemon_fixture_compiles_and_responds_to_commands() -> TestResult {
    let mut daemon = LiveDaemon::compile_and_start()?;
    assert!(daemon.pid > 0);
    assert_eq!(daemon.send_cmd("PING")?, "PONG seq=0");
    assert_eq!(daemon.send_cmd("DEPOSIT 777 500000")?, "ACK op=DEPOSIT seq=1");
    assert_eq!(daemon.send_cmd("PING")?, "PONG seq=1");
    daemon.shutdown()?;
    Ok(())
}

#[cfg(target_os = "linux")]
#[test]
fn live_daemon_blind_decompile_command_and_memory_extraction_e2e() -> TestResult {
    use object::{Object, ObjectSymbol};
    use serde_json::Value;

    let mut daemon = LiveDaemon::compile_and_start()?;
    let elf_bytes = std::fs::read(&daemon.bin_path)?;
    let obj = object::File::parse(&*elf_bytes)?;
    assert_eq!(
        obj.symbols().filter(|s| !s.name().unwrap_or("").is_empty()).count(),
        0,
        "daemon binary must be completely stripped (.symtab == 0)"
    );

    let pid_str = daemon.pid.to_string();
    let bin_str = daemon.bin_path.to_str().ok_or("non-utf8 daemon path")?.to_owned();

    // Phase 1: Blind static reverse-engineering of the stripped daemon binary.
    let (deposit_fn_va, rotate_fn_va, sig_hi, sig_lo) = discover_daemon_handlers_and_signatures(&bin_str)?;
    eprintln!(
        "[DAEMON E2E] pid={} discovered stripped handlers: deposit={deposit_fn_va} rotate={rotate_fn_va}, signatures=({sig_hi}, {sig_lo})",
        daemon.pid
    );

    // Phase 2: Before any DEPOSIT command is sent, the vault signature is NOT in live RAM.
    let pre_scan = run_xref(&["live", "memscan", "--pid", &pid_str, &sig_hi, &sig_lo, "--json"])?;
    assert!(pre_scan.status.success(), "pre_scan failed: {}", String::from_utf8_lossy(&pre_scan.stderr));
    let pre_json: Value = serde_json::from_slice(&pre_scan.stdout)?;
    assert_eq!(
        pre_json["hits"].as_array().map(Vec::len),
        Some(0),
        "vault signature must not exist in RAM before DEPOSIT command is sent"
    );

    // Phase 3: Send live command #1 (`DEPOSIT 777 500000`) -> scan RAM -> extract & decompile hook #1!
    assert_eq!(daemon.send_cmd("DEPOSIT 777 500000")?, "ACK op=DEPOSIT seq=1");

    let scan1_out =
        run_xref(&["live", "memscan", "--pid", &pid_str, "--after-words", "10", "--json", &sig_hi, &sig_lo])?;
    assert!(scan1_out.status.success(), "scan1 failed: {}", String::from_utf8_lossy(&scan1_out.stderr));
    let scan1: Value = serde_json::from_slice(&scan1_out.stdout)?;
    let hits1 = scan1["hits"].as_array().ok_or("missing hits1")?;
    assert!(hits1.len() >= 2, "expected both heap DaemonVault and .bss GLOBAL_LEDGER hits, got {}", hits1.len());

    // Find the heap `DaemonVault` hit (which carries the `code_ptr` commit_hook at +0x38 and banner at +0x40).
    let heap_hit1 = hits1
        .iter()
        .find(|h| {
            h["context"]
                .as_array()
                .is_some_and(|c| c.iter().any(|w| w["relative_offset"] == 56 && w["kind"] == "code_ptr"))
        })
        .ok_or_else(|| format!("missing heap DaemonVault hit with +0x38 code_ptr in {hits1:?}"))?;
    let vault_runtime_va = heap_hit1["runtime_va"].as_str().ok_or("missing vault runtime_va")?.to_owned();
    let ctx1 = heap_hit1["context"].as_array().ok_or("missing ctx1")?;

    assert_eq!(ctx_word(ctx1, 16)?["value"], "0x1", "tx_seq after DEPOSIT #1 must be 1");
    assert_eq!(ctx_word(ctx1, 24)?["value"], "0x309", "account_id must be 777 (0x309)");
    assert_eq!(ctx_word(ctx1, 32)?["value"], "0x7a120", "raw_balance must be 500,000 (0x7a120)");
    let expected_sealed1 =
        (0x0007_a120_u64 ^ 0x1357_9bdf_2468_ace0).wrapping_add(0x0042_0042_u64.wrapping_mul(0x31337));
    assert_eq!(ctx_word(ctx1, 40)?["value"], format!("{expected_sealed1:#x}"));
    assert_eq!(ctx_word(ctx1, 48)?["value"], "0x420042", "initial epoch_key must be 0x420042");
    assert_eq!(ctx_word(ctx1, 64)?["static_ascii_preview"], "XREF_DAEMON_VAULT_ACTIVE_V2");
    let expected_mac1 = (0xface_b00c_dead_beef_u64 ^ expected_sealed1).wrapping_add(0x55aa_77cc);
    assert_eq!(ctx_word(ctx1, 88)?["value"], format!("{expected_mac1:#x}"));

    let hook1_static_va = ctx_word(ctx1, 56)?["target_function"]
        .as_str()
        .ok_or("missing target_function on +0x38 commit_hook")?
        .to_owned();
    eprintln!(
        "[DAEMON E2E] DEPOSIT #1 live heap vault={vault_runtime_va} raw_balance=0x7a120 sealed={expected_sealed1:#x} mac={expected_mac1:#x} hook1={hook1_static_va}"
    );
    let decomp_hook1 = run_xref(&["--bin", &bin_str, "c", &hook1_static_va])?;
    let hook1_c = String::from_utf8_lossy(&decomp_hook1.stdout);
    assert!(
        hook1_c.to_ascii_lowercase().contains("13579bdf2468ace0"),
        "expected fast_seal_hook XOR constant 0x13579bdf2468ace0 when decompiling live RAM pointer {hook1_static_va}:\n{hook1_c}"
    );

    // Phase 4: Send `ROTATE 0x99` + `DEPOSIT 777 250000` -> verify in-place RAM mutation & swapped hook!
    verify_rotated_daemon_state(
        &mut daemon,
        &bin_str,
        &pid_str,
        &sig_hi,
        &sig_lo,
        &vault_runtime_va,
        &hook1_static_va,
    )?;

    daemon.shutdown()?;
    Ok(())
}

#[cfg(target_os = "linux")]
fn verify_rotated_daemon_state(
    daemon: &mut LiveDaemon,
    bin_str: &str,
    pid_str: &str,
    sig_hi: &str,
    sig_lo: &str,
    vault_runtime_va: &str,
    hook1_static_va: &str,
) -> TestResult {
    use serde_json::Value;

    assert_eq!(daemon.send_cmd("ROTATE 0x99")?, "ACK op=ROTATE seq=2");
    assert_eq!(daemon.send_cmd("DEPOSIT 777 250000")?, "ACK op=DEPOSIT seq=3");

    let scan2_out = run_xref(&["live", "memscan", "--pid", pid_str, "--after-words", "10", "--json", sig_hi, sig_lo])?;
    assert!(scan2_out.status.success(), "scan2 failed: {}", String::from_utf8_lossy(&scan2_out.stderr));
    let scan2: Value = serde_json::from_slice(&scan2_out.stdout)?;
    let hits2 = scan2["hits"].as_array().ok_or("missing hits2")?;
    let heap_hit2 = hits2
        .iter()
        .find(|h| h["runtime_va"].as_str() == Some(vault_runtime_va))
        .ok_or_else(|| format!("expected live DaemonVault at same runtime_va {vault_runtime_va} in {hits2:?}"))?;
    let ctx2 = heap_hit2["context"].as_array().ok_or("missing ctx2")?;

    assert_eq!(ctx_word(ctx2, 16)?["value"], "0x3", "tx_seq must mutate to 3 in live RAM");
    assert_eq!(ctx_word(ctx2, 32)?["value"], "0xb71b0", "raw_balance must mutate to 750,000 (0xb71b0) in live RAM");
    assert_eq!(ctx_word(ctx2, 48)?["value"], "0x99", "epoch_key must mutate to 0x99 in live RAM");
    let expected_sealed2 =
        (0x000b_71b0_u64.rotate_left(13) ^ 0xfedc_ba98_7654_3210).wrapping_add(0x99_u64.wrapping_mul(0x7331));
    assert_eq!(ctx_word(ctx2, 40)?["value"], format!("{expected_sealed2:#x}"));
    let expected_mac2 = (0xface_b00c_dead_beef_u64 ^ expected_sealed2).wrapping_add(3_u64.wrapping_mul(0x55aa_77cc));
    assert_eq!(ctx_word(ctx2, 88)?["value"], format!("{expected_mac2:#x}"));

    // Also verify the `.bss` / `.data` GLOBAL_LEDGER mirror mutated in lockstep with the heap struct!
    let global_hit2 = hits2
        .iter()
        .find(|h| h["static_va"].is_string() && h["runtime_va"].as_str() != Some(vault_runtime_va))
        .ok_or_else(|| format!("expected .bss/.data GLOBAL_LEDGER hit in {hits2:?}"))?;
    let gctx2 = global_hit2["context"].as_array().ok_or("missing global ctx2")?;
    assert_eq!(ctx_word(gctx2, 16)?["value"], "0x3");
    assert_eq!(ctx_word(gctx2, 32)?["value"], "0xb71b0");
    assert_eq!(ctx_word(gctx2, 40)?["value"], format!("{expected_sealed2:#x}"));

    // Verify `dyn AuditEngine` vtable (`relro_ptr_candidate` at +0x48 or +0x50) decompiles `SipAuditEngine::compute_mac`.
    let vtable_word = [ctx_word(ctx2, 72)?, ctx_word(ctx2, 80)?]
        .into_iter()
        .find(|w| w["kind"] == "relro_ptr_candidate")
        .ok_or("expected relro_ptr_candidate vtable in Box<dyn AuditEngine>")?;
    let vtable_cands = vtable_word["candidate_targets"].as_array().ok_or("missing vtable candidate_targets")?;
    let mut decompiled_mac_fn = false;
    for cand in vtable_cands {
        if let Some(va) = cand.as_str() {
            let out = run_xref(&["--bin", bin_str, "c", va])?;
            let c_text = String::from_utf8_lossy(&out.stdout);
            if c_text.to_ascii_lowercase().contains("55aa77cc") || c_text.contains("1437235148") {
                decompiled_mac_fn = true;
                break;
            }
        }
    }
    assert!(decompiled_mac_fn, "expected dyn AuditEngine vtable targets {vtable_cands:?} to decompile compute_mac");

    let hook2_static_va = ctx_word(ctx2, 56)?["target_function"]
        .as_str()
        .ok_or("missing target_function on rotated +0x38 commit_hook")?;
    assert_ne!(
        hook2_static_va, hook1_static_va,
        "ROTATE command must swap commit_hook function pointer in live RAM from fast_seal_hook to strict_seal_hook"
    );

    let decomp_hook2 = run_xref(&["--bin", bin_str, "c", hook2_static_va])?;
    let hook2_c = String::from_utf8_lossy(&decomp_hook2.stdout);
    let global_rva = global_hit2["runtime_va"].as_str().unwrap_or("?");
    eprintln!(
        "[DAEMON E2E] ROTATE+DEPOSIT #2 live heap vault={vault_runtime_va} & global={global_rva} mutated in-place: tx_seq=3 raw_balance=0xb71b0 sealed={expected_sealed2:#x} mac={expected_mac2:#x} swapped_hook={hook1_static_va}->{hook2_static_va}"
    );
    assert!(
        hook2_c.to_ascii_lowercase().contains("fedcba9876543210"),
        "expected strict_seal_hook constant 0xfedcba9876543210 when decompiling rotated live RAM pointer {hook2_static_va}:\n{hook2_c}"
    );
    Ok(())
}
