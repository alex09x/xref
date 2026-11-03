/*
 * XRef — End-to-end live analysis & stripped Rust decompilation integration test
 * Copyright (c) 2026 Alexander Panasenko
 * Contact: alex@prod.codes
 * Author: https://prod.codes/about/
 * Project: https://github.com/alex09x/xref
 * SPDX-License-Identifier: MIT OR Apache-2.0
 */

//! Compiles `tests/fixtures/live_target_app.rs` as a stripped optimized Rust binary, launches it
//! as a separate OS process, scans and extracts dynamic values and pointers from live RAM via
//! `xref live {maps, memscan, resolve}`, and feeds the discovered stripped function & vtable
//! addresses straight into `xref c` (pseudo-C decompiler) and `xref strings`.

use std::collections::BTreeMap;
use std::error::Error;
use std::io::{BufRead, BufReader};
#[cfg(target_os = "linux")]
use std::path::Path;
use std::path::PathBuf;
#[cfg(target_os = "linux")]
use std::process::Output;
use std::process::{Child, Command, Stdio};

type TestResult = Result<(), Box<dyn Error>>;

#[cfg(target_os = "linux")]
const fn xref_bin() -> &'static str {
    env!("CARGO_BIN_EXE_xref")
}

fn fixture_src() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/live_target_app.rs")
}

struct TempApp {
    dir: PathBuf,
    #[cfg(target_os = "linux")]
    bin_path: PathBuf,
    child: Option<Child>,
}

impl TempApp {
    fn compile_and_spawn(seed: u64) -> Result<(Self, BTreeMap<String, String>), Box<dyn Error>> {
        let nonce = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH)?.as_nanos();
        let dir = std::env::temp_dir().join(format!("xref-live-e2e-{}-{nonce}", std::process::id()));
        std::fs::create_dir_all(&dir)?;
        let bin_path = dir.join("live_target_app");
        let rustc = std::env::var("RUSTC").unwrap_or_else(|_| "rustc".to_owned());

        let compile = Command::new(rustc)
            .arg("--edition=2021")
            .arg("-O")
            .arg("-C")
            .arg("strip=symbols")
            .arg(fixture_src())
            .arg("-o")
            .arg(&bin_path)
            .output()?;
        if !compile.status.success() {
            let _ = std::fs::remove_dir_all(&dir);
            return Err(format!("rustc fixture build failed: {}", String::from_utf8_lossy(&compile.stderr)).into());
        }

        let mut child = Command::new(&bin_path)
            .arg(seed.to_string())
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()?;

        let stdout = child.stdout.take().ok_or("missing child stdout")?;
        let mut reader = BufReader::new(stdout);
        let mut ready_line = String::new();
        reader.read_line(&mut ready_line)?;
        if !ready_line.starts_with("READY ") {
            let _ = child.kill();
            let _ = child.wait();
            let _ = std::fs::remove_dir_all(&dir);
            return Err(format!("unexpected child readiness line: {ready_line:?}").into());
        }

        let mut kv = BTreeMap::new();
        for token in ready_line.split_ascii_whitespace().skip(1) {
            if let Some((k, v)) = token.split_once('=') {
                kv.insert(k.to_owned(), v.to_owned());
            }
        }
        Ok((
            Self {
                dir,
                #[cfg(target_os = "linux")]
                bin_path,
                child: Some(child),
            },
            kv,
        ))
    }

    fn finish(&mut self) -> Result<(), Box<dyn Error>> {
        if let Some(mut child) = self.child.take() {
            drop(child.stdin.take());
            let status = child.wait()?;
            assert!(status.success(), "target app exited with {status}");
        }
        Ok(())
    }
}

impl Drop for TempApp {
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
fn assert_stripped_elf(path: &Path) -> TestResult {
    use object::{Object, ObjectSymbol};

    let bytes = std::fs::read(path)?;
    let obj = object::File::parse(&*bytes)?;
    let symtab_count = obj.symbols().filter(|s| !s.name().unwrap_or("").is_empty()).count();
    assert_eq!(symtab_count, 0, "expected stripped ELF with 0 .symtab symbols, got {symtab_count}");
    Ok(())
}

#[test]
fn live_rust_fixture_source_compiles_cleanly() -> TestResult {
    let (mut app, kv) = TempApp::compile_and_spawn(424_242)?;
    assert!(kv.contains_key("secret") && kv.contains_key("fn_va"), "{kv:?}");
    #[cfg(target_os = "linux")]
    assert_stripped_elf(&app.bin_path)?;
    app.finish()?;
    Ok(())
}

#[cfg(target_os = "linux")]
#[test]
fn live_e2e_stripped_rust_app_memscan_extracts_values_and_decompiles_functions() -> TestResult {
    use serde_json::Value;

    let (mut app, kv) = TempApp::compile_and_spawn(987_654_321)?;
    assert_stripped_elf(&app.bin_path)?;

    let pid = kv.get("pid").ok_or("missing pid")?;
    let magic0 = kv.get("magic0").ok_or("missing magic0")?;
    let magic1 = kv.get("magic1").ok_or("missing magic1")?;
    let expected_secret = kv.get("secret").ok_or("missing secret")?;
    let expected_global_secret = kv.get("global_secret").ok_or("missing global_secret")?;
    let expected_heap_va = kv.get("heap_va").ok_or("missing heap_va")?;
    let expected_global_va = kv.get("global_va").ok_or("missing global_va")?;
    let expected_fn_va = kv.get("fn_va").ok_or("missing fn_va")?;
    let bin_str = app.bin_path.to_str().ok_or("non-utf8 bin path")?;

    // 1. Auto-attach `xref live maps` WITHOUT `--bin` (`proc_exe_auto`), even after `Backtrace::force_capture()`
    //    mapped `/proc/self/exe` a second time read-only.
    let maps_out = run_xref(&["live", "maps", "--pid", pid, "--json"])?;
    assert!(maps_out.status.success(), "live maps failed: {}", String::from_utf8_lossy(&maps_out.stderr));
    let maps_json: Value = serde_json::from_slice(&maps_out.stdout)?;
    assert_eq!(maps_json["process"]["binary_match"], "proc_exe_auto");
    assert_eq!(maps_json["process"]["pid_alive_after"], true);
    assert_eq!(maps_json["process"]["process_changed"], false);
    assert_ne!(maps_json["process"]["pie_slide"].as_i64().unwrap_or(0), 0);

    // 2. Scan live process memory ONLY by `[magic0, magic1]` and extract unknown runtime values + pointers!
    let scan_out = run_xref(&[
        "live",
        "memscan",
        "--pid",
        pid,
        "--before-words",
        "1",
        "--after-words",
        "5",
        "--json",
        magic0,
        magic1,
    ])?;
    assert!(scan_out.status.success(), "live memscan failed: {}", String::from_utf8_lossy(&scan_out.stderr));
    let scan_json: Value = serde_json::from_slice(&scan_out.stdout)?;
    assert_eq!(scan_json["stop_reason"], "complete");
    let hits = scan_json["hits"].as_array().ok_or("missing hits array")?;

    // 2a. Verify `.data` global slot hit (`GLOBAL_SLOT`) and read `global_secret` (+0x10) from live RAM.
    let global_hit = hits
        .iter()
        .find(|h| h["runtime_va"] == *expected_global_va)
        .ok_or_else(|| format!("GLOBAL_SLOT hit {expected_global_va} not found in {hits:?}"))?;
    assert!(global_hit["static_va"].as_str().is_some(), "expected static_va on .data hit: {global_hit}");
    let global_ctx = global_hit["context"].as_array().ok_or("missing global context")?;
    let global_val = global_ctx
        .iter()
        .find(|w| w["relative_offset"] == 16)
        .and_then(|w| w["value"].as_str())
        .ok_or("missing +0x10 in global hit")?;
    assert_eq!(global_val, expected_global_secret);

    // 2b. Verify heap `Box<VaultRecord>` hit and read `live_secret`, `code_ptr`, `static_data_ptr`,
    //     `heap_ptr`/`anon_ptr`, and `relro_ptr_candidate` (Rust `dyn VaultPolicy` vtable)!
    let heap_hit = hits
        .iter()
        .find(|h| h["runtime_va"] == *expected_heap_va)
        .ok_or_else(|| format!("Box<VaultRecord> hit {expected_heap_va} not found in {hits:?}"))?;
    let ctx = heap_hit["context"].as_array().ok_or("missing heap context")?;

    let read_secret = ctx
        .iter()
        .find(|w| w["relative_offset"] == 16)
        .and_then(|w| w["value"].as_str())
        .ok_or("missing +0x10 live_secret")?;
    assert_eq!(read_secret, expected_secret, "live_secret extracted from RAM mismatched");

    let fn_slot = ctx.iter().find(|w| w["relative_offset"] == 24).ok_or("missing +0x18 mix_fn")?;
    assert_eq!(fn_slot["kind"], "code_ptr");
    assert_eq!(fn_slot["value"], *expected_fn_va);
    let stripped_fn_static =
        fn_slot["target_function"].as_str().ok_or("missing target_function on stripped code_ptr")?;

    let banner_slot = ctx.iter().find(|w| w["relative_offset"] == 32).ok_or("missing +0x20 banner")?;
    assert_eq!(banner_slot["kind"], "static_data_ptr");
    assert_eq!(banner_slot["static_ascii_preview"], "XREF_VAULT_ENGINE_ACTIVE_v1");

    let wide_slots: Vec<&Value> =
        ctx.iter().filter(|w| w["relative_offset"] == 40 || w["relative_offset"] == 48).collect();
    assert_eq!(wide_slots.len(), 2);
    assert!(
        wide_slots.iter().any(|w| matches!(w["kind"].as_str(), Some("heap_ptr" | "anon_ptr"))),
        "expected heap_ptr/anon_ptr in Box<dyn VaultPolicy>: {wide_slots:?}"
    );
    let vtable_slot = wide_slots
        .iter()
        .copied()
        .find(|w| w["kind"] == "relro_ptr_candidate")
        .ok_or_else(|| format!("expected relro_ptr_candidate vtable in {wide_slots:?}"))?;
    let vtable_targets = vtable_slot["candidate_targets"].as_array().ok_or("missing vtable candidate_targets")?;
    assert!(!vtable_targets.is_empty(), "expected non-empty vtable candidate_targets");

    // Also verify human-readable tabular memscan output renders cleanly.
    let table_out = run_xref(&["live", "memscan", "--pid", pid, magic0, magic1])?;
    assert!(table_out.status.success());
    let table_text = String::from_utf8(table_out.stdout)?;
    assert!(table_text.contains("code_ptr") && table_text.contains("XREF_VAULT_ENGINE_ACTIVE_v1"), "{table_text}");

    verify_resolve_and_decompilation(bin_str, pid, expected_fn_va, stripped_fn_static, vtable_targets)?;

    // 6. Cleanly shut down the target process and verify post-exit `xref live` refuses dead PID.
    app.finish()?;
    let dead_out = run_xref(&["live", "maps", "--pid", pid])?;
    assert!(!dead_out.status.success(), "expected error after target process exited");
    Ok(())
}

#[cfg(target_os = "linux")]
fn verify_resolve_and_decompilation(
    bin_str: &str,
    pid: &str,
    expected_fn_va: &str,
    stripped_fn_static: &str,
    vtable_targets: &[serde_json::Value],
) -> TestResult {
    use serde_json::Value;

    let res_out =
        run_xref(&["--bin", bin_str, "live", "resolve", "--pid", pid, expected_fn_va, stripped_fn_static, "--json"])?;
    assert!(res_out.status.success(), "resolve failed: {}", String::from_utf8_lossy(&res_out.stderr));
    let res_json: Value = serde_json::from_slice(&res_out.stdout)?;
    assert_eq!(res_json["addresses"][0]["static_va"], stripped_fn_static);
    assert_eq!(res_json["addresses"][0]["executable"], true);
    assert_eq!(res_json["addresses"][0]["in_bss"], false);
    assert_eq!(res_json["addresses"][1]["runtime_va"], expected_fn_va);

    let decomp_fn = run_xref(&["--bin", bin_str, "c", stripped_fn_static])?;
    assert!(
        decomp_fn.status.success(),
        "xref c failed on {stripped_fn_static}: {}",
        String::from_utf8_lossy(&decomp_fn.stderr)
    );
    let pseudo_c = String::from_utf8(decomp_fn.stdout)?;
    assert!(
        pseudo_c.to_ascii_lowercase().contains("517cc1b727220a95")
            && (pseudo_c.contains("0x1337") || pseudo_c.contains("4919")),
        "expected vault_mix_secret constants in pseudo-C output:\n{pseudo_c}"
    );

    let mut found_trait_method_c = false;
    for cand in vtable_targets {
        let Some(va_str) = cand.as_str() else { continue };
        let decomp_vt = run_xref(&["--bin", bin_str, "c", va_str])?;
        if decomp_vt.status.success() {
            let vt_c = String::from_utf8_lossy(&decomp_vt.stdout);
            if vt_c.to_ascii_lowercase().contains("42429999") || vt_c.contains("1111660953") {
                found_trait_method_c = true;
                break;
            }
        }
    }
    assert!(
        found_trait_method_c,
        "expected vtable candidate_targets {vtable_targets:?} to decompile VaultPolicy::audit_tag (0x42429999)"
    );
    Ok(())
}
