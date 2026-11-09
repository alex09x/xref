/*
 * XRef — Stage L3 Increment 2 privileged E2E verification for dependent watch (`--follow`) and native C
 * Copyright (c) 2026 Alexander Panasenko
 * Contact: alex@prod.codes
 * Author: https://prod.codes/about/
 * Project: https://github.com/alex09x/xref
 * SPDX-License-Identifier: MIT OR Apache-2.0
 */

//! Verifies Stage L3 Increment 2 (`xref live watch --follow`):
//! 1. Against the stripped Rust daemon (`RichTypeMirror.vec_ptr` + `vec_len` + `ext_sig_hi` guard):
//!    - Discovers `RichTypeMirror` on the heap via `xref live memscan` (`EXT_SIG_HI`, `EXT_SIG_LO`).
//!    - Follows `tx_history[0]` across `VEC_WRITE0` (stable leaf write), `DEPOSIT` (in-place growth),
//!      `VEC_MOVE_WRITE0` (heap buffer reallocation -> leaf watch rebind to `generation = 2`), and
//!      `VEC_FREE_REUSE` (pointer nulled & freed chunk reused -> leaf watch disarmed so reuse writes
//!      are NOT attributed to the dependent watch).
//! 2. Cross-language against a stripped native C binary compiled with `cc -O2 -g0 -s` (`malloc`,
//!    `realloc` relocation, `free` + chunk reuse).

#[path = "fixtures/live_daemon_harness.rs"]
mod live_daemon_harness;

use std::error::Error;
use std::io::{BufRead, BufReader, Write};
use std::process::{Command, Stdio};

use live_daemon_harness::{ArmedProbe, LiveDaemon, TestResult, run_xref};

fn sudo_nopasswd_available() -> bool {
    Command::new("sudo").args(["-n", "true"]).status().is_ok_and(|s| s.success())
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

#[test]
fn live_daemon_rust_dependent_watch_rebind_and_disarm_e2e() -> TestResult {
    if !cfg!(all(target_os = "linux", target_arch = "x86_64")) || !sudo_nopasswd_available() {
        return Ok(());
    }

    let mut daemon = LiveDaemon::compile_and_start()?;
    let dpid_str = daemon.pid.to_string();

    // Seed initial DEPOSIT so tx_history has 1 element and RichTypeMirror has non-null vec_ptr.
    daemon.send_cmd("DEPOSIT 777 500000")?;

    // Discover RichTypeMirror via EXT_SIG_HI (0x5852454654595045) + EXT_SIG_LO (0x1122334455667788).
    // Layout of RichTypeMirror:
    // +0:  ext_sig_hi (u64)
    // +8:  ext_sig_lo (u64)
    // +16..+48: cmd_enum (32B)
    // +48..+80: policy (32B)
    // +80: vec_ptr (*const u64)
    // +88: vec_cap (usize)
    // +96: vec_len (usize)
    let scan_out = run_xref(&[
        "live",
        "memscan",
        "--pid",
        &dpid_str,
        "--after-words",
        "12",
        "--json",
        "0x5852454654595045",
        "0x1122334455667788",
    ])?;
    assert!(scan_out.status.success(), "memscan RichTypeMirror failed");
    let scan: serde_json::Value = serde_json::from_slice(&scan_out.stdout)?;
    let hits = scan["hits"].as_array().ok_or("missing hits")?;
    let rich_hit = hits.first().ok_or("missing RichTypeMirror hit")?;
    let ctx = rich_hit["context"].as_array().ok_or("missing context")?;

    let guard_slot_va = find_word_va(ctx, 0)?;
    let vec_ptr_slot_va = find_word_va(ctx, 80)?;
    let vec_len_slot_va = find_word_va(ctx, 96)?;
    let initial_vec_buf_va = ctx
        .iter()
        .find(|w| w["relative_offset"].as_i64() == Some(80))
        .and_then(|w| w["value"].as_str())
        .ok_or("missing initial vec_ptr value")?
        .to_owned();

    let follow_spec = format!(
        "ptr_slot={vec_ptr_slot_va},offset=0,len_slot={vec_len_slot_va},min_len=1,guard_slot={guard_slot_va},guard_val=0x5852454654595045"
    );
    let extra = ["--regs", "--follow", &follow_spec];
    let armed = ArmedProbe::spawn_watch(&dpid_str, "1600", &extra)?;
    let expected_ready = [vec_ptr_slot_va.as_str(), initial_vec_buf_va.as_str()];
    let _ = armed.wait_watch_ready(daemon.pid, 1, &expected_ready)?;

    // 1. Stable write to tx_history[0] at generation 1
    daemon.send_cmd("VEC_WRITE0 0x1111222233334444")?;
    std::thread::sleep(std::time::Duration::from_millis(60));
    // 2. Relocate tx_history buffer and write to tx_history[0] (triggers rebind to generation 2)
    daemon.send_cmd("VEC_MOVE_WRITE0 0x5555666677778888")?;
    std::thread::sleep(std::time::Duration::from_millis(80));
    // 3. Write to relocated tx_history[0] at generation 2
    daemon.send_cmd("VEC_WRITE0 0x9999aaaabbbbcccc")?;
    std::thread::sleep(std::time::Duration::from_millis(60));
    // 4. First clear/invalidate RichTypeMirror (vec_ptr = null, vec_len = 0), let watch disarm, then reuse buffer with decoy writes
    let poison_base = 0xdead_beef_cafe_babe_u64;
    let poison_xor = poison_base ^ 0x1111_u64;
    let clear_ack = daemon.send_cmd("VEC_CLEAR 0")?;
    std::thread::sleep(std::time::Duration::from_millis(60));
    let reuse_ack = daemon.send_cmd(&format!("VEC_FREE_REUSE {poison_base:#x}"))?;
    std::thread::sleep(std::time::Duration::from_millis(80));

    let report = armed.finish("perf_breakpoint")?;
    assert_eq!(report["observation"]["counts_are_lower_bound"].as_bool(), Some(true));
    let deps = report["dependent_watches"].as_array().ok_or("missing dependent_watches")?;
    assert_eq!(deps.len(), 1);
    let dep = &deps[0];

    assert_eq!(dep["hardware_slots_reserved"].as_u64(), Some(2));
    assert_eq!(dep["rebind_coverage_gap"].as_bool(), Some(true));
    assert!(
        dep["generation"].as_u64().unwrap_or(0) >= 2,
        "expected generation >= 2 after VEC_MOVE_WRITE0, got: {dep:#?}"
    );
    assert!(
        dep["accepted_hits"].as_u64().unwrap_or(0) >= 2,
        "expected >= 2 leaf hits across gen 1 and gen 2, got: {dep:#?}"
    );
    assert_eq!(
        dep["binding_state"].as_str(),
        Some("disarmed_bounds_violation"),
        "expected disarmed state after VEC_CLEAR + VEC_FREE_REUSE: {dep:#?}"
    );
    let rebind_events = dep["rebind_events"].as_array().ok_or("missing rebind_events")?;
    let transitions: Vec<&str> = rebind_events.iter().filter_map(|e| e["transition"].as_str()).collect();
    assert!(transitions.contains(&"initial_bind"), "transitions: {transitions:?}");
    assert!(transitions.contains(&"relocated_buffer"), "transitions: {transitions:?}");
    let gen2_leaf_va = rebind_events
        .iter()
        .rfind(|e| e["transition"].as_str() == Some("relocated_buffer"))
        .and_then(|e| e["new_leaf_va"].as_str())
        .ok_or("missing relocated_buffer new_leaf_va")?;
    assert!(
        clear_ack.contains(gen2_leaf_va) && reuse_ack.contains(gen2_leaf_va),
        "expected VEC_CLEAR ({clear_ack}) and VEC_FREE_REUSE ({reuse_ack}) to overwrite exact gen2 leaf address {gen2_leaf_va}"
    );

    // Ensure NEITHER poison decoy value (poison_base nor poison_base ^ 0x1111) written to gen2_leaf_va after disarm was attributed
    let poison_s1 = format!("{poison_base:#x}");
    let poison_s2 = format!("{poison_xor:#x}");
    let empty_samples = Vec::new();
    let samples = dep["samples"].as_array().unwrap_or(&empty_samples);
    for s in samples {
        let v = s["written_value"]["value"].as_str().unwrap_or("");
        assert_ne!(v, poison_s1, "reused allocation write {poison_s1} must not be attributed to disarmed watch");
        assert_ne!(v, poison_s2, "reused allocation write {poison_s2} must not be attributed to disarmed watch");
    }

    daemon.shutdown()?;
    Ok(())
}

const C_FIXTURE_SRC: &str = r#"
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/prctl.h>
#include <unistd.h>

struct __attribute__((packed, aligned(8))) CAnchor {
    uint64_t magic_hi;
    uint64_t magic_lo;
    uint64_t *buf_ptr;
    uint64_t buf_len;
    uint64_t counter;
};

__attribute__((noinline, noipa)) void c_mutate_counter(struct CAnchor *a, uint64_t delta) {
    a->counter += delta;
    if (a->buf_ptr && a->buf_len > 0) {
        a->buf_ptr[0] = a->counter ^ 0xabcdef00ULL;
    }
}

int main(void) {
    prctl(0x59616d61, -1UL, 0, 0, 0);
    struct CAnchor *anchor = (struct CAnchor *)calloc(1, sizeof(struct CAnchor));
    anchor->magic_hi = 0x4346495854555245ULL; /* "CFIXTURE" */
    anchor->magic_lo = 0x8877665544332211ULL;
    anchor->buf_ptr = (uint64_t *)calloc(4, sizeof(uint64_t));
    anchor->buf_len = 4;
    anchor->counter = 10;
    anchor->buf_ptr[0] = 0x100;
    /* The magic is never read by C code: without an escape, gcc 15 (IPA modref + DSE) drops it. */
    __asm__ volatile("" : : "r"(anchor) : "memory");

    printf("C_READY pid=%d\n", (int)getpid());
    fflush(stdout);

    char line[128];
    while (fgets(line, sizeof(line), stdin)) {
        unsigned long long arg = 0;
        if (sscanf(line, "ADD %llx", &arg) == 1) {
            c_mutate_counter(anchor, (uint64_t)arg);
            printf("ACK ADD\n");
            fflush(stdout);
        } else if (sscanf(line, "REALLOC_MOVE %llx", &arg) == 1) {
            uint64_t *new_buf = (uint64_t *)calloc(2048, sizeof(uint64_t));
            new_buf[0] = (uint64_t)arg;
            free(anchor->buf_ptr);
            anchor->buf_ptr = new_buf;
            anchor->buf_len = 2048;
            printf("ACK REALLOC_MOVE\n");
            fflush(stdout);
        } else if (sscanf(line, "FREE_REUSE %llx", &arg) == 1) {
            free(anchor->buf_ptr);
            anchor->buf_ptr = NULL;
            anchor->buf_len = 0;
            uint64_t *reused = (uint64_t *)calloc(2048, sizeof(uint64_t));
            reused[0] = (uint64_t)arg;
            printf("ACK FREE_REUSE\n");
            fflush(stdout);
        } else if (strncmp(line, "QUIT", 4) == 0) {
            printf("BYE\n");
            fflush(stdout);
            break;
        }
    }
    return 0;
}
"#;

#[test]
fn live_c_stripped_binary_memscan_and_watch_follow_e2e() -> TestResult {
    if !cfg!(all(target_os = "linux", target_arch = "x86_64")) || !sudo_nopasswd_available() {
        return Ok(());
    }
    if Command::new("cc").arg("--version").output().is_err() {
        return Ok(());
    }

    let nonce = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH)?.as_nanos();
    let dir = std::env::temp_dir().join(format!("xref-c-fixture-{}-{nonce}", std::process::id()));
    std::fs::create_dir_all(&dir)?;
    let c_path = dir.join("c_fixture.c");
    let bin_path = dir.join("c_fixture_bin");
    std::fs::write(&c_path, C_FIXTURE_SRC)?;

    let cc_out = Command::new("cc").args(["-O2", "-g0", "-s"]).arg(&c_path).arg("-o").arg(&bin_path).output()?;
    assert!(cc_out.status.success(), "cc failed: {}", String::from_utf8_lossy(&cc_out.stderr));

    let mut child = Command::new(&bin_path).stdin(Stdio::piped()).stdout(Stdio::piped()).spawn()?;
    let mut stdin = child.stdin.take().ok_or("no c stdin")?;
    let mut reader = BufReader::new(child.stdout.take().ok_or("no c stdout")?);
    let mut banner = String::new();
    reader.read_line(&mut banner)?;
    let cpid: u32 = banner.trim().strip_prefix("C_READY pid=").ok_or("bad C_READY")?.parse()?;
    let cpid_str = cpid.to_string();

    // Locate CAnchor via memscan ("CFIXTURE" magic_hi + magic_lo)
    let scan_out = run_xref(&[
        "live",
        "memscan",
        "--pid",
        &cpid_str,
        "--after-words",
        "6",
        "--json",
        "0x4346495854555245",
        "0x8877665544332211",
    ])?;
    assert!(scan_out.status.success(), "C memscan failed");
    let scan: serde_json::Value = serde_json::from_slice(&scan_out.stdout)?;
    let ctx = scan["hits"][0]["context"].as_array().ok_or("missing C hit context")?;
    let buf_ptr_va = find_word_va(ctx, 16)?;
    let buf_len_va = find_word_va(ctx, 24)?;
    let counter_va = find_word_va(ctx, 32)?;
    let init_buf_va = ctx
        .iter()
        .find(|w| w["relative_offset"].as_i64() == Some(16))
        .and_then(|w| w["value"].as_str())
        .ok_or("no C buf_ptr val")?
        .to_owned();

    let follow_spec = format!("ptr_slot={buf_ptr_va},offset=0,len_slot={buf_len_va},min_len=1");
    let extra = ["--follow", &follow_spec, &counter_va];
    let armed = ArmedProbe::spawn_watch(&cpid_str, "1400", &extra)?;
    let expected = [counter_va.as_str(), buf_ptr_va.as_str(), init_buf_va.as_str()];
    let _ = armed.wait_watch_ready(cpid, 1, &expected)?;

    let mut send_c = |cmd: &str| -> Result<(), Box<dyn Error>> {
        writeln!(stdin, "{cmd}")?;
        stdin.flush()?;
        let mut ack = String::new();
        reader.read_line(&mut ack)?;
        Ok(())
    };

    send_c("ADD 0x5")?;
    std::thread::sleep(std::time::Duration::from_millis(60));
    send_c("REALLOC_MOVE 0x777")?;
    std::thread::sleep(std::time::Duration::from_millis(80));
    send_c("ADD 0xa")?;
    std::thread::sleep(std::time::Duration::from_millis(60));
    send_c("FREE_REUSE 0xbadc0ffee")?;
    std::thread::sleep(std::time::Duration::from_millis(80));

    let report = armed.finish("perf_breakpoint")?;
    assert_eq!(report["watches"][0]["accepted_hits"].as_u64(), Some(2));
    assert_eq!(report["watches"][0]["initial_snapshot"].as_str(), Some("0xa"));
    assert_eq!(report["watches"][0]["latest_snapshot"].as_str(), Some("0x19"));

    let c_dep = &report["dependent_watches"][0];
    assert!(c_dep["generation"].as_u64().unwrap_or(0) >= 2, "expected C realloc rebind gen >= 2: {c_dep:#?}");
    assert!(c_dep["accepted_hits"].as_u64().unwrap_or(0) >= 2, "expected C leaf hits >= 2: {c_dep:#?}");
    assert_eq!(c_dep["binding_state"].as_str(), Some("disarmed_bounds_violation"));

    let _ = send_c("QUIT");
    let _ = child.wait();
    let _ = std::fs::remove_dir_all(&dir);
    Ok(())
}
