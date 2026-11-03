/*
 * XRef — Live Linux procfs inspection and xref-aware memory scanning
 * Copyright (c) 2026 Alexander Panasenko
 * Contact: alex@prod.codes
 * Author: https://prod.codes/about/
 * Project: https://github.com/alex09x/xref
 * SPDX-License-Identifier: MIT OR Apache-2.0
 */

use std::error::Error;

use serde_json::Value;

use crate::live::cli::{LiveCommand, LiveSubcommand};

type TestResult = Result<(), Box<dyn Error>>;

#[inline(never)]
const fn live_sample_probe_fn(x: u64) -> u64 {
    std::hint::black_box(x).wrapping_mul(0x517c_c1b7_2722_0a95).rotate_left(13)
}

#[test]
fn live_self_inspect_maps_resolve_and_memscan() -> TestResult {
    assert_ne!(live_sample_probe_fn(7), 0);
    let (exe, pid) = (std::env::current_exe()?, std::process::id());
    let fn_ptr: fn(u64) -> u64 = live_sample_probe_fn;
    let sample_fn_addr = crate::cli::parse_number(&format!("{fn_ptr:p}"))?;
    let heap_target = std::hint::black_box(Box::new(0xfeed_face_1234_5678_u64));
    let heap_target_addr = crate::cli::parse_number(&format!("{:p}", &raw const *heap_target))?;

    let magic0 = std::hint::black_box(0xa5a5_5a5a_f0f0_0f0f_u64) ^ 0x1357_9bdf_2468_ace0;
    let magic1 = std::hint::black_box(0xc3c3_3c3c_9696_6969_u64) ^ 0x0246_8ace_1357_9bdf;
    let payload: Box<[u64; 6]> =
        std::hint::black_box(Box::new([magic0, magic1, sample_fn_addr, heap_target_addr, 0x77, 0x88]));
    std::hint::black_box(payload.as_ref());
    let box_addr = crate::cli::parse_number(&format!("{:p}", payload.as_ptr()))?;

    let mut out = Vec::new();
    super::run(None, &LiveCommand::maps(pid, false, true), &mut out)?;
    let auto_maps: Value = serde_json::from_slice(&out)?;
    assert_eq!(
        (&auto_maps["schema_version"], &auto_maps["process"]["binary_match"]),
        (&Value::from(1), &Value::from("proc_exe_auto"))
    );
    assert_eq!(
        (&auto_maps["process"]["pid_alive_after"], &auto_maps["process"]["process_changed"]),
        (&Value::from(true), &Value::from(false))
    );
    assert!(auto_maps["regions"].as_array().is_some_and(|r| r.iter().any(|e| e["is_target_image"] == true)));

    out.clear();
    super::run(Some(&exe), &LiveCommand::resolve(pid, false, true, vec![sample_fn_addr]), &mut out)?;
    let rev_json: Value = serde_json::from_slice(&out)?;
    let static_va =
        crate::cli::parse_number(rev_json["addresses"][0]["static_va"].as_str().ok_or("missing static_va")?)?;
    let fn_start_str = rev_json["addresses"][0]["function_start"].as_str().ok_or("missing function_start")?;

    out.clear();
    super::run(Some(&exe), &LiveCommand::resolve(pid, false, true, vec![static_va]), &mut out)?;
    let fwd_json: Value = serde_json::from_slice(&out)?;
    assert_eq!(fwd_json["addresses"][0]["runtime_va"], format!("{sample_fn_addr:#x}"));

    out.clear();
    let subcommand = LiveSubcommand::Memscan {
        pid,
        align: 8,
        before_words: 2,
        after_words: 4,
        max_hits: 32,
        max_bytes: 1 << 29,
        timeout_ms: 10_000,
        force_bin: false,
        json: true,
        values: vec![magic0, magic1],
    };
    super::run(None, &LiveCommand { subcommand }, &mut out)?;
    let scan_json: Value = serde_json::from_slice(&out)?;
    let box_hit = scan_json["hits"]
        .as_array()
        .and_then(|hits| hits.iter().find(|h| h["runtime_va"] == format!("{box_addr:#x}")))
        .ok_or("Box hit not found in memscan")?;
    let ctx = box_hit["context"].as_array().ok_or("missing context")?;
    let word_10 = ctx.iter().find(|w| w["relative_offset"] == 16).ok_or("missing +0x10")?;
    assert_eq!(word_10["kind"], "code_ptr");
    assert_eq!(word_10["target_function"], fn_start_str);
    let kind_18 =
        ctx.iter().find(|w| w["relative_offset"] == 24).and_then(|w| w["kind"].as_str()).ok_or("missing +0x18")?;
    assert!(matches!(kind_18, "heap_ptr" | "anon_ptr"), "unexpected +0x18 kind: {kind_18}");
    std::hint::black_box((&payload, &heap_target));
    Ok(())
}
