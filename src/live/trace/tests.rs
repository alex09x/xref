/*
 * XRef — unit tests for live trace planning, monotonic ordering, and start filters
 * Copyright (c) 2026 Alexander Panasenko
 * Contact: alex@prod.codes
 * Author: https://prod.codes/about/
 * Project: https://github.com/alex09x/xref
 * SPDX-License-Identifier: MIT OR Apache-2.0
 */

use std::error::Error;

use serde_json::Value;

use crate::image::{Image, Segment};
use crate::image_format::{LoadSegment, Metadata};
use crate::live::probe::types::LostEvents;
use crate::live::trace::{
    cli::TraceArgs,
    output::{
        TraceEventKind, TraceStopReason, TraceWindowStatus, build_trace_report, write_trace_json, write_trace_text,
    },
    plan::{ReturnMode, TracePlan, build_trace_plan},
    window::{parse_trace_line, process_parsed_events, process_trace_lines},
};
use crate::live::types::{BinaryMatch, HexAddr, ProcessMeta, RegionEntry, ScanStatus};

pub(super) type TestResult = Result<(), Box<dyn Error>>;

pub(super) const SLIDE: i64 = 0x5555_5555_4000;

pub(super) fn make_exec_region() -> RegionEntry {
    RegionEntry {
        start: HexAddr(0x5555_5555_5000),
        end: HexAddr(0x5555_5555_6000),
        perms: "r-xp".to_owned(),
        offset: HexAddr(0x1000),
        dev: "08:01".to_owned(),
        inode: 777,
        pathname: Some("/usr/bin/app".to_owned()),
        vm_flags: Some(vec!["rd".to_owned(), "ex".to_owned(), "mr".to_owned()]),
        is_target_image: true,
        scan_status: ScanStatus::SkippedNonWritable,
    }
}

pub(super) fn make_process_meta(pid: u32) -> ProcessMeta {
    ProcessMeta {
        pid,
        starttime_ticks: 100,
        pid_alive_after: true,
        process_changed: false,
        binary_match: BinaryMatch::ProcExeAuto,
        exe_sha256: Some("00".repeat(32)),
        pie_slide: SLIDE,
        warnings: Vec::new(),
    }
}

/// Hand-assembled x86-64 image at static `0x1000..0x1100`: `fn_a` (`0x1000..0x1015`) calls
/// `fn_b` (`@0x1004`), `fn_c` (`@0x1009`), `fn_b` (`@0x100e`); `fn_c` (`0x1030..0x1038`) tail-jumps to `fn_d`.
pub(super) fn make_abc_image() -> Image {
    let mut data = vec![0_u8; 0x2000];
    data[0x1000..0x1015].copy_from_slice(&[
        0x55, 0x48, 0x89, 0xe5, // 0x1000: push rbp; mov rbp, rsp
        0xe8, 0x17, 0x00, 0x00, 0x00, // 0x1004: call 0x1020 (fn_b), ret site 0x1009
        0xe8, 0x22, 0x00, 0x00, 0x00, // 0x1009: call 0x1030 (fn_c), ret site 0x100e
        0xe8, 0x0d, 0x00, 0x00, 0x00, // 0x100e: call 0x1020 (fn_b), ret site 0x1013
        0x5d, 0xc3, // 0x1013: pop rbp; ret
    ]);
    data[0x1020..0x1024].copy_from_slice(&[0x48, 0x89, 0xf8, 0xc3]);
    data[0x1030..0x1038].copy_from_slice(&[0x48, 0xff, 0xc7, 0xe9, 0x08, 0x00, 0x00, 0x00]);
    data[0x1040..0x1044].copy_from_slice(&[0x48, 0x89, 0xf8, 0xc3]);
    data[0x1050..0x1056].copy_from_slice(&[0xe8, 0xab, 0xff, 0xff, 0xff, 0xc3]);

    Image {
        data,
        segments: vec![Segment { va: 0x1000, offset: 0x1000, size: 0x100 }],
        functions: vec![0x1000..0x1015, 0x1020..0x1024, 0x1030..0x1038, 0x1040..0x1044, 0x1050..0x1056],
        symbols: [(0x1000, "fn_a"), (0x1020, "fn_b"), (0x1030, "fn_c"), (0x1040, "fn_d"), (0x1050, "fn_root")]
            .into_iter()
            .map(|(va, s)| (va, s.to_owned()))
            .collect(),
        metadata: Metadata {
            load_segments: vec![LoadSegment {
                va: 0x1000,
                file_offset: 0x1000,
                file_size: 0x100,
                mem_size: 0x100,
                executable: true,
                writable: false,
            }],
            ..Metadata::default()
        },
        ..Image::default()
    }
}

pub(super) fn base_args() -> TraceArgs {
    TraceArgs {
        pid: 4242,
        start: vec![0x1000],
        start_filter: Vec::new(),
        stop_return: vec![0x1000],
        stop: Vec::new(),
        functions: Vec::new(),
        callees_of: Vec::new(),
        depth: None,
        fetch: Vec::new(),
        fetch_at: Vec::new(),
        fetch_ret: Vec::new(),
        max_windows: None,
        max_events: None,
        duration_ms: None,
        force_bin: false,
        json: false,
    }
}

pub(super) fn probe_idx(plan: &TracePlan, static_va: u64, is_retprobe: bool) -> Result<usize, String> {
    plan.probes
        .iter()
        .position(|p| p.spec.static_va == static_va && p.is_retprobe == is_retprobe)
        .ok_or_else(|| format!("missing probe va={static_va:#x} ret={is_retprobe}"))
}

pub(super) fn rt(static_va: u64) -> u64 {
    static_va.wrapping_add_signed(SLIDE)
}

#[test]
fn orders_parsed_tracefs_lines_for_a_calls_b_then_c_then_b_and_renders_text_and_json() -> TestResult {
    let image = make_abc_image();
    let regions = [make_exec_region()];
    let mut args = base_args();
    args.callees_of = vec!["fn_a".to_owned()];
    args.depth = Some(1);
    let plan = build_trace_plan(&image, SLIDE, &regions, &args)?;
    assert_eq!(plan.return_mode, ReturnMode::MixedUretprobeBestEffort);

    let p_a = probe_idx(&plan, 0x1000, false)?;
    let r_a = probe_idx(&plan, 0x1000, true)?;
    let p_cs1 = probe_idx(&plan, 0x1004, false)?;
    let p_cs2_and_ret1 = probe_idx(&plan, 0x1009, false)?;
    let p_cs3_and_ret2 = probe_idx(&plan, 0x100e, false)?;
    let p_ret3 = probe_idx(&plan, 0x1013, false)?;

    // Out-of-order across per-CPU trace_pipe merge + noise on untraced tid 9999:
    // Monotonic timestamps for tid 5001 encode exact program order: A -> B -> C -> B -> <A.
    let prefix = "xt_0102030405060708_";
    let raw_lines = [
        format!("wrk-9999 (4242) [001] d..1. 10.000025: {prefix}{p_cs1}: ({:#x})", rt(0x1004)),
        format!("app-5001 (4242) [002] d..1. 10.000030: {prefix}{p_cs3_and_ret2}: ({:#x})", rt(0x100e)),
        format!("app-5001 (4242) [000] d..1. 10.000010: {prefix}{p_a}: ({:#x}) ra={:#x}", rt(0x1000), rt(0x1055)),
        format!("app-5001 (4242) [001] d..1. 10.000050: {prefix}{r_a}: ({:#x} <- {:#x})", rt(0x1055), rt(0x1000)),
        format!("app-5001 (4242) [000] d..1. 10.000020: {prefix}{p_cs2_and_ret1}: ({:#x})", rt(0x1009)),
        format!("app-5001 (4242) [000] d..1. 10.000015: {prefix}{p_cs1}: ({:#x})", rt(0x1004)),
        format!("app-5001 (4242) [002] d..1. 10.000040: {prefix}{p_ret3}: ({:#x})", rt(0x1013)),
    ];
    let refs: Vec<&str> = raw_lines.iter().map(String::as_str).collect();
    let out = process_trace_lines(&image, SLIDE, &regions, &plan, prefix, Some(4242), 16, 256, &refs);

    assert_eq!(out.windows.len(), 1);
    let win = &out.windows[0];
    assert_eq!(
        (win.tid, win.status, win.start_va, win.stop_va),
        (5001, TraceWindowStatus::Complete, HexAddr(0x1000), Some(HexAddr(0x1000)))
    );
    let summary_seq: Vec<(TraceEventKind, usize, u64, Option<u64>)> =
        win.events.iter().map(|e| (e.kind, e.depth, e.target_va.0, e.call_site_va.map(|h| h.0))).collect();
    assert_eq!(
        summary_seq,
        vec![
            (TraceEventKind::Entry, 0, 0x1000, Some(0x1050)),
            (TraceEventKind::Entry, 1, 0x1020, Some(0x1004)),
            (TraceEventKind::Return, 1, 0x1020, Some(0x1004)),
            (TraceEventKind::Entry, 1, 0x1030, Some(0x1009)),
            (TraceEventKind::Return, 1, 0x1030, Some(0x1009)),
            (TraceEventKind::Entry, 1, 0x1020, Some(0x100e)),
            (TraceEventKind::Return, 1, 0x1020, Some(0x100e)),
            (TraceEventKind::Return, 0, 0x1000, None),
        ]
    );

    let report = build_trace_report(
        make_process_meta(4242),
        out.windows,
        out.total_events,
        LostEvents::Known { overrun: 0, commit_overrun: 0, dropped_events: 0, perf_lost_records: 0, total: 0 },
        TraceStopReason::DurationElapsed,
        plan.return_mode,
        12,
        0,
        0,
        0,
    );
    let mut text = Vec::new();
    write_trace_text(&report, &mut text)?;
    let rendered = String::from_utf8(text)?;
    assert!(rendered.contains("> 0x1020 @0x1004 (fn_b)"), "got:\n{rendered}");
    assert!(rendered.contains("> 0x1030 @0x1009 (fn_c)"), "got:\n{rendered}");
    assert!(rendered.contains("> 0x1020 @0x100e (fn_b)"), "got:\n{rendered}");
    assert!(rendered.contains("< 0x1020 (fn_b)"), "got:\n{rendered}");
    assert!(rendered.contains("summary: windows=1 events=8 lost=0 stop=duration_elapsed"));

    let mut json_buf = Vec::new();
    write_trace_json(&report, &mut json_buf)?;
    let parsed_json: Value = serde_json::from_slice(&json_buf)?;
    assert_eq!(parsed_json["schema_version"], 1);
    assert_eq!(parsed_json["operation"], "live_trace");
    assert_eq!(parsed_json["summary"]["windows"], 1);
    assert_eq!(parsed_json["windows"][0]["events"][1]["call_site_va"], "0x1004");
    assert_eq!(parsed_json["windows"][0]["events"][3]["call_site_va"], "0x1009");
    assert_eq!(parsed_json["windows"][0]["events"][5]["call_site_va"], "0x100e");
    Ok(())
}

#[test]
fn start_filter_non_matching_starts_record_nothing() -> TestResult {
    let image = make_abc_image();
    let regions = [make_exec_region()];
    let mut args = base_args();
    args.functions = vec![0x1020, 0x1030];
    args.fetch_at = vec!["0x1000".to_owned(), "op=%di:u64".to_owned()];
    args.start_filter = vec!["op == 7".to_owned()];
    let plan = build_trace_plan(&image, SLIDE, &regions, &args)?;

    let p_a = probe_idx(&plan, 0x1000, false)?;
    let r_a = probe_idx(&plan, 0x1000, true)?;
    let p_b = probe_idx(&plan, 0x1020, false)?;
    let r_b = probe_idx(&plan, 0x1020, true)?;
    let p_c = probe_idx(&plan, 0x1030, false)?;
    let r_c = probe_idx(&plan, 0x1030, true)?;
    let prefix = "xt_feedface00000001_";

    // First invocation has op=3 (non-matching): must record zero windows and zero events.
    let non_matching = [
        format!("app-5001 (4242) [000] d..1. 1.000001: {prefix}{p_a}: ({:#x}) ra={:#x} op=0x3", rt(0x1000), rt(0x1055)),
        format!("app-5001 (4242) [000] d..1. 1.000002: {prefix}{p_b}: ({:#x}) ra={:#x}", rt(0x1020), rt(0x1009)),
        format!("app-5001 (4242) [000] d..1. 1.000003: {prefix}{r_b}: ({:#x} <- {:#x})", rt(0x1009), rt(0x1020)),
        format!("app-5001 (4242) [000] d..1. 1.000004: {prefix}{p_c}: ({:#x}) ra={:#x}", rt(0x1030), rt(0x100e)),
        format!("app-5001 (4242) [000] d..1. 1.000005: {prefix}{r_c}: ({:#x} <- {:#x})", rt(0x100e), rt(0x1030)),
        format!("app-5001 (4242) [000] d..1. 1.000006: {prefix}{r_a}: ({:#x} <- {:#x})", rt(0x1055), rt(0x1000)),
    ];
    let nm_events: Vec<_> = non_matching.iter().filter_map(|l| parse_trace_line(l, prefix)).collect();
    let empty_out = process_parsed_events(&image, SLIDE, &regions, &plan, 16, 256, &nm_events);
    assert_eq!(empty_out.windows, []);
    assert_eq!(empty_out.total_events, 0);

    // Follow non-matching window with a matching op=7 window: only op=7 is recorded.
    let mut combined = non_matching.to_vec();
    combined.extend([
        format!("app-5001 (4242) [000] d..1. 2.000001: {prefix}{p_a}: ({:#x}) ra={:#x} op=0x7", rt(0x1000), rt(0x1055)),
        format!("app-5001 (4242) [000] d..1. 2.000002: {prefix}{p_b}: ({:#x}) ra={:#x}", rt(0x1020), rt(0x1009)),
        format!("app-5001 (4242) [000] d..1. 2.000003: {prefix}{r_b}: ({:#x} <- {:#x})", rt(0x1009), rt(0x1020)),
        format!("app-5001 (4242) [000] d..1. 2.000004: {prefix}{r_a}: ({:#x} <- {:#x})", rt(0x1055), rt(0x1000)),
    ]);
    let comb_refs: Vec<&str> = combined.iter().map(String::as_str).collect();
    let matched = process_trace_lines(&image, SLIDE, &regions, &plan, prefix, Some(4242), 16, 256, &comb_refs);
    assert_eq!(matched.windows.len(), 1);
    assert_eq!(matched.windows[0].start_fetches[0].value, HexAddr(7));
    assert_eq!(matched.windows[0].events[1].call_site_va, Some(HexAddr(0x1004)));
    assert!(matched.windows[0].events[1].call_site_verified);
    Ok(())
}

#[test]
fn depth_two_marks_tail_jumps_and_attaches_aliased_fetches() -> TestResult {
    let image = make_abc_image();
    let regions = [make_exec_region()];
    let mut args = base_args();
    args.stop_return.clear();
    args.stop = vec![0x1014];
    args.callees_of = vec!["0x1000".to_owned()];
    args.depth = Some(2);
    // Attach colliding fetch name `val` on fn_b return (at 0x1009) and fn_c entry (also at 0x1009).
    args.fetch_ret = vec!["0x1020".to_owned(), "val=%ax:u64".to_owned()];
    args.fetch_at = vec!["0x1030".to_owned(), "val=%di:u64".to_owned()];
    let plan = build_trace_plan(&image, SLIDE, &regions, &args)?;
    assert_eq!(plan.return_mode, ReturnMode::CallSite);

    let p_a = probe_idx(&plan, 0x1000, false)?;
    let p_cs1 = probe_idx(&plan, 0x1004, false)?;
    let p_shared = probe_idx(&plan, 0x1009, false)?;
    let p_tail = probe_idx(&plan, 0x1033, false)?;
    let p_ret_c = probe_idx(&plan, 0x100e, false)?;
    let p_ret_b2 = probe_idx(&plan, 0x1013, false)?;
    let p_stop = probe_idx(&plan, 0x1014, false)?;
    assert_eq!(plan.probes[p_shared].kernel_fetches.len(), 2);
    assert_eq!(plan.probes[p_shared].kernel_fetches[1].name, "_xf_1");

    let prefix = "xt_aaaa0000bbbb1111_";
    let lines = [
        format!("t-77 (4242) [000] d..1. 5.000001: {prefix}{p_a}: ({:#x}) ra={:#x}", rt(0x1000), rt(0x1055)),
        format!("t-77 (4242) [000] d..1. 5.000002: {prefix}{p_cs1}: ({:#x})", rt(0x1004)),
        format!("t-77 (4242) [000] d..1. 5.000003: {prefix}{p_shared}: ({:#x}) val=0xaa _xf_1=0xbb", rt(0x1009)),
        format!("t-77 (4242) [000] d..1. 5.000004: {prefix}{p_tail}: ({:#x})", rt(0x1033)),
        format!("t-77 (4242) [000] d..1. 5.000005: {prefix}{p_ret_c}: ({:#x})", rt(0x100e)),
        format!("t-77 (4242) [000] d..1. 5.000006: {prefix}{p_ret_b2}: ({:#x}) val=0xcc", rt(0x1013)),
        format!("t-77 (4242) [000] d..1. 5.000007: {prefix}{p_stop}: ({:#x})", rt(0x1014)),
    ];
    let refs: Vec<&str> = lines.iter().map(String::as_str).collect();
    let out = process_trace_lines(&image, SLIDE, &regions, &plan, prefix, Some(4242), 8, 64, &refs);
    assert_eq!(out.unparsed_lines, 0);
    let win = &out.windows[0];
    assert_eq!(win.status, TraceWindowStatus::Complete);
    assert_eq!(win.stop_va, Some(HexAddr(0x1014)));
    assert_eq!(win.events[2].fetches[0].value, HexAddr(0xaa)); // < fn_b val=%ax
    assert_eq!(win.events[3].fetches[0].value, HexAddr(0xbb)); // > fn_c val=%di (aliased _xf_1)
    assert!(win.events[4].tail_call);
    assert_eq!((win.events[4].target_va, win.events[4].depth), (HexAddr(0x1040), 2));
    Ok(())
}
