/*
 * XRef — Unit tests for binary perf_event_open ring decoding, wrap-around, CFI RA, and capability matrix
 * Copyright (c) 2026 Alexander Panasenko
 * Contact: alex@prod.codes
 * Author: https://prod.codes/about/
 * Project: https://github.com/alex09x/xref
 * SPDX-License-Identifier: MIT OR Apache-2.0
 */

use std::error::Error;
use std::io;
use std::path::Path;

use crate::live::probe::capabilities::{FieldAvailability, build_perf_capabilities, build_tracefs_capabilities};
use crate::live::probe::perf::{format_perf_open_error, parse_uprobe_pmu_type_str};
use crate::live::probe::perf_ring::{
    DecodedPerfRecord, PERF_RECORD_FORK, PERF_RECORD_LOST, PERF_RECORD_SAMPLE, PERF_SAMPLE_IP, PERF_SAMPLE_REGS_ABI_64,
    PERF_SAMPLE_REGS_ABI_NONE, PERF_SAMPLE_REGS_USER, PERF_SAMPLE_STACK_USER, PERF_SAMPLE_TID, PERF_SAMPLE_TIME,
    PerfDecodeError, PerfRegsSample, XREF_PERF_REGS_MASK, decode_perf_record, drain_raw_ring_bytes,
    extract_return_addr_from_perf_sample,
};
use crate::live::probe::types::{ProbeTargetSpec, UnwindEntryStatus};

type TestResult = Result<(), Box<dyn Error>>;

fn push_record_circular(ring: &mut [u8], pos: &mut u64, rec_type: u32, misc: u16, payload: &[u8]) {
    assert!(payload.len().is_multiple_of(8));
    let total_size = u16::try_from(8 + payload.len()).unwrap_or(0);
    let mut full = Vec::with_capacity(usize::from(total_size));
    full.extend_from_slice(&rec_type.to_le_bytes());
    full.extend_from_slice(&misc.to_le_bytes());
    full.extend_from_slice(&total_size.to_le_bytes());
    full.extend_from_slice(payload);

    let mask = ring.len() - 1;
    for byte in full {
        let idx = usize::try_from(*pos).map_or(0, |v| v & mask);
        ring[idx] = byte;
        *pos += 1;
    }
}

#[test]
fn ring_buffer_drains_wrapped_header_and_wrapped_payload_accurately() -> TestResult {
    // 64-byte power-of-two ring; start tail at 60 so the 8-byte header itself splits 4+4 across wrap!
    let mut ring = [0xaa_u8; 64];
    let tail = 60_u64;
    let mut head = tail;

    // 1. PERF_RECORD_LOST (16-byte payload -> 24 bytes total: wraps header at 60..68 and payload at 4..20)
    let mut lost_payload = Vec::new();
    lost_payload.extend_from_slice(&77_u64.to_le_bytes());
    lost_payload.extend_from_slice(&9_u64.to_le_bytes());
    push_record_circular(&mut ring, &mut head, PERF_RECORD_LOST, 0, &lost_payload);

    // 2. PERF_RECORD_FORK (24-byte payload -> 32 bytes total: wraps payload across 64->0 again!)
    let mut fork_payload = Vec::new();
    fork_payload.extend_from_slice(&5000_u32.to_le_bytes());
    fork_payload.extend_from_slice(&5000_u32.to_le_bytes());
    fork_payload.extend_from_slice(&5009_u32.to_le_bytes());
    fork_payload.extend_from_slice(&5000_u32.to_le_bytes());
    fork_payload.extend_from_slice(&123_456_789_u64.to_le_bytes());
    push_record_circular(&mut ring, &mut head, PERF_RECORD_FORK, 0, &fork_payload);

    let (records, new_tail) = drain_raw_ring_bytes(&ring, tail, head).map_err(|e| format!("{e:?}"))?;
    assert_eq!(new_tail, head);
    assert_eq!(records.len(), 2);

    let d0 = decode_perf_record(records[0].rec_type, records[0].misc, &records[0].payload, 0, 0)
        .map_err(|e| format!("{e:?}"))?;
    assert_eq!(d0, DecodedPerfRecord::Lost { event_id: 77, lost: 9 });

    let d1 = decode_perf_record(records[1].rec_type, records[1].misc, &records[1].payload, 0, 0)
        .map_err(|e| format!("{e:?}"))?;
    assert_eq!(
        d1,
        DecodedPerfRecord::Fork {
            tgid: 5000,
            parent_tgid: 5000,
            thread_id: 5009,
            parent_tid: 5000,
            timestamp_ns: 123_456_789,
        }
    );

    assert_eq!(drain_raw_ring_bytes(&[0_u8; 48], 0, 0), Err(PerfDecodeError::InvalidRingSize));
    assert_eq!(drain_raw_ring_bytes(&ring, 10, 8), Err(PerfDecodeError::HeadBeforeTail));
    Ok(())
}

#[test]
fn perf_sample_decoder_parses_abi64_regs_and_cfi_stack_return_slot() -> TestResult {
    let sample_type =
        PERF_SAMPLE_IP | PERF_SAMPLE_TID | PERF_SAMPLE_TIME | PERF_SAMPLE_REGS_USER | PERF_SAMPLE_STACK_USER;
    let mut payload = Vec::new();
    payload.extend_from_slice(&0x5555_5555_5140_u64.to_le_bytes()); // ip
    payload.extend_from_slice(&4242_u32.to_le_bytes()); // tgid (pid)
    payload.extend_from_slice(&4243_u32.to_le_bytes()); // tid
    payload.extend_from_slice(&987_654_321_u64.to_le_bytes()); // time_ns

    // XREF_PERF_REGS_MASK ascending bit order: AX(0), CX(2), DX(3), SI(4), DI(5), BP(6), SP(7), R8(16), R9(17)
    payload.extend_from_slice(&PERF_SAMPLE_REGS_ABI_64.to_le_bytes());
    let reg_words: [u64; 9] = [
        0xaa,             // rax
        0x44,             // rcx
        0x33,             // rdx
        0x22,             // rsi
        0x11,             // rdi
        0x7fff_ffff_e020, // rbp
        0x7fff_ffff_e000, // rsp
        0x55,             // r8
        0x66,             // r9
    ];
    for word in reg_words {
        payload.extend_from_slice(&word.to_le_bytes());
    }

    // 64-byte allocated stack, 48-byte dyn_size; [rsp+0] = 0x555555555205, [rbp+8] = [rsp+0x28] = 0x555555555999
    let mut stack = [0_u8; 64];
    stack[0..8].copy_from_slice(&0x5555_5555_5205_u64.to_le_bytes());
    stack[24..32].copy_from_slice(&0x5555_5555_5777_u64.to_le_bytes());
    stack[40..48].copy_from_slice(&0x5555_5555_5999_u64.to_le_bytes());
    payload.extend_from_slice(&64_u64.to_le_bytes());
    payload.extend_from_slice(&stack);
    payload.extend_from_slice(&48_u64.to_le_bytes());

    let decoded = decode_perf_record(PERF_RECORD_SAMPLE, 0, &payload, sample_type, XREF_PERF_REGS_MASK)
        .map_err(|e| format!("{e:?}"))?;
    let DecodedPerfRecord::Sample(ev) = decoded else {
        return Err("expected Sample variant".into());
    };
    assert_eq!(ev.ip, Some(0x5555_5555_5140));
    assert_eq!(ev.tgid, Some(4242));
    assert_eq!(ev.thread_id, Some(4243));
    assert_eq!(ev.timestamp_ns, Some(987_654_321));
    assert_eq!(ev.user_stack.len(), 48);

    let regs = ev.regs.ok_or("expected ABI_64 registers")?;
    assert_eq!(
        regs,
        PerfRegsSample {
            rdi: 0x11,
            rsi: 0x22,
            rdx: 0x33,
            rcx: 0x44,
            r8: 0x55,
            r9: 0x66,
            rax: 0xaa,
            rsp: 0x7fff_ffff_e000,
            rbp: 0x7fff_ffff_e020,
        }
    );

    assert_eq!(
        extract_return_addr_from_perf_sample(&UnwindEntryStatus::StandardRsp8RaMinus8, Some(&regs), &ev.user_stack),
        Some(0x5555_5555_5205)
    );
    assert_eq!(
        extract_return_addr_from_perf_sample(
            &UnwindEntryStatus::InteriorFrameOffset { base_register: "rsp", disp: 24 },
            Some(&regs),
            &ev.user_stack
        ),
        Some(0x5555_5555_5777)
    );
    assert_eq!(
        extract_return_addr_from_perf_sample(
            &UnwindEntryStatus::InteriorFrameOffset { base_register: "rbp", disp: 8 },
            Some(&regs),
            &ev.user_stack
        ),
        Some(0x5555_5555_5999)
    );
    assert_eq!(
        extract_return_addr_from_perf_sample(
            &UnwindEntryStatus::Unavailable { detail: "missing".to_owned() },
            Some(&regs),
            &ev.user_stack
        ),
        None
    );
    Ok(())
}

#[test]
fn perf_sample_decoder_handles_abi_none_and_zero_length_stack() -> TestResult {
    let sample_type = PERF_SAMPLE_REGS_USER | PERF_SAMPLE_STACK_USER;
    let mut payload = Vec::new();
    payload.extend_from_slice(&PERF_SAMPLE_REGS_ABI_NONE.to_le_bytes()); // abi == 0 -> 0 reg words!
    payload.extend_from_slice(&0_u64.to_le_bytes()); // stack size == 0 -> NO dyn_size trailer!

    let decoded = decode_perf_record(PERF_RECORD_SAMPLE, 0, &payload, sample_type, XREF_PERF_REGS_MASK)
        .map_err(|e| format!("{e:?}"))?;
    let DecodedPerfRecord::Sample(ev) = decoded else {
        return Err("expected Sample".into());
    };
    assert!(ev.regs.is_none());
    assert_eq!(ev.user_stack, [] as [u8; 0]);
    Ok(())
}

#[test]
fn capability_matrix_and_perf_error_preserve_backend_distinctions() -> TestResult {
    let spec = ProbeTargetSpec {
        input: 0x1000,
        static_va: 0x1000,
        runtime_va: 0x5555_5555_5000,
        file_offset: 0x1000,
        function_start: Some(0x1000),
        function_end: Some(0x1020),
        function_offset: Some(0),
        symbol: None,
        instruction_mnemonic: "push".to_owned(),
        unwind_entry_abi: UnwindEntryStatus::StandardRsp8RaMinus8,
        ra_fetch_arg: Some("+0(%sp):x64".to_owned()),
    };

    let perf_caps = build_perf_capabilities(std::slice::from_ref(&spec), true, false);
    let tracefs_caps = build_tracefs_capabilities(std::slice::from_ref(&spec), true, false, true);

    assert_eq!(perf_caps.pid_isolated_breakpoint.available, FieldAvailability::Supported);
    assert!(perf_caps.pid_isolated_breakpoint.collected);
    assert!(!perf_caps.silent_fallback_permitted);

    assert_eq!(tracefs_caps.pid_isolated_breakpoint.available, FieldAvailability::Unsupported);
    assert!(!tracefs_caps.pid_isolated_breakpoint.collected);
    assert!(!tracefs_caps.silent_fallback_permitted);
    assert!(!perf_caps.registers.collected);

    assert_eq!(parse_uprobe_pmu_type_str("7\n", Path::new("/sys/bus/event_source/devices/uprobe/type"))?, 7);
    let eacces = io::Error::from_raw_os_error(13);
    let msg = format_perf_open_error("uprobe tid=42 file_offset=0x1000", &eacces, Some(4));
    assert!(msg.starts_with("permission_denied: perf_event_open"));
    assert!(msg.contains("perf_event_paranoid=4"));
    assert!(msg.contains("refusing silent fallback to tracefs"));

    // Verify UAPI record type numbers independently: LOST=2, EXIT=4, FORK=7, READ=8 (Other), SAMPLE=9.
    let mut exit_payload = Vec::new();
    for v in [100_u32, 100_u32, 101_u32, 100_u32] {
        exit_payload.extend_from_slice(&v.to_le_bytes());
    }
    exit_payload.extend_from_slice(&999_u64.to_le_bytes());
    assert_eq!(
        decode_perf_record(4, 0, &exit_payload, 0, 0).map_err(|e| format!("{e:?}"))?,
        DecodedPerfRecord::Exit { tgid: 100, thread_id: 101, timestamp_ns: 999 }
    );
    assert_eq!(
        decode_perf_record(8, 0, &exit_payload, 0, 0).map_err(|e| format!("{e:?}"))?,
        DecodedPerfRecord::Other { rec_type: 8 }
    );
    Ok(())
}

#[cfg(target_os = "linux")]
#[test]
#[allow(clippy::too_many_lines)]
fn perf_coverage_gaps_final_drain_truncation_and_report_schema() -> TestResult {
    use std::collections::BTreeSet;
    use std::ffi::CString;
    use std::time::Duration;

    use crate::live::cli::ProbeBackend;
    use crate::live::probe::build_probe_report;
    use crate::live::probe::perf::finalize_perf_observation;
    use crate::live::probe::perf_ring::PerfSampleEvent;
    use crate::live::probe::perf_stream::{PerfDrainCtx, attach_pending_tids, process_decoded_perf_record};
    use crate::live::probe::tracefs::ProbeRunConfig;
    use crate::live::probe::types::ProbeStopReason;
    use crate::live::types::{BinaryMatch, ProcessMeta};

    let spec = ProbeTargetSpec {
        input: 0x1000,
        static_va: 0x1000,
        runtime_va: 0x5555_5555_5000,
        file_offset: 0x1000,
        function_start: Some(0x1000),
        function_end: Some(0x1020),
        function_offset: Some(0),
        symbol: None,
        instruction_mnemonic: "push".to_owned(),
        unwind_entry_abi: UnwindEntryStatus::StandardRsp8RaMinus8,
        ra_fetch_arg: Some("+0(%sp):x64".to_owned()),
    };
    let specs = [spec];
    let cfg = ProbeRunConfig {
        duration: Duration::from_millis(50),
        max_events: 1,
        want_callers: false,
        want_regs: false,
        fetches: Vec::new(),
        filters: Vec::new(),
        every: 1,
        first: None,
        until_hits: None,
        heartbeat_ms: None,
        mark_file: None,
        mark_regex: None,
        stream_json: false,
        spawn_watchdog: false,
        cancel: None,
    };

    // 1. Failed dynamic attach on a pending TID must increment `unattached_fork_tids` and set `counts_are_lower_bound = true`.
    let mut ctx =
        PerfDrainCtx::new(4242, PERF_SAMPLE_IP | PERF_SAMPLE_TID, 0, false, false, &specs, BTreeSet::from([4242]));
    ctx.pending_new_tids.insert(999_999);
    let mut samplers = Vec::new();
    let bad_exe = CString::new("/nonexistent/xref_exe")?;
    attach_pending_tids(u32::MAX, &bad_exe, 0, &mut samplers, &mut ctx);
    assert!(!ctx.attached_tids.contains(&999_999));
    assert_eq!(ctx.unattached_fork_tids, 1);
    let obs_gap = finalize_perf_observation(&ctx, &cfg, 1, 50, ProbeStopReason::DurationElapsed);
    assert!(obs_gap.thread_coverage.partial_coverage);
    assert_eq!(obs_gap.thread_coverage.unattached_fork_tids, 1);
    assert!(obs_gap.counts_are_lower_bound);

    // 2. Final drain hitting `max_events = 1` after `DurationElapsed` must promote stop_reason to `MaxEvents` and set `truncated_by_max_events = true`.
    let mut ctx2 =
        PerfDrainCtx::new(4242, PERF_SAMPLE_IP | PERF_SAMPLE_TID, 0, false, false, &specs, BTreeSet::from([4242]));
    let sample = PerfSampleEvent {
        ip: Some(0x5555_5555_5000),
        tgid: Some(4242),
        thread_id: Some(4242),
        timestamp_ns: Some(100),
        regs: None,
        user_stack: Vec::new(),
    };
    process_decoded_perf_record(0, Ok(DecodedPerfRecord::Sample(sample.clone())), &mut ctx2, 1);
    process_decoded_perf_record(0, Ok(DecodedPerfRecord::Sample(sample)), &mut ctx2, 1);
    crate::live::probe::types::record_thread_change(
        &mut ctx2.thread_changes,
        &mut ctx2.thread_changes_truncated,
        4243,
        "attached",
    );
    let obs_trunc = finalize_perf_observation(&ctx2, &cfg, 1, 50, ProbeStopReason::DurationElapsed);
    assert_eq!(obs_trunc.stop_reason, ProbeStopReason::MaxEvents);
    assert!(obs_trunc.truncated_by_max_events);
    assert!(obs_trunc.counts_are_lower_bound);
    assert_eq!(obs_trunc.thread_changes[0].tid, 4243);
    assert_eq!(obs_trunc.thread_changes[0].action, "attached");

    // 3. Verify `build_probe_report` JSON schema for both `Perf` and `Tracefs`.
    let proc_meta = ProcessMeta {
        pid: 4242,
        starttime_ticks: 100,
        pid_alive_after: true,
        process_changed: false,
        binary_match: BinaryMatch::ProcExeAuto,
        exe_sha256: None,
        pie_slide: 0,
        warnings: Vec::new(),
    };
    for (backend, expected_name, expected_isolated) in
        [(ProbeBackend::Perf, "perf", true), (ProbeBackend::Tracefs, "tracefs", false)]
    {
        let rep = build_probe_report(backend, proc_meta.clone(), obs_trunc.clone(), Vec::new(), &specs, false, false);
        let json = serde_json::to_value(&rep)?;
        assert_eq!(json["operation"], "live_probe");
        assert_eq!(json["backend"], expected_name);
        assert_eq!(json["backend_selection"], "explicit_or_default_no_silent_fallback");
        assert_eq!(json["capabilities"]["pid_isolated_breakpoint"]["collected"], expected_isolated);
        assert_eq!(json["capabilities"]["silent_fallback_permitted"], false);
        assert_eq!(json["observation"]["thread_changes"][0]["tid"], 4243);
    }
    Ok(())
}
