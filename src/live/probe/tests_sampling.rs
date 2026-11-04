/*
 * XRef — live probe fetch, filter, and sampling tests
 * Copyright (c) 2026 Alexander Panasenko
 *
 * Contact: alex@prod.codes
 * Author: https://prod.codes/about/
 * Project: https://github.com/alex09x/xref
 * SPDX-License-Identifier: MIT OR Apache-2.0
 */

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::unreadable_literal)] // Test oracles unwrap controlled fixture state.

use std::collections::BTreeSet;
use std::path::Path;
use std::time::Duration;

use crate::live::probe::fetch::FetchArg;
use crate::live::probe::filter::ValueFilter;
use crate::live::probe::tracefs::{ProbeRunConfig, finalize_tracefs_observation};
use crate::live::probe::tracefs_stream::{StreamState, process_trace_line};
use crate::live::probe::types::{
    FetchedSample, FetchedValue, LostEvents, MAX_FETCHED_VALUES_PER_SESSION, ProbeStopReason, ProbeTargetResult,
    ProbeTargetSpec, UnwindEntryStatus,
};
use crate::live::types::{BinaryMatch, HexAddr, ProcessMeta};

fn probe_config() -> ProbeRunConfig<'static> {
    ProbeRunConfig {
        duration: Duration::from_millis(100),
        max_events: 100,
        want_callers: false,
        want_regs: false,
        fetches: vec![FetchArg { name: "amount".to_owned(), expression: "+0x30(%rcx):u64".to_owned() }],
        filters: vec![ValueFilter::parse("amount > 5").unwrap()],
        every: 2,
        first: Some(2),
        until_hits: Some(2),
        heartbeat_ms: None,
        mark_file: None,
        mark_regex: None,
        stream_json: false,
        spawn_watchdog: false,
        cancel: None,
    }
}

fn probe_spec() -> ProbeTargetSpec {
    ProbeTargetSpec {
        input: 0x1000,
        static_va: 0x1000,
        runtime_va: 0x1000,
        file_offset: 0x1000,
        function_start: Some(0x1000),
        function_end: Some(0x1010),
        function_offset: Some(0),
        symbol: None,
        instruction_mnemonic: "push".to_owned(),
        unwind_entry_abi: UnwindEntryStatus::StandardRsp8RaMinus8,
        ra_fetch_arg: None,
    }
}

fn probe_process() -> ProcessMeta {
    ProcessMeta {
        pid: 101,
        starttime_ticks: 1,
        pid_alive_after: true,
        process_changed: false,
        binary_match: BinaryMatch::ProcExeAuto,
        exe_sha256: None,
        pie_slide: 0,
        warnings: Vec::new(),
    }
}

#[test]
fn tracefs_fetch_filter_every_first_and_until_hits_are_bounded_and_reported() {
    let cfg = probe_config();
    let mut state = StreamState::new(101, BTreeSet::from([101]), 1);
    for i in 1..=8 {
        let line = format!(
            "app-101 (101) [000] d..1 {}.000001: xp_t_0: (0x555555555000) amount={} ",
            i,
            if i == 2 { 1 } else { 9 }
        );
        process_trace_line(&line, "xp_t_", Path::new("/missing"), &cfg, &mut state);
    }
    assert_eq!(state.total_accepted, 2);
    assert!(state.hit_until_hits);
    assert_eq!(state.accumulators[0].fetched_samples.len(), 2);
    assert_eq!(state.accumulators[0].fetched_samples[0].values[0].value.0, 9);
    assert_eq!(state.fetched_values, 2);

    let mut changed_tid = StreamState::new(101, BTreeSet::from([101]), 1);
    process_trace_line(
        "app-102 (101) [000] d..1 8.000001: xp_t_0: (0x555555555000) amount=9",
        "xp_t_",
        Path::new("/missing"),
        &cfg,
        &mut changed_tid,
    );
    assert_eq!(changed_tid.thread_changes[0].tid, 102);
    assert_eq!(changed_tid.thread_changes[0].action, "observed");

    let observation = finalize_tracefs_observation(
        &state,
        &cfg,
        1,
        100,
        ProbeStopReason::UntilHits,
        true,
        true,
        LostEvents::Known { overrun: 0, commit_overrun: 0, dropped_events: 0, perf_lost_records: 0, total: 0 },
    );
    assert_eq!(observation.stop_reason, ProbeStopReason::UntilHits);
    assert_eq!(observation.every, 2);
    assert_eq!(observation.first, Some(2));
    assert_eq!(observation.until_hits, Some(2));
    assert!(observation.counts_are_lower_bound);

    let mut capped = StreamState::new(101, BTreeSet::from([101]), 1);
    capped.fetched_values = MAX_FETCHED_VALUES_PER_SESSION;
    process_trace_line(
        "app-101 (101) [000] d..1 9.000001: xp_t_0: (0x555555555000) amount=9",
        "xp_t_",
        Path::new("/missing"),
        &cfg,
        &mut capped,
    );
    assert_eq!(capped.accumulators[0].fetched_samples.len(), 0, "fetch cap should not retain partial samples");
    assert!(capped.accumulators[0].fetched_samples_truncated);
}

#[test]
fn probe_table_renders_bounded_fetched_samples() {
    let cfg = probe_config();
    let empty_state = StreamState::new(101, BTreeSet::from([101]), 1);
    let observation = finalize_tracefs_observation(
        &empty_state,
        &cfg,
        1,
        1,
        ProbeStopReason::DurationElapsed,
        true,
        true,
        LostEvents::Known { overrun: 0, commit_overrun: 0, dropped_events: 0, perf_lost_records: 0, total: 0 },
    );
    let spec = probe_spec();
    let result = ProbeTargetResult {
        input: HexAddr(0x1000),
        static_va: HexAddr(0x1000),
        runtime_va: HexAddr(0x1000),
        file_offset: HexAddr(0x1000),
        function_start: Some(HexAddr(0x1000)),
        function_end: Some(HexAddr(0x1010)),
        function_offset: Some(0),
        symbol: None,
        instruction_mnemonic: "push".to_owned(),
        unwind_entry_abi: UnwindEntryStatus::StandardRsp8RaMinus8,
        accepted_hits: 1,
        first_timestamp_ns: Some(9),
        last_timestamp_ns: Some(9),
        callers: Vec::new(),
        callers_truncated: false,
        register_samples_truncated: false,
        register_samples: Vec::new(),
        fetched_samples: vec![FetchedSample {
            timestamp_ns: 9,
            va: None,
            tid: None,
            ret: None,
            mark: None,
            values: vec![FetchedValue { name: "amount".to_owned(), value: HexAddr(9) }],
        }],
        fetched_samples_truncated: false,
    };
    let report = crate::live::probe::build_probe_report(
        crate::live::cli::ProbeBackend::Tracefs,
        probe_process(),
        observation,
        vec![result],
        &[spec],
        false,
        false,
    );
    let mut table = Vec::new();
    crate::live::probe::write_probe_table(&report, &mut table).unwrap();
    let table = String::from_utf8(table).unwrap();
    assert!(table.contains("fetch ts 9  amount=0x9"), "{table}");
}

#[test]
fn probe_table_renders_multiple_probe_vas_and_marks() {
    let cfg = probe_config();
    let empty_state = StreamState::new(101, BTreeSet::from([101]), 2);
    let observation = finalize_tracefs_observation(
        &empty_state,
        &cfg,
        2,
        2,
        ProbeStopReason::DurationElapsed,
        true,
        true,
        LostEvents::Known { overrun: 0, commit_overrun: 0, dropped_events: 0, perf_lost_records: 0, total: 0 },
    );
    let spec1 = probe_spec();
    let mut spec2 = probe_spec();
    spec2.input = 0x2000;
    spec2.static_va = 0x2000;

    let result1 = ProbeTargetResult {
        input: HexAddr(0x1000),
        static_va: HexAddr(0x1000),
        runtime_va: HexAddr(0x1000),
        file_offset: HexAddr(0x1000),
        function_start: Some(HexAddr(0x1000)),
        function_end: Some(HexAddr(0x1010)),
        function_offset: Some(0),
        symbol: None,
        instruction_mnemonic: "push".to_owned(),
        unwind_entry_abi: UnwindEntryStatus::StandardRsp8RaMinus8,
        accepted_hits: 1,
        first_timestamp_ns: Some(9),
        last_timestamp_ns: Some(9),
        callers: Vec::new(),
        callers_truncated: false,
        register_samples_truncated: false,
        register_samples: Vec::new(),
        fetched_samples: vec![FetchedSample {
            timestamp_ns: 9,
            va: Some(HexAddr(0x1000)),
            tid: Some(101),
            ret: Some(HexAddr(0x401234)),
            mark: Some("TX-42".to_owned()),
            values: vec![FetchedValue { name: "amount".to_owned(), value: HexAddr(9) }],
        }],
        fetched_samples_truncated: false,
    };
    let mut result2 = result1.clone();
    result2.input = HexAddr(0x2000);
    result2.static_va = HexAddr(0x2000);
    result2.fetched_samples[0].va = Some(HexAddr(0x2000));

    let report = crate::live::probe::build_probe_report(
        crate::live::cli::ProbeBackend::Tracefs,
        probe_process(),
        observation,
        vec![result1, result2],
        &[spec1, spec2],
        false,
        false,
    );
    let mut table = Vec::new();
    crate::live::probe::write_probe_table(&report, &mut table).unwrap();
    let table = String::from_utf8(table).unwrap();
    assert!(table.contains("fetch va 0x1000  ts 9  amount=0x9  mark \"TX-42\""), "{table}");
    assert!(table.contains("fetch va 0x2000  ts 9  amount=0x9  mark \"TX-42\""), "{table}");
}

#[test]
fn format_hit_json_serializes_fields_correctly() {
    let mut fetch = std::collections::BTreeMap::new();
    fetch.insert("x".to_owned(), 0x123);
    let json = crate::live::probe::output::format_hit_json(0x401000, 42, &fetch, Some(0x402000), Some("REQ-99"));
    assert!(json.contains("\"va\":\"0x401000\""));
    assert!(json.contains("\"tid\":42"));
    assert!(json.contains("\"ret\":\"0x402000\""));
    assert!(json.contains("\"mark\":\"REQ-99\""));
    assert!(json.contains("\"x\":\"0x123\""));
}
