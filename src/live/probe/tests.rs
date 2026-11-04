/*
 * XRef — Stage L2 unit tests for tracefs parsing, loss stats, caller attribution, and teardown
 * Copyright (c) 2026 Alexander Panasenko
 * Contact: alex@prod.codes
 * Author: https://prod.codes/about/
 * Project: https://github.com/alex09x/xref
 * SPDX-License-Identifier: MIT OR Apache-2.0
 */

use std::error::Error;
use std::io;
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

use crate::image::{Image, Segment};
use crate::image_format::{LoadSegment, Metadata};
use crate::live::probe::caller::attribute_caller;
use crate::live::probe::fetch::FetchArg;
use crate::live::probe::trace_parse::{
    StreamingTraceLineBuffer, format_uprobe_definition, format_uprobe_definition_with_fetches, parse_per_cpu_stats_dir,
    parse_uprobe_trace_line,
};
use crate::live::probe::tracefs_cleanup::{format_tracefs_io_error, teardown_session_resources};
use crate::live::probe::types::{LostEvents, UnwindEntryStatus};
use crate::live::probe::validate::{validate_probe_targets, validate_session_for_probe};
use crate::live::procfs::LiveSession;
use crate::live::types::{BinaryMatch, HexAddr, ProcessMeta, RegionEntry, ScanStatus};

type TestResult = Result<(), Box<dyn Error>>;

fn temp_test_dir(tag: &str) -> Result<PathBuf, Box<dyn Error>> {
    let nanos = SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos();
    let dir = std::env::temp_dir().join(format!("xref-probe-unit-{tag}-{}-{nanos}", std::process::id()));
    std::fs::create_dir_all(&dir)?;
    Ok(dir)
}

fn make_exec_region(start: u64, end: u64, is_target: bool) -> RegionEntry {
    RegionEntry {
        start: HexAddr(start),
        end: HexAddr(end),
        perms: "r-xp".to_owned(),
        offset: HexAddr(0x1000),
        dev: "08:01".to_owned(),
        inode: 777,
        pathname: Some("/usr/bin/app".to_owned()),
        vm_flags: Some(vec!["rd".to_owned(), "ex".to_owned(), "mr".to_owned()]),
        is_target_image: is_target,
        scan_status: ScanStatus::SkippedNonWritable,
    }
}

#[test]
fn uprobe_definition_uses_kernel_x86_64_pt_regs_names() {
    let def = format_uprobe_definition(
        "xp_0123456789abcdef",
        "xp_0123456789abcdef_0",
        "/proc/1234/exe",
        0x1420,
        Some("+0(%sp):x64"),
        true,
    );
    assert_eq!(
        def,
        "p:xp_0123456789abcdef/xp_0123456789abcdef_0 /proc/1234/exe:0x1420 ra=+0(%sp):x64 rdi=%di:x64 rsi=%si:x64 rdx=%dx:x64 rcx=%cx:x64 r8=%r8:x64 r9=%r9:x64 rax=%ax:x64 rsp=%sp:x64 rbp=%bp:x64\n"
    );
}

#[test]
fn uprobe_definition_appends_validated_fetch_arguments() {
    let fetches = [FetchArg { name: "amount".to_owned(), expression: "+0x30(%rcx):u64".to_owned() }];
    let def = format_uprobe_definition_with_fetches("xp", "xp_0", "/proc/1/exe", 0x1000, None, false, &fetches);
    assert_eq!(def, "p:xp/xp_0 /proc/1/exe:0x1000 amount=+0x30(%rcx):u64\n");
}

#[test]
fn trace_line_parser_handles_adversarial_comm_and_record_tgid() -> TestResult {
    let prefix = "xp_deadbeefcafebabe_";
    let line_with_tgid = "my - [007] (9):xp-42424   (  12345) [015] d..1. 99.123456: xp_deadbeefcafebabe_2: (0x555555555140) ra=0x555555555205 rdi=0x1 rsi=0x2 rdx=0x3 rcx=0x4 r8=0x5 r9=0x6 rax=0x7 rsp=0x7fffffffe000 rbp=0x7fffffffe020 amount=0x2a";
    let ev = parse_uprobe_trace_line(line_with_tgid, prefix).ok_or("expected parse")?;
    assert_eq!(ev.probe_index, 2);
    assert_eq!(ev.tid, 42424);
    assert_eq!(ev.tgid, Some(12345));
    assert_eq!(ev.timestamp_ns, Some(99_123_456_000));
    assert_eq!(ev.fetch_values.get("amount"), Some(&0x2a));
    assert_eq!(ev.value("rdi"), Some(1));
    assert_eq!(ev.value("amount"), Some(0x2a));
    assert_eq!(ev.hit_ip, 0x5555_5555_5140);
    assert_eq!(ev.return_addr, Some(0x5555_5555_5205));
    let regs = ev.regs.ok_or("expected regs")?;
    assert_eq!((regs.rdi, regs.rsi, regs.rax, regs.rsp, regs.rbp), (1, 2, 7, 0x7fff_ffff_e000, Some(0x7fff_ffff_e020)));

    let line_dash_tgid =
        "worker:pool-1-777     (  -----) [000] ..... 10.000001: xp_deadbeefcafebabe_0: (0x401000) ra=0x401055";
    let ev2 = parse_uprobe_trace_line(line_dash_tgid, prefix).ok_or("expected parse dash tgid")?;
    assert_eq!((ev2.probe_index, ev2.tid, ev2.tgid, ev2.return_addr), (0, 777, None, Some(0x0040_1055)));

    let line_no_tgid = "foo (99)-8888  [003] d.... 11.5: xp_deadbeefcafebabe_1: (0x402000)";
    let ev3 = parse_uprobe_trace_line(line_no_tgid, prefix).ok_or("expected parse without record-tgid")?;
    assert_eq!((ev3.probe_index, ev3.tid, ev3.tgid, ev3.return_addr), (1, 8888, None, None));
    Ok(())
}

#[test]
fn streaming_line_buffer_reassembles_split_reads_and_skips_comments() {
    let raw = b"# tracer: nop\n# header\ncmd-101 [001] .... 1.0: xp_0011223344556677_0: (0x401000)\ncmd-102 [002] .... 2.0: xp_0011223344556677_0: (0x401000)";
    let mut buf = StreamingTraceLineBuffer::default();
    let mut lines = Vec::new();
    for small in raw.chunks(5) {
        buf.push_chunk(small, |l| lines.push(l.to_owned()));
    }
    buf.finish(|l| lines.push(l.to_owned()));
    assert_eq!(lines.len(), 2);
    assert!(lines[0].contains("cmd-101"));
    assert!(lines[1].contains("cmd-102"));
}

#[test]
fn per_cpu_stats_sums_all_loss_counters_and_marks_missing_as_unknown() -> TestResult {
    let root = temp_test_dir("stats")?;
    let missing = parse_per_cpu_stats_dir(&root.join("nonexistent"));
    assert!(matches!(missing, LostEvents::Unknown { .. }));
    assert!(missing.has_possible_loss());

    let per_cpu = root.join("per_cpu");
    std::fs::create_dir_all(per_cpu.join("cpu0"))?;
    std::fs::create_dir_all(per_cpu.join("cpu1"))?;
    std::fs::write(
        per_cpu.join("cpu0/stats"),
        "entries: 12\noverrun: 3\ncommit overrun: 2\nbytes: 512\ndropped events: 5\n",
    )?;
    std::fs::write(
        per_cpu.join("cpu1/stats"),
        "entries: 0\noverrun: 1\ncommit overrun: 4\nbytes: 0\ndropped events: 0\n",
    )?;

    let parsed = parse_per_cpu_stats_dir(&per_cpu);
    assert_eq!(
        parsed,
        LostEvents::Known { overrun: 4, commit_overrun: 6, dropped_events: 5, perf_lost_records: 0, total: 15 }
    );

    // Missing required counters (e.g. only `entries` and `bytes`) must return Unknown, never Known { total: 0 }!
    std::fs::write(per_cpu.join("cpu0/stats"), "entries: 0\nbytes: 0\n")?;
    let incomplete = parse_per_cpu_stats_dir(&per_cpu);
    assert!(matches!(incomplete, LostEvents::Unknown { .. }), "incomplete stats must be Unknown: {incomplete:?}");

    // Duplicate counter line in a single CPU stats file must also return Unknown.
    std::fs::write(per_cpu.join("cpu0/stats"), "overrun: 0\noverrun: 1\ncommit overrun: 0\ndropped events: 0\n")?;
    let dup = parse_per_cpu_stats_dir(&per_cpu);
    assert!(matches!(dup, LostEvents::Unknown { .. }), "duplicate counter must be Unknown: {dup:?}");

    let _ = std::fs::remove_dir_all(&root);
    Ok(())
}

#[test]
fn tracefs_format_guard_and_final_drain_coverage_lower_bounds() -> TestResult {
    use std::collections::BTreeSet;
    use std::time::Duration;

    use crate::live::probe::tracefs::{ProbeRunConfig, finalize_tracefs_observation};
    use crate::live::probe::tracefs_setup::configure_tracefs_instance_format;
    use crate::live::probe::tracefs_stream::{StreamState, process_trace_line};
    use crate::live::probe::types::ProbeStopReason;

    let root = temp_test_dir("fmt-and-drain")?;
    let inst = root.join("instances/xref_test");
    std::fs::create_dir_all(inst.join("options"))?;
    std::fs::write(inst.join("tracing_on"), "1\n")?;
    std::fs::write(inst.join("trace_clock"), "local\n")?;
    for opt in ["context-info", "raw", "hex", "bin", "latency-format"] {
        std::fs::write(inst.join("options").join(opt), "init\n")?;
    }
    configure_tracefs_instance_format(&inst)?;
    assert_eq!(std::fs::read_to_string(inst.join("trace_clock"))?.trim(), "mono");
    assert_eq!(std::fs::read_to_string(inst.join("options/context-info"))?.trim(), "1");
    assert_eq!(std::fs::read_to_string(inst.join("options/raw"))?.trim(), "0");
    assert_eq!(std::fs::read_to_string(inst.join("options/hex"))?.trim(), "0");
    assert_eq!(std::fs::read_to_string(inst.join("options/bin"))?.trim(), "0");
    assert_eq!(std::fs::read_to_string(inst.join("options/latency-format"))?.trim(), "0");

    // Verify `nolatency-format` standard header (`[000]` + `seconds.fraction`) parses cleanly while `latency-format` (`000` without brackets + relative `us`) is rejected as unparsed.
    let std_line = "app-100   (    100) [000] d..1  1234.567890: xp_t_0: (0x555555555000)";
    let lat_line = "app-100     100 000 d..1    12us : xp_t_0: (0x555555555000)";
    assert!(parse_uprobe_trace_line(std_line, "xp_t_").is_some());
    assert!(parse_uprobe_trace_line(lat_line, "xp_t_").is_none());

    // Final drain hitting `max_events = 1` after `DurationElapsed` must set `MaxEvents`, `truncated_by_max_events`, and `counts_are_lower_bound`.
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
    let mut state = StreamState::new(100, BTreeSet::from([100]), 1);
    let line1 = "app-100 (100) [000] d..1 1.000000: xp_t_0: (0x555555555000)";
    let line2 = "app-100 (100) [000] d..1 1.000001: xp_t_0: (0x555555555000)";
    process_trace_line(line1, "xp_t_", &root, &cfg, &mut state);
    process_trace_line(line2, "xp_t_", &root, &cfg, &mut state);
    let zero_loss =
        LostEvents::Known { overrun: 0, commit_overrun: 0, dropped_events: 0, perf_lost_records: 0, total: 0 };
    let obs = finalize_tracefs_observation(
        &state,
        &cfg,
        1,
        50,
        ProbeStopReason::DurationElapsed,
        true,
        true,
        zero_loss.clone(),
    );
    assert_eq!(obs.stop_reason, ProbeStopReason::MaxEvents);
    assert!(obs.truncated_by_max_events);
    assert!(obs.counts_are_lower_bound);

    // Unparsed line or disabled event-fork or ambiguous_tid must also mark lower_bound = true.
    let mut state2 = StreamState::new(100, BTreeSet::from([100]), 1);
    let cfg2 = ProbeRunConfig { max_events: 10, ..cfg };
    process_trace_line("corrupted raw line without header", "xp_t", &root, &cfg2, &mut state2);
    let obs2 =
        finalize_tracefs_observation(&state2, &cfg2, 1, 50, ProbeStopReason::DurationElapsed, true, true, zero_loss);
    assert_eq!(obs2.thread_coverage.unparsed_events, 1);
    assert!(obs2.thread_coverage.partial_coverage);
    assert!(obs2.counts_are_lower_bound);

    let _ = std::fs::remove_dir_all(&root);
    Ok(())
}

#[test]
fn caller_attribution_uses_ra_minus_one_for_trailing_noreturn_calls() {
    // caller_fn = 0x1000..0x1006: `nop` (0x90) at 0x1000, `call +0x20` (e8 1a 00 00 00) at 0x1001..0x1006
    // adjacent next_fn starts immediately at 0x1006!
    let mut data = vec![0_u8; 0x2000];
    data[0x1000] = 0x90;
    data[0x1001..0x1006].copy_from_slice(&[0xe8, 0x1a, 0x00, 0x00, 0x00]);
    data[0x1006] = 0xc3;

    let image = Image {
        data,
        segments: vec![Segment { va: 0x1000, offset: 0x1000, size: 0x100 }],
        functions: vec![0x1000..0x1006, 0x1006..0x1007],
        pointers: Vec::new(),
        imports: Vec::new(),
        symbols: vec![(0x1000, "caller_noreturn".to_owned()), (0x1006, "adjacent_next".to_owned())],
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
    };
    let slide = 0x5555_5555_4000_i64;
    let regions = vec![make_exec_region(0x5555_5555_5000, 0x5555_5555_6000, true)];

    // Return address pushed by trailing CALL at 0x1001..0x1006 is 0x1006 (+ slide).
    let entry =
        attribute_caller(&image, slide, &regions, &UnwindEntryStatus::StandardRsp8RaMinus8, 0x5555_5555_5006, 7);
    assert_eq!(entry.return_static_va, Some(HexAddr(0x1006)));
    assert_eq!(entry.caller_function, Some(HexAddr(0x1000)));
    assert_eq!(entry.caller_symbol.as_deref(), Some("caller_noreturn"));
    assert_eq!(entry.call_site_static_va, Some(HexAddr(0x1001)));
    assert!(entry.call_verified);
    assert_eq!(entry.caveat, "unwind_evidence_only_tail_call_possible");
}

#[test]
fn validate_session_and_mid_instruction_rejection() -> TestResult {
    // 0x1000: 48 83 ec 10 (`sub rsp, 0x10`), 0x1004: c3 (`ret`)
    let mut data = vec![0_u8; 0x2000];
    data[0x1000..0x1005].copy_from_slice(&[0x48, 0x83, 0xec, 0x10, 0xc3]);
    let image = Image {
        data,
        segments: vec![Segment { va: 0x1000, offset: 0x1000, size: 0x100 }],
        functions: std::slice::from_ref(&(0x1000..0x1005)).to_vec(),
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
    };
    let regions = vec![make_exec_region(0x5555_5555_5000, 0x5555_5555_6000, true)];

    let ok_specs = validate_probe_targets(&image, 0x5555_5555_4000, &regions, &[0x1000, 0x1004])?;
    assert_eq!(ok_specs.len(), 2);
    assert_eq!(ok_specs[0].instruction_mnemonic, "sub");
    assert_eq!(ok_specs[1].instruction_mnemonic, "ret");

    let mid_err = validate_probe_targets(&image, 0x5555_5555_4000, &regions, &[0x1002])
        .err()
        .ok_or("expected mid-instruction error")?;
    assert!(mid_err.contains("lands mid-instruction"), "got: {mid_err}");

    let forced_session = LiveSession {
        image,
        process: ProcessMeta {
            pid: 99,
            starttime_ticks: 1,
            pid_alive_after: true,
            process_changed: false,
            binary_match: BinaryMatch::ForcedMismatch,
            exe_sha256: None,
            pie_slide: 0,
            warnings: Vec::new(),
        },
        regions,
        #[cfg(target_os = "linux")]
        exe_dev_ino: Some((1, 2)),
    };
    let sess_err = validate_session_for_probe(&forced_session).err().ok_or("expected forced mismatch rejection")?;
    assert!(sess_err.contains("verified executable identity required"), "got: {sess_err}");
    Ok(())
}

#[test]
fn teardown_preserves_foreign_uprobes_and_permission_denied_is_honest() -> TestResult {
    let root = temp_test_dir("teardown")?;
    let uprobe_events = root.join("uprobe_events");
    std::fs::write(&uprobe_events, "p:foreign/keep_probe /usr/bin/other:0x100\n")?;
    let inst = root.join("instances/xref_42_abcd");
    std::fs::create_dir_all(&inst)?;

    let registered = vec!["xp_abcd/xp_abcd_0".to_owned(), "xp_abcd/xp_abcd_1".to_owned()];
    let warns = teardown_session_resources(&root, &inst, &registered, None, None);
    assert!(warns.is_empty(), "unexpected warnings: {warns:?}");
    assert!(!inst.exists(), "empty instance directory should be rmdir'd");

    let final_events = std::fs::read_to_string(&uprobe_events)?;
    assert!(final_events.starts_with("p:foreign/keep_probe /usr/bin/other:0x100\n"));
    assert!(final_events.contains("-:xp_abcd/xp_abcd_1\n"));
    assert!(final_events.contains("-:xp_abcd/xp_abcd_0\n"));

    let eacces = io::Error::from_raw_os_error(13);
    let diag = format_tracefs_io_error("open uprobe_events", &uprobe_events, &eacces);
    assert!(diag.starts_with("permission_denied:"));
    assert!(diag.contains("errno 13:"));
    assert!(diag.contains("CAP_PERFMON alone does not bypass"));

    let _ = std::fs::remove_dir_all(&root);
    Ok(())
}
