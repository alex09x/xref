/*
 * XRef — session bounds, fake-tracefs teardown, CLI validation, and Linux E2E tests for live trace
 * Copyright (c) 2026 Alexander Panasenko
 * Contact: alex@prod.codes
 * Author: https://prod.codes/about/
 * Project: https://github.com/alex09x/xref
 * SPDX-License-Identifier: MIT OR Apache-2.0
 */

use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use clap::Parser;

use crate::cli::{Cli, Command};
use crate::live::{
    cli::LiveSubcommand,
    procfs::LiveSession,
    trace::{
        cli::TraceLimits,
        output::{TraceStopReason, TraceWindowStatus, write_trace_text},
        plan::build_trace_plan,
        run_trace_session,
        tests::{SLIDE, TestResult, base_args, make_abc_image, make_exec_region, make_process_meta, probe_idx, rt},
        window::process_trace_lines,
    },
};

fn temp_trace_dir(tag: &str) -> Result<PathBuf, Box<dyn std::error::Error>> {
    let nanos = SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos();
    let dir = std::env::temp_dir().join(format!("xref-trace-unit-{tag}-{}-{nanos}", std::process::id()));
    std::fs::create_dir_all(&dir)?;
    Ok(dir)
}

fn setup_fake_tracefs_and_proc(
    root: &Path,
    pid: u32,
    nonce: &str,
    num_probes: usize,
    pipe_content: &str,
) -> Result<(PathBuf, PathBuf, PathBuf), Box<dyn std::error::Error>> {
    let tracefs_root = root.join("tracefs");
    let proc_root = root.join("proc");
    std::fs::create_dir_all(tracefs_root.join("instances"))?;
    std::fs::write(tracefs_root.join("uprobe_events"), "p:foreign/keep /bin/true:0x100\n")?;

    let inst_dir = tracefs_root.join("instances").join(format!("xref_trace_{pid}_{nonce}"));
    std::fs::create_dir_all(inst_dir.join("options"))?;
    std::fs::write(inst_dir.join("tracing_on"), "0\n")?;
    std::fs::write(inst_dir.join("trace_clock"), "local [mono]\n")?;
    std::fs::write(inst_dir.join("set_event_pid"), "")?;
    std::fs::write(inst_dir.join("free_buffer"), "")?;
    std::fs::write(inst_dir.join("trace_pipe"), pipe_content)?;

    for opt in ["context-info", "raw", "hex", "bin", "latency-format", "disable_on_free", "event-fork", "record-tgid"] {
        std::fs::write(inst_dir.join("options").join(opt), "0\n")?;
    }
    let group = format!("xt_{nonce}");
    for idx in 0..num_probes {
        let ev_dir = inst_dir.join("events").join(&group).join(format!("xt_{nonce}_{idx}"));
        std::fs::create_dir_all(&ev_dir)?;
        std::fs::write(ev_dir.join("enable"), "0\n")?;
        std::fs::write(ev_dir.join("filter"), "none\n")?;
    }
    let cpu0 = inst_dir.join("per_cpu/cpu0");
    std::fs::create_dir_all(&cpu0)?;
    std::fs::write(cpu0.join("stats"), "entries: 4\noverrun: 2\ncommit overrun: 0\ndropped events: 1\n")?;

    std::fs::create_dir_all(proc_root.join(format!("{pid}/task/5001")))?;
    Ok((tracefs_root, proc_root, inst_dir))
}

#[test]
fn cli_parser_and_validation_enforce_trace_contracts() -> TestResult {
    let cli = Cli::try_parse_from([
        "xref",
        "live",
        "trace",
        "--pid",
        "1234",
        "--start",
        "0x1000",
        "--start-filter",
        "op == 1",
        "--stop-return",
        "0x1000",
        "--callees-of",
        "fn_a",
        "--depth",
        "2",
        "--fetch-at",
        "0x1000",
        "op=%di:u64",
        "--fetch-ret",
        "0x1020",
        "rv=%ax:u64",
        "--max-windows",
        "5",
        "--json",
    ])?;
    let Command::Live(live_cmd) = cli.command else {
        return Err("expected Command::Live".into());
    };
    live_cmd.validate()?;
    let LiveSubcommand::Trace(args) = &live_cmd.subcommand else {
        return Err("expected LiveSubcommand::Trace".into());
    };
    let limits = args.effective_limits();
    assert_eq!((limits.duration_ms, limits.max_windows), (0, 5));

    let mut bad_both = base_args();
    bad_both.stop = vec![0x1014];
    assert!(bad_both.validate().is_err());

    let mut bad_depth = base_args();
    bad_depth.depth = Some(2);
    assert!(bad_depth.validate().is_err());

    let image = make_abc_image();
    let regions = [make_exec_region()];
    let mut bad_sr = base_args();
    bad_sr.stop_return = vec![0x1020];
    assert!(build_trace_plan(&image, SLIDE, &regions, &bad_sr).is_err());

    let mut unused_fetch = base_args();
    unused_fetch.fetch_at = vec!["0x1040".to_owned(), "x=%di:u64".to_owned()];
    assert!(build_trace_plan(&image, SLIDE, &regions, &unused_fetch).is_err());
    Ok(())
}

#[test]
fn fake_tracefs_max_windows_and_max_events_detach_all_probes_and_report_summary() -> TestResult {
    let image = make_abc_image();
    let regions = vec![make_exec_region()];
    let mut args = base_args();
    args.stop_return.clear();
    args.stop = vec![0x1014];
    args.callees_of = vec!["fn_a".to_owned()];
    args.fetch_at = vec!["0x1000".to_owned(), "op=%di:u64".to_owned()];
    args.start_filter = vec!["op == 1".to_owned()];
    let plan = build_trace_plan(&image, SLIDE, &regions, &args)?;

    let p_a = probe_idx(&plan, 0x1000, false)?;
    let p_stop = probe_idx(&plan, 0x1014, false)?;
    let p_cs1 = probe_idx(&plan, 0x1004, false)?;
    let p_ret1 = probe_idx(&plan, 0x1009, false)?;
    let nonce = "deadbeef00000001";
    let prefix = format!("xt_{nonce}_");

    // Two complete windows in pipe; --max-windows 1 must stop after window 1 and detach all probes.
    let pipe = [
        format!(
            "app-5001 (4242) [000] d..1. 1.000010: {prefix}{p_a}: ({:#x}) ra={:#x} op=0x1\n",
            rt(0x1000),
            rt(0x1055)
        ),
        format!("app-5001 (4242) [000] d..1. 1.000020: {prefix}{p_cs1}: ({:#x})\n", rt(0x1004)),
        format!("app-5001 (4242) [000] d..1. 1.000030: {prefix}{p_ret1}: ({:#x})\n", rt(0x1009)),
        format!("app-5001 (4242) [000] d..1. 1.000040: {prefix}{p_stop}: ({:#x})\n", rt(0x1014)),
        format!(
            "app-5001 (4242) [000] d..1. 2.000010: {prefix}{p_a}: ({:#x}) ra={:#x} op=0x1\n",
            rt(0x1000),
            rt(0x1055)
        ),
        format!("app-5001 (4242) [000] d..1. 2.000040: {prefix}{p_stop}: ({:#x})\n", rt(0x1014)),
    ]
    .concat();

    let root = temp_trace_dir("session")?;
    let (tracefs_root, proc_root, inst_dir) =
        setup_fake_tracefs_and_proc(&root, 4242, nonce, plan.probes.len(), &pipe)?;
    let mut session = LiveSession {
        image: make_abc_image(),
        process: make_process_meta(4242),
        regions: regions.clone(),
        #[cfg(target_os = "linux")]
        exe_dev_ino: Some((1, 2)),
    };

    let report = run_trace_session(
        &mut session,
        &plan,
        TraceLimits { duration_ms: 5000, max_windows: 1, max_events: 256 },
        false,
        None,
        &tracefs_root,
        &proc_root,
        nonce,
        false,
    )?;

    assert_eq!(report.summary.stop_reason, TraceStopReason::MaxWindows);
    assert_eq!(report.summary.windows, 1);
    assert_eq!(report.summary.lost, Some(3));
    assert!(report.windows[0].possible_loss);
    assert_eq!(std::fs::read_to_string(inst_dir.join("trace_clock"))?.trim(), "mono");
    let start_filter_file = std::fs::read_to_string(inst_dir.join(format!("events/xt_{nonce}/{prefix}{p_a}/filter")))?;
    assert_eq!(start_filter_file.trim(), "op == 1");

    let uprobe_log = std::fs::read_to_string(tracefs_root.join("uprobe_events"))?;
    assert!(uprobe_log.starts_with("p:foreign/keep /bin/true:0x100\n"));
    for idx in 0..plan.probes.len() {
        assert!(uprobe_log.contains(&format!("-:xt_{nonce}/{prefix}{idx}\n")));
    }

    let mut text = Vec::new();
    write_trace_text(&report, &mut text)?;
    let text_str = String::from_utf8(text)?;
    assert!(text_str.contains("summary: windows=1 events=4 lost=3 stop=max_windows"), "got:\n{text_str}");

    // Also verify --max-events truncation on the pure state machine.
    let lines: Vec<&str> = pipe.lines().collect();
    let trunc = process_trace_lines(&image, SLIDE, &regions, &plan, &prefix, Some(4242), 8, 2, &lines);
    assert_eq!(trunc.stop_reason, TraceStopReason::MaxEvents);
    assert_eq!(trunc.total_events, 2);
    assert_eq!(trunc.windows[0].status, TraceWindowStatus::Truncated);

    let _ = std::fs::remove_dir_all(&root);
    Ok(())
}

#[cfg(target_os = "linux")]
#[test]
fn linux_cc_compiled_target_validates_callees_plan_and_runs_when_privileged() -> TestResult {
    use std::io::BufRead;
    use std::process::{Command as ProcCommand, Stdio};

    let dir = temp_trace_dir("cc-e2e")?;
    let src = dir.join("target.c");
    let bin = dir.join("target_bin");
    std::fs::write(
        &src,
        r#"
#include <stdio.h>
#include <unistd.h>
__attribute__((noinline)) long fn_b(long x) { asm volatile("" : "+r"(x)); return x + 1; }
__attribute__((noinline)) long fn_c(long x) { asm volatile("" : "+r"(x)); return x * 2; }
__attribute__((noinline)) long fn_a(long x) {
    long r = fn_b(x);
    r = fn_c(r);
    return fn_b(r);
}
int main(void) {
    printf("READY\n");
    fflush(stdout);
    for (int i = 0; i < 400; ++i) {
        fn_a(i);
        usleep(5000);
    }
    return 0;
}
"#,
    )?;
    let status = ProcCommand::new("cc")
        .args(["-O1", "-fno-optimize-sibling-calls", "-g"])
        .arg(&src)
        .arg("-o")
        .arg(&bin)
        .status()?;
    assert!(status.success(), "cc failed to compile trace C fixture");

    let mut child = ProcCommand::new(&bin).stdout(Stdio::piped()).spawn()?;
    let pid = child.id();
    if let Some(stdout) = child.stdout.as_mut() {
        let mut line = String::new();
        let _ = std::io::BufReader::new(stdout).read_line(&mut line);
    }

    let session = crate::live::procfs::open_session(pid, Some(&bin), false)?;
    let sym_a = session.image.symbols.iter().find(|(_, n)| n == "fn_a").map(|(va, _)| *va).ok_or("missing fn_a")?;
    let mut args = base_args();
    args.pid = pid;
    args.start = vec![sym_a];
    args.stop_return = vec![sym_a];
    args.callees_of = vec!["fn_a".to_owned()];
    args.depth = Some(1);
    args.max_windows = Some(1);
    args.duration_ms = Some(1500);
    args.json = true;

    let plan = build_trace_plan(&session.image, session.process.pie_slide, &session.regions, &args)?;
    assert!(plan.probes.len() >= 5, "expected start + ret + 3 call/return probes, got {}", plan.probes.len());

    let writable_tracefs = std::fs::OpenOptions::new().append(true).open("/sys/kernel/tracing/uprobe_events").is_ok();
    let mut out = Vec::new();
    let exec_res = crate::live::trace::execute_trace(Some(&bin), &args, None, &mut out);
    let _ = child.kill();
    let _ = child.wait();
    let _ = std::fs::remove_dir_all(&dir);

    if writable_tracefs {
        exec_res?;
        let val: serde_json::Value = serde_json::from_slice(&out)?;
        assert_eq!(val["summary"]["windows"], 1);
        let window = &val["windows"][0];
        assert_eq!(window["status"], "complete", "window: {window}");
        let events = window["events"].as_array().ok_or("events must be an array")?;
        let order: Vec<String> = events
            .iter()
            .map(|e| {
                format!("{}:{}:{}", e["kind"].as_str().unwrap_or("?"), e["depth"], e["symbol"].as_str().unwrap_or("?"))
            })
            .collect();
        assert_eq!(
            order,
            [
                "entry:0:fn_a",
                "entry:1:fn_b",
                "return:1:fn_b",
                "entry:1:fn_c",
                "return:1:fn_c",
                "entry:1:fn_b",
                "return:1:fn_b",
                "return:0:fn_a"
            ],
            "program order inside one thread-scoped window"
        );
        let stamps: Vec<u64> = events.iter().filter_map(|e| e["timestamp_ns"].as_u64()).collect();
        assert!(stamps.windows(2).all(|w| w[0] <= w[1]), "monotonic timestamps: {stamps:?}");
    } else if let Err(err) = exec_res {
        let msg = err.to_string();
        assert!(msg.contains("uprobe_events"), "unexpected unprivileged tracefs error: {msg}");
    }
    Ok(())
}
