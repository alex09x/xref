/*
 * XRef — Linux tracefs uprobe session orchestration for live call trace windows
 * Copyright (c) 2026 Alexander Panasenko
 * Contact: alex@prod.codes
 * Author: https://prod.codes/about/
 * Project: https://github.com/alex09x/xref
 * SPDX-License-Identifier: MIT OR Apache-2.0
 */

pub mod cli;
#[cfg(any(target_os = "linux", test))]
pub mod output;
#[cfg(any(target_os = "linux", test))]
pub mod plan;
#[cfg(any(target_os = "linux", test))]
mod plan_helpers;
#[cfg(any(target_os = "linux", test))]
mod stream;
#[cfg(test)]
mod tests;
#[cfg(test)]
mod tests_runtime;
#[cfg(any(target_os = "linux", test))]
pub mod window;
#[cfg(any(target_os = "linux", test))]
mod window_helpers;
#[cfg(any(target_os = "linux", test))]
mod window_parse;

#[cfg(any(target_os = "linux", test))]
use std::{
    error::Error,
    fs::{File, OpenOptions},
    io::Write,
    path::Path,
    sync::atomic::AtomicBool,
    time::{Duration, Instant},
};

#[cfg(any(target_os = "linux", test))]
use crate::live::{
    probe::{
        trace_parse::{StreamingTraceLineBuffer, parse_per_cpu_stats_dir},
        tracefs::{enable_session_events, make_session_hex, seed_target_tids, verify_exe_still_matches},
        tracefs_cleanup::{
            CleanupSupervisor, append_tracefs_line, discover_tracefs_root, format_tracefs_io_error,
            teardown_session_resources, write_tracefs_control,
        },
        tracefs_filter::configure_probe_filters,
        tracefs_setup::{configure_tracefs_instance_format, open_nonblocking_read},
        tracefs_stream::StreamState,
        types::{ProbeTargetSpec, emit_probe_ready_stderr},
        validate::validate_session_for_probe,
    },
    procfs::{LiveSession, open_session, refresh_session_identity},
    trace::{
        cli::{TraceArgs, TraceLimits},
        output::{TraceReport, build_trace_report, write_trace_json, write_trace_text},
        plan::{ReturnMode, TracePlan, build_trace_plan},
        stream::{drain_remaining_trace_pipe, stream_trace_pipe},
        window::TraceWindowEngine,
    },
};

#[cfg(any(target_os = "linux", test))]
pub fn execute_trace(
    bin: Option<&Path>,
    args: &TraceArgs,
    cancel: Option<&AtomicBool>,
    out: &mut dyn Write,
) -> Result<(), Box<dyn Error>> {
    let mut session = open_session(args.pid, bin, args.force_bin)?;
    validate_session_for_probe(&session)?;
    let plan = build_trace_plan(&session.image, session.process.pie_slide, &session.regions, args)?;
    if plan.return_mode != ReturnMode::CallSite
        && !session.process.warnings.iter().any(|w| w == "uretprobe_returns_are_best_effort_under_unwind")
    {
        session.process.warnings.push("uretprobe_returns_are_best_effort_under_unwind".to_owned());
    }
    let root = discover_tracefs_root();
    let report =
        run_trace_with_roots(&mut session, &plan, args.effective_limits(), true, cancel, &root, Path::new("/proc"))?;
    if args.json { write_trace_json(&report, out) } else { write_trace_text(&report, out).map_err(Into::into) }
}

#[cfg(any(target_os = "linux", test))]
pub fn run_trace_with_roots(
    session: &mut LiveSession,
    plan: &TracePlan,
    limits: TraceLimits,
    spawn_watchdog: bool,
    cancel: Option<&AtomicBool>,
    tracefs_root: &Path,
    proc_root: &Path,
) -> Result<TraceReport, String> {
    let nonce_hex = make_session_hex();
    run_trace_session(session, plan, limits, spawn_watchdog, cancel, tracefs_root, proc_root, &nonce_hex, true)
}

#[cfg(any(target_os = "linux", test))]
#[allow(clippy::too_many_arguments)]
pub fn run_trace_session(
    session: &mut LiveSession,
    plan: &TracePlan,
    limits: TraceLimits,
    spawn_watchdog: bool,
    cancel: Option<&AtomicBool>,
    tracefs_root: &Path,
    proc_root: &Path,
    nonce_hex: &str,
    create_instance_dir: bool,
) -> Result<TraceReport, String> {
    verify_exe_still_matches(session, proc_root)?;
    let uprobe_events_path = tracefs_root.join("uprobe_events");
    let _probe_check = OpenOptions::new()
        .append(true)
        .open(&uprobe_events_path)
        .map_err(|e| format_tracefs_io_error("open uprobe_events", &uprobe_events_path, &e))?;

    let group = format!("xt_{nonce_hex}");
    let event_prefix = format!("xt_{nonce_hex}_");
    let instance_name = format!("xref_trace_{}_{nonce_hex}", session.process.pid);
    let instance_dir = tracefs_root.join("instances").join(&instance_name);
    let planned_events: Vec<String> = (0..plan.probes.len()).map(|i| format!("{group}/{event_prefix}{i}")).collect();

    let mut supervisor =
        if spawn_watchdog { CleanupSupervisor::spawn(tracefs_root, &instance_name, &planned_events) } else { None };

    let exec_path = proc_root.join(session.process.pid.to_string()).join("exe");
    let exec_path_str = exec_path.to_string_lossy();
    let mut registered_events = Vec::with_capacity(plan.probes.len());
    for (idx, probe) in plan.probes.iter().enumerate() {
        let ev_name = format!("{event_prefix}{idx}");
        let def = probe.uprobe_definition(&group, &ev_name, &exec_path_str);
        if let Err(err) = append_tracefs_line(&uprobe_events_path, &def, "register trace uprobe") {
            let _ = teardown_session_resources(tracefs_root, &instance_dir, &registered_events, None, None);
            if let Some(sup) = &mut supervisor {
                sup.disarm_and_wait();
            }
            return Err(err);
        }
        registered_events.push(format!("{group}/{ev_name}"));
    }

    let outcome = execute_trace_instance(
        session,
        plan,
        limits,
        cancel,
        tracefs_root,
        proc_root,
        &instance_dir,
        &event_prefix,
        &registered_events,
        create_instance_dir,
    );
    if let Some(sup) = &mut supervisor {
        sup.disarm_and_wait();
    }
    outcome
}

#[cfg(any(target_os = "linux", test))]
#[allow(clippy::too_many_arguments, clippy::too_many_lines)]
fn execute_trace_instance(
    session: &mut LiveSession,
    plan: &TracePlan,
    limits: TraceLimits,
    cancel: Option<&AtomicBool>,
    tracefs_root: &Path,
    proc_root: &Path,
    instance_dir: &Path,
    event_prefix: &str,
    registered_events: &[String],
    create_instance_dir: bool,
) -> Result<TraceReport, String> {
    if create_instance_dir && let Err(err) = std::fs::create_dir(instance_dir) {
        let _ = teardown_session_resources(tracefs_root, instance_dir, registered_events, None, None);
        return Err(format_tracefs_io_error("mkdir instance", instance_dir, &err));
    }
    if let Err(err) = configure_tracefs_instance_format(instance_dir) {
        let _ = teardown_session_resources(tracefs_root, instance_dir, registered_events, None, None);
        return Err(err);
    }
    let _ = write_tracefs_control(&instance_dir.join("options/disable_on_free"), "1\n", "set disable_on_free");
    let _ = write_tracefs_control(&instance_dir.join("options/event-fork"), "1\n", "set event-fork");
    let _ = write_tracefs_control(&instance_dir.join("options/record-tgid"), "1\n", "set record-tgid");

    let known_tids = match seed_target_tids(proc_root, session.process.pid, instance_dir) {
        Ok(tids) => tids,
        Err(err) => {
            let _ = teardown_session_resources(tracefs_root, instance_dir, registered_events, None, None);
            return Err(err);
        }
    };

    let free_buffer_fd = OpenOptions::new()
        .write(true)
        .open(instance_dir.join("free_buffer"))
        .or_else(|_| File::open(instance_dir.join("free_buffer")))
        .ok();
    let trace_pipe_path = instance_dir.join("trace_pipe");
    let mut trace_pipe_fd = match open_nonblocking_read(&trace_pipe_path) {
        Ok(fd) => fd,
        Err(err) => {
            let _ = teardown_session_resources(tracefs_root, instance_dir, registered_events, None, free_buffer_fd);
            return Err(format_tracefs_io_error("open trace_pipe O_NONBLOCK", &trace_pipe_path, &err));
        }
    };

    let setup_res = (|| -> Result<(), String> {
        for (idx, probe) in plan.probes.iter().enumerate() {
            if !probe.kernel_filters.is_empty() {
                configure_probe_filters(
                    instance_dir,
                    std::slice::from_ref(&registered_events[idx]),
                    &probe.kernel_filters,
                )?;
            }
        }
        enable_session_events(instance_dir, registered_events)
    })();
    if let Err(err) = setup_res {
        let _ = teardown_session_resources(
            tracefs_root,
            instance_dir,
            registered_events,
            Some(trace_pipe_fd),
            free_buffer_fd,
        );
        return Err(err);
    }

    let specs = plan.probes.iter().map(|p| p.spec.clone()).collect::<Vec<ProbeTargetSpec>>();
    emit_probe_ready_stderr(
        "tracefs",
        session.process.pid,
        &known_tids,
        &specs,
        instance_dir.file_name().and_then(|n| n.to_str()),
        registered_events,
    );

    let image = std::mem::take(&mut session.image);
    let regions = std::mem::take(&mut session.regions);
    let mut tid_state = StreamState::new(session.process.pid, known_tids, 0);
    let mut engine = TraceWindowEngine::new(
        &image,
        session.process.pie_slide,
        &regions,
        plan,
        limits.max_windows,
        limits.max_events,
    );
    let mut line_buf = StreamingTraceLineBuffer::default();
    let started = Instant::now();
    let deadline = (limits.duration_ms != 0).then(|| started + Duration::from_millis(limits.duration_ms));

    let loop_stop = stream_trace_pipe(
        session,
        &mut trace_pipe_fd,
        &mut line_buf,
        &mut tid_state,
        &mut engine,
        proc_root,
        event_prefix,
        cancel,
        deadline,
    );
    let elapsed_ms = u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX);

    let _ = write_tracefs_control(&instance_dir.join("tracing_on"), "0\n", "stop tracing_on");
    for (grp, ev) in registered_events.iter().filter_map(|e| e.split_once('/')) {
        let _ = write_tracefs_control(&instance_dir.join("events").join(grp).join(ev).join("enable"), "0\n", "off");
    }
    drain_remaining_trace_pipe(&mut trace_pipe_fd, &mut line_buf, &mut tid_state, &mut engine, proc_root, event_prefix);
    let lost_events = parse_per_cpu_stats_dir(&instance_dir.join("per_cpu"));
    let (windows, total_events, final_stop) = engine.finish(loop_stop, lost_events.has_possible_loss());
    session.image = image;
    session.regions = regions;

    let warns =
        teardown_session_resources(tracefs_root, instance_dir, registered_events, Some(trace_pipe_fd), free_buffer_fd);
    session.process.warnings.extend(warns);
    refresh_session_identity(session);

    Ok(build_trace_report(
        session.process.clone(),
        windows,
        total_events,
        lost_events,
        final_stop,
        plan.return_mode,
        elapsed_ms,
        tid_state.unparsed_lines,
        tid_state.excluded_other_tgid,
        tid_state.ambiguous_tid,
    ))
}
