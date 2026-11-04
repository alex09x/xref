/*
 * XRef — Stage L2 Linux tracefs uprobe session lifecycle and TID seeding
 * Copyright (c) 2026 Alexander Panasenko
 * Contact: alex@prod.codes
 * Author: https://prod.codes/about/
 * Project: https://github.com/alex09x/xref
 * SPDX-License-Identifier: MIT OR Apache-2.0
 */

//! Orchestrates isolated `tracefs` uprobe registration, two-pass `/proc/<pid>/task` seeding,
//! bounded stream execution, loss accounting, and deterministic cleanup.

use std::collections::BTreeSet;
use std::fmt::Write as _;
use std::fs::{File, OpenOptions};
use std::path::Path;
use std::sync::atomic::AtomicBool;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use crate::live::probe::trace_parse::{
    StreamingTraceLineBuffer, format_uprobe_definition_with_fetches, parse_per_cpu_stats_dir,
};
use crate::live::probe::tracefs_cleanup::{
    CleanupSupervisor, append_tracefs_line, discover_tracefs_root, format_tracefs_io_error, teardown_session_resources,
    write_tracefs_control,
};
use crate::live::probe::tracefs_filter::configure_probe_filters;
use crate::live::probe::tracefs_setup::configure_tracefs_instance_format;
use crate::live::probe::tracefs_stream::{
    StreamState, build_probe_results, drain_available_nonblocking, open_nonblocking_read, read_bounded_loop,
};
use crate::live::probe::types::{
    LostEvents, ProbeObservation, ProbeStopReason, ProbeTargetResult, ProbeTargetSpec, ThreadCoverage,
};
use crate::live::procfs::{LiveSession, refresh_session_identity};

#[derive(Clone, Debug)]
#[allow(clippy::struct_excessive_bools)]
pub struct ProbeRunConfig<'a> {
    pub duration: Duration,
    pub max_events: usize,
    pub want_callers: bool,
    pub want_regs: bool,
    pub fetches: Vec<super::fetch::FetchArg>,
    pub filters: Vec<super::filter::ValueFilter>,
    pub every: usize,
    pub first: Option<usize>,
    pub until_hits: Option<usize>,
    pub spawn_watchdog: bool,
    pub cancel: Option<&'a AtomicBool>,
    pub heartbeat_ms: Option<u64>,
    pub mark_file: Option<std::path::PathBuf>,
    pub mark_regex: Option<String>,
    pub stream_json: bool,
}

pub fn run_tracefs_probe(
    session: &mut LiveSession,
    specs: &[ProbeTargetSpec],
    cfg: &ProbeRunConfig<'_>,
) -> Result<(ProbeObservation, Vec<ProbeTargetResult>), String> {
    let tracefs_root = discover_tracefs_root();
    run_tracefs_with_roots(session, specs, cfg, &tracefs_root, Path::new("/proc"))
}

pub fn run_tracefs_with_roots(
    session: &mut LiveSession,
    specs: &[ProbeTargetSpec],
    cfg: &ProbeRunConfig<'_>,
    tracefs_root: &Path,
    proc_root: &Path,
) -> Result<(ProbeObservation, Vec<ProbeTargetResult>), String> {
    verify_exe_still_matches(session, proc_root)?;
    let uprobe_events_path = tracefs_root.join("uprobe_events");
    let _probe_check = OpenOptions::new()
        .append(true)
        .open(&uprobe_events_path)
        .map_err(|e| format_tracefs_io_error("open uprobe_events", &uprobe_events_path, &e))?;

    let nonce_hex = make_session_hex();
    let group = format!("xp_{nonce_hex}");
    let event_prefix = format!("xp_{nonce_hex}_");
    let instance_name = format!("xref_{}_{nonce_hex}", session.process.pid);
    let instance_dir = tracefs_root.join("instances").join(&instance_name);
    let planned_events: Vec<String> = (0..specs.len()).map(|i| format!("{group}/{event_prefix}{i}")).collect();

    let mut supervisor =
        if cfg.spawn_watchdog { CleanupSupervisor::spawn(tracefs_root, &instance_name, &planned_events) } else { None };

    let exec_path = proc_root.join(session.process.pid.to_string()).join("exe");
    let exec_path_str = exec_path.to_string_lossy();
    let mut registered_events = Vec::with_capacity(specs.len());

    for (idx, spec) in specs.iter().enumerate() {
        let ev_name = format!("{event_prefix}{idx}");
        let ra_arg = if cfg.want_callers { spec.ra_fetch_arg.as_deref() } else { None };
        let def = format_uprobe_definition_with_fetches(
            &group,
            &ev_name,
            &exec_path_str,
            spec.file_offset,
            ra_arg,
            cfg.want_regs,
            &cfg.fetches,
        );
        if let Err(err) = append_tracefs_line(&uprobe_events_path, &def, "register uprobe") {
            let _ = teardown_session_resources(tracefs_root, &instance_dir, &registered_events, None, None);
            if let Some(sup) = &mut supervisor {
                sup.disarm_and_wait();
            }
            return Err(err);
        }
        registered_events.push(format!("{group}/{ev_name}"));
    }

    let outcome = execute_instance_session(
        session,
        specs,
        cfg,
        tracefs_root,
        proc_root,
        &instance_dir,
        &event_prefix,
        &registered_events,
    );
    if let Some(sup) = &mut supervisor {
        sup.disarm_and_wait();
    }
    outcome
}

#[allow(clippy::too_many_arguments, clippy::too_many_lines)]
fn execute_instance_session(
    session: &mut LiveSession,
    specs: &[ProbeTargetSpec],
    cfg: &ProbeRunConfig<'_>,
    tracefs_root: &Path,
    proc_root: &Path,
    instance_dir: &Path,
    event_prefix: &str,
    registered_events: &[String],
) -> Result<(ProbeObservation, Vec<ProbeTargetResult>), String> {
    if let Err(err) = std::fs::create_dir(instance_dir) {
        let _ = teardown_session_resources(tracefs_root, instance_dir, registered_events, None, None);
        return Err(format_tracefs_io_error("mkdir instance", instance_dir, &err));
    }

    if let Err(err) = configure_tracefs_instance_format(instance_dir) {
        let _ = teardown_session_resources(tracefs_root, instance_dir, registered_events, None, None);
        return Err(err);
    }
    let _ = write_tracefs_control(&instance_dir.join("options/disable_on_free"), "1\n", "set disable_on_free");
    let event_fork_enabled =
        write_tracefs_control(&instance_dir.join("options/event-fork"), "1\n", "set event-fork").is_ok();
    let record_tgid_enabled =
        write_tracefs_control(&instance_dir.join("options/record-tgid"), "1\n", "set record-tgid").is_ok();

    let known_tids = match seed_target_tids(proc_root, session.process.pid, instance_dir) {
        Ok(tids) => tids,
        Err(err) => {
            let _ = teardown_session_resources(tracefs_root, instance_dir, registered_events, None, None);
            return Err(err);
        }
    };
    let seeded_tids = known_tids.len();

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

    // Read the mark file before events are enabled: lines present now get observation time 0 and
    // precede every hit, while lines written later are timestamped as they are polled.
    let mark_tracker = match (&cfg.mark_file, &cfg.mark_regex) {
        (Some(path), Some(re)) => crate::live::probe::mark::MarkTracker::new(path.clone(), re).ok(),
        _ => None,
    };
    if let Err(err) = configure_probe_filters(instance_dir, registered_events, &cfg.filters)
        .and_then(|()| enable_session_events(instance_dir, registered_events))
    {
        let _ = teardown_session_resources(
            tracefs_root,
            instance_dir,
            registered_events,
            Some(trace_pipe_fd),
            free_buffer_fd,
        );
        return Err(err);
    }
    let inst_name = instance_dir.file_name().and_then(|n| n.to_str());
    crate::live::probe::types::emit_probe_ready_stderr(
        "tracefs",
        session.process.pid,
        &known_tids,
        specs,
        inst_name,
        registered_events,
    );

    let mut state = StreamState::new(session.process.pid, known_tids, specs.len());
    state.set_context(specs.iter().map(|s| s.static_va).collect(), session.process.pie_slide, mark_tracker);
    state.set_target_exec(crate::live::probe::output::target_exec_ranges(&session.regions));
    let mut line_buf = StreamingTraceLineBuffer::default();
    let started = Instant::now();
    let deadline = if cfg.duration.is_zero() { None } else { Some(started + cfg.duration) };
    let stop_reason = read_bounded_loop(
        session,
        &mut trace_pipe_fd,
        &mut line_buf,
        &mut state,
        proc_root,
        event_prefix,
        cfg,
        deadline,
    );
    let elapsed_ms = u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX);

    let _ = write_tracefs_control(&instance_dir.join("tracing_on"), "0\n", "stop tracing_on");
    for (grp, ev) in registered_events.iter().filter_map(|e| e.split_once('/')) {
        let _ = write_tracefs_control(&instance_dir.join("events").join(grp).join(ev).join("enable"), "0\n", "off");
    }
    drain_available_nonblocking(&mut trace_pipe_fd, &mut line_buf, &mut state, proc_root, event_prefix, cfg);
    let lost_events = parse_per_cpu_stats_dir(&instance_dir.join("per_cpu"));

    let warns =
        teardown_session_resources(tracefs_root, instance_dir, registered_events, Some(trace_pipe_fd), free_buffer_fd);
    session.process.warnings.extend(warns);
    refresh_session_identity(session);

    let observation = finalize_tracefs_observation(
        &state,
        cfg,
        seeded_tids,
        elapsed_ms,
        stop_reason,
        event_fork_enabled,
        record_tgid_enabled,
        lost_events,
    );
    let results = build_probe_results(session, specs, state.accumulators, cfg.want_callers);
    Ok((observation, results))
}

#[allow(clippy::too_many_arguments)]
#[must_use]
pub fn finalize_tracefs_observation(
    state: &StreamState,
    cfg: &ProbeRunConfig<'_>,
    seeded_tids: usize,
    elapsed_ms: u64,
    stop_reason: ProbeStopReason,
    event_fork_enabled: bool,
    record_tgid_enabled: bool,
    lost_events: LostEvents,
) -> ProbeObservation {
    let truncated_by_max_events =
        stop_reason == ProbeStopReason::MaxEvents || state.hit_max_events || state.total_accepted >= cfg.max_events;
    let effective_stop = if truncated_by_max_events && stop_reason == ProbeStopReason::DurationElapsed {
        ProbeStopReason::MaxEvents
    } else {
        stop_reason
    };
    let dynamically_attached_tids = state.known_tids.len().saturating_sub(seeded_tids);
    let mut reasons = Vec::new();
    if !event_fork_enabled {
        reasons.push("event_fork_unavailable_new_threads_untracked_by_set_event_pid".to_owned());
    }
    if state.ambiguous_tid > 0 {
        reasons.push("ambiguous_tid_events_dropped".to_owned());
    }
    if state.unparsed_lines > 0 {
        reasons.push("unparsed_trace_pipe_lines".to_owned());
    }
    let partial_coverage = !reasons.is_empty();
    let counts_are_lower_bound = lost_events.has_possible_loss()
        || truncated_by_max_events
        || partial_coverage
        || cfg.every > 1
        || cfg.first.is_some();

    ProbeObservation {
        duration_requested_ms: u64::try_from(cfg.duration.as_millis()).unwrap_or(u64::MAX),
        elapsed_ms,
        max_events: cfg.max_events,
        stop_reason: effective_stop,
        truncated_by_max_events,
        thread_coverage: ThreadCoverage {
            seeded_tids,
            dynamically_attached_tids,
            unattached_fork_tids: 0,
            event_fork_enabled,
            record_tgid_enabled,
            excluded_other_tgid_events: state.excluded_other_tgid,
            ambiguous_tid_events: state.ambiguous_tid,
            unparsed_events: state.unparsed_lines,
            partial_coverage,
            partial_coverage_reasons: reasons,
            note: "two_pass_proc_task_seed_plus_event_fork_with_tgid_filter",
        },
        thread_changes: state.thread_changes.clone(),
        thread_changes_truncated: state.thread_changes_truncated,
        every: cfg.every,
        first: cfg.first,
        until_hits: cfg.until_hits,
        lost_events,
        counts_are_lower_bound,
    }
}

fn enable_session_events(instance_dir: &Path, registered_events: &[String]) -> Result<(), String> {
    for full_ev in registered_events {
        if let Some((grp, ev)) = full_ev.split_once('/') {
            let p = instance_dir.join("events").join(grp).join(ev).join("enable");
            write_tracefs_control(&p, "1\n", "enable probe event")?;
        }
    }
    write_tracefs_control(&instance_dir.join("tracing_on"), "1\n", "enable tracing_on")
}

fn seed_target_tids(proc_root: &Path, pid: u32, instance_dir: &Path) -> Result<BTreeSet<u32>, String> {
    let task_dir = proc_root.join(pid.to_string()).join("task");
    let pass1 = read_tid_set(&task_dir)?;
    if pass1.is_empty() {
        return Err(format!("process {pid} has no threads in {}", task_dir.display()));
    }
    let pid_file = instance_dir.join("set_event_pid");
    let mut initial_buf = String::new();
    for tid in &pass1 {
        let _ = writeln!(initial_buf, "{tid}");
    }
    write_tracefs_control(&pid_file, &initial_buf, "seed set_event_pid")?;

    let pass2 = read_tid_set(&task_dir).unwrap_or_default();
    let mut combined = pass1;
    for tid in pass2 {
        if combined.insert(tid) {
            append_tracefs_line(&pid_file, &format!("{tid}\n"), "append set_event_pid")?;
        }
    }
    Ok(combined)
}

pub fn read_tid_set(task_dir: &Path) -> Result<BTreeSet<u32>, String> {
    let entries = std::fs::read_dir(task_dir).map_err(|e| format!("failed to read {}: {e}", task_dir.display()))?;
    let mut tids = BTreeSet::new();
    for entry in entries.flatten() {
        if let Ok(tid) = entry.file_name().to_string_lossy().parse::<u32>() {
            tids.insert(tid);
        }
    }
    Ok(tids)
}

#[cfg(target_os = "linux")]
pub fn verify_exe_still_matches(session: &LiveSession, proc_root: &Path) -> Result<(), String> {
    use std::os::unix::fs::MetadataExt;
    if proc_root == Path::new("/proc")
        && let Some(expected) = session.exe_dev_ino
    {
        let exe = proc_root.join(session.process.pid.to_string()).join("exe");
        let meta = std::fs::metadata(&exe).map_err(|e| format!("failed to re-stat {}: {e}", exe.display()))?;
        if (meta.dev(), meta.ino()) != expected {
            return Err("target /proc/<pid>/exe changed before probe registration".to_owned());
        }
    }
    Ok(())
}

#[cfg(not(target_os = "linux"))]
pub const fn verify_exe_still_matches(_session: &LiveSession, _proc_root: &Path) -> Result<(), String> {
    Ok(())
}

fn make_session_hex() -> String {
    let nanos = SystemTime::now().duration_since(UNIX_EPOCH).map_or(0, |d| d.as_nanos());
    let low = u64::try_from(nanos & u128::from(u32::MAX)).unwrap_or(0);
    format!("{:08x}{low:08x}", std::process::id())
}
