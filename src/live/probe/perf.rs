/*
 * XRef — Primary Linux perf_event_open + mmap binary ring-buffer uprobe engine
 * Copyright (c) 2026 Alexander Panasenko
 * Contact: alex@prod.codes
 * Author: https://prod.codes/about/
 * Project: https://github.com/alex09x/xref
 * SPDX-License-Identifier: MIT OR Apache-2.0
 */

//! Native `perf_event_open` + `mmap` binary ring-buffer uprobe collector (`--backend perf`).
//! Uses per-thread dynamic uprobe PMU counters (`mm`-filtered to target process), nonblocking
//! binary `PERF_RECORD_*` decoding, `PERF_RECORD_LOST` accounting, and automatic FD cleanup.

use std::io;
use std::path::Path;

#[cfg(target_os = "linux")]
use crate::live::probe::perf_ring::{
    PERF_SAMPLE_IP, PERF_SAMPLE_REGS_USER, PERF_SAMPLE_STACK_USER, PERF_SAMPLE_TID, PERF_SAMPLE_TIME,
    XREF_PERF_REGS_MASK, XREF_PERF_STACK_USER_BYTES,
};
use crate::live::probe::tracefs::ProbeRunConfig;
use crate::live::probe::types::{ProbeObservation, ProbeTargetResult, ProbeTargetSpec};
use crate::live::procfs::LiveSession;

#[cfg(target_os = "linux")]
pub const UPROBE_PMU_TYPE_PATH: &str = "/sys/bus/event_source/devices/uprobe/type";
#[cfg(target_os = "linux")]
pub const PERF_PARANOID_PATH: &str = "/proc/sys/kernel/perf_event_paranoid";
#[cfg(target_os = "linux")]
pub const MAX_PERF_SAMPLERS_PER_SESSION: usize = 256;
#[cfg(target_os = "linux")]
const RING_DATA_BYTES_PER_SAMPLER: usize = 32 * 1024;

pub fn parse_uprobe_pmu_type_str(raw: &str, source_path: &Path) -> Result<u32, String> {
    raw.trim().parse::<u32>().map_err(|err| {
        format!("unsupported_uprobe_pmu: failed to parse dynamic uprobe PMU type from {}: {err}", source_path.display())
    })
}

#[cfg(target_os = "linux")]
pub fn read_uprobe_pmu_type(type_path: &Path) -> Result<u32, String> {
    let raw = std::fs::read_to_string(type_path).map_err(|err| {
        format!(
            "unsupported_uprobe_pmu: cannot read {} ({err}); kernel may lack CONFIG_UPROBE_EVENTS",
            type_path.display()
        )
    })?;
    parse_uprobe_pmu_type_str(&raw, type_path)
}

#[must_use]
pub fn format_perf_open_error(operation: &str, err: &io::Error, paranoid_value: Option<i32>) -> String {
    let errno_part = err.raw_os_error().map_or_else(String::new, |code| format!("errno {code}: "));
    let paranoid_part =
        paranoid_value.map_or_else(|| "perf_event_paranoid=unknown".to_owned(), |v| format!("perf_event_paranoid={v}"));
    if matches!(err.kind(), io::ErrorKind::PermissionDenied) || matches!(err.raw_os_error(), Some(1 | 13)) {
        format!(
            "permission_denied: perf_event_open {operation} failed ({errno_part}{err}; {paranoid_part}); Linux dynamic uprobes require CAP_PERFMON/CAP_SYS_ADMIN or permissive perf_event_paranoid (refusing silent fallback to tracefs)"
        )
    } else {
        format!("perf_event_open {operation} failed ({errno_part}{err}; {paranoid_part})")
    }
}

#[cfg(target_os = "linux")]
#[must_use]
pub fn read_perf_event_paranoid(path: &Path) -> Option<i32> {
    std::fs::read_to_string(path).ok()?.trim().parse::<i32>().ok()
}

#[cfg(not(target_os = "linux"))]
pub fn run_perf_probe(
    _session: &mut LiveSession,
    _specs: &[ProbeTargetSpec],
    _cfg: &ProbeRunConfig,
) -> Result<(ProbeObservation, Vec<ProbeTargetResult>), String> {
    Err("unsupported_platform: perf_event_open live probe requires Linux x86-64".to_owned())
}

#[cfg(target_os = "linux")]
pub struct ActiveSampler {
    pub probe_index: usize,
    pub sampler: perf_event::Sampler,
}

#[cfg(target_os = "linux")]
pub fn run_perf_probe(
    session: &mut LiveSession,
    specs: &[ProbeTargetSpec],
    cfg: &ProbeRunConfig,
) -> Result<(ProbeObservation, Vec<ProbeTargetResult>), String> {
    use std::ffi::CString;
    use std::os::unix::ffi::OsStrExt;
    use std::time::Instant;

    use crate::live::probe::perf_stream::{PerfDrainCtx, drain_all_samplers, run_perf_loop};
    use crate::live::probe::tracefs::verify_exe_still_matches;
    use crate::live::probe::tracefs_stream::build_probe_results;
    use crate::live::procfs::refresh_session_identity;

    let proc_root = Path::new("/proc");
    verify_exe_still_matches(session, proc_root)?;
    let pmu_type = read_uprobe_pmu_type(Path::new(UPROBE_PMU_TYPE_PATH))?;
    let exec_path = proc_root.join(session.process.pid.to_string()).join("exe");
    let exec_cstr = CString::new(exec_path.as_os_str().as_bytes())
        .map_err(|_| "invalid NUL byte in /proc/<pid>/exe path".to_owned())?;
    let task_dir = proc_root.join(session.process.pid.to_string()).join("task");
    let initial_tids = collect_initial_tids(session.process.pid, &task_dir, specs.len())?;

    let (sample_type, regs_mask, stack_bytes) = compute_sample_flags(cfg);
    let mut samplers = Vec::with_capacity(specs.len().saturating_mul(initial_tids.len()));
    for &tid in &initial_tids {
        attach_samplers_for_tid(pmu_type, &exec_cstr, specs, tid, sample_type, regs_mask, stack_bytes, &mut samplers)?;
    }
    let seeded_tids = initial_tids.len();
    enable_all_samplers(&mut samplers)?;
    crate::live::probe::types::emit_probe_ready_stderr("perf", session.process.pid, &initial_tids, specs, None, &[]);

    let mut ctx = PerfDrainCtx::new(
        session.process.pid,
        sample_type,
        regs_mask,
        cfg.want_callers,
        cfg.want_regs,
        specs,
        initial_tids,
    );
    let started = Instant::now();
    let stop_reason = run_perf_loop(
        session,
        &task_dir,
        pmu_type,
        &exec_cstr,
        stack_bytes,
        &mut samplers,
        &mut ctx,
        cfg.max_events,
        started + cfg.duration,
    );
    let elapsed_ms = u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX);

    for active in &mut samplers {
        let _ = active.sampler.disable();
    }
    drain_all_samplers(&mut samplers, &mut ctx, cfg.max_events);
    drop(samplers);
    refresh_session_identity(session);

    let observation = finalize_perf_observation(&ctx, cfg, seeded_tids, elapsed_ms, stop_reason);
    let results = build_probe_results(session, specs, ctx.accumulators, cfg.want_callers);
    Ok((observation, results))
}

#[cfg(target_os = "linux")]
fn collect_initial_tids(
    pid: u32,
    task_dir: &Path,
    probe_count: usize,
) -> Result<std::collections::BTreeSet<u32>, String> {
    use crate::live::probe::tracefs::read_tid_set;
    let mut tids = read_tid_set(task_dir)?;
    if let Ok(pass2) = read_tid_set(task_dir) {
        tids.extend(pass2);
    }
    if tids.is_empty() {
        return Err(format!("process {pid} has no active threads in {}", task_dir.display()));
    }
    let required = probe_count.saturating_mul(tids.len());
    if required > MAX_PERF_SAMPLERS_PER_SESSION {
        return Err(format!(
            "target process {pid} requires {required} perf uprobe samplers ({probe_count} probes * {} threads), exceeding session cap {MAX_PERF_SAMPLERS_PER_SESSION}",
            tids.len()
        ));
    }
    Ok(tids)
}

#[cfg(target_os = "linux")]
fn enable_all_samplers(samplers: &mut [ActiveSampler]) -> Result<(), String> {
    for active in samplers {
        active.sampler.enable().map_err(|e| {
            format_perf_open_error("PERF_EVENT_IOC_ENABLE", &e, read_perf_event_paranoid(Path::new(PERF_PARANOID_PATH)))
        })?;
    }
    Ok(())
}

#[cfg(target_os = "linux")]
pub fn finalize_perf_observation(
    ctx: &crate::live::probe::perf_stream::PerfDrainCtx<'_>,
    cfg: &ProbeRunConfig,
    seeded_tids: usize,
    elapsed_ms: u64,
    stop_reason: crate::live::probe::types::ProbeStopReason,
) -> ProbeObservation {
    use crate::live::probe::types::{LostEvents, ProbeStopReason, ThreadCoverage};
    let lost_events = if ctx.decode_errors > 0 {
        LostEvents::Unknown { reason: format!("{} malformed perf ring record(s)", ctx.decode_errors) }
    } else {
        LostEvents::Known {
            overrun: 0,
            commit_overrun: 0,
            dropped_events: 0,
            perf_lost_records: ctx.perf_lost_records,
            total: ctx.perf_lost_records,
        }
    };
    let truncated_by_max_events =
        stop_reason == ProbeStopReason::MaxEvents || ctx.hit_max_events || ctx.total_accepted >= cfg.max_events;
    let effective_stop = if truncated_by_max_events && stop_reason == ProbeStopReason::DurationElapsed {
        ProbeStopReason::MaxEvents
    } else {
        stop_reason
    };
    let dynamically_attached_tids = ctx.attached_tids.len().saturating_sub(seeded_tids);
    let pending_unattached =
        u64::try_from(ctx.pending_new_tids.iter().filter(|tid| !ctx.attached_tids.contains(tid)).count()).unwrap_or(0);
    let unattached_fork_tids = ctx.unattached_fork_tids.saturating_add(pending_unattached);

    let mut reasons = ctx.coverage_gap_reasons.clone();
    if dynamically_attached_tids > 0 && !reasons.iter().any(|r| r == "dynamic_tid_inherit_false_pre_attach_window") {
        reasons.push("dynamic_tid_inherit_false_pre_attach_window".to_owned());
    }
    if unattached_fork_tids > 0 && !reasons.iter().any(|r| r.contains("dynamic_tid") || r.contains("unattached")) {
        reasons.push("unattached_fork_tids".to_owned());
    }
    if ctx.decode_errors > 0 {
        reasons.push("malformed_perf_ring_records".to_owned());
    }
    let partial_coverage =
        unattached_fork_tids > 0 || dynamically_attached_tids > 0 || ctx.ambiguous_tid > 0 || ctx.decode_errors > 0;
    let counts_are_lower_bound = lost_events.has_possible_loss() || truncated_by_max_events || partial_coverage;
    ProbeObservation {
        duration_requested_ms: u64::try_from(cfg.duration.as_millis()).unwrap_or(u64::MAX),
        elapsed_ms,
        max_events: cfg.max_events,
        stop_reason: effective_stop,
        truncated_by_max_events,
        thread_coverage: ThreadCoverage {
            seeded_tids,
            dynamically_attached_tids,
            unattached_fork_tids,
            event_fork_enabled: true,
            record_tgid_enabled: true,
            excluded_other_tgid_events: ctx.excluded_other_tgid,
            ambiguous_tid_events: ctx.ambiguous_tid,
            unparsed_events: ctx.decode_errors,
            partial_coverage,
            partial_coverage_reasons: reasons,
            note: "per_tid_perf_uprobe_mmap_ring_plus_fork_record_and_proc_task_attach",
        },
        lost_events,
        counts_are_lower_bound,
    }
}

#[cfg(target_os = "linux")]
const fn compute_sample_flags(cfg: &ProbeRunConfig) -> (u64, u64, u32) {
    let mut sample_type = PERF_SAMPLE_IP | PERF_SAMPLE_TID | PERF_SAMPLE_TIME;
    let regs_mask = if cfg.want_regs || cfg.want_callers {
        sample_type |= PERF_SAMPLE_REGS_USER;
        XREF_PERF_REGS_MASK
    } else {
        0
    };
    let stack_bytes = if cfg.want_callers {
        sample_type |= PERF_SAMPLE_STACK_USER;
        XREF_PERF_STACK_USER_BYTES
    } else {
        0
    };
    (sample_type, regs_mask, stack_bytes)
}

#[cfg(target_os = "linux")]
#[allow(clippy::too_many_arguments)]
pub fn attach_samplers_for_tid(
    pmu_type: u32,
    exec_cstr: &std::ffi::CString,
    specs: &[ProbeTargetSpec],
    tid: u32,
    sample_type: u64,
    regs_mask: u64,
    stack_bytes: u32,
    out: &mut Vec<ActiveSampler>,
) -> Result<(), String> {
    use perf_event::{Builder, Clock, events::Software};

    let pid_i32 = i32::try_from(tid).map_err(|_| format!("TID {tid} overflows pid_t"))?;
    for (probe_index, spec) in specs.iter().enumerate() {
        let mut builder = Builder::new(Software::DUMMY);
        builder
            .observe_pid(pid_i32)
            .any_cpu()
            .inherit(false)
            .remove_on_exec(true)
            .task(true)
            .clockid(Clock::MONOTONIC)
            .sample_period(1)
            .wakeup_events(1);
        {
            let attrs = builder.attrs_mut();
            attrs.type_ = pmu_type;
            attrs.config = 0;
            attrs.kprobe_func = exec_cstr.as_ptr() as usize as u64;
            attrs.probe_offset = spec.file_offset;
            attrs.sample_type = sample_type;
            attrs.sample_regs_user = regs_mask;
            attrs.sample_stack_user = stack_bytes;
        }
        let counter = builder.build().map_err(|err| {
            format_perf_open_error(
                &format!("uprobe tid={tid} file_offset={:#x}", spec.file_offset),
                &err,
                read_perf_event_paranoid(Path::new(PERF_PARANOID_PATH)),
            )
        })?;
        let sampler = counter.sampled(RING_DATA_BYTES_PER_SAMPLER).map_err(|err| {
            format_perf_open_error(
                &format!("mmap ring tid={tid} file_offset={:#x}", spec.file_offset),
                &err,
                read_perf_event_paranoid(Path::new(PERF_PARANOID_PATH)),
            )
        })?;
        out.push(ActiveSampler { probe_index, sampler });
    }
    Ok(())
}
