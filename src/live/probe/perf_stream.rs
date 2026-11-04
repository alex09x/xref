/*
 * XRef — Nonblocking perf_event_open mmap ring drain loop and dynamic thread tracker
 * Copyright (c) 2026 Alexander Panasenko
 * Contact: alex@prod.codes
 * Author: https://prod.codes/about/
 * Project: https://github.com/alex09x/xref
 * SPDX-License-Identifier: MIT OR Apache-2.0
 */

//! Drains `perf_event::Sampler` `mmap` rings without blocking, decodes `PERF_RECORD_SAMPLE`,
//! `PERF_RECORD_LOST`, and `PERF_RECORD_FORK`, and dynamically attaches newly spawned target TIDs.

#![cfg(target_os = "linux")]

use std::collections::{BTreeMap, BTreeSet};
use std::ffi::CString;
use std::io::Write as _;
use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

use crate::live::probe::perf::{ActiveSampler, MAX_PERF_SAMPLERS_PER_SESSION, attach_samplers_for_tid};
use crate::live::probe::perf_ring::{
    DecodedPerfRecord, PerfSampleEvent, decode_perf_record, extract_return_addr_from_perf_sample,
};
use crate::live::probe::tracefs::read_tid_set;
use crate::live::probe::tracefs_stream::ProbeAccumulator;
use crate::live::probe::types::{ProbeStopReason, ProbeTargetSpec, REGISTER_SEMANTICS_CAVEAT, RegisterSample};
use crate::live::procfs::{LiveSession, refresh_session_identity};
use crate::live::types::HexAddr;

#[allow(clippy::struct_excessive_bools)] // Independent capture and event-state flags feed distinct perf record paths.
pub struct PerfDrainCtx<'a> {
    pub target_pid: u32,
    pub sample_type: u64,
    pub regs_mask: u64,
    pub want_callers: bool,
    pub want_regs: bool,
    pub specs: &'a [ProbeTargetSpec],
    pub attached_tids: BTreeSet<u32>,
    pub pending_new_tids: BTreeSet<u32>,
    pub unattached_fork_tids: u64,
    pub excluded_other_tgid: u64,
    pub ambiguous_tid: u64,
    pub perf_lost_records: u64,
    pub decode_errors: u64,
    pub total_accepted: usize,
    pub hit_max_events: bool,
    pub coverage_gap_reasons: Vec<String>,
    pub accumulators: Vec<ProbeAccumulator>,
    pub thread_changes: Vec<crate::live::probe::types::ThreadChange>,
    pub thread_changes_truncated: bool,
    /// Emit one JSON line per accepted hit (`--json-lines`), with return sites slide-removed.
    pub stream_json: bool,
    pub pie_slide: i64,
}

impl<'a> PerfDrainCtx<'a> {
    #[must_use]
    pub fn new(
        target_pid: u32,
        sample_type: u64,
        regs_mask: u64,
        want_callers: bool,
        want_regs: bool,
        specs: &'a [ProbeTargetSpec],
        attached_tids: BTreeSet<u32>,
    ) -> Self {
        Self {
            target_pid,
            sample_type,
            regs_mask,
            want_callers,
            want_regs,
            specs,
            attached_tids,
            pending_new_tids: BTreeSet::new(),
            unattached_fork_tids: 0,
            excluded_other_tgid: 0,
            ambiguous_tid: 0,
            perf_lost_records: 0,
            decode_errors: 0,
            total_accepted: 0,
            hit_max_events: false,
            coverage_gap_reasons: Vec::new(),
            accumulators: (0..specs.len()).map(|_| ProbeAccumulator::default()).collect(),
            thread_changes: Vec::new(),
            thread_changes_truncated: false,
            stream_json: false,
            pie_slide: 0,
        }
    }
}

#[allow(clippy::too_many_arguments)]
pub fn run_perf_loop(
    session: &mut LiveSession,
    task_dir: &Path,
    pmu_type: u32,
    exec_cstr: &CString,
    stack_bytes: u32,
    samplers: &mut Vec<ActiveSampler>,
    ctx: &mut PerfDrainCtx<'_>,
    max_events: usize,
    deadline: Option<Instant>,
    cancel: Option<&AtomicBool>,
    heartbeat_ms: Option<u64>,
    until_hits: Option<usize>,
) -> ProbeStopReason {
    let mut last_recheck = Instant::now();
    let mut last_heartbeat = Instant::now();
    let mut last_hit_instant: Option<Instant> = None;
    loop {
        if cancel.is_some_and(|flag| flag.load(Ordering::Relaxed)) {
            return ProbeStopReason::Interrupted;
        }
        let before_accepted = ctx.total_accepted;
        let progressed = drain_all_samplers(samplers, ctx, max_events);
        if ctx.total_accepted > before_accepted {
            last_hit_instant = Some(Instant::now());
        }
        if ctx.total_accepted >= max_events {
            return ProbeStopReason::MaxEvents;
        }
        if until_hits.is_some_and(|limit| ctx.total_accepted >= limit) {
            return ProbeStopReason::UntilHits;
        }
        if deadline.is_some_and(|dl| Instant::now() >= dl) {
            return ProbeStopReason::DurationElapsed;
        }
        if let Some(hb_ms) = heartbeat_ms
            && last_heartbeat.elapsed() >= Duration::from_millis(hb_ms)
        {
            last_heartbeat = Instant::now();
            let age_str =
                last_hit_instant.map_or_else(|| "none".to_string(), |t| format!("{}ms", t.elapsed().as_millis()));
            let mut stderr = std::io::stderr().lock();
            let _ = writeln!(
                stderr,
                "xref: heartbeat hits {}  alive {}  last_hit_age {}",
                ctx.total_accepted, session.process.pid_alive_after, age_str
            );
            let _ = stderr.flush();
        }
        if last_recheck.elapsed() >= Duration::from_millis(25) {
            refresh_session_identity(session);
            last_recheck = Instant::now();
            if session.process.process_changed {
                return ProbeStopReason::ProcessChanged;
            }
            if !session.process.pid_alive_after {
                return ProbeStopReason::ProcessExited;
            }
            if let Ok(live_tids) = read_tid_set(task_dir) {
                for tid in live_tids {
                    if !ctx.attached_tids.contains(&tid) {
                        ctx.pending_new_tids.insert(tid);
                    }
                }
            }
        }
        attach_pending_tids(pmu_type, exec_cstr, stack_bytes, samplers, ctx);
        if !progressed {
            let rem = deadline.map_or(Duration::from_millis(2), |dl| {
                dl.saturating_duration_since(Instant::now()).min(Duration::from_millis(2))
            });
            if !rem.is_zero() {
                std::thread::sleep(rem);
            }
        }
    }
}

pub fn attach_pending_tids(
    pmu_type: u32,
    exec_cstr: &CString,
    stack_bytes: u32,
    samplers: &mut Vec<ActiveSampler>,
    ctx: &mut PerfDrainCtx<'_>,
) {
    let candidates: Vec<u32> = ctx.pending_new_tids.iter().copied().collect();
    ctx.pending_new_tids.clear();
    for tid in candidates {
        if ctx.attached_tids.contains(&tid) {
            continue;
        }
        if samplers.len().saturating_add(ctx.specs.len()) > MAX_PERF_SAMPLERS_PER_SESSION {
            ctx.unattached_fork_tids = ctx.unattached_fork_tids.saturating_add(1);
            push_unique_reason(&mut ctx.coverage_gap_reasons, "sampler_session_cap_exceeded_for_dynamic_tid");
            continue;
        }
        let mut tid_samplers = Vec::with_capacity(ctx.specs.len());
        if attach_samplers_for_tid(
            pmu_type,
            exec_cstr,
            ctx.specs,
            tid,
            ctx.sample_type,
            ctx.regs_mask,
            stack_bytes,
            &mut tid_samplers,
        )
        .is_err()
        {
            // Dropping `tid_samplers` closes any partially opened FDs for `tid`.
            ctx.unattached_fork_tids = ctx.unattached_fork_tids.saturating_add(1);
            push_unique_reason(&mut ctx.coverage_gap_reasons, "dynamic_tid_perf_event_open_failed");
            continue;
        }
        let mut all_enabled = true;
        for active in &mut tid_samplers {
            if active.sampler.enable().is_err() {
                all_enabled = false;
                break;
            }
        }
        if !all_enabled {
            // Roll back all samplers opened for `tid` if any probe failed to enable.
            for active in &mut tid_samplers {
                let _ = active.sampler.disable();
            }
            drop(tid_samplers);
            ctx.unattached_fork_tids = ctx.unattached_fork_tids.saturating_add(1);
            push_unique_reason(&mut ctx.coverage_gap_reasons, "dynamic_tid_perf_enable_failed");
            continue;
        }
        samplers.extend(tid_samplers);
        ctx.attached_tids.insert(tid);
        crate::live::probe::types::record_thread_change(
            &mut ctx.thread_changes,
            &mut ctx.thread_changes_truncated,
            tid,
            "attached",
        );
        eprintln!("xref: tid_attached {tid}");
        push_unique_reason(&mut ctx.coverage_gap_reasons, "dynamic_tid_inherit_false_pre_attach_window");
    }
}

fn push_unique_reason(reasons: &mut Vec<String>, reason: &str) {
    if !reasons.iter().any(|r| r == reason) {
        reasons.push(reason.to_owned());
    }
}

pub fn drain_all_samplers(samplers: &mut [ActiveSampler], ctx: &mut PerfDrainCtx<'_>, max_events: usize) -> bool {
    let mut any_record = false;
    for active in samplers {
        loop {
            if ctx.total_accepted >= max_events {
                ctx.hit_max_events = true;
                break;
            }
            let Some(rec) = active.sampler.next_record() else { break };
            any_record = true;
            let bytes = rec.to_contiguous();
            let decoded = decode_perf_record(rec.ty(), rec.misc(), &bytes, ctx.sample_type, ctx.regs_mask);
            process_decoded_perf_record(active.probe_index, decoded, ctx, max_events);
        }
        if ctx.total_accepted >= max_events {
            ctx.hit_max_events = true;
            break;
        }
    }
    any_record
}

pub fn process_decoded_perf_record(
    probe_index: usize,
    decoded: Result<DecodedPerfRecord, crate::live::probe::perf_ring::PerfDecodeError>,
    ctx: &mut PerfDrainCtx<'_>,
    max_events: usize,
) {
    if ctx.total_accepted >= max_events {
        ctx.hit_max_events = true;
        return;
    }
    match decoded {
        Ok(DecodedPerfRecord::Sample(ev)) => handle_sample(probe_index, &ev, ctx, max_events),
        Ok(DecodedPerfRecord::Lost { lost, .. }) => {
            ctx.perf_lost_records = ctx.perf_lost_records.saturating_add(lost);
        }
        Ok(DecodedPerfRecord::Fork { tgid, thread_id, .. }) => {
            if tgid == ctx.target_pid && !ctx.attached_tids.contains(&thread_id) {
                ctx.pending_new_tids.insert(thread_id);
            }
        }
        Ok(DecodedPerfRecord::Exit { .. } | DecodedPerfRecord::Other { .. }) => {}
        Err(_) => {
            ctx.decode_errors = ctx.decode_errors.saturating_add(1);
        }
    }
}

fn handle_sample(probe_index: usize, ev: &PerfSampleEvent, ctx: &mut PerfDrainCtx<'_>, max_events: usize) {
    if let Some(tgid) = ev.tgid {
        if tgid != ctx.target_pid {
            ctx.excluded_other_tgid = ctx.excluded_other_tgid.saturating_add(1);
            return;
        }
    } else if ev.thread_id.is_none_or(|tid| !ctx.attached_tids.contains(&tid)) {
        ctx.ambiguous_tid = ctx.ambiguous_tid.saturating_add(1);
        push_unique_reason(&mut ctx.coverage_gap_reasons, "ambiguous_sample_missing_tgid");
        return;
    }
    let Some(spec) = ctx.specs.get(probe_index) else { return };
    ctx.total_accepted += 1;
    if ctx.total_accepted >= max_events {
        ctx.hit_max_events = true;
    }
    let return_addr = if ctx.want_callers || ctx.stream_json {
        extract_return_addr_from_perf_sample(&spec.unwind_entry_abi, ev.regs.as_ref(), &ev.user_stack)
    } else {
        None
    };
    if ctx.stream_json {
        let ret_static = return_addr.and_then(|ra| crate::live::types::remove_slide(ra, ctx.pie_slide));
        let tid = ev.thread_id.unwrap_or(ctx.target_pid);
        let line = crate::live::probe::output::format_hit_json(spec.static_va, tid, &BTreeMap::new(), ret_static, None);
        println!("{line}");
    }
    let acc = &mut ctx.accumulators[probe_index];
    acc.accepted_hits = acc.accepted_hits.saturating_add(1);
    acc.record_timestamp(ev.timestamp_ns);

    if ctx.want_callers
        && let Some(ra) = return_addr
    {
        acc.count_caller(ra);
    }
    if ctx.want_regs
        && let Some(r) = ev.regs
    {
        acc.push_reg_sample(RegisterSample {
            tgid: ev.tgid,
            tid: ev.thread_id.unwrap_or(ctx.target_pid),
            timestamp_ns: ev.timestamp_ns,
            ip: ev.ip.map(HexAddr),
            rdi: HexAddr(r.rdi),
            rsi: HexAddr(r.rsi),
            rdx: HexAddr(r.rdx),
            rcx: HexAddr(r.rcx),
            r8: HexAddr(r.r8),
            r9: HexAddr(r.r9),
            rax: HexAddr(r.rax),
            rsp: HexAddr(r.rsp),
            rbp: Some(HexAddr(r.rbp)),
            mark: None,
            caveat: REGISTER_SEMANTICS_CAVEAT,
        });
    }
}
