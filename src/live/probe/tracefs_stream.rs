/*
 * XRef — Stage L2 nonblocking trace_pipe stream consumer and TGID/PID event aggregation
 * Copyright (c) 2026 Alexander Panasenko
 * Contact: alex@prod.codes
 * Author: https://prod.codes/about/
 * Project: https://github.com/alex09x/xref
 * SPDX-License-Identifier: MIT OR Apache-2.0
 */

//! Bounded nonblocking `trace_pipe` reader, `fork`-child TGID filter, and per-probe accumulator.

use std::collections::BTreeSet;
use std::fs::File;
use std::io::{self, Read, Write as _};
use std::path::Path;
use std::sync::atomic::Ordering;
use std::time::{Duration, Instant};

use crate::live::probe::trace_parse::{StreamingTraceLineBuffer, parse_uprobe_trace_line};
use crate::live::probe::tracefs::ProbeRunConfig;
use crate::live::probe::tracefs_tid::accept_tid_for_target;
use crate::live::probe::types::{
    FetchedSample, FetchedValue, MAX_FETCH_SAMPLES_PER_PROBE, MAX_FETCHED_VALUES_PER_SESSION, ProbeStopReason,
    REGISTER_SEMANTICS_CAVEAT, RegisterSample,
};
use crate::live::procfs::{LiveSession, refresh_session_identity};
use crate::live::types::HexAddr;

pub use crate::live::probe::accumulator::ProbeAccumulator;

pub struct StreamState {
    pub target_pid: u32,
    pub known_tids: BTreeSet<u32>,
    pub other_tgid_tids: BTreeSet<u32>,
    pub excluded_other_tgid: u64,
    pub ambiguous_tid: u64,
    pub unparsed_lines: u64,
    pub total_accepted: usize,
    pub hit_max_events: bool,
    pub hit_until_hits: bool,
    pub seen_hits_per_probe: Vec<u64>,
    pub fetched_values: usize,
    pub accumulators: Vec<ProbeAccumulator>,
    pub thread_changes: Vec<crate::live::probe::types::ThreadChange>,
    pub thread_changes_truncated: bool,
    pub probe_static_vas: Vec<u64>,
    pub pie_slide: i64,
    pub mark_tracker: Option<crate::live::probe::mark::MarkTracker>,
    pub target_exec: Vec<(u64, u64)>,
}

impl StreamState {
    #[must_use]
    pub fn new(target_pid: u32, known_tids: BTreeSet<u32>, probe_count: usize) -> Self {
        Self {
            target_pid,
            known_tids,
            other_tgid_tids: BTreeSet::new(),
            excluded_other_tgid: 0,
            ambiguous_tid: 0,
            unparsed_lines: 0,
            total_accepted: 0,
            hit_max_events: false,
            hit_until_hits: false,
            seen_hits_per_probe: vec![0; probe_count],
            fetched_values: 0,
            accumulators: (0..probe_count).map(|_| ProbeAccumulator::default()).collect(),
            thread_changes: Vec::new(),
            thread_changes_truncated: false,
            probe_static_vas: vec![0; probe_count],
            pie_slide: 0,
            mark_tracker: None,
            target_exec: Vec::new(),
        }
    }

    pub fn set_context(
        &mut self,
        probe_static_vas: Vec<u64>,
        pie_slide: i64,
        mark_tracker: Option<crate::live::probe::mark::MarkTracker>,
    ) {
        self.probe_static_vas = probe_static_vas;
        self.pie_slide = pie_slide;
        self.mark_tracker = mark_tracker;
    }

    /// Executable mappings of the target, used to accept only in-image return sites.
    pub fn set_target_exec(&mut self, target_exec: Vec<(u64, u64)>) {
        self.target_exec = target_exec;
    }
}

#[allow(clippy::too_many_arguments)]
pub fn read_bounded_loop(
    session: &mut LiveSession,
    trace_pipe_fd: &mut File,
    line_buf: &mut StreamingTraceLineBuffer,
    state: &mut StreamState,
    proc_root: &Path,
    event_prefix: &str,
    cfg: &ProbeRunConfig<'_>,
    deadline: Option<Instant>,
) -> ProbeStopReason {
    let mut chunk = [0_u8; 8192];
    let mut last_recheck = Instant::now();
    let mut last_heartbeat = Instant::now();
    let mut last_hit_instant: Option<Instant> = None;
    loop {
        if cfg.cancel.is_some_and(|flag| flag.load(Ordering::Relaxed)) {
            return ProbeStopReason::Interrupted;
        }
        if state.total_accepted >= cfg.max_events {
            return ProbeStopReason::MaxEvents;
        }
        if state.hit_until_hits {
            return ProbeStopReason::UntilHits;
        }
        if let Some(tracker) = state.mark_tracker.as_mut() {
            tracker.poll();
        }
        if deadline.is_some_and(|dl| Instant::now() >= dl) {
            return ProbeStopReason::DurationElapsed;
        }
        if let Some(hb_ms) = cfg.heartbeat_ms
            && last_heartbeat.elapsed() >= Duration::from_millis(hb_ms)
        {
            last_heartbeat = Instant::now();
            let age_str =
                last_hit_instant.map_or_else(|| "none".to_string(), |t| format!("{}ms", t.elapsed().as_millis()));
            let mut stderr = std::io::stderr().lock();
            let _ = writeln!(
                stderr,
                "xref: heartbeat hits {}  alive {}  last_hit_age {}",
                state.total_accepted, session.process.pid_alive_after, age_str
            );
            let _ = stderr.flush();
        }
        let before_accepted = state.total_accepted;
        match trace_pipe_fd.read(&mut chunk) {
            Ok(n) if n > 0 => {
                line_buf.push_chunk(&chunk[..n], |line| {
                    process_trace_line(line, event_prefix, proc_root, cfg, state);
                });
                if state.total_accepted > before_accepted {
                    last_hit_instant = Some(Instant::now());
                }
            }
            Ok(_) => sleep_or_recheck(session, &mut last_recheck, deadline),
            Err(err) if err.kind() == io::ErrorKind::WouldBlock => {
                sleep_or_recheck(session, &mut last_recheck, deadline);
            }
            Err(err) if err.kind() == io::ErrorKind::Interrupted => {
                return ProbeStopReason::Interrupted;
            }
            Err(_) => return ProbeStopReason::DurationElapsed,
        }
        if session.process.process_changed {
            return ProbeStopReason::ProcessChanged;
        }
        if !session.process.pid_alive_after {
            return ProbeStopReason::ProcessExited;
        }
    }
}

fn sleep_or_recheck(session: &mut LiveSession, last_recheck: &mut Instant, deadline: Option<Instant>) {
    if last_recheck.elapsed() >= Duration::from_millis(25) {
        refresh_session_identity(session);
        *last_recheck = Instant::now();
        if !session.process.pid_alive_after || session.process.process_changed {
            return;
        }
    }
    let now = Instant::now();
    let sleep_dur = match deadline {
        Some(dl) if now < dl => (dl - now).min(Duration::from_millis(5)),
        Some(_) => Duration::ZERO,
        None => Duration::from_millis(5),
    };
    if !sleep_dur.is_zero() {
        std::thread::sleep(sleep_dur);
    }
}

pub fn drain_available_nonblocking(
    trace_pipe_fd: &mut File,
    line_buf: &mut StreamingTraceLineBuffer,
    state: &mut StreamState,
    proc_root: &Path,
    event_prefix: &str,
    cfg: &ProbeRunConfig<'_>,
) {
    let mut chunk = [0_u8; 8192];
    while state.total_accepted < cfg.max_events && !state.hit_until_hits {
        match trace_pipe_fd.read(&mut chunk) {
            Ok(n) if n > 0 => {
                line_buf.push_chunk(&chunk[..n], |line| {
                    process_trace_line(line, event_prefix, proc_root, cfg, state);
                });
            }
            _ => break,
        }
    }
    // Only the event cap truncates; reaching --until-hits is a normal, complete stop.
    if state.total_accepted >= cfg.max_events {
        state.hit_max_events = true;
    }
    line_buf.finish(|line| process_trace_line(line, event_prefix, proc_root, cfg, state));
}

pub fn process_trace_line(
    line: &str,
    event_prefix: &str,
    proc_root: &Path,
    cfg: &ProbeRunConfig<'_>,
    state: &mut StreamState,
) {
    if state.total_accepted >= cfg.max_events {
        state.hit_max_events = true;
        return;
    }
    // Once --until-hits is reached, later lines from the same read or the final drain are not
    // accepted, so the reported count equals the requested limit.
    if state.hit_until_hits {
        return;
    }
    let Some(ev) = parse_uprobe_trace_line(line, event_prefix) else {
        state.unparsed_lines = state.unparsed_lines.saturating_add(1);
        return;
    };
    if ev.probe_index >= state.accumulators.len() {
        state.unparsed_lines = state.unparsed_lines.saturating_add(1);
        return;
    }
    if !accept_tid_for_target(&ev, proc_root, state) {
        return;
    }
    if cfg.filters.iter().any(|filter| ev.value(&filter.field).is_none()) {
        state.unparsed_lines = state.unparsed_lines.saturating_add(1);
        return;
    }
    if cfg.fetches.iter().any(|fetch| !ev.fetch_values.contains_key(&fetch.name)) {
        state.unparsed_lines = state.unparsed_lines.saturating_add(1);
        return;
    }
    if !cfg.filters.iter().all(|filter| filter.op.test(ev.value(&filter.field).unwrap_or(0), filter.value)) {
        return;
    }
    let seen = &mut state.seen_hits_per_probe[ev.probe_index];
    *seen = seen.saturating_add(1);
    if cfg.first.is_some_and(|limit| {
        state.accumulators[ev.probe_index].accepted_hits >= u64::try_from(limit).unwrap_or(u64::MAX)
    }) || !(*seen - 1).is_multiple_of(u64::try_from(cfg.every).unwrap_or(1))
    {
        return;
    }
    state.total_accepted += 1;
    if state.total_accepted >= cfg.max_events {
        state.hit_max_events = true;
    }
    let static_va = state.probe_static_vas.get(ev.probe_index).copied().unwrap_or(0);
    let ret_static = ev
        .return_addr
        .and_then(|ra| crate::live::probe::output::static_return(ra, state.pie_slide, &state.target_exec));
    // With trace_clock=mono the event timestamp and the mark observation times share CLOCK_MONOTONIC:
    // pick the mark that was current at the hit, not whatever the file says at processing time.
    let mark = state.mark_tracker.as_mut().and_then(|tracker| match ev.timestamp_ns {
        Some(ts) => tracker.mark_at(ts).map(str::to_owned),
        None => tracker.current_mark().map(str::to_owned),
    });
    {
        let acc = &mut state.accumulators[ev.probe_index];
        acc.accepted_hits = acc.accepted_hits.saturating_add(1);
        acc.record_timestamp(ev.timestamp_ns);
    }
    if !cfg.fetches.is_empty() {
        record_fetched_sample(cfg, state, ev.probe_index, &ev, static_va, ret_static, mark.clone());
    }
    if cfg.stream_json {
        let line = crate::live::probe::output::format_hit_json(
            static_va,
            ev.tid,
            &ev.fetch_values,
            ret_static,
            mark.as_deref(),
        );
        stream_hit(cfg, &line);
    }
    let acc = &mut state.accumulators[ev.probe_index];
    if cfg.want_callers
        && let Some(ra) = ev.return_addr
    {
        acc.count_caller(ra);
    }
    if cfg.want_regs
        && let Some(r) = ev.regs
    {
        acc.push_reg_sample(RegisterSample {
            tgid: Some(state.target_pid),
            tid: ev.tid,
            timestamp_ns: ev.timestamp_ns,
            ip: Some(HexAddr(ev.hit_ip)),
            rdi: HexAddr(r.rdi),
            rsi: HexAddr(r.rsi),
            rdx: HexAddr(r.rdx),
            rcx: HexAddr(r.rcx),
            r8: HexAddr(r.r8),
            r9: HexAddr(r.r9),
            rax: HexAddr(r.rax),
            rsp: HexAddr(r.rsp),
            rbp: r.rbp.map(HexAddr),
            caveat: REGISTER_SEMANTICS_CAVEAT,
            mark,
        });
    }
    if cfg.until_hits.is_some_and(|limit| state.total_accepted >= limit) {
        state.hit_until_hits = true;
    }
}

/// Prints one `--json-lines` hit; when stdout is closed (e.g. `| head`) the observation stops via
/// the cancel flag instead of panicking.
fn stream_hit(cfg: &ProbeRunConfig<'_>, line: &str) {
    if !crate::live::probe::output::emit_hit_line(line)
        && let Some(cancel) = cfg.cancel
    {
        cancel.store(true, Ordering::Relaxed);
    }
}

fn record_fetched_sample(
    cfg: &ProbeRunConfig<'_>,
    state: &mut StreamState,
    probe_index: usize,
    ev: &crate::live::probe::trace_parse::ParsedTraceEvent,
    static_va: u64,
    ret_static: Option<u64>,
    mark: Option<String>,
) {
    let remaining = MAX_FETCHED_VALUES_PER_SESSION.saturating_sub(state.fetched_values);
    let values = cfg
        .fetches
        .iter()
        .take(remaining)
        .map(|fetch| FetchedValue { name: fetch.name.clone(), value: HexAddr(ev.fetch_values[&fetch.name]) })
        .collect::<Vec<_>>();
    state.fetched_values = state.fetched_values.saturating_add(values.len());
    let acc = &mut state.accumulators[probe_index];
    if values.len() != cfg.fetches.len() {
        acc.fetched_samples_truncated = true;
    }
    if values.len() == cfg.fetches.len()
        && !values.is_empty()
        && acc.fetched_samples.len() < MAX_FETCH_SAMPLES_PER_PROBE
    {
        acc.fetched_samples.push(FetchedSample {
            va: Some(HexAddr(static_va)),
            tid: Some(ev.tid),
            timestamp_ns: ev.timestamp_ns.unwrap_or(0),
            values,
            ret: ret_static.map(HexAddr),
            mark,
        });
    } else if acc.fetched_samples.len() >= MAX_FETCH_SAMPLES_PER_PROBE {
        acc.fetched_samples_truncated = true;
    }
}

pub use crate::live::probe::output::build_probe_results;
pub use crate::live::probe::tracefs_setup::open_nonblocking_read;
