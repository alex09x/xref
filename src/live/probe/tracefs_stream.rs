/*
 * XRef — Stage L2 nonblocking trace_pipe stream consumer and TGID/PID event aggregation
 * Copyright (c) 2026 Alexander Panasenko
 * Contact: alex@prod.codes
 * Author: https://prod.codes/about/
 * Project: https://github.com/alex09x/xref
 * SPDX-License-Identifier: MIT OR Apache-2.0
 */

//! Bounded nonblocking `trace_pipe` reader, `fork`-child TGID filter, and per-probe accumulator.

use std::collections::{BTreeMap, BTreeSet};
use std::fs::{File, OpenOptions};
use std::io::{self, Read};
use std::path::Path;
use std::sync::atomic::Ordering;
use std::time::{Duration, Instant};

use crate::live::probe::caller::attribute_caller;
use crate::live::probe::trace_parse::{StreamingTraceLineBuffer, parse_uprobe_trace_line};
use crate::live::probe::tracefs::ProbeRunConfig;
use crate::live::probe::tracefs_tid::accept_tid_for_target;
use crate::live::probe::types::{
    FetchedSample, FetchedValue, MAX_FETCH_SAMPLES_PER_PROBE, MAX_FETCHED_VALUES_PER_SESSION,
    MAX_REGISTER_SAMPLES_PER_PROBE, ProbeStopReason, ProbeTargetResult, ProbeTargetSpec, REGISTER_SEMANTICS_CAVEAT,
    RegisterSample,
};
use crate::live::procfs::{LiveSession, refresh_session_identity};
use crate::live::types::HexAddr;

#[derive(Default)]
pub struct ProbeAccumulator {
    pub accepted_hits: u64,
    pub first_timestamp_ns: Option<u64>,
    pub last_timestamp_ns: Option<u64>,
    pub caller_counts: BTreeMap<u64, u64>,
    pub reg_samples: Vec<RegisterSample>,
    pub reg_samples_truncated: bool,
    pub fetched_samples: Vec<FetchedSample>,
    pub fetched_samples_truncated: bool,
}

impl ProbeAccumulator {
    pub fn record_timestamp(&mut self, ts: Option<u64>) {
        if let Some(t) = ts {
            self.first_timestamp_ns = Some(self.first_timestamp_ns.map_or(t, |prev| prev.min(t)));
            self.last_timestamp_ns = Some(self.last_timestamp_ns.map_or(t, |prev| prev.max(t)));
        }
    }

    pub fn push_reg_sample(&mut self, sample: RegisterSample) {
        if self.reg_samples.len() < MAX_REGISTER_SAMPLES_PER_PROBE {
            self.reg_samples.push(sample);
        } else {
            self.reg_samples_truncated = true;
        }
    }
}

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
        }
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
    deadline: Instant,
) -> ProbeStopReason {
    let mut chunk = [0_u8; 8192];
    let mut last_recheck = Instant::now();
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
        let now = Instant::now();
        if now >= deadline {
            return ProbeStopReason::DurationElapsed;
        }
        match trace_pipe_fd.read(&mut chunk) {
            Ok(n) if n > 0 => {
                line_buf.push_chunk(&chunk[..n], |line| {
                    process_trace_line(line, event_prefix, proc_root, cfg, state);
                });
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

fn sleep_or_recheck(session: &mut LiveSession, last_recheck: &mut Instant, deadline: Instant) {
    if last_recheck.elapsed() >= Duration::from_millis(25) {
        refresh_session_identity(session);
        *last_recheck = Instant::now();
        if !session.process.pid_alive_after || session.process.process_changed {
            return;
        }
    }
    let now = Instant::now();
    if now < deadline {
        std::thread::sleep((deadline - now).min(Duration::from_millis(5)));
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
    while state.total_accepted < cfg.max_events {
        match trace_pipe_fd.read(&mut chunk) {
            Ok(n) if n > 0 => {
                line_buf.push_chunk(&chunk[..n], |line| {
                    process_trace_line(line, event_prefix, proc_root, cfg, state);
                });
            }
            _ => break,
        }
    }
    if state.total_accepted >= cfg.max_events || state.hit_until_hits {
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
    if cfg.first.is_some_and(|limit| state.accumulators[ev.probe_index].accepted_hits >= limit as u64)
        || !(*seen - 1).is_multiple_of(cfg.every as u64)
    {
        return;
    }
    state.total_accepted += 1;
    if state.total_accepted >= cfg.max_events {
        state.hit_max_events = true;
    }
    let acc = &mut state.accumulators[ev.probe_index];
    acc.accepted_hits = acc.accepted_hits.saturating_add(1);
    acc.record_timestamp(ev.timestamp_ns);
    if !cfg.fetches.is_empty() {
        let remaining = MAX_FETCHED_VALUES_PER_SESSION.saturating_sub(state.fetched_values);
        let values = cfg
            .fetches
            .iter()
            .take(remaining)
            .map(|fetch| FetchedValue { name: fetch.name.clone(), value: HexAddr(ev.fetch_values[&fetch.name]) })
            .collect::<Vec<_>>();
        state.fetched_values = state.fetched_values.saturating_add(values.len());
        if values.len() != cfg.fetches.len() {
            acc.fetched_samples_truncated = true;
        }
        if values.len() == cfg.fetches.len()
            && !values.is_empty()
            && acc.fetched_samples.len() < MAX_FETCH_SAMPLES_PER_PROBE
        {
            acc.fetched_samples.push(FetchedSample { timestamp_ns: ev.timestamp_ns.unwrap_or(0), values });
        } else if acc.fetched_samples.len() >= MAX_FETCH_SAMPLES_PER_PROBE {
            acc.fetched_samples_truncated = true;
        }
    }
    if cfg.want_callers
        && let Some(ra) = ev.return_addr
    {
        let entry = acc.caller_counts.entry(ra).or_insert(0);
        *entry = entry.saturating_add(1);
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
        });
    }
    if cfg.until_hits.is_some_and(|limit| state.total_accepted >= limit) {
        state.hit_until_hits = true;
    }
}

pub fn build_probe_results(
    session: &mut LiveSession,
    specs: &[ProbeTargetSpec],
    accumulators: Vec<ProbeAccumulator>,
    want_callers: bool,
) -> Vec<ProbeTargetResult> {
    let mut out = Vec::with_capacity(specs.len());
    for (spec, acc) in specs.iter().zip(accumulators) {
        if want_callers && spec.ra_fetch_arg.is_none() {
            let warn = format!("caller_recovery_unavailable_at_{:#x}", spec.static_va);
            if !session.process.warnings.contains(&warn) {
                session.process.warnings.push(warn);
            }
        }
        let mut callers: Vec<_> = acc
            .caller_counts
            .into_iter()
            .map(|(ra, hits)| {
                attribute_caller(
                    &session.image,
                    session.process.pie_slide,
                    &session.regions,
                    &spec.unwind_entry_abi,
                    ra,
                    hits,
                )
            })
            .collect();
        callers.sort_by(|a, b| b.hits.cmp(&a.hits).then_with(|| a.raw_return_runtime_va.cmp(&b.raw_return_runtime_va)));

        out.push(ProbeTargetResult {
            input: HexAddr(spec.input),
            static_va: HexAddr(spec.static_va),
            runtime_va: HexAddr(spec.runtime_va),
            file_offset: HexAddr(spec.file_offset),
            function_start: spec.function_start.map(HexAddr),
            function_end: spec.function_end.map(HexAddr),
            function_offset: spec.function_offset,
            symbol: spec.symbol.clone(),
            instruction_mnemonic: spec.instruction_mnemonic.clone(),
            unwind_entry_abi: spec.unwind_entry_abi.clone(),
            accepted_hits: acc.accepted_hits,
            first_timestamp_ns: acc.first_timestamp_ns,
            last_timestamp_ns: acc.last_timestamp_ns,
            callers,
            register_samples_truncated: acc.reg_samples_truncated,
            register_samples: acc.reg_samples,
            fetched_samples: acc.fetched_samples,
            fetched_samples_truncated: acc.fetched_samples_truncated,
        });
    }
    out
}

#[cfg(unix)]
pub fn open_nonblocking_read(path: &Path) -> io::Result<File> {
    use std::os::unix::fs::OpenOptionsExt;
    #[cfg(target_os = "linux")]
    const O_NONBLOCK_FLAG: i32 = 0o4000;
    #[cfg(not(target_os = "linux"))]
    const O_NONBLOCK_FLAG: i32 = 0x0004;
    OpenOptions::new().read(true).custom_flags(O_NONBLOCK_FLAG).open(path)
}

#[cfg(not(unix))]
pub fn open_nonblocking_read(path: &Path) -> io::Result<File> {
    File::open(path)
}
