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
use std::time::{Duration, Instant};

use crate::live::probe::caller::attribute_caller;
use crate::live::probe::trace_parse::{ParsedTraceEvent, StreamingTraceLineBuffer, parse_uprobe_trace_line};
use crate::live::probe::tracefs::ProbeRunConfig;
use crate::live::probe::types::{
    MAX_REGISTER_SAMPLES_PER_PROBE, ProbeStopReason, ProbeTargetResult, ProbeTargetSpec, RegisterSample,
};
use crate::live::procfs::{LiveSession, refresh_session_identity};
use crate::live::types::HexAddr;

#[derive(Default)]
pub struct ProbeAccumulator {
    pub accepted_hits: u64,
    pub caller_counts: BTreeMap<u64, u64>,
    pub reg_samples: Vec<RegisterSample>,
}

pub struct StreamState {
    pub target_pid: u32,
    pub known_tids: BTreeSet<u32>,
    pub other_tgid_tids: BTreeSet<u32>,
    pub excluded_other_tgid: u64,
    pub ambiguous_tid: u64,
    pub total_accepted: usize,
    pub accumulators: Vec<ProbeAccumulator>,
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
            total_accepted: 0,
            accumulators: (0..probe_count).map(|_| ProbeAccumulator::default()).collect(),
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
    cfg: &ProbeRunConfig,
    deadline: Instant,
) -> ProbeStopReason {
    let mut chunk = [0_u8; 8192];
    let mut last_recheck = Instant::now();
    loop {
        if state.total_accepted >= cfg.max_events {
            return ProbeStopReason::MaxEvents;
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
    cfg: &ProbeRunConfig,
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
    line_buf.finish(|line| process_trace_line(line, event_prefix, proc_root, cfg, state));
}

fn process_trace_line(line: &str, event_prefix: &str, proc_root: &Path, cfg: &ProbeRunConfig, state: &mut StreamState) {
    if state.total_accepted >= cfg.max_events {
        return;
    }
    let Some(ev) = parse_uprobe_trace_line(line, event_prefix) else { return };
    if ev.probe_index >= state.accumulators.len() {
        return;
    }
    if !accept_tid_for_target(&ev, proc_root, state) {
        return;
    }
    state.total_accepted += 1;
    let acc = &mut state.accumulators[ev.probe_index];
    acc.accepted_hits = acc.accepted_hits.saturating_add(1);
    if cfg.want_callers
        && let Some(ra) = ev.return_addr
    {
        let entry = acc.caller_counts.entry(ra).or_insert(0);
        *entry = entry.saturating_add(1);
    }
    if cfg.want_regs
        && acc.reg_samples.len() < MAX_REGISTER_SAMPLES_PER_PROBE
        && let Some(r) = ev.regs
    {
        acc.reg_samples.push(RegisterSample {
            tid: ev.tid,
            rdi: HexAddr(r.rdi),
            rsi: HexAddr(r.rsi),
            rdx: HexAddr(r.rdx),
            rcx: HexAddr(r.rcx),
            r8: HexAddr(r.r8),
            r9: HexAddr(r.r9),
            rax: HexAddr(r.rax),
            rsp: HexAddr(r.rsp),
        });
    }
}

fn accept_tid_for_target(ev: &ParsedTraceEvent, proc_root: &Path, state: &mut StreamState) -> bool {
    if let Some(tgid) = ev.tgid {
        if tgid == state.target_pid {
            state.known_tids.insert(ev.tid);
            return true;
        }
        state.excluded_other_tgid = state.excluded_other_tgid.saturating_add(1);
        return false;
    }
    if state.known_tids.contains(&ev.tid) {
        return true;
    }
    if state.other_tgid_tids.contains(&ev.tid) {
        state.excluded_other_tgid = state.excluded_other_tgid.saturating_add(1);
        return false;
    }
    let task_path = proc_root.join(state.target_pid.to_string()).join("task").join(ev.tid.to_string());
    if task_path.exists() {
        state.known_tids.insert(ev.tid);
        return true;
    }
    let status_path = proc_root.join(ev.tid.to_string()).join("status");
    if let Ok(status) = std::fs::read_to_string(status_path)
        && let Some(tgid) = status.lines().find_map(|l| l.strip_prefix("Tgid:")?.trim().parse::<u32>().ok())
    {
        if tgid == state.target_pid {
            state.known_tids.insert(ev.tid);
            return true;
        }
        state.other_tgid_tids.insert(ev.tid);
        state.excluded_other_tgid = state.excluded_other_tgid.saturating_add(1);
        return false;
    }
    state.ambiguous_tid = state.ambiguous_tid.saturating_add(1);
    false
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
            callers,
            register_samples: acc.reg_samples,
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
