/*
 * XRef — `live sched` capture: context switches, off-CPU stacks and system calls of every thread
 * Copyright (c) 2026 Alexander Panasenko
 * Contact: alex@prod.codes
 * Author: https://prod.codes/about/
 * Project: https://github.com/alex09x/xref
 * SPDX-License-Identifier: MIT OR Apache-2.0
 */

//! Each thread gets a software `context-switches` event with `context_switch` set: the kernel then
//! writes a switch record each time the thread leaves or gets a CPU (the leaving one says whether
//! it was preempted), and the event samples the user registers and stack at every switch-out, the
//! stack the thread blocked in. With the `raw_syscalls` tracepoints, each system call's entry and
//! exit pair up into a latency. Records from all rings are applied in timestamp order: after a
//! drain, every record no later than the newest one of the previous drain has been read.

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

use perf_event::{
    Builder, Clock, Sampler,
    events::{Software, Tracepoint},
};
use serde::Serialize;

use super::super::capture::REGISTER_MASK;
use super::super::perf_decode::{
    self, SAMPLE_IP, SAMPLE_PERIOD, SAMPLE_RAW, SAMPLE_REGS_USER, SAMPLE_STACK_USER, SAMPLE_TID, SAMPLE_TIME,
};
use super::super::types::{Mapping, Sample};
use super::syscalls::Histogram;
use crate::live::probe::tracefs::read_tid_set;
use crate::live::procfs::{LiveSession, refresh_session_identity};

const SWITCH_RING_BYTES: usize = 1024 * 1024;
const SYSCALL_RING_BYTES: usize = 256 * 1024;
const PERF_RECORD_SWITCH: u32 = 14;
const MISC_SWITCH_OUT: u16 = 1 << 13;
const MISC_SWITCH_OUT_PREEMPT: u16 = 1 << 14;
const SWITCH_SAMPLE: u64 = SAMPLE_IP | SAMPLE_TID | SAMPLE_TIME | SAMPLE_PERIOD | SAMPLE_REGS_USER | SAMPLE_STACK_USER;
const SYSCALL_SAMPLE: u64 = SAMPLE_TID | SAMPLE_TIME | SAMPLE_RAW;

/// The tracepoint ID of `raw_syscalls/<name>`.
fn tracepoint_id(name: &str) -> Result<u64, String> {
    for root in ["/sys/kernel/tracing", "/sys/kernel/debug/tracing"] {
        if let Ok(text) = std::fs::read_to_string(format!("{root}/events/raw_syscalls/{name}/id")) {
            return text.trim().parse().map_err(|_| format!("invalid tracepoint id for {name}"));
        }
    }
    Err(format!(
        "permission_denied: cannot read the raw_syscalls/{name} tracepoint id (system calls need root or tracefs access; pass --no-syscalls to leave them out)"
    ))
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Ring {
    Switch,
    Enter,
    Exit,
}

struct ThreadEvents {
    tid: u32,
    rings: Vec<(Ring, Sampler)>,
}

fn open_thread(tid: u32, syscalls: Option<(u64, u64)>, stack_bytes: u32) -> Result<ThreadEvents, String> {
    let pid = i32::try_from(tid).map_err(|_| "TID exceeds pid_t")?;
    let mut rings = Vec::new();
    let mut builder = Builder::new(Software::CONTEXT_SWITCHES);
    builder
        .observe_pid(pid)
        .any_cpu()
        .inherit(false)
        .sample_period(1)
        // The switch happens in the kernel: the event counts there, and samples the user registers
        // and stack the thread entered it with.
        .exclude_kernel(false)
        .clockid(Clock::MONOTONIC)
        .sample_id_all(true)
        .context_switch(true)
        .mmap(true)
        .mmap2(true)
        .task(true);
    let attributes = builder.attrs_mut();
    attributes.sample_type = SWITCH_SAMPLE;
    attributes.sample_regs_user = REGISTER_MASK;
    attributes.sample_stack_user = stack_bytes;
    let counter = builder.build().map_err(|error| format!("perf_event_open context-switches: {error}"))?;
    let mut sampler = counter.sampled(SWITCH_RING_BYTES).map_err(|error| format!("perf mmap: {error}"))?;
    sampler.enable().map_err(|error| format!("perf enable: {error}"))?;
    rings.push((Ring::Switch, sampler));
    if let Some((enter, exit)) = syscalls {
        for (ring, id) in [(Ring::Enter, enter), (Ring::Exit, exit)] {
            let mut builder = Builder::new(Tracepoint::with_id(id));
            builder
                .observe_pid(pid)
                .any_cpu()
                .inherit(false)
                .sample_period(1)
                .exclude_kernel(false)
                .clockid(Clock::MONOTONIC);
            builder.attrs_mut().sample_type = SYSCALL_SAMPLE;
            let counter = builder.build().map_err(|error| format!("perf_event_open raw_syscalls: {error}"))?;
            let mut sampler = counter.sampled(SYSCALL_RING_BYTES).map_err(|error| format!("perf mmap: {error}"))?;
            sampler.enable().map_err(|error| format!("perf enable: {error}"))?;
            rings.push((ring, sampler));
        }
    }
    Ok(ThreadEvents { tid, rings })
}

/// One decoded record, ordered by time.
enum Event {
    /// A switch-out sample: the stack the thread leaves the CPU with.
    Stack(Box<Sample>),
    SwitchOut {
        preempted: bool,
    },
    SwitchIn,
    Enter {
        number: u64,
    },
    Exit {
        number: u64,
    },
}

struct Timed {
    ts: u64,
    tid: u32,
    /// Orders records of one instant: a switch-out sample before its switch record.
    order: u8,
    event: Event,
}

/// Per thread totals.
#[derive(Clone, Debug, Default, Serialize)]
pub struct ThreadStats {
    pub tid: u32,
    pub comm: String,
    pub off_cpu_ns: u64,
    pub voluntary_switches: u64,
    pub involuntary_switches: u64,
    /// Times the thread got a CPU again after blocking (voluntarily leaving it).
    pub wakeups: u64,
    pub syscalls: u64,
}

/// What a capture saw.
#[derive(Debug, Default, Serialize)]
pub struct SchedStats {
    pub elapsed_ms: u64,
    pub threads: usize,
    pub unattached_threads: usize,
    pub lost: u64,
    pub undecoded: u64,
    pub syscalls_traced: bool,
    pub stop_reason: &'static str,
}

/// The result of a capture.
pub struct Capture {
    pub stats: SchedStats,
    pub threads: BTreeMap<u32, ThreadStats>,
    pub syscalls: BTreeMap<u64, Histogram>,
    /// Switch-out stacks weighted by the nanoseconds the thread then spent off CPU.
    pub off_cpu: Vec<Sample>,
    pub mappings: Vec<Mapping>,
}

#[derive(Default)]
struct ThreadState {
    /// The newest switch-out stack and whether it waits for its interval.
    stack: Option<Box<Sample>>,
    out_since: Option<(u64, bool)>,
    syscall: Option<(u64, u64)>,
}

struct Applier {
    waiting: Vec<Timed>,
    newest_previous: u64,
    newest: u64,
    state: HashMap<u32, ThreadState>,
    threads: BTreeMap<u32, ThreadStats>,
    syscalls: BTreeMap<u64, Histogram>,
    off_cpu: Vec<Sample>,
}

impl Applier {
    fn push(&mut self, timed: Timed) {
        self.newest = self.newest.max(timed.ts);
        self.waiting.push(timed);
    }

    fn settle(&mut self, all: bool) {
        let limit = if all { u64::MAX } else { self.newest_previous };
        self.newest_previous = self.newest;
        self.waiting.sort_by_key(|timed| (timed.ts, timed.tid, timed.order));
        let split = self.waiting.partition_point(|timed| timed.ts <= limit);
        let ready: Vec<Timed> = self.waiting.drain(..split).collect();
        for timed in ready {
            self.apply(timed);
        }
    }

    fn apply(&mut self, timed: Timed) {
        let state = self.state.entry(timed.tid).or_default();
        let totals =
            self.threads.entry(timed.tid).or_insert_with(|| ThreadStats { tid: timed.tid, ..ThreadStats::default() });
        match timed.event {
            Event::Stack(sample) => state.stack = Some(sample),
            Event::SwitchOut { preempted } => {
                if preempted {
                    totals.involuntary_switches += 1;
                } else {
                    totals.voluntary_switches += 1;
                }
                state.out_since = Some((timed.ts, preempted));
            }
            Event::SwitchIn => {
                if let Some((since, preempted)) = state.out_since.take() {
                    let off = timed.ts.saturating_sub(since);
                    totals.off_cpu_ns = totals.off_cpu_ns.saturating_add(off);
                    if !preempted {
                        totals.wakeups += 1;
                    }
                    if let Some(mut sample) = state.stack.take() {
                        sample.period = off.max(1);
                        self.off_cpu.push(*sample);
                    }
                }
            }
            Event::Enter { number } => state.syscall = Some((number, timed.ts)),
            Event::Exit { number } => {
                // A lost entry or exit leaves an unmatched record, never a wrong pair.
                if let Some((entered, since)) = state.syscall.take()
                    && entered == number
                {
                    totals.syscalls += 1;
                    self.syscalls.entry(number).or_default().record(timed.ts.saturating_sub(since));
                }
            }
        }
    }

    /// Closes the off-CPU intervals still open when the capture ends.
    fn close(&mut self, end_ns: u64) {
        for (tid, state) in &mut self.state {
            if let Some((since, _)) = state.out_since.take() {
                let off = end_ns.saturating_sub(since);
                if let Some(stats) = self.threads.get_mut(tid) {
                    stats.off_cpu_ns = stats.off_cpu_ns.saturating_add(off);
                }
                if let Some(mut sample) = state.stack.take() {
                    sample.period = off.max(1);
                    self.off_cpu.push(*sample);
                }
            }
        }
    }
}

/// `PERF_RECORD_MISC_USER`.
const CPU_MODE_USER: u16 = 2;
/// The perf x86 register index of IP.
const PERF_REG_IP: u32 = 8;

/// The user IP from the sampled user registers: its position is the number of mask bits below it.
fn user_ip(sample: &Sample) -> Option<u64> {
    if sample.registers_mask & (1 << PERF_REG_IP) == 0 {
        return None;
    }
    let position = (sample.registers_mask & ((1 << PERF_REG_IP) - 1)).count_ones();
    sample.registers.get(usize::try_from(position).ok()?).copied().filter(|ip| *ip != 0)
}

fn word(raw: &[u8], offset: usize) -> Option<u64> {
    raw.get(offset..offset + 8).and_then(|bytes| bytes.try_into().ok()).map(u64::from_le_bytes)
}

/// The monotonic clock, as perf timestamps it.
fn monotonic_ns() -> u64 {
    let now = rustix::time::clock_gettime(rustix::time::ClockId::Monotonic);
    u64::try_from(now.tv_sec)
        .unwrap_or(0)
        .saturating_mul(1_000_000_000)
        .saturating_add(u64::try_from(now.tv_nsec).unwrap_or(0))
}

/// Observes the process for `duration`, or until it exits or `cancel` is set.
pub fn observe(
    session: &mut LiveSession,
    duration: Duration,
    stack_bytes: u32,
    syscalls: bool,
    cancel: Option<&AtomicBool>,
    mut mappings: Vec<Mapping>,
) -> Result<Capture, String> {
    let ids = if syscalls { Some((tracepoint_id("sys_enter")?, tracepoint_id("sys_exit")?)) } else { None };
    let pid = session.process.pid;
    let task_dir = Path::new("/proc").join(pid.to_string()).join("task");
    let mut applier = Applier {
        waiting: Vec::new(),
        newest_previous: 0,
        newest: 0,
        state: HashMap::new(),
        threads: BTreeMap::new(),
        syscalls: BTreeMap::new(),
        off_cpu: Vec::new(),
    };
    let mut threads: Vec<ThreadEvents> = Vec::new();
    let mut failed: BTreeSet<u32> = BTreeSet::new();
    let mut stats = SchedStats { stop_reason: "duration", syscalls_traced: syscalls, ..SchedStats::default() };
    let started = Instant::now();
    let mut last_check: Option<Instant> = None;
    loop {
        if last_check.is_none_or(|at| at.elapsed() >= Duration::from_millis(25)) {
            refresh_session_identity(session);
            if !session.process.pid_alive_after || !Path::new(&format!("/proc/{pid}")).exists() {
                stats.stop_reason = "process_exited";
                break;
            }
            if session.process.process_changed {
                stats.stop_reason = "process_changed";
                break;
            }
            let live = read_tid_set(&task_dir).unwrap_or_default();
            threads.retain(|thread| live.contains(&thread.tid));
            for tid in live {
                if threads.iter().any(|thread| thread.tid == tid) || failed.contains(&tid) {
                    continue;
                }
                match open_thread(tid, ids, stack_bytes) {
                    Ok(events) => threads.push(events),
                    Err(error) if threads.is_empty() && failed.is_empty() => return Err(error),
                    Err(_) => {
                        failed.insert(tid);
                    }
                }
            }
            stats.threads = stats.threads.max(threads.len());
            last_check = Some(Instant::now());
        }
        let read = drain(&mut threads, pid, &mut applier, &mut mappings, &mut stats);
        applier.settle(false);
        if cancel.is_some_and(|flag| flag.load(Ordering::Relaxed)) {
            stats.stop_reason = "cancelled";
            break;
        }
        if started.elapsed() >= duration {
            break;
        }
        if read == 0 {
            std::thread::sleep(Duration::from_millis(2));
        }
    }
    drain(&mut threads, pid, &mut applier, &mut mappings, &mut stats);
    drop(threads);
    applier.settle(true);
    applier.close(monotonic_ns());
    for (tid, thread) in &mut applier.threads {
        thread.comm = std::fs::read_to_string(format!("/proc/{pid}/task/{tid}/comm"))
            .map(|name| name.trim().to_owned())
            .unwrap_or_default();
    }
    stats.unattached_threads = failed.len();
    stats.elapsed_ms = u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX);
    Ok(Capture { stats, threads: applier.threads, syscalls: applier.syscalls, off_cpu: applier.off_cpu, mappings })
}

/// Reads every ring once; returns the records read.
fn drain(
    threads: &mut [ThreadEvents],
    pid: u32,
    applier: &mut Applier,
    mappings: &mut Vec<Mapping>,
    stats: &mut SchedStats,
) -> usize {
    let mut read = 0;
    for thread in threads.iter_mut() {
        for (ring, sampler) in &mut thread.rings {
            while let Some(record) = sampler.next_record() {
                read += 1;
                let bytes = record.to_contiguous();
                match (record.ty(), *ring) {
                    (9, Ring::Switch) => match perf_decode::decode_sample(&bytes, SWITCH_SAMPLE, REGISTER_MASK) {
                        Ok(mut sample) if sample.pid == pid => {
                            // The sample is taken in the kernel's scheduler; the stack of interest is
                            // the user one the thread entered the kernel with (its user IP and
                            // registers), so the sample is unwound as a user-mode one from there.
                            match user_ip(&sample) {
                                Some(ip) => {
                                    sample.ip = ip;
                                    sample.cpu_mode = CPU_MODE_USER;
                                }
                                None => sample.cpu_mode = record.misc() & 7,
                            }
                            let (ts, tid) = (sample.timestamp_ns, sample.tid);
                            applier.push(Timed { ts, tid, order: 0, event: Event::Stack(Box::new(sample)) });
                        }
                        Ok(_) => {}
                        Err(_) => stats.undecoded += 1,
                    },
                    (PERF_RECORD_SWITCH, Ring::Switch) => {
                        // The sample_id trailer: pid, tid, time.
                        let (Some(tid), Some(ts)) =
                            (bytes.get(4..8).and_then(|b| b.try_into().ok()).map(u32::from_le_bytes), word(&bytes, 8))
                        else {
                            stats.undecoded += 1;
                            continue;
                        };
                        let misc = record.misc();
                        let event = if misc & MISC_SWITCH_OUT == 0 {
                            Event::SwitchIn
                        } else {
                            Event::SwitchOut { preempted: misc & MISC_SWITCH_OUT_PREEMPT != 0 }
                        };
                        applier.push(Timed { ts, tid, order: 1, event });
                    }
                    (9, Ring::Enter | Ring::Exit) => match perf_decode::decode_sample_raw(&bytes, SYSCALL_SAMPLE, 0) {
                        Ok((sample, raw)) if sample.pid == pid => {
                            let Some(number) = word(&raw, 8) else {
                                stats.undecoded += 1;
                                continue;
                            };
                            let event =
                                if *ring == Ring::Enter { Event::Enter { number } } else { Event::Exit { number } };
                            applier.push(Timed { ts: sample.timestamp_ns, tid: sample.tid, order: 2, event });
                        }
                        Ok(_) => {}
                        Err(_) => stats.undecoded += 1,
                    },
                    (10, Ring::Switch) => {
                        if let Ok(mapping) = perf_decode::decode_mmap2(&bytes, record.misc(), true)
                            && mapping.pid == pid
                        {
                            mappings.push(mapping);
                        }
                    }
                    (2, _) => stats.lost += word(&bytes, 8).unwrap_or(1),
                    _ => {}
                }
            }
        }
    }
    read
}

#[cfg(test)]
mod tests {
    use super::{Applier, Event, Timed};
    use std::collections::{BTreeMap, HashMap};

    fn applier() -> Applier {
        Applier {
            waiting: Vec::new(),
            newest_previous: 0,
            newest: 0,
            state: HashMap::new(),
            threads: BTreeMap::new(),
            syscalls: BTreeMap::new(),
            off_cpu: Vec::new(),
        }
    }

    fn sample(ts: u64) -> Box<super::Sample> {
        Box::new(super::Sample {
            timestamp_ns: ts,
            pid: 1,
            tid: 7,
            cpu_mode: 2,
            ip: 0x1000,
            period: 1,
            registers_mask: 0,
            registers: Vec::new(),
            user_stack: Vec::new(),
            callchain: Vec::new(),
            branches: Vec::new(),
        })
    }

    #[test]
    fn off_cpu_intervals_weigh_the_stack_and_count_wakeups_and_preemptions() {
        let mut a = applier();
        let events = vec![
            Timed { ts: 100, tid: 7, order: 0, event: Event::Stack(sample(100)) },
            Timed { ts: 100, tid: 7, order: 1, event: Event::SwitchOut { preempted: false } },
            Timed { ts: 600, tid: 7, order: 1, event: Event::SwitchIn },
            Timed { ts: 700, tid: 7, order: 0, event: Event::Stack(sample(700)) },
            Timed { ts: 700, tid: 7, order: 1, event: Event::SwitchOut { preempted: true } },
            Timed { ts: 750, tid: 7, order: 1, event: Event::SwitchIn },
            Timed { ts: 800, tid: 7, order: 2, event: Event::Enter { number: 7 } },
            Timed { ts: 900, tid: 7, order: 2, event: Event::Exit { number: 7 } },
            Timed { ts: 950, tid: 7, order: 2, event: Event::Exit { number: 0 } },
        ];
        // Arrival order does not matter: records are applied by time.
        for timed in events.into_iter().rev() {
            a.push(timed);
        }
        a.settle(true);
        let stats = &a.threads[&7];
        assert_eq!((stats.off_cpu_ns, stats.voluntary_switches, stats.involuntary_switches), (550, 1, 1));
        assert_eq!(
            (stats.wakeups, stats.syscalls),
            (1, 1),
            "a preemption is not a wakeup; an unmatched exit is dropped"
        );
        assert_eq!(a.off_cpu.iter().map(|s| s.period).collect::<Vec<_>>(), vec![500, 50]);
        assert_eq!(a.syscalls[&7].max, 100);
    }

    #[test]
    fn an_interval_open_at_the_end_is_closed_there() {
        let mut a = applier();
        a.push(Timed { ts: 10, tid: 7, order: 0, event: Event::Stack(sample(10)) });
        a.push(Timed { ts: 10, tid: 7, order: 1, event: Event::SwitchOut { preempted: false } });
        a.settle(true);
        a.close(1010);
        assert_eq!(a.threads[&7].off_cpu_ns, 1000);
        assert_eq!(a.off_cpu[0].period, 1000);
    }
}
