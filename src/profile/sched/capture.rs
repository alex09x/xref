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
//! drain, every record no later than the newest one of the previous drain has been read. A lost
//! record breaks a thread's stream, so no wait or call is paired across the gap. Weighted off-CPU
//! samples are handed to a sink as they complete, so their stacks are not kept.

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
use super::super::types::{Record, Sample};
use super::syscalls::Histogram;
use crate::live::probe::tracefs::read_tid_set;
use crate::live::procfs::{LiveSession, refresh_session_identity};

const SWITCH_RING_BYTES: usize = 1024 * 1024;
const SYSCALL_RING_BYTES: usize = 256 * 1024;
const PERF_RECORD_LOST: u32 = 2;
const PERF_RECORD_EXIT: u32 = 4;
const PERF_RECORD_THROTTLE: u32 = 5;
const PERF_RECORD_MMAP2: u32 = 10;
const PERF_RECORD_SAMPLE: u32 = 9;
const PERF_RECORD_SWITCH: u32 = 14;
const MISC_SWITCH_OUT: u16 = 1 << 13;
const MISC_SWITCH_OUT_PREEMPT: u16 = 1 << 14;
const SWITCH_SAMPLE: u64 = SAMPLE_IP | SAMPLE_TID | SAMPLE_TIME | SAMPLE_PERIOD | SAMPLE_REGS_USER | SAMPLE_STACK_USER;
const SYSCALL_SAMPLE: u64 = SAMPLE_TID | SAMPLE_TIME | SAMPLE_RAW;
/// `PERF_RECORD_MISC_USER`.
const CPU_MODE_USER: u16 = 2;
/// The perf x86 register index of IP.
const PERF_REG_IP: u32 = 8;

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
    /// Each ring with the time of the newest record read from it.
    rings: Vec<(Ring, Sampler, u64)>,
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
    rings.push((Ring::Switch, sampler, 0));
    if let Some((enter, exit)) = syscalls {
        for (ring, id) in [(Ring::Enter, enter), (Ring::Exit, exit)] {
            let mut builder = Builder::new(Tracepoint::with_id(id));
            builder
                .observe_pid(pid)
                .any_cpu()
                .inherit(false)
                .sample_period(1)
                .exclude_kernel(false)
                .sample_id_all(true)
                .clockid(Clock::MONOTONIC);
            builder.attrs_mut().sample_type = SYSCALL_SAMPLE;
            let counter = builder.build().map_err(|error| format!("perf_event_open raw_syscalls: {error}"))?;
            let mut sampler = counter.sampled(SYSCALL_RING_BYTES).map_err(|error| format!("perf mmap: {error}"))?;
            sampler.enable().map_err(|error| format!("perf enable: {error}"))?;
            rings.push((ring, sampler, 0));
        }
    }
    Ok(ThreadEvents { tid, rings })
}

/// One decoded record, ordered by time.
enum Event {
    /// The thread is observed from here (its sampler was attached); `sleeping` when it was off CPU
    /// then.
    Attached {
        sleeping: bool,
    },
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
    /// Records of the thread were lost: nothing pairs across this point.
    Gap,
    /// The thread exited.
    ThreadExit,
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
    /// Times the thread got a CPU again after leaving it voluntarily (blocking, or yielding).
    pub wakeups: u64,
    /// System calls entered while observed.
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
    /// Times the kernel throttled an event (records missing until it resumed).
    pub throttled: u64,
    pub syscalls_traced: bool,
    /// Waits that began before the thread was attached: only their observed part is counted.
    pub waits_started_before_attach: u64,
    pub stop_reason: &'static str,
}

/// A system call's entries and the latencies of those that returned while observed.
#[derive(Clone, Debug, Default)]
pub struct Calls {
    pub entered: u64,
    pub latency: Histogram,
}

/// The result of a capture; the weighted off-CPU samples went to the sink.
pub struct Capture {
    pub stats: SchedStats,
    pub threads: BTreeMap<u32, ThreadStats>,
    pub syscalls: BTreeMap<u64, Calls>,
}

#[derive(Default)]
struct ThreadState {
    /// The newest switch-out stack, waiting for its interval.
    stack: Option<Box<Sample>>,
    out_since: Option<(u64, bool)>,
    syscall: Option<(u64, u64)>,
    /// The open wait began before the thread was attached (it counts from the attachment).
    initial_wait: bool,
}

/// Where the weighted off-CPU samples and mappings go.
pub type Sink<'a> = dyn FnMut(Record) -> Result<(), String> + 'a;

struct Applier {
    waiting: Vec<Timed>,
    newest_previous: u64,
    newest: u64,
    state: HashMap<u32, ThreadState>,
    threads: BTreeMap<u32, ThreadStats>,
    syscalls: BTreeMap<u64, Calls>,
    completed: Vec<Sample>,
    waits_started_before_attach: u64,
}

impl Applier {
    fn new() -> Self {
        Self {
            waiting: Vec::new(),
            newest_previous: 0,
            newest: 0,
            state: HashMap::new(),
            threads: BTreeMap::new(),
            syscalls: BTreeMap::new(),
            completed: Vec::new(),
            waits_started_before_attach: 0,
        }
    }

    fn push(&mut self, timed: Timed) {
        self.newest = self.newest.max(timed.ts);
        self.waiting.push(timed);
    }

    /// Applies every waiting record up to `end_ns` and drops the later ones (after the capture).
    fn settle_until(&mut self, end_ns: u64) {
        self.waiting.retain(|timed| timed.ts <= end_ns);
        self.settle(true);
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

    fn finish_wait(&mut self, tid: u32, since: u64, until: u64, stack: Option<Box<Sample>>) -> u64 {
        let off = until.saturating_sub(since);
        if let Some(totals) = self.threads.get_mut(&tid) {
            totals.off_cpu_ns = totals.off_cpu_ns.saturating_add(off);
        }
        if let Some(mut sample) = stack {
            sample.period = off.max(1);
            self.completed.push(*sample);
        }
        off
    }

    fn apply(&mut self, timed: Timed) {
        let tid = timed.tid;
        self.threads.entry(tid).or_insert_with(|| ThreadStats { tid, ..ThreadStats::default() });
        let state = self.state.entry(tid).or_default();
        match timed.event {
            Event::Attached { sleeping } => {
                if sleeping {
                    // Off CPU when attached: the wait's start is unknown, its observed part counts.
                    state.out_since = Some((timed.ts, false));
                    state.initial_wait = true;
                }
            }
            Event::Stack(sample) => state.stack = Some(sample),
            Event::SwitchOut { preempted } => {
                // A switch-out while a wait is open means its switch-in came before the rings
                // were on: that interval is not a wait and is dropped.
                state.initial_wait = false;
                state.out_since = Some((timed.ts, preempted));
                let totals = self.threads.get_mut(&tid);
                if let Some(totals) = totals {
                    if preempted {
                        totals.involuntary_switches += 1;
                    } else {
                        totals.voluntary_switches += 1;
                    }
                }
            }
            Event::SwitchIn => {
                if let Some((since, preempted)) = state.out_since.take() {
                    let stack = state.stack.take();
                    if std::mem::take(&mut state.initial_wait) {
                        self.waits_started_before_attach += 1;
                    }
                    self.finish_wait(tid, since, timed.ts, stack);
                    if !preempted && let Some(totals) = self.threads.get_mut(&tid) {
                        totals.wakeups += 1;
                    }
                }
            }
            Event::Enter { number } => {
                state.syscall = Some((number, timed.ts));
                self.syscalls.entry(number).or_default().entered += 1;
                if let Some(totals) = self.threads.get_mut(&tid) {
                    totals.syscalls += 1;
                }
            }
            Event::Exit { number } => {
                // A lost entry or exit leaves an unmatched record, never a wrong pair.
                if let Some((entered, since)) = state.syscall.take()
                    && entered == number
                {
                    self.syscalls.entry(number).or_default().latency.record(timed.ts.saturating_sub(since));
                }
            }
            Event::Gap => {
                state.syscall = None;
                state.out_since = None;
                state.stack = None;
                state.initial_wait = false;
            }
            Event::ThreadExit => {
                // A thread that exits while switched out is gone, not waiting: its wait ends here.
                if let Some((since, _)) = state.out_since.take() {
                    let stack = state.stack.take();
                    self.finish_wait(tid, since, timed.ts, stack);
                }
                self.state.remove(&tid);
            }
        }
    }

    /// Closes the off-CPU intervals still open at the end of the capture.
    fn close(&mut self, end_ns: u64, still_sleeping: impl Fn(u32) -> bool) {
        let mut initial = 0;
        let open: Vec<(u32, u64, Option<Box<Sample>>)> = self
            .state
            .iter_mut()
            .filter_map(|(tid, state)| {
                let (since, _) = state.out_since.take()?;
                // A wait seen only in the /proc snapshot, with no switch since, counts to the end
                // only if the thread still sleeps now: it may have woken before its sampler was
                // enabled and stayed on CPU (had it run and slept again, a switch would be seen).
                if std::mem::take(&mut state.initial_wait) {
                    initial += 1;
                    if !still_sleeping(*tid) {
                        return None;
                    }
                }
                Some((*tid, since, state.stack.take()))
            })
            .collect();
        self.waits_started_before_attach += initial;
        for (tid, since, stack) in open {
            self.finish_wait(tid, since, end_ns, stack);
        }
    }

    fn flush(&mut self, sink: &mut Sink<'_>) -> Result<(), String> {
        for sample in self.completed.drain(..) {
            sink(Record::Sample(sample))?;
        }
        Ok(())
    }
}

/// Whether a thread is off CPU now: sleeping, in uninterruptible wait, stopped or traced.
fn thread_sleeping(pid: u32, tid: u32) -> bool {
    std::fs::read(format!("/proc/{pid}/task/{tid}/stat")).is_ok_and(|stat| {
        let after = stat.iter().rposition(|&byte| byte == b')').map_or(0, |close| close + 2);
        matches!(stat.get(after), Some(b'S' | b'D' | b'T' | b't' | b'I'))
    })
}

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

fn tid_time(trailer: &[u8]) -> Option<(u32, u64)> {
    Some((u32::from_le_bytes(trailer.get(4..8)?.try_into().ok()?), word(trailer, 8)?))
}

/// The monotonic clock, as perf timestamps it.
fn monotonic_ns() -> u64 {
    let now = rustix::time::clock_gettime(rustix::time::ClockId::Monotonic);
    u64::try_from(now.tv_sec)
        .unwrap_or(0)
        .saturating_mul(1_000_000_000)
        .saturating_add(u64::try_from(now.tv_nsec).unwrap_or(0))
}

/// The capture settings.
pub struct Settings<'a> {
    pub duration: Duration,
    pub stack_bytes: u32,
    pub syscalls: bool,
    pub cancel: Option<&'a AtomicBool>,
}

/// Observes the process for the duration, or until it exits or the capture is cancelled; weighted
/// off-CPU samples and new mappings go to `sink` as they complete.
#[allow(clippy::too_many_lines)] // One loop owns thread attachment, draining and settling.
pub fn observe(session: &mut LiveSession, settings: &Settings<'_>, sink: &mut Sink<'_>) -> Result<Capture, String> {
    let ids = if settings.syscalls { Some((tracepoint_id("sys_enter")?, tracepoint_id("sys_exit")?)) } else { None };
    let pid = session.process.pid;
    let task_dir = Path::new("/proc").join(pid.to_string()).join("task");
    let mut applier = Applier::new();
    let mut threads: Vec<ThreadEvents> = Vec::new();
    let mut failed: BTreeSet<u32> = BTreeSet::new();
    let mut stats = SchedStats { stop_reason: "duration", syscalls_traced: settings.syscalls, ..SchedStats::default() };
    let started = Instant::now();
    let mut last_check: Option<Instant> = None;
    let mut first_error = None;
    let end_ns = loop {
        if last_check.is_none_or(|at| at.elapsed() >= Duration::from_millis(25)) {
            refresh_session_identity(session);
            if !session.process.pid_alive_after || !Path::new(&format!("/proc/{pid}")).exists() {
                stats.stop_reason = "process_exited";
                break monotonic_ns();
            }
            if session.process.process_changed {
                stats.stop_reason = "process_changed";
                break monotonic_ns();
            }
            // Only a successful enumeration retires threads; their rings are drained first.
            if let Ok(live) = read_tid_set(&task_dir) {
                drain(&mut threads, pid, &mut applier, sink, &mut stats)?;
                threads.retain(|thread| live.contains(&thread.tid));
                for tid in live {
                    if threads.iter().any(|thread| thread.tid == tid) || failed.contains(&tid) {
                        continue;
                    }
                    // The attachment boundary is taken before the rings are enabled, with the
                    // thread's state then: a sleeping thread is off CPU from here.
                    let sleeping = thread_sleeping(pid, tid);
                    let attached_ns = monotonic_ns();
                    match open_thread(tid, ids, settings.stack_bytes) {
                        Ok(events) => {
                            applier.push(Timed { ts: attached_ns, tid, order: 0, event: Event::Attached { sleeping } });
                            threads.push(events);
                        }
                        Err(error) => {
                            first_error.get_or_insert(error);
                            failed.insert(tid);
                        }
                    }
                }
                if threads.is_empty() {
                    // Every thread failed to attach (a thread that exited first is retried away).
                    return Err(first_error.unwrap_or_else(|| "no thread of the process could be attached".to_owned()));
                }
            }
            stats.threads = stats.threads.max(threads.len());
            last_check = Some(Instant::now());
        }
        let read = drain(&mut threads, pid, &mut applier, sink, &mut stats)?;
        applier.settle(false);
        applier.flush(sink)?;
        if settings.cancel.is_some_and(|flag| flag.load(Ordering::Relaxed)) {
            stats.stop_reason = "cancelled";
            break monotonic_ns();
        }
        if started.elapsed() >= settings.duration {
            break monotonic_ns();
        }
        if read == 0 {
            std::thread::sleep(Duration::from_millis(2));
        }
    };
    let elapsed = started.elapsed();
    // The rings stop first; what they hold is drained, and nothing after the end is applied.
    for thread in &mut threads {
        for (_, sampler, _) in &mut thread.rings {
            let _ = sampler.disable();
        }
    }
    drain(&mut threads, pid, &mut applier, sink, &mut stats)?;
    drop(threads);
    applier.settle_until(end_ns);
    applier.close(end_ns, |tid| thread_sleeping(pid, tid));
    applier.flush(sink)?;
    for (tid, thread) in &mut applier.threads {
        thread.comm = std::fs::read_to_string(format!("/proc/{pid}/task/{tid}/comm"))
            .map(|name| name.trim().to_owned())
            .unwrap_or_default();
    }
    stats.unattached_threads = failed.len();
    // Every thread seen during the capture, not only those attached at one time.
    stats.threads = stats.threads.max(applier.threads.len());
    stats.waits_started_before_attach = applier.waits_started_before_attach;
    stats.elapsed_ms = u64::try_from(elapsed.as_millis()).unwrap_or(u64::MAX);
    Ok(Capture { stats, threads: applier.threads, syscalls: applier.syscalls })
}

/// Reads every ring once; returns the records read.
fn drain(
    threads: &mut [ThreadEvents],
    pid: u32,
    applier: &mut Applier,
    sink: &mut Sink<'_>,
    stats: &mut SchedStats,
) -> Result<usize, String> {
    let mut read = 0;
    for thread in threads.iter_mut() {
        let tid = thread.tid;
        for (ring, sampler, last) in &mut thread.rings {
            while let Some(record) = sampler.next_record() {
                read += 1;
                let bytes = record.to_contiguous();
                match (record.ty(), *ring) {
                    (PERF_RECORD_SAMPLE, Ring::Switch) => {
                        match perf_decode::decode_sample(&bytes, SWITCH_SAMPLE, REGISTER_MASK) {
                            Ok(mut sample) if sample.pid == pid => {
                                // The sample is taken in the kernel's scheduler; the stack of interest is
                                // the user one the thread entered the kernel with (its user IP and
                                // registers), so it is unwound as a user-mode sample from there.
                                match user_ip(&sample) {
                                    Some(ip) => {
                                        sample.ip = ip;
                                        sample.cpu_mode = CPU_MODE_USER;
                                    }
                                    None => sample.cpu_mode = record.misc() & 7,
                                }
                                let (ts, tid) = (sample.timestamp_ns, sample.tid);
                                *last = (*last).max(ts);
                                applier.push(Timed { ts, tid, order: 1, event: Event::Stack(Box::new(sample)) });
                            }
                            Ok(_) => {}
                            Err(_) => stats.undecoded += 1,
                        }
                    }
                    (PERF_RECORD_SWITCH, Ring::Switch) => {
                        // The sample_id trailer: pid, tid, time.
                        let Some((tid, ts)) = tid_time(&bytes) else {
                            stats.undecoded += 1;
                            continue;
                        };
                        let misc = record.misc();
                        let event = if misc & MISC_SWITCH_OUT == 0 {
                            Event::SwitchIn
                        } else {
                            Event::SwitchOut { preempted: misc & MISC_SWITCH_OUT_PREEMPT != 0 }
                        };
                        *last = (*last).max(ts);
                        applier.push(Timed { ts, tid, order: 2, event });
                    }
                    (PERF_RECORD_SAMPLE, Ring::Enter | Ring::Exit) => {
                        match perf_decode::decode_sample_raw(&bytes, SYSCALL_SAMPLE, 0) {
                            Ok((sample, raw)) if sample.pid == pid => {
                                let Some(number) = word(&raw, 8) else {
                                    stats.undecoded += 1;
                                    continue;
                                };
                                let event =
                                    if *ring == Ring::Enter { Event::Enter { number } } else { Event::Exit { number } };
                                *last = (*last).max(sample.timestamp_ns);
                                applier.push(Timed { ts: sample.timestamp_ns, tid: sample.tid, order: 3, event });
                            }
                            Ok(_) => {}
                            Err(_) => stats.undecoded += 1,
                        }
                    }
                    (PERF_RECORD_MMAP2, Ring::Switch) => match perf_decode::decode_mmap2(&bytes, record.misc(), true) {
                        Ok(mapping) if mapping.pid == pid => sink(Record::Mapping(mapping))?,
                        Ok(_) => {}
                        // A mapping that cannot be read leaves later stacks unresolved: counted.
                        Err(_) => stats.undecoded += 1,
                    },
                    (PERF_RECORD_EXIT, Ring::Switch) => {
                        // pid, ppid, tid, ptid, time.
                        if let (Some(exited), Some(ts)) =
                            (bytes.get(8..12).and_then(|b| b.try_into().ok()).map(u32::from_le_bytes), word(&bytes, 16))
                        {
                            applier.push(Timed { ts, tid: exited, order: 4, event: Event::ThreadExit });
                        }
                    }
                    (PERF_RECORD_LOST, _) => {
                        let lost = word(&bytes, 8).unwrap_or(1);
                        stats.lost += lost;
                        sink(Record::Lost { timestamp_ns: 0, tid, count: lost })?;
                        // The lost records are of this thread and came after the newest record read from
                        // this ring (a ring is in time order): the gap starts there, so no pair is
                        // formed across the lost span.
                        applier.push(Timed { ts: *last, tid, order: 5, event: Event::Gap });
                    }
                    (PERF_RECORD_THROTTLE, _) => {
                        // The kernel stops a period-1 event that fires too often: records are
                        // missing until it unthrottles, so the stream breaks here as for a loss.
                        stats.throttled += 1;
                        sink(Record::Lost { timestamp_ns: 0, tid, count: 1 })?;
                        applier.push(Timed { ts: *last, tid, order: 5, event: Event::Gap });
                    }
                    _ => {}
                }
            }
        }
    }
    Ok(read)
}

#[cfg(test)]
mod tests {
    use super::{Applier, Event, Timed};

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

    fn at(ts: u64, order: u8, event: Event) -> Timed {
        Timed { ts, tid: 7, order, event }
    }

    #[test]
    fn off_cpu_intervals_weigh_the_stack_and_count_wakeups_and_preemptions() {
        let mut a = Applier::new();
        let events = vec![
            at(100, 1, Event::Stack(sample(100))),
            at(100, 2, Event::SwitchOut { preempted: false }),
            at(600, 2, Event::SwitchIn),
            at(700, 1, Event::Stack(sample(700))),
            at(700, 2, Event::SwitchOut { preempted: true }),
            at(750, 2, Event::SwitchIn),
            at(800, 3, Event::Enter { number: 7 }),
            at(900, 3, Event::Exit { number: 7 }),
            at(950, 3, Event::Exit { number: 0 }),
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
        assert_eq!(a.completed.iter().map(|s| s.period).collect::<Vec<_>>(), vec![500, 50]);
        assert_eq!((a.syscalls[&7].entered, a.syscalls[&7].latency.max), (1, 100));
    }

    #[test]
    fn open_waits_end_at_the_capture_end_or_the_thread_exit_and_gaps_break_pairs() {
        let mut a = Applier::new();
        a.push(at(10, 1, Event::Stack(sample(10))));
        a.push(at(10, 2, Event::SwitchOut { preempted: false }));
        a.settle(true);
        a.close(1010, |_| true);
        assert_eq!(a.threads[&7].off_cpu_ns, 1000);
        assert_eq!(a.completed[0].period, 1000);
        // A thread that exits while switched out stops waiting at its exit.
        let mut b = Applier::new();
        for timed in [at(10, 2, Event::SwitchOut { preempted: false }), at(60, 4, Event::ThreadExit)] {
            b.push(timed);
        }
        b.settle(true);
        b.close(5000, |_| true);
        assert_eq!(b.threads[&7].off_cpu_ns, 50);
        // A gap between an entry and an exit of the same call: no latency.
        let mut c = Applier::new();
        for timed in
            [at(10, 3, Event::Enter { number: 1 }), at(20, 0, Event::Gap), at(30, 3, Event::Exit { number: 1 })]
        {
            c.push(timed);
        }
        c.settle(true);
        assert_eq!((c.syscalls[&1].entered, c.syscalls[&1].latency.count), (1, 0));
        // The gap sits right after the newest record read before the loss: call A's exit and call
        // B's entry were lost, and B's exit does not pair with A's entry.
        let mut d = Applier::new();
        for timed in
            [at(10, 3, Event::Enter { number: 1 }), at(10, 5, Event::Gap), at(90, 3, Event::Exit { number: 1 })]
        {
            d.push(timed);
        }
        d.settle(true);
        assert_eq!(d.syscalls[&1].latency.count, 0);
    }

    #[test]
    fn a_thread_sleeping_when_attached_counts_its_observed_wait() {
        let mut a = Applier::new();
        for timed in [at(100, 0, Event::Attached { sleeping: true }), at(400, 2, Event::SwitchIn)] {
            a.push(timed);
        }
        a.settle(true);
        assert_eq!((a.threads[&7].off_cpu_ns, a.waits_started_before_attach, a.threads[&7].wakeups), (300, 1, 1));
        // Asleep for the whole capture: the wait counts to the end.
        let mut b = Applier::new();
        b.push(at(100, 0, Event::Attached { sleeping: true }));
        b.settle(true);
        b.close(1100, |_| true);
        assert_eq!((b.threads[&7].off_cpu_ns, b.waits_started_before_attach), (1000, 1));
        // Woken unseen before the sampler was enabled and running at the end: not charged.
        let mut w = Applier::new();
        w.push(at(100, 0, Event::Attached { sleeping: true }));
        w.settle(true);
        w.close(1100, |_| false);
        assert_eq!((w.threads.get(&7).map_or(0, |t| t.off_cpu_ns), w.waits_started_before_attach), (0, 1));
        // Running when attached: no wait until it switches out.
        let mut c = Applier::new();
        c.push(at(100, 0, Event::Attached { sleeping: false }));
        c.settle(true);
        c.close(1100, |_| true);
        assert_eq!(c.threads[&7].off_cpu_ns, 0);
    }

    #[test]
    fn records_after_the_capture_end_are_not_applied() {
        let mut a = Applier::new();
        for timed in [at(10, 2, Event::SwitchOut { preempted: false }), at(500, 2, Event::SwitchIn)] {
            a.push(timed);
        }
        a.settle_until(100);
        a.close(100, |_| true);
        assert_eq!((a.threads[&7].off_cpu_ns, a.threads[&7].wakeups), (90, 0));
    }
}
