/*
 * XRef — live heap attribution: memory syscall tracepoints of every thread, applied to the ledger
 * Copyright (c) 2026 Alexander Panasenko
 * Contact: alex@prod.codes
 * Author: https://prod.codes/about/
 * Project: https://github.com/alex09x/xref
 * SPDX-License-Identifier: MIT OR Apache-2.0
 */

//! Each thread gets one perf event per memory syscall tracepoint. Entries that map memory
//! (`mmap`, `mremap`, `brk`, `mprotect`) also copy the user registers and stack, so the call
//! stack is unwound later through `.eh_frame` like a `live profile` sample. Exits carry the
//! address the kernel chose. Records from all rings are applied in timestamp order: after a
//! drain, every record no later than the newest one of the previous drain has been read.

use std::collections::{BTreeMap, BTreeSet, HashMap, VecDeque};
use std::path::Path;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

use perf_event::{Builder, Clock, Sampler, events::Tracepoint};

use super::super::capture::REGISTER_MASK;
use super::super::perf_decode::{
    self, SAMPLE_IP, SAMPLE_PERIOD, SAMPLE_RAW, SAMPLE_REGS_USER, SAMPLE_STACK_USER, SAMPLE_TID, SAMPLE_TIME,
};
use super::super::types::{Mapping, Sample};
use super::ledger::Ledger;
use crate::live::probe::tracefs::read_tid_set;
use crate::live::procfs::{LiveSession, refresh_session_identity};

/// Ring per event: entries copy the user stack (kilobytes each), exits carry 8 bytes.
const STACK_RING_BYTES: usize = 1024 * 1024;
const RING_BYTES: usize = 64 * 1024;
const PAGE: u64 = 4096;
const MAP_ANONYMOUS: u64 = 0x20;

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
enum Kind {
    EnterMmap,
    EnterMremap,
    EnterBrk,
    EnterMprotect,
    EnterMunmap,
    ExitMmap,
    ExitMremap,
    ExitBrk,
}

impl Kind {
    const ALL: [Self; 8] = [
        Self::EnterMmap,
        Self::EnterMremap,
        Self::EnterBrk,
        Self::EnterMprotect,
        Self::EnterMunmap,
        Self::ExitMmap,
        Self::ExitMremap,
        Self::ExitBrk,
    ];

    const fn tracepoint(self) -> &'static str {
        match self {
            Self::EnterMmap => "sys_enter_mmap",
            Self::EnterMremap => "sys_enter_mremap",
            Self::EnterBrk => "sys_enter_brk",
            Self::EnterMprotect => "sys_enter_mprotect",
            Self::EnterMunmap => "sys_enter_munmap",
            Self::ExitMmap => "sys_exit_mmap",
            Self::ExitMremap => "sys_exit_mremap",
            Self::ExitBrk => "sys_exit_brk",
        }
    }

    /// Entries that map memory carry the stack that asked for it.
    const fn has_stack(self) -> bool {
        matches!(self, Self::EnterMmap | Self::EnterMremap | Self::EnterBrk | Self::EnterMprotect)
    }

    const fn sample_type(self) -> u64 {
        let base = SAMPLE_IP | SAMPLE_TID | SAMPLE_TIME | SAMPLE_PERIOD | SAMPLE_RAW;
        if self.has_stack() { base | SAMPLE_REGS_USER | SAMPLE_STACK_USER } else { base }
    }
}

/// The tracepoint ID of `syscalls/<name>`.
fn tracepoint_id(name: &str) -> Result<u64, String> {
    for root in ["/sys/kernel/tracing", "/sys/kernel/debug/tracing"] {
        if let Ok(text) = std::fs::read_to_string(format!("{root}/events/syscalls/{name}/id")) {
            return text.trim().parse().map_err(|_| format!("invalid tracepoint id for {name}"));
        }
    }
    Err(format!(
        "permission_denied: cannot read the syscalls/{name} tracepoint id (live heap needs root or CAP_PERFMON with tracefs access)"
    ))
}

struct ThreadEvents {
    tid: u32,
    events: Vec<(Kind, Sampler)>,
}

fn open_thread(tid: u32, ids: &BTreeMap<Kind, u64>, stack_bytes: u32) -> Result<ThreadEvents, String> {
    let pid = i32::try_from(tid).map_err(|_| "TID exceeds pid_t")?;
    let mut events = Vec::new();
    for kind in Kind::ALL {
        let mut builder = Builder::new(Tracepoint::with_id(ids[&kind]));
        builder
            .observe_pid(pid)
            .any_cpu()
            .inherit(false)
            .sample_period(1)
            .clockid(Clock::MONOTONIC)
            .sample_id_all(true);
        if kind == Kind::EnterMmap {
            // One event per thread reports new file mappings, forks and exits.
            builder.mmap(true).mmap2(true).task(true);
        }
        let attributes = builder.attrs_mut();
        attributes.sample_type = kind.sample_type();
        if kind.has_stack() {
            attributes.sample_regs_user = REGISTER_MASK;
            attributes.sample_stack_user = stack_bytes;
        }
        let counter = builder.build().map_err(|error| format!("perf_event_open {}: {error}", kind.tracepoint()))?;
        let ring = if kind.has_stack() { STACK_RING_BYTES } else { RING_BYTES };
        let mut sampler = counter.sampled(ring).map_err(|error| format!("perf mmap: {error}"))?;
        sampler.enable().map_err(|error| format!("perf enable: {error}"))?;
        events.push((kind, sampler));
    }
    Ok(ThreadEvents { tid, events })
}

/// One decoded tracepoint record.
struct Event {
    ts: u64,
    tid: u32,
    kind: Kind,
    args: [u64; 5],
    sample: Option<Arc<Sample>>,
}

fn decode(kind: Kind, bytes: &[u8]) -> Option<Event> {
    let mask = if kind.has_stack() { REGISTER_MASK } else { 0 };
    let (sample, raw) = perf_decode::decode_sample_raw(bytes, kind.sample_type(), mask).ok()?;
    let word = |offset: usize| raw.get(offset..offset + 8).and_then(|b| b.try_into().ok()).map(u64::from_le_bytes);
    let mut args = [0; 5];
    for (i, arg) in args.iter_mut().enumerate() {
        *arg = word(16 + 8 * i).unwrap_or(0);
    }
    let (ts, tid) = (sample.timestamp_ns, sample.tid);
    Some(Event { ts, tid, kind, args, sample: kind.has_stack().then(|| Arc::new(sample)) })
}

/// What a capture saw.
#[derive(Debug, Default, serde::Serialize)]
pub struct HeapStats {
    pub events: u64,
    pub lost: u64,
    pub undecoded: u64,
    pub threads: usize,
    pub unattached_threads: usize,
    pub elapsed_ms: u64,
    pub stop_reason: &'static str,
}

/// Applies records in timestamp order, pairing each syscall exit with its thread's entry.
struct Applier {
    ledger: Ledger,
    waiting: Vec<Event>,
    entries: HashMap<(u32, Kind), VecDeque<Event>>,
    newest_previous: u64,
    newest: u64,
}

impl Applier {
    fn push(&mut self, event: Event) {
        self.newest = self.newest.max(event.ts);
        self.waiting.push(event);
    }

    /// Applies what is safe after a drain (`all` at the end of the capture).
    fn settle(&mut self, all: bool) {
        let limit = if all { u64::MAX } else { self.newest_previous };
        self.newest_previous = self.newest;
        self.waiting.sort_by_key(|e| (e.ts, e.kind));
        let split = self.waiting.partition_point(|e| e.ts <= limit);
        let ready: Vec<Event> = self.waiting.drain(..split).collect();
        for event in ready {
            self.apply(event);
        }
    }

    fn apply(&mut self, event: Event) {
        // munmap and mprotect are applied at entry: a range the kernel would reject (unaligned,
        // empty, beyond the 57-bit address space) is skipped rather than recorded.
        let span = |addr: u64, len: u64| {
            let paged = len.div_ceil(PAGE).checked_mul(PAGE)?;
            (addr.is_multiple_of(PAGE) && len > 0 && addr.checked_add(paged)? <= 1 << 57).then_some(paged)
        };
        let page = |len: u64| len.div_ceil(PAGE).saturating_mul(PAGE);
        // -4095..=-1 as an unsigned return value is an errno.
        let failed = |ret: u64| ret > u64::MAX - 4095;
        let [a0, a1, a2, ..] = event.args;
        match event.kind {
            Kind::EnterMmap | Kind::EnterMremap | Kind::EnterBrk => {
                let exit = match event.kind {
                    Kind::EnterMmap => Kind::ExitMmap,
                    Kind::EnterMremap => Kind::ExitMremap,
                    _ => Kind::ExitBrk,
                };
                self.entries.entry((event.tid, exit)).or_default().push_back(event);
            }
            Kind::EnterMunmap => {
                if let Some(len) = span(a0, a1) {
                    self.ledger.munmap(a0, len);
                }
            }
            Kind::EnterMprotect => {
                if let (Some(sample), Some(len)) = (&event.sample, span(a0, a1)) {
                    self.ledger.mprotect(a0, len, a2, sample);
                }
            }
            exit => {
                // The entry is the latest one of this thread before the exit; older ones lost their
                // exit records and are dropped, so a loss never shifts later pairs.
                let Some(queue) = self.entries.get_mut(&(event.tid, exit)) else { return };
                let before = queue.partition_point(|entry| entry.ts <= event.ts);
                let mut older: VecDeque<Event> = queue.drain(..before).collect();
                let Some(entry) = older.pop_back() else { return };
                let (Some(sample), ret) = (entry.sample.as_ref(), a0) else { return };
                if failed(ret) {
                    return;
                }
                let [e0, e1, e2, e3, _] = entry.args;
                match exit {
                    Kind::ExitMmap => self.ledger.mmap(ret, page(e1), e2, e3 & MAP_ANONYMOUS != 0, sample),
                    Kind::ExitMremap => self.ledger.mremap(e0, page(e1), ret, page(e2), sample),
                    _ => self.ledger.brk(ret, sample),
                }
            }
        }
    }
}

/// Capture settings.
pub struct HeapCapture<'a> {
    pub duration: Duration,
    pub interval: Option<Duration>,
    pub sample_bytes: u64,
    pub stack_bytes: u32,
    pub cancel: Option<&'a AtomicBool>,
}

/// Observes the process and calls `snapshot` with the ledger and every mapping seen so far, every
/// `interval` and at the end.
pub fn observe(
    session: &mut LiveSession,
    settings: &HeapCapture<'_>,
    mut mappings: Vec<Mapping>,
    mut snapshot: impl FnMut(&Ledger, &[Mapping]) -> Result<(), String>,
) -> Result<HeapStats, String> {
    let ids: BTreeMap<Kind, u64> = Kind::ALL
        .iter()
        .map(|kind| tracepoint_id(kind.tracepoint()).map(|id| (*kind, id)))
        .collect::<Result<_, _>>()?;
    let pid = session.process.pid;
    // `[heap]` can be split into several VMAs; the break is the end of the highest one.
    let brk = session.regions.iter().filter(|r| r.pathname.as_deref() == Some("[heap]")).map(|r| r.end.0).max();
    let mut applier = Applier {
        ledger: Ledger::new(settings.sample_bytes, brk),
        waiting: Vec::new(),
        entries: HashMap::new(),
        newest_previous: 0,
        newest: 0,
    };
    let task_dir = Path::new("/proc").join(pid.to_string()).join("task");
    let mut threads: Vec<ThreadEvents> = Vec::new();
    let mut failed: BTreeSet<u32> = BTreeSet::new();
    let mut stats = HeapStats { stop_reason: "duration", ..HeapStats::default() };
    let started = Instant::now();
    let (mut last_check, mut last_snapshot): (Option<Instant>, Instant) = (None, Instant::now());
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
            threads.retain(|t| live.contains(&t.tid));
            for tid in live {
                if threads.iter().any(|t| t.tid == tid) || failed.contains(&tid) {
                    continue;
                }
                match open_thread(tid, &ids, settings.stack_bytes) {
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
        if settings.interval.is_some_and(|every| last_snapshot.elapsed() >= every) {
            snapshot(&applier.ledger, &mappings)?;
            last_snapshot = Instant::now();
        }
        if settings.cancel.is_some_and(|flag| flag.load(Ordering::Relaxed)) {
            stats.stop_reason = "cancelled";
            break;
        }
        if started.elapsed() >= settings.duration {
            break;
        }
        if read == 0 {
            std::thread::sleep(Duration::from_millis(2));
        }
    }
    drain(&mut threads, pid, &mut applier, &mut mappings, &mut stats);
    drop(threads);
    applier.settle(true);
    snapshot(&applier.ledger, &mappings)?;
    stats.unattached_threads = failed.len();
    stats.elapsed_ms = u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX);
    Ok(stats)
}

/// Reads every ring once; returns the records read.
fn drain(
    threads: &mut [ThreadEvents],
    pid: u32,
    applier: &mut Applier,
    mappings: &mut Vec<Mapping>,
    stats: &mut HeapStats,
) -> usize {
    let mut read = 0;
    for thread in threads.iter_mut() {
        for (kind, sampler) in &mut thread.events {
            while let Some(record) = sampler.next_record() {
                read += 1;
                let bytes = record.to_contiguous();
                match record.ty() {
                    9 => match decode(*kind, &bytes) {
                        Some(event) => {
                            stats.events += 1;
                            applier.push(event);
                        }
                        None => stats.undecoded += 1,
                    },
                    10 => {
                        if let Ok(mapping) = perf_decode::decode_mmap2(&bytes, record.misc(), true)
                            && mapping.pid == pid
                        {
                            mappings.push(mapping);
                        }
                    }
                    2 => stats.lost += bytes.get(8..16).and_then(|b| b.try_into().ok()).map_or(1, u64::from_le_bytes),
                    _ => {}
                }
            }
        }
    }
    read
}
