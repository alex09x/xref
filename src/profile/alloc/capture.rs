/*
 * XRef — `live alloc` capture: uprobes on the allocator, call stacks unwound as they arrive
 * Copyright (c) 2026 Alexander Panasenko
 * Contact: alex@prod.codes
 * Author: https://prod.codes/about/
 * Project: https://github.com/alex09x/xref
 * SPDX-License-Identifier: MIT OR Apache-2.0
 */

//! Every thread gets uprobes on the allocator's `malloc`, `calloc`, `realloc` and `free` entries
//! and uretprobes on the first three. An entry copies the user registers and stack, which are
//! unwound through `.eh_frame` at once into the call chain; chains are counted, not kept, so a
//! long capture of a busy allocator stays small. A return gives the block's address. Records from
//! all rings are applied in timestamp order. A call made by another allocator call (glibc's
//! `realloc` calling `malloc`) is not counted twice: only the outermost call of a thread counts.

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::ffi::CString;
use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

use perf_event::{Builder, Clock, Sampler, events::Software};
use serde::Serialize;

use super::super::capture::REGISTER_MASK;
use super::super::perf_decode::{self, SAMPLE_IP, SAMPLE_REGS_USER, SAMPLE_STACK_USER, SAMPLE_TID, SAMPLE_TIME};
use super::super::resolve::MappingIndex;
use super::super::types::{Header, Mapping, Sample};
use super::symbols::Allocator;
use crate::live::probe::tracefs::read_tid_set;
use crate::live::procfs::{LiveSession, refresh_session_identity};

const ENTRY_RING_BYTES: usize = 1024 * 1024;
const RETURN_RING_BYTES: usize = 128 * 1024;
const ENTRY_SAMPLE: u64 = SAMPLE_IP | SAMPLE_TID | SAMPLE_TIME | SAMPLE_REGS_USER | SAMPLE_STACK_USER;
const RETURN_SAMPLE: u64 = SAMPLE_TID | SAMPLE_TIME | SAMPLE_REGS_USER;
/// `rax` only, the return value.
const RETURN_REGISTERS: u64 = 1;
/// Positions of `rsi`, `rdi` in the sampled registers of `REGISTER_MASK` (AX, BX, CX, DX, SI, DI, ...).
const SI: usize = 4;
const DI: usize = 5;
const UNWIND_FRAMES: usize = 128;

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
enum Call {
    Malloc,
    Calloc,
    Realloc,
    Free,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Probe {
    call: Call,
    exit: bool,
}

struct ThreadProbes {
    tid: u32,
    /// Each probe's ring with the time of the newest record read from it.
    rings: Vec<(Probe, Sampler, u64, bool)>,
}

/// The retprobe bit of the uprobe PMU's `config` (`/sys/bus/event_source/devices/uprobe/format/retprobe`).
fn retprobe_bit() -> u64 {
    std::fs::read_to_string("/sys/bus/event_source/devices/uprobe/format/retprobe")
        .ok()
        .and_then(|text| text.trim().strip_prefix("config:").and_then(|bit| bit.parse::<u32>().ok()))
        .map_or(1, |bit| 1 << bit)
}

fn probes(allocator: &Allocator) -> Vec<(Probe, u64)> {
    let mut out = vec![
        (Probe { call: Call::Malloc, exit: false }, allocator.malloc),
        (Probe { call: Call::Malloc, exit: true }, allocator.malloc),
        (Probe { call: Call::Free, exit: false }, allocator.free),
    ];
    for (call, offset) in [(Call::Calloc, allocator.calloc), (Call::Realloc, allocator.realloc)] {
        if let Some(offset) = offset {
            out.push((Probe { call, exit: false }, offset));
            out.push((Probe { call, exit: true }, offset));
        }
    }
    out
}

fn open_thread(
    tid: u32,
    pmu_type: u32,
    retprobe: u64,
    path: &CString,
    probes: &[(Probe, u64)],
    stack_bytes: u32,
) -> Result<ThreadProbes, String> {
    let pid = i32::try_from(tid).map_err(|_| "TID exceeds pid_t")?;
    let mut rings = Vec::new();
    for &(probe, offset) in probes {
        let mut builder = Builder::new(Software::DUMMY);
        builder.observe_pid(pid).any_cpu().inherit(false).sample_period(1).clockid(Clock::MONOTONIC);
        let entry_with_stack = !probe.exit && probe.call != Call::Free;
        {
            let attrs = builder.attrs_mut();
            attrs.type_ = pmu_type;
            attrs.config = if probe.exit { retprobe } else { 0 };
            attrs.kprobe_func = path.as_ptr() as usize as u64;
            attrs.probe_offset = offset;
            if probe.exit {
                attrs.sample_type = RETURN_SAMPLE;
                attrs.sample_regs_user = RETURN_REGISTERS;
            } else {
                attrs.sample_type = if entry_with_stack { ENTRY_SAMPLE } else { RETURN_SAMPLE | SAMPLE_IP };
                attrs.sample_regs_user = REGISTER_MASK;
                attrs.sample_stack_user = if entry_with_stack { stack_bytes } else { 0 };
            }
        }
        let counter = builder.build().map_err(|error| format!("uprobe on {probe:?} at {offset:#x}: {error}"))?;
        let ring = if entry_with_stack { ENTRY_RING_BYTES } else { RETURN_RING_BYTES };
        let sampler = counter.sampled(ring).map_err(|error| format!("perf mmap: {error}"))?;
        rings.push((probe, sampler, 0, false));
    }
    // Returns are armed before entries: an entry seen without its return probe would make every
    // later call of the thread look nested inside it.
    for exits_first in [true, false] {
        for (probe, sampler, _, _) in &mut rings {
            if probe.exit == exits_first {
                sampler.enable().map_err(|error| format!("perf enable: {error}"))?;
            }
        }
    }
    Ok(ThreadProbes { tid, rings })
}

/// One decoded probe hit.
struct Hit {
    ts: u64,
    tid: u32,
    probe: Probe,
    /// Entry: the first two arguments; return: the return value.
    a0: u64,
    a1: u64,
    /// The unwound call chain of an entry with a stack.
    chain: Option<Vec<u64>>,
    /// Records of the thread were lost here: calls open across it are dropped.
    gap: bool,
    /// At a realloc entry, the identity of the block it was given (filled when applied).
    block: Option<u64>,
}

/// Allocations of one call chain.
#[derive(Clone, Debug, Default, Serialize)]
pub struct Chain {
    /// Innermost first: the allocator's address, then return addresses.
    pub ips: Vec<u64>,
    pub allocations: u64,
    pub bytes: u64,
    pub live_blocks: u64,
    pub live_bytes: u64,
}

/// What a capture saw.
#[derive(Debug, Default, Serialize)]
pub struct AllocStats {
    pub elapsed_ms: u64,
    pub threads: usize,
    pub unattached_threads: usize,
    pub allocations: u64,
    pub allocated_bytes: u64,
    pub frees: u64,
    /// Frees of blocks allocated before the capture started (their size is unknown).
    pub frees_of_earlier_blocks: u64,
    pub reallocations: u64,
    pub live_blocks: u64,
    pub live_bytes: u64,
    pub lost: u64,
    pub undecoded: u64,
    pub stop_reason: &'static str,
}

pub struct Capture {
    pub stats: AllocStats,
    pub chains: Vec<Chain>,
}

#[derive(Default)]
struct Ledger {
    chain_ids: HashMap<Vec<u64>, usize>,
    chains: Vec<Chain>,
    /// Live blocks: address -> (size, chain, identity).
    live: HashMap<u64, (u64, usize, u64)>,
    next_block: u64,
    /// Per thread, the allocator calls entered and not yet returned (outermost first).
    open: HashMap<u32, Vec<Hit>>,
    stats: AllocStats,
}

impl Ledger {
    fn chain(&mut self, ips: Vec<u64>) -> usize {
        if let Some(id) = self.chain_ids.get(&ips) {
            return *id;
        }
        let id = self.chains.len();
        self.chains.push(Chain { ips: ips.clone(), ..Chain::default() });
        self.chain_ids.insert(ips, id);
        id
    }

    fn allocate(&mut self, address: u64, size: u64, chain: Option<Vec<u64>>) {
        let id = self.chain(chain.unwrap_or_default());
        let entry = &mut self.chains[id];
        entry.allocations += 1;
        entry.bytes = entry.bytes.saturating_add(size);
        self.stats.allocations += 1;
        self.stats.allocated_bytes = self.stats.allocated_bytes.saturating_add(size);
        self.next_block += 1;
        if let Some((old_size, old_chain, _)) = self.live.insert(address, (size, id, self.next_block)) {
            // A block reported again without a free in between: a free record was lost.
            let old = &mut self.chains[old_chain];
            old.live_blocks = old.live_blocks.saturating_sub(1);
            old.live_bytes = old.live_bytes.saturating_sub(old_size);
        }
        let entry = &mut self.chains[id];
        entry.live_blocks += 1;
        entry.live_bytes = entry.live_bytes.saturating_add(size);
    }

    /// Drops a block from the live set; a `free` call (not a realloc move) is also counted.
    fn release(&mut self, address: u64, free_call: bool) {
        if address == 0 {
            return;
        }
        let known = self.live.remove(&address);
        if let Some((size, id, _)) = known {
            let chain = &mut self.chains[id];
            chain.live_blocks = chain.live_blocks.saturating_sub(1);
            chain.live_bytes = chain.live_bytes.saturating_sub(size);
        }
        if free_call {
            self.stats.frees += 1;
            if known.is_none() {
                self.stats.frees_of_earlier_blocks += 1;
            }
        }
    }

    fn apply(&mut self, mut hit: Hit) {
        if hit.gap {
            // Calls open across lost records cannot be paired: they are dropped, and the totals
            // are marked incomplete by the loss count.
            self.open.remove(&hit.tid);
            return;
        }
        if !hit.probe.exit && hit.probe.call == Call::Realloc {
            hit.block = self.live.get(&hit.a0).map(|(_, _, block)| *block);
        }
        let open = self.open.entry(hit.tid).or_default();
        if !hit.probe.exit {
            if hit.probe.call == Call::Free {
                // A free made by realloc is part of the realloc.
                if open.is_empty() {
                    self.release(hit.a0, true);
                }
                return;
            }
            open.push(hit);
            return;
        }
        // The matching entry is the innermost open call of the same function; entries above it
        // lost their returns and are dropped.
        let Some(position) = open.iter().rposition(|entry| entry.probe.call == hit.probe.call) else { return };
        let entry = open.remove(position);
        open.truncate(position);
        if !open.is_empty() {
            return;
        }
        let returned = hit.a0;
        match entry.probe.call {
            Call::Malloc => {
                if returned != 0 {
                    self.allocate(returned, entry.a0, entry.chain);
                }
            }
            Call::Calloc => {
                if returned != 0 {
                    self.allocate(returned, entry.a0.saturating_mul(entry.a1), entry.chain);
                }
            }
            Call::Realloc => {
                self.stats.reallocations += 1;
                let (old, size) = (entry.a0, entry.a1);
                // realloc(p, 0) may free p and return NULL; a failed realloc keeps p. The old block is
                // dropped only if the address still holds the block realloc was given: a moving
                // realloc frees it inside, and another thread may have been handed the address
                // before this return was seen.
                let same_block = self.live.get(&old).map(|(_, _, block)| *block) == entry.block;
                if old != 0 && (returned != 0 || size == 0) && same_block {
                    self.release(old, false);
                }
                if returned != 0 {
                    self.allocate(returned, size, entry.chain);
                }
            }
            Call::Free => {}
        }
    }
}

struct Applier {
    waiting: Vec<Hit>,
    newest_previous: u64,
    newest: u64,
    ledger: Ledger,
}

impl Applier {
    fn push(&mut self, hit: Hit) {
        self.newest = self.newest.max(hit.ts);
        self.waiting.push(hit);
    }

    fn settle(&mut self, all: bool) {
        let limit = if all { u64::MAX } else { self.newest_previous };
        self.newest_previous = self.newest;
        // An entry and its return never share a timestamp; at one instant, entries first and a
        // loss gap last.
        self.waiting.sort_by_key(|hit| (hit.ts, hit.tid, hit.gap, hit.probe.exit));
        let split = self.waiting.partition_point(|hit| hit.ts <= limit);
        let ready: Vec<Hit> = self.waiting.drain(..split).collect();
        for hit in ready {
            self.ledger.apply(hit);
        }
    }
}

/// Unwinds an entry sample into its call chain (innermost first) with the session's CFI.
struct Unwind<'a> {
    index: &'a MappingIndex,
    header: &'a Header,
    unwinders: BTreeMap<(u32, i64), super::super::unwind::Unwinder<'a>>,
}

impl Unwind<'_> {
    fn chain(&self, sample: &Sample) -> Vec<u64> {
        super::super::unwind::unwind_with(sample, UNWIND_FRAMES, |ip, return_address| {
            self.index
                .unwinder_key(self.header, sample.pid, sample.timestamp_ns, ip, return_address)
                .and_then(|key| self.unwinders.get(&key))
        })
        .frames
    }
}

/// A decoded hit; `Ok(None)` for a hit of another process (a TID reused before its counter opened).
fn decode(probe: Probe, bytes: &[u8], pid: u32, unwind: &Unwind<'_>) -> Result<Option<Hit>, ()> {
    let entry_with_stack = !probe.exit && probe.call != Call::Free;
    let (sample_type, mask) = if probe.exit {
        (RETURN_SAMPLE, RETURN_REGISTERS)
    } else if entry_with_stack {
        (ENTRY_SAMPLE, REGISTER_MASK)
    } else {
        (RETURN_SAMPLE | SAMPLE_IP, REGISTER_MASK)
    };
    let sample = perf_decode::decode_sample(bytes, sample_type, mask).map_err(|_| ())?;
    if sample.pid != pid {
        return Ok(None);
    }
    let register = |index: usize| sample.registers.get(index).copied();
    let (a0, a1) =
        if probe.exit { (register(0).ok_or(())?, 0) } else { (register(DI).ok_or(())?, register(SI).ok_or(())?) };
    let chain = entry_with_stack.then(|| unwind.chain(&sample));
    Ok(Some(Hit { ts: sample.timestamp_ns, tid: sample.tid, probe, a0, a1, chain, gap: false, block: None }))
}

/// A break in a thread's stream at `ts`: its open calls are dropped there.
const fn gap(ts: u64, tid: u32, probe: Probe) -> Hit {
    Hit { ts, tid, probe, a0: 0, a1: 0, chain: None, gap: true, block: None }
}

/// Reads every ring once; returns the records read.
fn drain(
    threads: &mut [ThreadProbes],
    pid: u32,
    applier: &mut Applier,
    unwind: &Unwind<'_>,
    lost: &mut u64,
    undecoded: &mut u64,
) -> usize {
    let mut read = 0;
    for thread in threads {
        let tid = thread.tid;
        for (probe, sampler, last, broken) in &mut thread.rings {
            while let Some(record) = sampler.next_record() {
                read += 1;
                let bytes = record.to_contiguous();
                match record.ty() {
                    9 => match decode(*probe, &bytes, pid, unwind) {
                        Ok(Some(hit)) => {
                            *last = (*last).max(hit.ts);
                            if std::mem::take(broken) {
                                // The missing hits lie between the previous hit of this ring and
                                // this one: the thread's open calls are dropped just before it, so
                                // an entry whose return was lost is not left open.
                                applier.push(gap(hit.ts.saturating_sub(1), tid, *probe));
                            }
                            applier.push(hit);
                        }
                        Ok(None) => {}
                        Err(()) => {
                            *undecoded += 1;
                            *broken = true;
                        }
                    },
                    2 => {
                        *lost += bytes.get(8..16).and_then(|b| b.try_into().ok()).map_or(1, u64::from_le_bytes);
                        // Applied at the next hit read from this ring (or at the newest one if none
                        // follows before the end).
                        *broken = true;
                        applier.push(gap(*last, tid, *probe));
                    }
                    _ => {}
                }
            }
        }
    }
    read
}

/// The capture settings.
pub struct Settings<'a> {
    pub duration: Duration,
    pub stack_bytes: u32,
    pub cancel: Option<&'a AtomicBool>,
}

/// Observes the process for the duration, or until it exits or the capture is cancelled.
pub fn observe(
    session: &mut LiveSession,
    allocator: &Allocator,
    header: &Header,
    mappings: Vec<Mapping>,
    settings: &Settings<'_>,
) -> Result<Capture, String> {
    // The unwinders borrow the image for the whole capture while the session's identity is
    // refreshed: the image is lent out and always given back.
    let image = std::mem::take(&mut session.image);
    let result = observe_with(session, &image, allocator, header, mappings, settings);
    session.image = image;
    result
}

#[allow(clippy::too_many_lines)] // One loop owns thread attachment, draining and settling.
fn observe_with(
    session: &mut LiveSession,
    image: &crate::image::Image,
    allocator: &Allocator,
    header: &Header,
    mappings: Vec<Mapping>,
    settings: &Settings<'_>,
) -> Result<Capture, String> {
    use crate::live::probe::perf::{UPROBE_PMU_TYPE_PATH, read_uprobe_pmu_type};
    let (duration, stack_bytes, cancel) = (settings.duration, settings.stack_bytes, settings.cancel);
    let pmu_type = read_uprobe_pmu_type(Path::new(UPROBE_PMU_TYPE_PATH))?;
    let retprobe = retprobe_bit();
    let path = CString::new(allocator.probe_path.clone()).map_err(|_| "allocator path holds a NUL byte")?;
    let probes = probes(allocator);
    let index = MappingIndex::new(mappings, header);
    let unwind = Unwind { unwinders: index.unwinders(image, header), index: &index, header };
    let pid = session.process.pid;
    let task_dir = Path::new("/proc").join(pid.to_string()).join("task");
    let mut applier = Applier { waiting: Vec::new(), newest_previous: 0, newest: 0, ledger: Ledger::default() };
    let mut threads: Vec<ThreadProbes> = Vec::new();
    let mut failed: BTreeSet<u32> = BTreeSet::new();
    let mut lost = 0_u64;
    let mut undecoded = 0_u64;
    let mut stop_reason = "duration";
    let mut max_threads = 0;
    let mut first_error = None;
    let started = Instant::now();
    let mut last_check: Option<Instant> = None;
    loop {
        if last_check.is_none_or(|at| at.elapsed() >= Duration::from_millis(25)) {
            refresh_session_identity(session);
            if !session.process.pid_alive_after || !Path::new(&format!("/proc/{pid}")).exists() {
                stop_reason = "process_exited";
                break;
            }
            if session.process.process_changed {
                stop_reason = "process_changed";
                break;
            }
            // Only a successful enumeration retires threads; their rings are drained first.
            if let Ok(live) = read_tid_set(&task_dir) {
                drain(&mut threads, pid, &mut applier, &unwind, &mut lost, &mut undecoded);
                threads.retain(|thread| live.contains(&thread.tid));
                for tid in live {
                    if threads.iter().any(|thread| thread.tid == tid) || failed.contains(&tid) {
                        continue;
                    }
                    match open_thread(tid, pmu_type, retprobe, &path, &probes, stack_bytes) {
                        Ok(probes) => threads.push(probes),
                        Err(error) => {
                            first_error.get_or_insert(error);
                            failed.insert(tid);
                        }
                    }
                }
                if threads.is_empty() {
                    return Err(first_error.unwrap_or_else(|| "no thread of the process could be attached".to_owned()));
                }
            }
            max_threads = max_threads.max(threads.len());
            last_check = Some(Instant::now());
        }
        let read = drain(&mut threads, pid, &mut applier, &unwind, &mut lost, &mut undecoded);
        applier.settle(false);
        if cancel.is_some_and(|flag| flag.load(Ordering::Relaxed)) {
            stop_reason = "cancelled";
            break;
        }
        if started.elapsed() >= duration {
            break;
        }
        if read == 0 {
            std::thread::sleep(Duration::from_millis(2));
        }
    }
    // The probes stop first, so the capture ends at one point for every ring; then what they wrote
    // is drained like any other pass.
    for thread in &mut threads {
        for (_, sampler, _, _) in &mut thread.rings {
            let _ = sampler.disable();
        }
    }
    drain(&mut threads, pid, &mut applier, &unwind, &mut lost, &mut undecoded);
    drop(threads);
    applier.settle(true);
    let mut ledger = applier.ledger;
    ledger.stats.live_blocks = u64::try_from(ledger.live.len()).unwrap_or(u64::MAX);
    ledger.stats.live_bytes = ledger.live.values().map(|(size, _, _)| *size).sum();
    ledger.stats.threads = max_threads;
    ledger.stats.unattached_threads = failed.len();
    ledger.stats.lost = lost;
    ledger.stats.undecoded = undecoded;
    ledger.stats.stop_reason = stop_reason;
    ledger.stats.elapsed_ms = u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX);
    Ok(Capture { stats: ledger.stats, chains: ledger.chains })
}

#[cfg(test)]
mod tests {
    use super::{Call, Hit, Ledger, Probe};

    fn hit(tid: u32, call: Call, exit: bool, a0: u64, a1: u64, chain: u64) -> Hit {
        Hit {
            ts: 0,
            tid,
            probe: Probe { call, exit },
            a0,
            a1,
            chain: (!exit).then(|| vec![chain]),
            gap: false,
            block: None,
        }
    }

    #[test]
    fn a_moving_realloc_does_not_free_a_block_another_thread_got_at_the_old_address() {
        let mut ledger = Ledger::default();
        ledger.apply(hit(1, Call::Malloc, false, 32, 0, 1));
        ledger.apply(hit(1, Call::Malloc, true, 0x1000, 0, 0));
        // Thread 1 reallocs 0x1000; inside, the block is freed and thread 2 is handed 0x1000
        // before thread 1's return is seen.
        ledger.apply(hit(1, Call::Realloc, false, 0x1000, 64, 3));
        ledger.apply(hit(2, Call::Malloc, false, 48, 0, 2));
        ledger.apply(hit(2, Call::Malloc, true, 0x1000, 0, 0));
        ledger.apply(hit(1, Call::Realloc, true, 0x3000, 0, 0));
        assert_eq!(ledger.live.get(&0x1000).map(|(size, _, _)| *size), Some(48), "thread 2's block stays");
        assert_eq!(ledger.live.get(&0x3000).map(|(size, _, _)| *size), Some(64));
    }

    #[test]
    fn a_loss_drops_the_thread_s_open_calls() {
        let mut ledger = Ledger::default();
        ledger.apply(hit(1, Call::Malloc, false, 32, 0, 1));
        let mut gap = hit(1, Call::Malloc, true, 0, 0, 0);
        gap.gap = true;
        ledger.apply(gap);
        // Without the gap, the unmatched entry would make this call look nested and uncounted.
        ledger.apply(hit(1, Call::Malloc, false, 16, 0, 2));
        ledger.apply(hit(1, Call::Malloc, true, 0x2000, 0, 0));
        assert_eq!(ledger.stats.allocations, 1);
    }

    #[test]
    fn calls_pair_by_thread_and_only_the_outermost_call_counts() {
        let mut ledger = Ledger::default();
        // malloc(32) -> 0x1000 from chain 1; calloc(4, 8) -> 0x2000 from chain 2.
        for h in [
            hit(1, Call::Malloc, false, 32, 0, 1),
            hit(1, Call::Malloc, true, 0x1000, 0, 0),
            hit(1, Call::Calloc, false, 4, 8, 2),
            hit(1, Call::Calloc, true, 0x2000, 0, 0),
        ] {
            ledger.apply(h);
        }
        // realloc(0x1000, 64) calls malloc and free inside: one move, counted once.
        for h in [
            hit(1, Call::Realloc, false, 0x1000, 64, 3),
            hit(1, Call::Malloc, false, 64, 0, 9),
            hit(1, Call::Malloc, true, 0x3000, 0, 0),
            hit(1, Call::Free, false, 0x1000, 0, 0),
            hit(1, Call::Realloc, true, 0x3000, 0, 0),
        ] {
            ledger.apply(h);
        }
        // free of the calloc block, and of a block from before the capture.
        ledger.apply(hit(1, Call::Free, false, 0x2000, 0, 0));
        ledger.apply(hit(1, Call::Free, false, 0x9999, 0, 0));
        let stats = &ledger.stats;
        assert_eq!((stats.allocations, stats.allocated_bytes), (3, 32 + 32 + 64));
        assert_eq!((stats.frees, stats.frees_of_earlier_blocks, stats.reallocations), (2, 1, 1));
        assert_eq!(ledger.live.len(), 1, "only the realloc'd block is live");
        assert_eq!(ledger.live.get(&0x3000).map(|(size, _, _)| *size), Some(64));
        let by_chain = |ip| ledger.chains.iter().find(|c| c.ips == vec![ip]).map(|c| (c.allocations, c.live_bytes));
        assert_eq!(by_chain(1), Some((1, 0)), "the malloc block was moved by realloc");
        assert_eq!(by_chain(3), Some((1, 64)));
        assert_eq!(by_chain(9), None, "malloc inside realloc is not counted");
    }

    #[test]
    fn a_thread_s_calls_do_not_pair_with_another_thread_s() {
        let mut ledger = Ledger::default();
        ledger.apply(hit(1, Call::Malloc, false, 16, 0, 1));
        ledger.apply(hit(2, Call::Malloc, true, 0x5000, 0, 0));
        assert_eq!(ledger.stats.allocations, 0);
        ledger.apply(hit(1, Call::Malloc, true, 0x6000, 0, 0));
        assert_eq!(ledger.stats.allocations, 1);
    }
}
