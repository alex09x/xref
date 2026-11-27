/*
 * XRef — bounded Linux profile ring draining
 * Copyright (c) 2026 Alexander Panasenko
 * Contact: alex@prod.codes
 * Author: https://prod.codes/about/
 * Project: https://github.com/alex09x/xref
 * SPDX-License-Identifier: MIT OR Apache-2.0
 */
use super::{
    capture::{ActiveSampler, CaptureStats, layout, open_sampler},
    codec::ProfileWriter,
    config::{Config, MAX_THREADS},
    flight::Flight,
    follow::Targets,
    perf_decode,
    trigger::TriggerSetup,
    types::Record,
};
use crate::live::{
    probe::{
        perf_ring::{DecodedPerfRecord, decode_perf_record},
        tracefs::read_tid_set,
    },
    procfs::{LiveSession, refresh_session_identity},
};
use std::{
    collections::BTreeSet,
    io::Write,
    path::Path,
    sync::atomic::{AtomicBool, Ordering},
    time::{Duration, Instant},
};

#[derive(Default)]
pub(super) struct DrainEvents {
    born: BTreeSet<u32>,
    /// The process of each new thread reported by a fork record (others are the first target's).
    born_owner: std::collections::BTreeMap<u32, u32>,
    exited: BTreeSet<u32>,
    exec: bool,
    /// Followed processes that exec'd another program and leave the profile.
    exec_followers: BTreeSet<u32>,
    /// New processes forked by a sampled process: (child, parent).
    forked: Vec<(u32, u32)>,
}

/// What the loop needs to add followed processes.
pub(super) struct FollowCtx<'a> {
    pub targets: &'a mut Targets,
    /// Verified shared-object hashes by (device, inode); grows with the libraries of followers.
    pub module_hashes: &'a mut std::collections::BTreeMap<(String, u64), String>,
    pub cancel: Option<&'a AtomicBool>,
}

/// New processes set up per poll, so a burst of followers does not starve the perf rings.
const MAX_NEW_PROCESSES_PER_POLL: usize = 8;

/// Queues the threads of a newly set up process; a TID still sampled for its previous owner keeps
/// that owner until its sampler is closed.
fn register(
    threads: BTreeSet<u32>,
    pid: u32,
    owner: &mut std::collections::BTreeMap<u32, u32>,
    attached: &BTreeSet<u32>,
    pending: &mut BTreeSet<u32>,
) {
    for tid in threads {
        if attached.contains(&tid) && owner.get(&tid).is_some_and(|previous| *previous != pid) {
            continue;
        }
        owner.insert(tid, pid);
        if !attached.contains(&tid) {
            pending.insert(tid);
        }
    }
}

/// Closes the samplers and drops the pending threads of processes that stopped being sampled.
fn retire(
    targets: &mut Targets,
    owner: &mut std::collections::BTreeMap<u32, u32>,
    attached: &mut BTreeSet<u32>,
    pending: &mut BTreeSet<u32>,
    samplers: &mut Vec<ActiveSampler>,
) {
    let retired: BTreeSet<u32> = targets.take_retired().into_iter().collect();
    if retired.is_empty() {
        return;
    }
    let tids: BTreeSet<u32> = owner.iter().filter(|(_, pid)| retired.contains(pid)).map(|(tid, _)| *tid).collect();
    owner.retain(|tid, _| !tids.contains(tid));
    attached.retain(|tid| !tids.contains(tid));
    pending.retain(|tid| !tids.contains(tid));
    samplers.retain_mut(|sampler| {
        if tids.contains(&sampler.tid) {
            sampler.disable();
            false
        } else {
            true
        }
    });
}

impl FollowCtx<'_> {
    /// Writes the mappings of a newly accepted process and returns its threads, or `None` (and
    /// stops following it) when it is gone, or exec'd or was replaced while its maps were read.
    fn add<W: Write>(
        &mut self,
        pid: u32,
        session: &LiveSession,
        writer: &mut ProfileWriter<W>,
    ) -> Result<Option<BTreeSet<u32>>, String> {
        let Ok((regions, _slide)) = crate::live::procfs::read_process_regions(pid, &session.image) else {
            self.targets.remove(pid, true);
            return Ok(None);
        };
        let missing: Vec<_> = regions
            .iter()
            .filter(|region| region.inode != 0 && !self.module_hashes.contains_key(&(region.dev.clone(), region.inode)))
            .cloned()
            .collect();
        if !missing.is_empty()
            && let Ok(more) = super::module_hash::collect(pid, &missing, self.cancel)
        {
            self.module_hashes.extend(more);
        }
        let threads = read_tid_set(&Path::new("/proc").join(pid.to_string()).join("task"));
        // The process must still be the one accepted: an exec or PID reuse during the reads would
        // stamp another program's maps with the target's identity.
        let Ok(threads) =
            threads.map_err(|_| ()).and_then(|t| if self.targets.still_same(pid) { Ok(t) } else { Err(()) })
        else {
            self.targets.remove(pid, true);
            return Ok(None);
        };
        for region in &regions {
            let mapping = super::capture::initial_mapping(
                region,
                pid,
                session.process.exe_sha256.as_deref(),
                self.module_hashes,
            )?;
            writer.write_record(&Record::Mapping(mapping)).map_err(|error| error.to_string())?;
        }
        Ok(Some(threads))
    }
}

/// Applies trigger hits earliest first, so window limits keep the earliest triggers even when
/// rings were drained out of time order; every hit thread is queued for attachment.
fn apply_trigger_hits(
    mut hits: Vec<(u64, u32)>,
    flight: &mut Option<Flight>,
    windows: &mut Option<super::windowing::CaptureWindows>,
    born: &mut BTreeSet<u32>,
) -> Result<(), String> {
    hits.sort_unstable();
    for (timestamp_ns, tid) in hits {
        if let Some(flight) = flight.as_mut() {
            flight.trigger(timestamp_ns);
        }
        if let Some(windows) = windows.as_mut() {
            windows.trigger(timestamp_ns).map_err(str::to_owned)?;
        }
        born.insert(tid);
    }
    Ok(())
}

#[test]
fn trigger_hits_drained_out_of_order_open_the_earliest_window() -> Result<(), String> {
    let mut windows = Some(super::windowing::CaptureWindows::new(1, Duration::from_millis(10)));
    let mut born = BTreeSet::new();
    // CPU 0's ring holds the later hit, CPU 1's the earlier one; ring order is 0 then 1.
    apply_trigger_hits(vec![(200, 11), (100, 12)], &mut None, &mut windows, &mut born)?;
    let opened = windows.as_ref().map(|w| w.windows.iter().map(|window| window.trigger_ns).collect::<Vec<_>>());
    assert_eq!(opened, Some(vec![100]));
    assert_eq!(born, BTreeSet::from([11, 12]));
    Ok(())
}

/// Trigger records from per-thread or system-wide samplers.
struct TriggerCtx<'a, 'b> {
    pid: u32,
    setup: Option<&'a TriggerSetup>,
    flight: &'b mut Option<Flight>,
    windows: &'b mut Option<super::windowing::CaptureWindows>,
    stats: &'b mut CaptureStats,
    events: &'b mut DrainEvents,
    /// (timestamp, tid) of accepted hits; applied in time order once every ring is drained.
    hits: Vec<(u64, u32)>,
}

impl TriggerCtx<'_, '_> {
    /// Rings (per CPU or per thread) are drained one after another, so hits arrive out of time
    /// order; window limits are applied to the time-sorted hits, earliest first.
    fn apply(self) -> Result<(), String> {
        apply_trigger_hits(self.hits, self.flight, self.windows, &mut self.events.born)
    }

    fn handle(&mut self, ty: u32, misc: u16, bytes: &[u8]) -> Result<(), String> {
        if ty == 9 {
            match self.setup.ok_or("missing trigger setup")?.decode(bytes) {
                Ok(Some(sample)) if sample.pid == self.pid => self.hits.push((sample.timestamp_ns, sample.tid)),
                Ok(_) => {}
                Err(_) => self.stats.trigger_lost = self.stats.trigger_lost.saturating_add(1),
            }
        } else if ty == 2 {
            let lost = match decode_perf_record(ty, misc, bytes, 0, 0) {
                Ok(DecodedPerfRecord::Lost { lost, .. }) => lost,
                _ => 1,
            };
            self.stats.trigger_lost = self.stats.trigger_lost.saturating_add(lost);
        }
        Ok(())
    }
}

#[allow(clippy::too_many_arguments, clippy::too_many_lines)] // Record variants share one bounded ring-draining loop.
pub(super) fn drain<W: Write>(
    targets: &Targets,
    config: &Config,
    samplers: &mut [ActiveSampler],
    writer: &mut ProfileWriter<W>,
    stats: &mut CaptureStats,
    flight: &mut Option<Flight>,
    windows: &mut Option<super::windowing::CaptureWindows>,
    trigger_setup: Option<&TriggerSetup>,
) -> Result<DrainEvents, String> {
    let mut events = DrainEvents::default();
    let (sample_type, mask, _, _) = layout(config);
    let pid = targets.primary;
    {
        let mut trigger_ctx = TriggerCtx {
            pid,
            setup: trigger_setup,
            flight: &mut *flight,
            windows: &mut *windows,
            stats: &mut *stats,
            events: &mut events,
            hits: Vec::new(),
        };
        for active in samplers.iter_mut() {
            if let Some(trigger) = &mut active.trigger {
                while let Some(record) = trigger.next_record() {
                    trigger_ctx.handle(record.ty(), record.misc(), &record.to_contiguous())?;
                }
            }
        }
        if let Some(setup) = trigger_setup {
            for sampler in setup.cpu_triggers.borrow_mut().iter_mut() {
                while let Some(record) = sampler.next_record() {
                    trigger_ctx.handle(record.ty(), record.misc(), &record.to_contiguous())?;
                }
            }
        }
        trigger_ctx.apply()?;
    }
    for active in samplers.iter_mut() {
        while let Some(record) = active.sampler.next_record() {
            let bytes = record.to_contiguous();
            match record.ty() {
                9 => {
                    if flight.is_none() && stats.samples >= config.max_samples {
                        stats.stop_reason = "max_samples";
                        break;
                    }
                    match perf_decode::decode_sample(&bytes, sample_type, mask) {
                        Ok(mut sample) if targets.contains(sample.pid) => {
                            sample.cpu_mode = record.misc() & 7;
                            stats.last_timestamp_ns = stats.last_timestamp_ns.max(sample.timestamp_ns);
                            stats.observed_samples = stats.observed_samples.saturating_add(1);
                            if let Some(flight) = flight {
                                flight.push(sample);
                            } else if let Some(windows) = windows {
                                if windows.contains(sample.timestamp_ns) {
                                    writer.write_record(&Record::Sample(sample)).map_err(|error| error.to_string())?;
                                    stats.samples += 1;
                                }
                            } else {
                                writer.write_record(&Record::Sample(sample)).map_err(|error| error.to_string())?;
                                stats.samples += 1;
                            }
                        }
                        Ok(_) | Err(_) => {
                            stats.dropped = stats.dropped.saturating_add(1);
                        }
                    }
                }
                10 => match perf_decode::decode_mmap2(&bytes, record.misc(), true) {
                    Ok(mapping) if targets.contains(mapping.pid) => {
                        stats.last_timestamp_ns = stats.last_timestamp_ns.max(mapping.timestamp_ns);
                        writer.write_record(&Record::Mapping(mapping)).map_err(|error| error.to_string())?;
                    }
                    Ok(_) => {}
                    Err(_) => {
                        stats.dropped = stats.dropped.saturating_add(1);
                    }
                },
                3 if record.misc() & (1 << 13) != 0 => {
                    let exec_pid = bytes.get(..4).and_then(|raw| raw.try_into().ok()).map(u32::from_le_bytes);
                    match exec_pid {
                        // Without following, an exec of the target ends the capture as before.
                        Some(p) if p == pid && !targets.follow.any() => events.exec = true,
                        Some(p) if targets.contains(p) => {
                            events.exec_followers.insert(p);
                        }
                        _ => {}
                    }
                }
                2 | 4 | 7 => match decode_perf_record(record.ty(), record.misc(), &bytes, 0, 0) {
                    Ok(DecodedPerfRecord::Lost { lost, .. }) => {
                        stats.lost = stats.lost.saturating_add(lost);
                        writer
                            .write_record(&Record::Lost { timestamp_ns: 0, tid: active.tid, count: lost })
                            .map_err(|error| error.to_string())?;
                    }
                    Ok(DecodedPerfRecord::Fork { tgid, parent_tgid, .. })
                        if tgid != parent_tgid && targets.contains(parent_tgid) =>
                    {
                        // A new process; it is checked and added by the loop.
                        events.forked.push((tgid, parent_tgid));
                    }
                    Ok(DecodedPerfRecord::Fork { tgid, thread_id, parent_tgid, parent_tid, timestamp_ns })
                        if targets.contains(tgid) =>
                    {
                        stats.last_timestamp_ns = stats.last_timestamp_ns.max(timestamp_ns);
                        events.born.insert(thread_id);
                        events.born_owner.insert(thread_id, tgid);
                        writer
                            .write_record(&Record::Fork {
                                timestamp_ns,
                                pid: tgid,
                                tid: thread_id,
                                parent_pid: parent_tgid,
                                parent_tid,
                            })
                            .map_err(|error| error.to_string())?;
                    }
                    Ok(DecodedPerfRecord::Exit { tgid, thread_id, timestamp_ns }) if targets.contains(tgid) => {
                        stats.last_timestamp_ns = stats.last_timestamp_ns.max(timestamp_ns);
                        events.exited.insert(thread_id);
                        writer
                            .write_record(&Record::Exit { timestamp_ns, pid: tgid, tid: thread_id })
                            .map_err(|error| error.to_string())?;
                    }
                    Ok(_) => {}
                    Err(_) => {
                        stats.dropped = stats.dropped.saturating_add(1);
                    }
                },
                5 => {
                    stats.partial_coverage = true;
                }
                _ => {}
            }
        }
    }
    Ok(events)
}

#[allow(clippy::too_many_arguments, clippy::too_many_lines)] // One loop owns all sampler lifecycle state.
pub(super) fn run<W: Write>(
    session: &mut LiveSession,
    config: &Config,
    trigger: Option<&TriggerSetup>,
    task_dir: &Path,
    samplers: &mut Vec<ActiveSampler>,
    writer: &mut ProfileWriter<W>,
    stats: &mut CaptureStats,
    flight: &mut Option<Flight>,
    windows: &mut Option<super::windowing::CaptureWindows>,
    started: Instant,
    cancel: Option<&AtomicBool>,
    follow: &mut FollowCtx<'_>,
) -> Result<(), String> {
    let mut attached: BTreeSet<_> = samplers.iter().map(|sampler| sampler.tid).collect();
    // The process each thread belongs to, so a retired process's samplers are closed with it and
    // a follower counts once its first sampler is enabled.
    let primary = follow.targets.primary;
    let mut owner: std::collections::BTreeMap<u32, u32> = attached.iter().map(|tid| (*tid, primary)).collect();
    let mut deferred_forks: std::collections::VecDeque<(u32, u32, Option<u64>)> = std::collections::VecDeque::new();
    let mut pending = BTreeSet::new();
    let mut failed = BTreeSet::new();
    let mut last_check = Instant::now();
    let mut trigger_seen_at = None;
    let mut sampling_on = false;
    loop {
        if cancel.is_some_and(|flag| flag.load(Ordering::Relaxed)) {
            stats.stop_reason = "cancelled";
            break;
        }
        let events = drain(&*follow.targets, config, samplers, writer, stats, flight, windows, trigger)?;
        if let Some(windows) = windows.as_ref() {
            let active = windows.active();
            if active != sampling_on {
                for sampler in samplers.iter_mut() {
                    if active {
                        sampler.sampler.enable().map_err(|error| error.to_string())?;
                    } else {
                        sampler.sampler.disable().map_err(|error| error.to_string())?;
                    }
                }
                sampling_on = active;
            }
            if windows.complete() {
                stats.stop_reason = "max_windows";
                break;
            }
        }
        if events.exec {
            stats.stop_reason = "process_changed";
            break;
        }
        if stats.stop_reason == "max_samples" {
            break;
        }
        for tid in events.exited {
            if pending.remove(&tid) && !attached.contains(&tid) {
                failed.insert(tid);
            }
            attached.remove(&tid);
            owner.remove(&tid);
            samplers.retain_mut(|sampler| {
                if sampler.tid == tid {
                    sampler.disable();
                    false
                } else {
                    true
                }
            });
        }
        if config.tids.is_empty() {
            // New threads are owned by the process the fork record names (trigger hits: the target).
            for tid in events.born {
                let pid = events.born_owner.get(&tid).copied().unwrap_or(follow.targets.primary);
                register(BTreeSet::from([tid]), pid, &mut owner, &attached, &mut pending);
            }
        }
        if flight.as_ref().is_some_and(|flight| flight.trigger_ns.is_some()) {
            let seen = *trigger_seen_at.get_or_insert_with(Instant::now);
            let window_ns = u64::try_from(config.trigger_window.as_nanos()).unwrap_or(u64::MAX);
            if seen.elapsed() >= Duration::from_nanos(window_ns - window_ns / 2) {
                stats.stop_reason = "trigger_window_complete";
                break;
            }
        }
        if started.elapsed() >= config.duration {
            if let Some(flight) = flight {
                stats.stop_reason =
                    if flight.trigger_ns.is_some() { "trigger_window_truncated" } else { "trigger_not_observed" };
            }
            break;
        }
        for pid in events.exec_followers {
            follow.targets.remove(pid, false);
        }
        retire(&mut *follow.targets, &mut owner, &mut attached, &mut pending, samplers);
        // New processes share one budget per poll between fork records and the /proc scan; the
        // rest wait for the next poll, so the perf rings keep being drained.
        let mut budget = MAX_NEW_PROCESSES_PER_POLL;
        // Each queued fork keeps the child's start time from when it was queued.
        deferred_forks
            .extend(events.forked.into_iter().map(|(child, parent)| (child, parent, super::follow::start_of(child))));
        while budget > 0 && !cancel.is_some_and(|flag| flag.load(Ordering::Relaxed)) {
            let Some((child, parent, start)) = deferred_forks.pop_front() else { break };
            let accepted = follow.targets.on_fork(child, parent, start);
            // A replaced identity under this PID closes its samplers before any thread is opened,
            // whether or not the new process was accepted.
            retire(&mut *follow.targets, &mut owner, &mut attached, &mut pending, samplers);
            if accepted {
                budget -= 1;
                if let Some(threads) = follow.add(child, session, writer)? {
                    register(threads, child, &mut owner, &attached, &mut pending);
                }
            }
        }
        if last_check.elapsed() >= Duration::from_millis(25) {
            let following = follow.targets.follow.any();
            let primary = follow.targets.primary;
            if !following || follow.targets.primary_is_original() {
                refresh_session_identity(session);
                if session.process.process_changed || !session.process.pid_alive_after {
                    if !following {
                        stats.stop_reason =
                            if session.process.process_changed { "process_changed" } else { "process_exited" };
                        break;
                    }
                    // While following, the first target may exit (a daemon's parent) or exec.
                    follow.targets.remove(primary, false);
                }
            }
            // Every live thread and the process it belongs to now.
            let live: std::collections::BTreeMap<u32, u32> = if following {
                // The processes already sampled are checked first: one that exited (its PID possibly
                // reused) or exec'd is retired before any new process is looked for.
                let mut live = std::collections::BTreeMap::new();
                for pid in follow.targets.pids.clone() {
                    let threads = read_tid_set(&Path::new("/proc").join(pid.to_string()).join("task"));
                    match threads {
                        Ok(threads) if follow.targets.still_same(pid) => {
                            live.extend(threads.into_iter().map(|tid| (tid, pid)));
                        }
                        _ => follow.targets.remove(pid, false),
                    }
                }
                retire(&mut *follow.targets, &mut owner, &mut attached, &mut pending, samplers);
                for pid in follow.targets.scan(Path::new("/proc"), budget) {
                    if cancel.is_some_and(|flag| flag.load(Ordering::Relaxed)) {
                        follow.targets.remove(pid, false);
                        continue;
                    }
                    retire(&mut *follow.targets, &mut owner, &mut attached, &mut pending, samplers);
                    if let Some(threads) = follow.add(pid, session, writer)? {
                        live.extend(threads.iter().map(|tid| (*tid, pid)));
                        register(threads, pid, &mut owner, &attached, &mut pending);
                    }
                }
                if follow.targets.pids.is_empty() && !follow.targets.waits_for_matches() && deferred_forks.is_empty() {
                    stats.stop_reason = "process_exited";
                    break;
                }
                live
            } else {
                let Ok(live) = read_tid_set(task_dir) else {
                    stats.stop_reason = "thread_enumeration_failed";
                    break;
                };
                live.into_iter().map(|tid| (tid, follow.targets.primary)).collect()
            };
            // A sampler stays only while its thread is live in the process it was opened for: a TID
            // reused by another process gets a new sampler under its new owner.
            samplers.retain_mut(|sampler| {
                let keep = live.get(&sampler.tid).is_some_and(|pid| owner.get(&sampler.tid) == Some(pid));
                if !keep {
                    attached.remove(&sampler.tid);
                    sampler.disable();
                }
                keep
            });
            pending.retain(|tid| {
                if live.contains_key(tid) {
                    true
                } else {
                    failed.insert(*tid);
                    false
                }
            });
            // Owners follow the live threads, not their history.
            owner.clone_from(&live);
            if config.tids.is_empty() {
                pending.extend(live.keys().filter(|tid| !attached.contains(tid)).copied());
            }
            last_check = Instant::now();
        }
        if cancel.is_some_and(|flag| flag.load(Ordering::Relaxed)) {
            stats.stop_reason = "cancelled";
            break;
        }
        // Queued threads (new threads, forked children, processes found by the scan) get their
        // samplers at once, not at the next 25 ms check.
        {
            for tid in std::mem::take(&mut pending) {
                if attached.contains(&tid) {
                    continue;
                }
                // The TID must still be a thread of the process it was queued for: a thread that
                // exited before this poll may have its TID reused by another task.
                let process = owner.get(&tid).copied().unwrap_or(follow.targets.primary);
                if !follow.targets.contains(process)
                    || !Path::new("/proc").join(process.to_string()).join("task").join(tid.to_string()).exists()
                {
                    failed.insert(tid);
                    continue;
                }
                if samplers.len() >= MAX_THREADS {
                    failed.insert(tid);
                    continue;
                }
                match open_sampler(tid, config, trigger) {
                    Ok(mut sampler) => {
                        let enabled = if windows.is_some() {
                            sampler.enable_trigger_only().and_then(|()| {
                                if sampling_on {
                                    sampler.sampler.enable().map_err(|error| error.to_string())
                                } else {
                                    Ok(())
                                }
                            })
                        } else {
                            sampler.enable()
                        };
                        if enabled.is_ok() {
                            attached.insert(tid);
                            samplers.push(sampler);
                            if let Some(pid) = owner.get(&tid) {
                                follow.targets.confirm(*pid);
                            }
                            stats.dynamically_attached_threads = stats.dynamically_attached_threads.saturating_add(1);
                        } else {
                            failed.insert(tid);
                        }
                    }
                    Err(_) => {
                        failed.insert(tid);
                    }
                }
            }
        }
        std::thread::sleep(Duration::from_millis(2));
    }
    stats.unattached_threads = u64::try_from(failed.len()).unwrap_or(u64::MAX);
    Ok(())
}
