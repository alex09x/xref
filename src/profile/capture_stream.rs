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
    exited: BTreeSet<u32>,
    exec: bool,
}

#[allow(clippy::too_many_arguments, clippy::too_many_lines)] // Record variants share one bounded ring-draining loop.
pub(super) fn drain<W: Write>(
    pid: u32,
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
    for active in samplers.iter_mut() {
        if let Some(trigger) = &mut active.trigger {
            while let Some(record) = trigger.next_record() {
                let bytes = record.to_contiguous();
                if record.ty() == 9 {
                    match trigger_setup.ok_or("missing trigger setup")?.decode(&bytes) {
                        Ok(Some(sample)) if sample.pid == pid => {
                            if let Some(flight) = flight {
                                flight.trigger(sample.timestamp_ns);
                            }
                            if let Some(windows) = windows {
                                windows.trigger(sample.timestamp_ns).map_err(str::to_owned)?;
                            }
                        }
                        Ok(_) => {}
                        Err(_) => {
                            stats.trigger_lost = stats.trigger_lost.saturating_add(1);
                        }
                    }
                } else if record.ty() == 2 {
                    if let Ok(DecodedPerfRecord::Lost { lost, .. }) =
                        decode_perf_record(record.ty(), record.misc(), &bytes, 0, 0)
                    {
                        stats.trigger_lost = stats.trigger_lost.saturating_add(lost);
                    } else {
                        stats.trigger_lost = stats.trigger_lost.saturating_add(1);
                    }
                }
            }
        }
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
                        Ok(mut sample) if sample.pid == pid => {
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
                    Ok(mapping) if mapping.pid == pid => {
                        stats.last_timestamp_ns = stats.last_timestamp_ns.max(mapping.timestamp_ns);
                        writer.write_record(&Record::Mapping(mapping)).map_err(|error| error.to_string())?;
                    }
                    Ok(_) => {}
                    Err(_) => {
                        stats.dropped = stats.dropped.saturating_add(1);
                    }
                },
                3 if record.misc() & (1 << 13) != 0 && bytes.get(..4).is_some_and(|raw| raw == pid.to_le_bytes()) => {
                    events.exec = true;
                }
                2 | 4 | 7 => match decode_perf_record(record.ty(), record.misc(), &bytes, 0, 0) {
                    Ok(DecodedPerfRecord::Lost { lost, .. }) => {
                        stats.lost = stats.lost.saturating_add(lost);
                        writer
                            .write_record(&Record::Lost { timestamp_ns: 0, tid: active.tid, count: lost })
                            .map_err(|error| error.to_string())?;
                    }
                    Ok(DecodedPerfRecord::Fork { tgid, thread_id, parent_tgid, parent_tid, timestamp_ns })
                        if tgid == pid =>
                    {
                        stats.last_timestamp_ns = stats.last_timestamp_ns.max(timestamp_ns);
                        events.born.insert(thread_id);
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
                    Ok(DecodedPerfRecord::Exit { tgid, thread_id, timestamp_ns }) if tgid == pid => {
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
) -> Result<(), String> {
    let mut attached: BTreeSet<_> = samplers.iter().map(|sampler| sampler.tid).collect();
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
        let events = drain(session.process.pid, config, samplers, writer, stats, flight, windows, trigger)?;
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
            pending.extend(events.born.into_iter().filter(|tid| !attached.contains(tid)));
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
        if last_check.elapsed() >= Duration::from_millis(25) {
            refresh_session_identity(session);
            if session.process.process_changed {
                stats.stop_reason = "process_changed";
                break;
            }
            if !session.process.pid_alive_after {
                stats.stop_reason = "process_exited";
                break;
            }
            let Ok(live) = read_tid_set(task_dir) else {
                stats.stop_reason = "thread_enumeration_failed";
                break;
            };
            samplers.retain_mut(|sampler| {
                if live.contains(&sampler.tid) {
                    true
                } else {
                    attached.remove(&sampler.tid);
                    sampler.disable();
                    false
                }
            });
            pending.retain(|tid| {
                if live.contains(tid) {
                    true
                } else {
                    failed.insert(*tid);
                    false
                }
            });
            if config.tids.is_empty() {
                pending.extend(live.iter().filter(|tid| !attached.contains(tid)).copied());
            }
            for tid in std::mem::take(&mut pending) {
                if attached.contains(&tid) {
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
            last_check = Instant::now();
        }
        std::thread::sleep(Duration::from_millis(2));
    }
    stats.unattached_threads = u64::try_from(failed.len()).unwrap_or(u64::MAX);
    Ok(())
}
