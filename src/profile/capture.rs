/*
 * XRef — Linux hardware sampling session
 * Copyright (c) 2026 Alexander Panasenko
 * Contact: alex@prod.codes
 * Author: https://prod.codes/about/
 * Project: https://github.com/alex09x/xref
 * SPDX-License-Identifier: MIT OR Apache-2.0
 */
use super::{
    codec::ProfileWriter,
    config::{Callers, Config, Event, MAX_THREADS},
    perf_decode,
    types::{Header, Mapping, Record},
};
use crate::live::{
    probe::{
        perf::read_perf_event_paranoid,
        tracefs::{read_tid_set, verify_exe_still_matches},
    },
    procfs::{LiveSession, refresh_session_identity},
    types::BinaryMatch,
};
use perf_event::{Builder, Clock, Sampler, events::Hardware};
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::{collections::BTreeSet, io::Write, path::Path, sync::atomic::AtomicBool, time::Instant};

const RING_BYTES: usize = 256 * 1024;
const PARANOID: &str = "/proc/sys/kernel/perf_event_paranoid";
/// x86 perf register indexes AX..IP and R8..R15; segment registers are omitted.
pub(super) const REGISTER_MASK: u64 = 0x00ff_01ff;
const BRANCH_USER: u64 = 1;
const BRANCH_CALL_STACK: u64 = 1 << 11;

pub(super) struct ActiveSampler {
    pub tid: u32,
    pub sampler: Sampler,
    pub trigger: Option<Sampler>,
}

impl ActiveSampler {
    /// Enable only this thread's trigger; with a system-wide trigger there is none per thread.
    pub fn enable_trigger_only(&mut self) -> Result<(), String> {
        self.trigger.as_mut().map_or(Ok(()), |trigger| {
            trigger.enable().map_err(|error| sampling_error("profile trigger enable", &error))
        })
    }
    pub fn enable(&mut self) -> Result<(), String> {
        self.sampler.enable().map_err(|error| sampling_error("profile enable", &error))?;
        if let Some(trigger) = &mut self.trigger
            && let Err(error) = trigger.enable()
        {
            let _ = self.sampler.disable();
            return Err(sampling_error("profile trigger enable", &error));
        }
        Ok(())
    }
    pub fn disable(&mut self) {
        if let Some(trigger) = &mut self.trigger {
            let _ = trigger.disable();
        }
        let _ = self.sampler.disable();
    }
}

fn sampling_error(operation: &str, error: &std::io::Error) -> String {
    let paranoid =
        read_perf_event_paranoid(Path::new(PARANOID)).map_or_else(|| "unknown".to_owned(), |value| value.to_string());
    let code = if error.kind() == std::io::ErrorKind::PermissionDenied || matches!(error.raw_os_error(), Some(1 | 13)) {
        "permission_denied"
    } else {
        "perf_open_failed"
    };
    format!("{code}: {operation} failed ({error}; perf_event_paranoid={paranoid})")
}

#[derive(Debug, Serialize)]
pub struct CaptureStats {
    pub samples: u64,
    pub lost: u64,
    pub dropped: u64,
    pub initial_threads: usize,
    pub dynamically_attached_threads: u64,
    pub unattached_threads: u64,
    pub partial_coverage: bool,
    pub elapsed_ms: u64,
    /// CPU time of the capture thread; excludes target and interrupt-context costs.
    pub observer_thread_cpu_ms: Option<u64>,
    pub last_timestamp_ns: u64,
    pub trigger_timestamp_ns: Option<u64>,
    pub trigger_lost: u64,
    pub observed_samples: u64,
    pub stop_reason: &'static str,
}

pub(super) const fn layout(config: &Config) -> (u64, u64, u32, u64) {
    let mut sample_type =
        perf_decode::SAMPLE_IP | perf_decode::SAMPLE_TID | perf_decode::SAMPLE_TIME | perf_decode::SAMPLE_PERIOD;
    match config.callers {
        Callers::Dwarf => {
            sample_type |= perf_decode::SAMPLE_REGS_USER | perf_decode::SAMPLE_STACK_USER;
            (sample_type, REGISTER_MASK, config.stack_bytes, 0)
        }
        Callers::Lbr => {
            sample_type |= perf_decode::SAMPLE_BRANCH_STACK;
            (sample_type, 0, 0, BRANCH_USER | BRANCH_CALL_STACK)
        }
        Callers::Fp => (sample_type | perf_decode::SAMPLE_CALLCHAIN, 0, 0, 0),
        Callers::None => (sample_type, 0, 0, 0),
    }
}

pub(super) fn open_sampler(
    tid: u32,
    config: &Config,
    trigger: Option<&super::trigger::TriggerSetup>,
) -> Result<ActiveSampler, String> {
    let event = match config.event {
        Event::Cycles => Hardware::CPU_CYCLES,
        Event::Instructions => Hardware::INSTRUCTIONS,
        Event::CacheMisses => Hardware::CACHE_MISSES,
        Event::BranchMisses => Hardware::BRANCH_MISSES,
    };
    let mut builder = Builder::new(event);
    builder
        .observe_pid(i32::try_from(tid).map_err(|_| "TID exceeds pid_t")?)
        .any_cpu()
        .inherit(false)
        .remove_on_exec(true)
        .task(true)
        .mmap(true)
        .mmap2(true)
        .sample_id_all(true)
        .comm(true)
        .comm_exec(true)
        .clockid(Clock::MONOTONIC)
        .exclude_kernel(!config.include_kernel)
        .wakeup_events(1);
    if let Some(frequency) = config.frequency_hz {
        builder.sample_frequency(frequency);
    }
    if let Some(period) = config.period {
        builder.sample_period(period);
    }
    let (sample_type, registers, stack, branches) = layout(config);
    let attributes = builder.attrs_mut();
    attributes.sample_type = sample_type;
    attributes.sample_regs_user = registers;
    attributes.sample_stack_user = stack;
    attributes.branch_sample_type = branches;
    let counter = builder.build().map_err(|error| sampling_error("profile perf_event_open", &error))?;
    let sampler = counter.sampled(RING_BYTES).map_err(|error| sampling_error("profile perf mmap", &error))?;
    let trigger = trigger.map(|trigger| trigger.open(tid)).transpose()?.flatten();
    Ok(ActiveSampler { tid, sampler, trigger })
}

pub(super) fn initial_mapping(
    region: &crate::live::types::RegionEntry,
    pid: u32,
    process_hash: Option<&str>,
    module_hashes: &std::collections::BTreeMap<(String, u64), String>,
) -> Result<Mapping, String> {
    let (major, minor) = region.dev.split_once(':').ok_or("invalid proc maps device")?;
    Ok(Mapping {
        timestamp_ns: 0,
        pid,
        tid: pid,
        start: region.start.0,
        length: region.end.0.checked_sub(region.start.0).ok_or("invalid proc maps range")?,
        file_offset: region.offset.0,
        device_major: u32::from_str_radix(major, 16).map_err(|_| "invalid proc maps major")?,
        device_minor: u32::from_str_radix(minor, 16).map_err(|_| "invalid proc maps minor")?,
        inode: region.inode,
        executable: region.perms.as_bytes().get(2) == Some(&b'x'),
        sha256: if region.is_target_image {
            process_hash.map(str::to_owned)
        } else {
            module_hashes.get(&(region.dev.clone(), region.inode)).cloned()
        },
        path: region.pathname.clone().unwrap_or_default(),
    })
}

#[allow(clippy::too_many_lines)] // Keep sampler setup, cleanup and identity validation in one lifecycle.
pub fn capture<W: Write>(
    session: &mut LiveSession,
    config: &Config,
    output: W,
    cancel: Option<&AtomicBool>,
) -> Result<(W, CaptureStats), String> {
    let cpu_start = thread_cpu_ns();
    config.validate()?;
    if session.process.process_changed || !session.process.pid_alive_after {
        return Err("process_changed: target identity changed before profiling".to_owned());
    }
    let (device, inode) = session.exe_dev_ino.ok_or("binary_mismatch: missing executable device/inode")?;
    let device_major = ((device >> 8) & 0xfff) | ((device >> 32) & !0xfff);
    let device_minor = (device & 0xff) | ((device >> 12) & !0xff);
    if !matches!(
        session.process.binary_match,
        BinaryMatch::VerifiedBuildId | BinaryMatch::VerifiedSha256 | BinaryMatch::ProcExeAuto
    ) {
        return Err("binary_mismatch: profile requires a verified target image".to_owned());
    }
    verify_exe_still_matches(session, Path::new("/proc"))?;
    let trigger =
        config.trigger_probe.map(|address| super::trigger::TriggerSetup::new(session, address, config)).transpose()?;
    let module_hashes = super::module_hash::collect(session.process.pid, &session.regions, cancel)?;
    refresh_session_identity(session);
    if session.process.process_changed || !session.process.pid_alive_after {
        return Err("process_changed: target identity changed while collecting module identities".to_owned());
    }
    let task_dir = Path::new("/proc").join(session.process.pid.to_string()).join("task");
    let live = read_tid_set(&task_dir)?;
    let selected: BTreeSet<_> =
        if config.tids.is_empty() { live.clone() } else { config.tids.iter().copied().collect() };
    if selected.is_empty() || selected.len() > MAX_THREADS || !selected.is_subset(&live) {
        return Err("profile target thread set is empty, too large, or contains a TID outside the process".to_owned());
    }
    let mut samplers = Vec::with_capacity(selected.len());
    for &tid in &selected {
        samplers.push(open_sampler(tid, config, trigger.as_ref())?);
    }
    for active in &mut samplers {
        if config.max_windows.is_some() {
            active.enable_trigger_only()?;
        } else {
            active.enable()?;
        }
    }
    if let Some(trigger) = trigger.as_ref() {
        trigger.enable_system_wide()?;
    }
    let image_hash = crate::trace_analysis::index::hex_bytes(&Sha256::digest(&session.image.data));
    let header = Header {
        // Schema 4 marks a system-wide trigger (every trigger capture since it became mandatory),
        // so older trigger profiles, possibly per-thread, keep their short-lived-thread warning.
        schema_version: if trigger.is_some() { 4 } else { 1 },
        image_sha256: image_hash,
        pid: session.process.pid,
        process_exe_sha256: session.process.exe_sha256.clone(),
        binary_match: session.process.binary_match.as_str().to_owned(),
        pie_slide: session.process.pie_slide,
        exe_device_major: device_major,
        exe_device_minor: device_minor,
        exe_inode: inode,
        starttime_ticks: session.process.starttime_ticks,
        event: config.event.name().to_owned(),
        frequency_hz: config.frequency_hz,
        period: config.period,
        callchain: config.callers.name().to_owned(),
        started_monotonic_ns: 0,
        trigger_static_va: trigger.as_ref().map(|trigger| trigger.static_va),
        trigger_window_ns: trigger
            .as_ref()
            .map(|_| u64::try_from(config.trigger_window.as_nanos()).unwrap_or(u64::MAX)),
    };
    let mut writer = ProfileWriter::new(output, &header).map_err(|error| error.to_string())?;
    for region in &session.regions {
        writer
            .write_record(&Record::Mapping(initial_mapping(
                region,
                session.process.pid,
                session.process.exe_sha256.as_deref(),
                &module_hashes,
            )?))
            .map_err(|error| error.to_string())?;
    }
    let started = Instant::now();
    let mut stats = CaptureStats {
        samples: 0,
        lost: 0,
        dropped: 0,
        initial_threads: selected.len(),
        dynamically_attached_threads: 0,
        unattached_threads: 0,
        partial_coverage: true,
        elapsed_ms: 0,
        observer_thread_cpu_ms: None,
        last_timestamp_ns: 0,
        trigger_timestamp_ns: None,
        trigger_lost: 0,
        observed_samples: 0,
        stop_reason: "duration",
    };
    let mut flight = trigger.as_ref().filter(|_| config.max_windows.is_none()).map(|_| {
        super::flight::Flight::new(
            u64::try_from(config.trigger_window.as_nanos()).unwrap_or(u64::MAX),
            32 * 1024 * 1024,
        )
    });
    let mut windows = config.max_windows.map(|max| super::windowing::CaptureWindows::new(max, config.trigger_window));
    super::capture_stream::run(
        session,
        config,
        trigger.as_ref(),
        &task_dir,
        &mut samplers,
        &mut writer,
        &mut stats,
        &mut flight,
        &mut windows,
        started,
        cancel,
    )?;
    for active in &mut samplers {
        active.disable();
    }
    super::capture_stream::drain(
        session.process.pid,
        config,
        &mut samplers,
        &mut writer,
        &mut stats,
        &mut flight,
        &mut windows,
        trigger.as_ref(),
    )?;
    if let Some(flight) = flight {
        stats.trigger_timestamp_ns = flight.trigger_ns;
        if stats.trigger_timestamp_ns.is_some() && stats.stop_reason == "trigger_not_observed" {
            stats.stop_reason = "trigger_window_truncated";
        }
        stats.dropped = stats.dropped.saturating_add(flight.evicted);
        stats.partial_coverage |= flight.coverage_gap;
        for sample in flight.into_window() {
            if stats.samples >= config.max_samples {
                stats.stop_reason = "max_samples";
                stats.dropped = stats.dropped.saturating_add(1);
                continue;
            }
            writer.write_record(&Record::Sample(sample)).map_err(|error| error.to_string())?;
            stats.samples += 1;
        }
    }
    if let Some(mut windows) = windows {
        if windows.active() && stats.stop_reason == "duration" {
            stats.stop_reason = "trigger_window_truncated";
        }
        windows.windows.sort_by_key(|window| window.trigger_ns);
        stats.trigger_timestamp_ns = windows.windows.first().map(|window| window.trigger_ns);
        if windows.windows.is_empty() {
            stats.stop_reason = "trigger_not_observed";
        }
        for window in windows.windows {
            writer
                .write_record(&Record::Window { trigger_ns: window.trigger_ns, end_ns: window.end_ns })
                .map_err(|error| error.to_string())?;
        }
        // Perf sampling is enabled by the observer after it receives a trigger.
        stats.partial_coverage = true;
    }
    drop(samplers);
    refresh_session_identity(session);
    if session.process.process_changed {
        stats.stop_reason = "process_changed";
    } else if !session.process.pid_alive_after && stats.stop_reason == "duration" {
        stats.stop_reason = "process_exited";
    }
    stats.elapsed_ms = u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX);
    stats.observer_thread_cpu_ms =
        cpu_start.zip(thread_cpu_ns()).map(|(start, end)| end.saturating_sub(start) / 1_000_000);
    let output = writer
        .finish(
            stats.last_timestamp_ns,
            stats.dropped,
            stats.partial_coverage,
            stats.stop_reason,
            stats.trigger_timestamp_ns,
            stats.trigger_lost,
        )
        .map_err(|error| error.to_string())?;
    Ok((output, stats))
}

fn thread_cpu_ns() -> Option<u64> {
    std::fs::read_to_string("/proc/thread-self/schedstat").ok()?.split_whitespace().next()?.parse().ok()
}
