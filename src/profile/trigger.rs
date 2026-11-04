/*
 * XRef — verified uprobe trigger for profile windows
 * Copyright (c) 2026 Alexander Panasenko
 * Contact: alex@prod.codes
 * Author: https://prod.codes/about/
 * Project: https://github.com/alex09x/xref
 * SPDX-License-Identifier: MIT OR Apache-2.0
 */
use crate::live::{
    probe::{
        perf::read_uprobe_pmu_type,
        validate::{validate_probe_targets, validate_session_for_probe},
    },
    procfs::LiveSession,
};
use perf_event::{Builder, Clock, Sampler, events::Software};
use std::{
    ffi::CString,
    os::unix::ffi::OsStrExt,
    path::{Path, PathBuf},
};

pub(super) struct TriggerSetup {
    pub static_va: u64,
    pmu_type: u32,
    file_offset: u64,
    executable: CString,
    /// System-wide (`pid = -1`) samplers of the trigger tracepoint, one per online CPU. A uprobe
    /// fires in every thread that executes the code, including threads created after attach, so
    /// short-lived threads cannot slip between `/proc` polls. Empty when unavailable; then each
    /// thread gets its own trigger. Declared before `tracepoint` so the fds close before teardown.
    pub cpu_triggers: std::cell::RefCell<Vec<Sampler>>,
    tracepoint: Option<super::trigger_tracefs::Registration>,
}

/// Online CPU ids from `/sys/devices/system/cpu/online` (`0-3,8-11`).
fn online_cpus() -> Result<Vec<usize>, String> {
    let text = std::fs::read_to_string("/sys/devices/system/cpu/online").map_err(|error| error.to_string())?;
    parse_cpu_list(text.trim())
}

fn parse_cpu_list(text: &str) -> Result<Vec<usize>, String> {
    let mut cpus = Vec::new();
    for part in text.split(',').filter(|part| !part.is_empty()) {
        let (first, last) = part.split_once('-').unwrap_or((part, part));
        let (first, last): (usize, usize) =
            (first.parse().map_err(|_| "invalid cpu list")?, last.parse().map_err(|_| "invalid cpu list")?);
        if last < first || last - first > 4096 {
            return Err("invalid cpu range".to_owned());
        }
        cpus.extend(first..=last);
    }
    Ok(cpus)
}

#[test]
fn parses_online_cpu_lists() {
    assert_eq!(parse_cpu_list("0-3,8,10-11"), Ok(vec![0, 1, 2, 3, 8, 10, 11]));
    assert!(parse_cpu_list("3-1").is_err());
}

impl TriggerSetup {
    pub fn new(session: &LiveSession, address: u64, config: &super::config::Config) -> Result<Self, String> {
        validate_session_for_probe(session)?;
        let spec = validate_probe_targets(&session.image, session.process.pie_slide, &session.regions, &[address])?
            .into_iter()
            .next()
            .ok_or("missing trigger target")?;
        let pmu_type = read_uprobe_pmu_type(Path::new("/sys/bus/event_source/devices/uprobe/type"))?;
        let path = PathBuf::from(format!("/proc/{}/exe", session.process.pid));
        let executable = CString::new(path.as_os_str().as_bytes()).map_err(|_| "invalid proc executable path")?;
        let needs_tracepoint = !(config.trigger_fetch.is_empty() && config.trigger_filter.is_empty());
        let registration = super::trigger_tracefs::Registration::new(
            session.process.pid,
            spec.file_offset,
            &config.trigger_fetch,
            &config.trigger_filter,
        );
        let tracepoint = match registration {
            Ok(registration) => Some(registration),
            Err(error) if needs_tracepoint => return Err(error),
            Err(_) => None,
        };
        let mut setup = Self {
            static_va: spec.static_va,
            pmu_type,
            file_offset: spec.file_offset,
            executable,
            cpu_triggers: std::cell::RefCell::new(Vec::new()),
            tracepoint,
        };
        // Every trigger profile is system-wide: a per-thread fallback would miss short-lived threads
        // without any trace of that in the saved profile, so it is not offered.
        let samplers = setup.open_system_wide().map_err(|reason| {
            format!(
                "system-wide trigger unavailable ({reason}); --trigger-probe needs writable tracefs and system-wide perf access (run as root or with CAP_PERFMON)"
            )
        })?;
        setup.cpu_triggers = std::cell::RefCell::new(samplers);
        Ok(setup)
    }

    fn open_system_wide(&self) -> Result<Vec<Sampler>, String> {
        let tracepoint = self.tracepoint.as_ref().ok_or("tracefs trigger tracepoint not registered")?;
        let mut samplers = Vec::new();
        for cpu in online_cpus()? {
            let mut builder = Builder::new(Software::DUMMY);
            builder.any_pid().one_cpu(cpu).clockid(Clock::MONOTONIC).sample_period(1).wakeup_events(1);
            let attributes = builder.attrs_mut();
            attributes.type_ = 2;
            attributes.config = tracepoint.id;
            attributes.sample_type = super::perf_decode::SAMPLE_IP
                | super::perf_decode::SAMPLE_TID
                | super::perf_decode::SAMPLE_TIME
                | (1 << 10); // PERF_SAMPLE_RAW
            let counter = builder.build().map_err(|error| format!("cpu {cpu}: {error}"))?;
            samplers.push(counter.sampled(64 * 1024).map_err(|error| format!("cpu {cpu} mmap: {error}"))?);
        }
        Ok(samplers)
    }

    /// Enable the system-wide trigger samplers; a no-op in per-thread mode.
    pub fn enable_system_wide(&self) -> Result<(), String> {
        for sampler in self.cpu_triggers.borrow_mut().iter_mut() {
            sampler.enable().map_err(|error| format!("profile trigger enable: {error}"))?;
        }
        Ok(())
    }

    /// Per-thread trigger for `tid`, or `None` when the system-wide trigger already covers it.
    pub fn open(&self, tid: u32) -> Result<Option<Sampler>, String> {
        if !self.cpu_triggers.borrow().is_empty() {
            return Ok(None);
        }
        self.open_thread(tid).map(Some)
    }

    fn open_thread(&self, tid: u32) -> Result<Sampler, String> {
        let mut builder = Builder::new(Software::DUMMY);
        builder
            .observe_pid(i32::try_from(tid).map_err(|_| "TID exceeds pid_t")?)
            .any_cpu()
            .inherit(false)
            .remove_on_exec(true)
            .clockid(Clock::MONOTONIC)
            .sample_period(1)
            .wakeup_events(1);
        let attributes = builder.attrs_mut();
        if let Some(tracepoint) = &self.tracepoint {
            attributes.type_ = 2;
            attributes.config = tracepoint.id;
        } else {
            attributes.type_ = self.pmu_type;
            attributes.config = 0;
            attributes.kprobe_func = self.executable.as_ptr() as usize as u64;
            attributes.probe_offset = self.file_offset;
        }
        attributes.sample_type =
            super::perf_decode::SAMPLE_IP | super::perf_decode::SAMPLE_TID | super::perf_decode::SAMPLE_TIME;
        if self.tracepoint.is_some() {
            attributes.sample_type |= 1 << 10;
        } // PERF_SAMPLE_RAW
        let counter = builder.build().map_err(|error| format!("trigger perf_event_open failed: {error}"))?;
        counter.sampled(64 * 1024).map_err(|error| format!("trigger perf mmap failed: {error}"))
    }

    pub fn decode(&self, bytes: &[u8]) -> Result<Option<super::types::Sample>, String> {
        let fields = super::perf_decode::SAMPLE_IP | super::perf_decode::SAMPLE_TID | super::perf_decode::SAMPLE_TIME;
        if let Some(tracepoint) = &self.tracepoint {
            let prefix = bytes.get(..24).ok_or("truncated trigger sample")?;
            let size = u32::from_le_bytes(
                bytes.get(24..28).ok_or("truncated trigger raw size")?.try_into().map_err(|_| "invalid raw size")?,
            );
            let size = usize::try_from(size).map_err(|_| "trigger raw size overflow")?;
            let raw = bytes
                .get(28..28_usize.checked_add(size).ok_or("trigger raw size overflow")?)
                .ok_or("truncated trigger raw payload")?;
            if !tracepoint.accepts(raw)? {
                return Ok(None);
            }
            Ok(Some(super::perf_decode::decode_sample(prefix, fields, 0)?))
        } else {
            Ok(Some(super::perf_decode::decode_sample(bytes, fields, 0)?))
        }
    }
}
