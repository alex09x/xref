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
}

impl TriggerSetup {
    pub fn new(session: &LiveSession, address: u64) -> Result<Self, String> {
        validate_session_for_probe(session)?;
        let spec = validate_probe_targets(&session.image, session.process.pie_slide, &session.regions, &[address])?
            .into_iter()
            .next()
            .ok_or("missing trigger target")?;
        let pmu_type = read_uprobe_pmu_type(Path::new("/sys/bus/event_source/devices/uprobe/type"))?;
        let path = PathBuf::from(format!("/proc/{}/exe", session.process.pid));
        let executable = CString::new(path.as_os_str().as_bytes()).map_err(|_| "invalid proc executable path")?;
        Ok(Self { static_va: spec.static_va, pmu_type, file_offset: spec.file_offset, executable })
    }

    pub fn open(&self, tid: u32) -> Result<Sampler, String> {
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
        attributes.type_ = self.pmu_type;
        attributes.config = 0;
        attributes.kprobe_func = self.executable.as_ptr() as usize as u64;
        attributes.probe_offset = self.file_offset;
        attributes.sample_type =
            super::perf_decode::SAMPLE_IP | super::perf_decode::SAMPLE_TID | super::perf_decode::SAMPLE_TIME;
        let counter = builder.build().map_err(|error| format!("trigger perf_event_open failed: {error}"))?;
        counter.sampled(64 * 1024).map_err(|error| format!("trigger perf mmap failed: {error}"))
    }
}
