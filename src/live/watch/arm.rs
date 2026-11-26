/*
 * XRef — `xref live watch --arm-at`: hold the data watchpoints until a code address first runs
 * Copyright (c) 2026 Alexander Panasenko
 * Contact: alex@prod.codes
 * Author: https://prod.codes/about/
 * Project: https://github.com/alex09x/xref
 * SPDX-License-Identifier: MIT OR Apache-2.0
 */

//! `--arm-at <code VA>` counts executions of one code address with a uprobe per thread (inherited
//! by threads they create) and attaches the hardware watchpoints only after the first one, so a
//! long session does not spend its `DR0`–`DR3` hits on writes made before the object exists.

use serde::Serialize;

use crate::live::types::HexAddr;

/// Caveat carried by every armed report: the watchpoints go in after the arm address ran.
pub const ARM_WINDOW_CAVEAT: &str = "watchpoints are attached a few milliseconds after the first execution of the arm address is seen; a write inside that window is not observed";

/// The resolved `--arm-at` code address.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ArmTarget {
    pub static_va: u64,
    pub runtime_va: u64,
    pub file_offset: u64,
}

/// What happened to `--arm-at` in the report.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct WatchArmResult {
    pub static_va: HexAddr,
    pub runtime_va: HexAddr,
    /// Whether the arm address ran and the watchpoints were attached.
    pub armed: bool,
    /// Milliseconds from the start of the session to the arming, when armed.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub armed_after_ms: Option<u64>,
    pub caveat: &'static str,
}

impl WatchArmResult {
    #[must_use]
    pub const fn new(target: ArmTarget, armed_after_ms: Option<u64>) -> Self {
        Self {
            static_va: HexAddr(target.static_va),
            runtime_va: HexAddr(target.runtime_va),
            armed: armed_after_ms.is_some(),
            armed_after_ms,
            caveat: ARM_WINDOW_CAVEAT,
        }
    }
}

/// Resolves `--arm-at` like a `live probe` address: an instruction start in the target executable.
pub fn resolve_arm_target(session: &crate::live::procfs::LiveSession, input: u64) -> Result<ArmTarget, String> {
    use crate::live::probe::validate::{validate_probe_targets, validate_session_for_probe};

    validate_session_for_probe(session).map_err(|e| format!("--arm-at: {e}"))?;
    let specs = validate_probe_targets(&session.image, session.process.pie_slide, &session.regions, &[input])
        .map_err(|e| format!("--arm-at: {e}"))?;
    let spec = specs.first().ok_or_else(|| format!("--arm-at {input:#x} did not resolve"))?;
    Ok(ArmTarget { static_va: spec.static_va, runtime_va: spec.runtime_va, file_offset: spec.file_offset })
}

/// One stderr heartbeat line for a session with `--heartbeat-ms` (`hits` counts accepted hits).
#[cfg(target_os = "linux")]
pub fn emit_watch_heartbeat(hits: usize, alive: bool, armed: bool, last_hit_ms: Option<u128>) {
    use std::io::Write as _;
    let age = last_hit_ms.map_or_else(|| "none".to_owned(), |ms| format!("{ms}ms"));
    let mut stderr = std::io::stderr().lock();
    let _ = writeln!(stderr, "xref: heartbeat hits {hits}  alive {alive}  armed {armed}  last_hit_age {age}");
    let _ = stderr.flush();
}

/// Runs before the watch targets are resolved: waits for the arm address, then re-reads the
/// process mappings (the watched object may have been mapped by the code leading up to it) and
/// shortens `cfg.duration` by the time spent waiting.
///
/// Returns `Ok(Ok(armed_after_ms))`, or `Ok(Err((stop_reason, elapsed_ms)))` when the session
/// ended first and no watchpoint was attached.
#[cfg(target_os = "linux")]
pub fn arm_session(
    session: &mut crate::live::procfs::LiveSession,
    target: ArmTarget,
    cfg: &mut crate::live::watch::perf::WatchRunConfig<'_>,
) -> Result<Result<u64, (crate::live::probe::types::ProbeStopReason, u64)>, String> {
    use std::time::{Duration, Instant};

    let started = Instant::now();
    let deadline = (!cfg.duration.is_zero()).then(|| started + cfg.duration);
    let task_dir = std::path::Path::new("/proc").join(session.process.pid.to_string()).join("task");
    let stop = wait_for_arm(session, &task_dir, target, cfg, deadline)?;
    let elapsed = started.elapsed();
    let elapsed_ms = u64::try_from(elapsed.as_millis()).unwrap_or(u64::MAX);
    if let Some(stop_reason) = stop {
        return Ok(Err((stop_reason, elapsed_ms)));
    }
    crate::live::procfs::refresh_session_regions(session)?;
    if !cfg.duration.is_zero() {
        // Zero would mean "unbounded"; keep at least 1 ms of the requested window.
        cfg.duration = cfg.duration.saturating_sub(elapsed).max(Duration::from_millis(1));
    }
    Ok(Ok(elapsed_ms))
}

#[cfg(not(target_os = "linux"))]
pub fn arm_session(
    _session: &mut crate::live::procfs::LiveSession,
    _target: ArmTarget,
    _cfg: &mut crate::live::watch::perf::WatchRunConfig<'_>,
) -> Result<Result<u64, (crate::live::probe::types::ProbeStopReason, u64)>, String> {
    Err("unsupported_platform: --arm-at uses Linux uprobes".to_owned())
}

/// Waits until the arm address has run in any thread of the target.
///
/// Returns `Ok(None)` once armed, or `Ok(Some(reason))` when the session ended first (signal,
/// deadline, target exit or exec).
#[cfg(target_os = "linux")]
pub fn wait_for_arm(
    session: &mut crate::live::procfs::LiveSession,
    task_dir: &std::path::Path,
    target: ArmTarget,
    cfg: &crate::live::watch::perf::WatchRunConfig<'_>,
    deadline: Option<std::time::Instant>,
) -> Result<Option<crate::live::probe::types::ProbeStopReason>, String> {
    use std::collections::BTreeSet;
    use std::ffi::CString;
    use std::os::unix::ffi::OsStrExt;
    use std::path::Path;
    use std::sync::atomic::Ordering;
    use std::time::{Duration, Instant};

    use crate::live::probe::perf::{UPROBE_PMU_TYPE_PATH, read_uprobe_pmu_type};
    use crate::live::probe::tracefs::read_tid_set;
    use crate::live::probe::types::ProbeStopReason;
    use crate::live::procfs::refresh_session_identity;

    let pmu_type = read_uprobe_pmu_type(Path::new(UPROBE_PMU_TYPE_PATH))?;
    let exec_path = Path::new("/proc").join(session.process.pid.to_string()).join("exe");
    let exec_cstr = CString::new(exec_path.as_os_str().as_bytes())
        .map_err(|_| "invalid NUL byte in /proc/<pid>/exe path".to_owned())?;
    let mut counters = Vec::new();
    let mut covered = BTreeSet::new();
    for tid in read_tid_set(task_dir)? {
        counters.push(open_arm_counter(pmu_type, &exec_cstr, target.file_offset, tid)?);
        covered.insert(tid);
    }
    let mut last_recheck = Instant::now();
    let mut last_heartbeat = Instant::now();
    loop {
        if counters.iter_mut().any(|c| c.read().is_ok_and(|n| n > 0)) {
            return Ok(None);
        }
        if cfg.cancel.is_some_and(|flag| flag.load(Ordering::Relaxed)) {
            return Ok(Some(ProbeStopReason::Interrupted));
        }
        if deadline.is_some_and(|dl| Instant::now() >= dl) {
            return Ok(Some(ProbeStopReason::DurationElapsed));
        }
        if let Some(hb_ms) = cfg.heartbeat_ms
            && last_heartbeat.elapsed() >= Duration::from_millis(hb_ms)
        {
            last_heartbeat = Instant::now();
            emit_watch_heartbeat(0, session.process.pid_alive_after, false, None);
        }
        if last_recheck.elapsed() >= Duration::from_millis(25) {
            last_recheck = Instant::now();
            refresh_session_identity(session);
            if session.process.process_changed {
                return Ok(Some(ProbeStopReason::ProcessChanged));
            }
            if !session.process.pid_alive_after {
                return Ok(Some(ProbeStopReason::ProcessExited));
            }
            // Counters are inherited by threads created later; a thread that appeared between the
            // first task scan and its parent's counter is added here.
            for tid in read_tid_set(task_dir).unwrap_or_default() {
                if covered.insert(tid)
                    && let Ok(counter) = open_arm_counter(pmu_type, &exec_cstr, target.file_offset, tid)
                {
                    counters.push(counter);
                }
            }
        }
        std::thread::sleep(Duration::from_millis(1));
    }
}

#[cfg(target_os = "linux")]
fn open_arm_counter(
    pmu_type: u32,
    exec_cstr: &std::ffi::CString,
    file_offset: u64,
    tid: u32,
) -> Result<perf_event::Counter, String> {
    use std::path::Path;

    use perf_event::{Builder, events::Software};

    use crate::live::probe::perf::{PERF_PARANOID_PATH, format_perf_open_error, read_perf_event_paranoid};

    let pid = i32::try_from(tid).map_err(|_| format!("TID {tid} overflows pid_t"))?;
    let mut builder = Builder::new(Software::DUMMY);
    builder.observe_pid(pid).any_cpu().inherit(true).remove_on_exec(true);
    {
        let attrs = builder.attrs_mut();
        attrs.type_ = pmu_type;
        attrs.config = 0;
        attrs.kprobe_func = exec_cstr.as_ptr() as usize as u64;
        attrs.probe_offset = file_offset;
    }
    let paranoid = || read_perf_event_paranoid(Path::new(PERF_PARANOID_PATH));
    let mut counter = builder.build().map_err(|err| {
        format_perf_open_error(&format!("arm uprobe tid={tid} file_offset={file_offset:#x}"), &err, paranoid())
    })?;
    counter.enable().map_err(|err| format_perf_open_error("PERF_EVENT_IOC_ENABLE (arm)", &err, paranoid()))?;
    Ok(counter)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn arm_result_reports_armed_only_with_a_time() {
        let target = ArmTarget { static_va: 0x0040_1230, runtime_va: 0x5555_5555_5230, file_offset: 0x1230 };
        let armed = WatchArmResult::new(target, Some(120_000));
        assert!(armed.armed);
        assert_eq!(armed.armed_after_ms, Some(120_000));
        let json = serde_json::to_value(WatchArmResult::new(target, None)).unwrap_or_default();
        assert_eq!(json["armed"], false);
        assert!(json.get("armed_after_ms").is_none());
    }
}
