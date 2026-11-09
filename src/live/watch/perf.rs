/*
 * XRef — Stage L3 hardware data watchpoint perf_event_open + mmap binary ring collector
 * Copyright (c) 2026 Alexander Panasenko
 * Contact: alex@prod.codes
 * Author: https://prod.codes/about/
 * Project: https://github.com/alex09x/xref
 * SPDX-License-Identifier: MIT OR Apache-2.0
 */

//! Opens per-TID `PERF_TYPE_BREAKPOINT` (`HW_BREAKPOINT_W` / `HW_BREAKPOINT_RW`) hardware debug
//! registers (`DR0`–`DR3`), decodes `PERF_SAMPLE_REGS_INTR` binary records, and attributes hits.

use std::sync::atomic::AtomicBool;
use std::time::Duration;

#[cfg(any(target_os = "linux", test))]
use crate::live::probe::perf_ring::{
    PERF_RECORD_EXIT, PERF_RECORD_FORK, PERF_RECORD_LOST, PERF_RECORD_SAMPLE, PERF_REG_X86_AX, PERF_REG_X86_BP,
    PERF_REG_X86_CX, PERF_REG_X86_DI, PERF_REG_X86_DX, PERF_REG_X86_R8, PERF_REG_X86_R9, PERF_REG_X86_SI,
    PERF_REG_X86_SP, PERF_SAMPLE_IP, PERF_SAMPLE_REGS_ABI_64, PERF_SAMPLE_REGS_ABI_NONE, PERF_SAMPLE_TID,
    PERF_SAMPLE_TIME, PerfDecodeError, reg_from_mask,
};
use crate::live::probe::types::ProbeObservation;
use crate::live::procfs::LiveSession;
#[cfg(any(target_os = "linux", test))]
use crate::live::types::HexAddr;
use crate::live::watch::rebind::DependentWatchResult;
use crate::live::watch::rebind_runtime::RuntimeDependentWatch;
#[cfg(any(target_os = "linux", test))]
use crate::live::watch::types::WatchRegsSnapshot;
use crate::live::watch::types::{WatchTargetResult, WatchTargetSpec};

pub const PERF_SAMPLE_REGS_INTR: u64 = 1 << 18;
pub const PERF_REG_X86_BX: u32 = 1;
pub const PERF_REG_X86_R10: u32 = 18;
pub const PERF_REG_X86_R11: u32 = 19;
pub const PERF_REG_X86_R12: u32 = 20;
pub const PERF_REG_X86_R13: u32 = 21;
pub const PERF_REG_X86_R14: u32 = 22;
pub const PERF_REG_X86_R15: u32 = 23;

#[cfg(any(target_os = "linux", test))]
pub const XREF_WATCH_INTR_REGS_MASK: u64 = (1_u64 << PERF_REG_X86_AX)
    | (1_u64 << PERF_REG_X86_BX)
    | (1_u64 << PERF_REG_X86_CX)
    | (1_u64 << PERF_REG_X86_DX)
    | (1_u64 << PERF_REG_X86_SI)
    | (1_u64 << PERF_REG_X86_DI)
    | (1_u64 << PERF_REG_X86_BP)
    | (1_u64 << PERF_REG_X86_SP)
    | (1_u64 << PERF_REG_X86_R8)
    | (1_u64 << PERF_REG_X86_R9)
    | (1_u64 << PERF_REG_X86_R10)
    | (1_u64 << PERF_REG_X86_R11)
    | (1_u64 << PERF_REG_X86_R12)
    | (1_u64 << PERF_REG_X86_R13)
    | (1_u64 << PERF_REG_X86_R14)
    | (1_u64 << PERF_REG_X86_R15);

#[cfg(target_os = "linux")]
pub const MAX_WATCH_SAMPLERS_PER_SESSION: usize = 256;
#[cfg(target_os = "linux")]
const RING_DATA_BYTES_PER_SAMPLER: usize = 32 * 1024;

#[derive(Clone, Copy, Debug)]
pub struct WatchRunConfig<'a> {
    pub duration: Duration,
    pub max_events: usize,
    pub want_regs: bool,
    pub cancel: Option<&'a AtomicBool>,
    /// Which accepted hits are kept as samples.
    pub keep: crate::live::watch::samples::SampleKeep,
}

#[cfg(any(target_os = "linux", test))]
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct WatchSampleEvent {
    pub ip: Option<u64>,
    pub tgid: Option<u32>,
    pub thread_id: Option<u32>,
    pub timestamp_ns: Option<u64>,
    pub intr_regs: Option<WatchRegsSnapshot>,
}

#[cfg(any(target_os = "linux", test))]
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum DecodedWatchRecord {
    Sample(WatchSampleEvent),
    Lost { event_id: u64, lost: u64 },
    Fork { tgid: u32, parent_tgid: u32, thread_id: u32, parent_tid: u32, timestamp_ns: u64 },
    Exit { tgid: u32, thread_id: u32, timestamp_ns: u64 },
    Other { rec_type: u32 },
}

#[cfg(any(target_os = "linux", test))]
pub fn decode_watch_record(
    rec_type: u32,
    _misc: u16,
    payload: &[u8],
    sample_type: u64,
    intr_regs_mask: u64,
) -> Result<DecodedWatchRecord, PerfDecodeError> {
    let mut pos = 0_usize;
    match rec_type {
        PERF_RECORD_LOST => {
            let event_id = read_u64(payload, &mut pos)?;
            let lost = read_u64(payload, &mut pos)?;
            Ok(DecodedWatchRecord::Lost { event_id, lost })
        }
        PERF_RECORD_FORK => {
            let tgid = read_u32(payload, &mut pos)?;
            let spawner_tgid = read_u32(payload, &mut pos)?;
            let thread_id = read_u32(payload, &mut pos)?;
            let spawner_thread = read_u32(payload, &mut pos)?;
            let timestamp_ns = read_u64(payload, &mut pos)?;
            Ok(DecodedWatchRecord::Fork {
                tgid,
                parent_tgid: spawner_tgid,
                thread_id,
                parent_tid: spawner_thread,
                timestamp_ns,
            })
        }
        PERF_RECORD_EXIT => {
            let tgid = read_u32(payload, &mut pos)?;
            let _spawner_tgid = read_u32(payload, &mut pos)?;
            let thread_id = read_u32(payload, &mut pos)?;
            let _spawner_thread = read_u32(payload, &mut pos)?;
            let timestamp_ns = read_u64(payload, &mut pos)?;
            Ok(DecodedWatchRecord::Exit { tgid, thread_id, timestamp_ns })
        }
        PERF_RECORD_SAMPLE => {
            let ip = if sample_type & PERF_SAMPLE_IP != 0 { Some(read_u64(payload, &mut pos)?) } else { None };
            let (tgid, thread_id) = if sample_type & PERF_SAMPLE_TID != 0 {
                let g = read_u32(payload, &mut pos)?;
                let t = read_u32(payload, &mut pos)?;
                (Some(g), Some(t))
            } else {
                (None, None)
            };
            let timestamp_ns =
                if sample_type & PERF_SAMPLE_TIME != 0 { Some(read_u64(payload, &mut pos)?) } else { None };
            let intr_regs = if sample_type & PERF_SAMPLE_REGS_INTR != 0 {
                let abi = read_u64(payload, &mut pos)?;
                if abi == PERF_SAMPLE_REGS_ABI_NONE {
                    None
                } else if abi == PERF_SAMPLE_REGS_ABI_64 {
                    let count = intr_regs_mask.count_ones() as usize;
                    let mut words = Vec::with_capacity(count);
                    for _ in 0..count {
                        words.push(read_u64(payload, &mut pos)?);
                    }
                    extract_watch_regs(&words, intr_regs_mask)
                } else {
                    return Err(PerfDecodeError::UnexpectedRegsAbi { abi });
                }
            } else {
                None
            };
            Ok(DecodedWatchRecord::Sample(WatchSampleEvent { ip, tgid, thread_id, timestamp_ns, intr_regs }))
        }
        other => Ok(DecodedWatchRecord::Other { rec_type: other }),
    }
}

#[cfg(any(target_os = "linux", test))]
fn extract_watch_regs(words: &[u64], mask: u64) -> Option<WatchRegsSnapshot> {
    let r = |reg: u32| Some(HexAddr(reg_from_mask(words, mask, reg)?));
    Some(WatchRegsSnapshot {
        rax: r(PERF_REG_X86_AX)?,
        rbx: r(PERF_REG_X86_BX)?,
        rcx: r(PERF_REG_X86_CX)?,
        rdx: r(PERF_REG_X86_DX)?,
        rsi: r(PERF_REG_X86_SI)?,
        rdi: r(PERF_REG_X86_DI)?,
        rbp: r(PERF_REG_X86_BP)?,
        rsp: r(PERF_REG_X86_SP)?,
        r8: r(PERF_REG_X86_R8)?,
        r9: r(PERF_REG_X86_R9)?,
        r10: r(PERF_REG_X86_R10)?,
        r11: r(PERF_REG_X86_R11)?,
        r12: r(PERF_REG_X86_R12)?,
        r13: r(PERF_REG_X86_R13)?,
        r14: r(PERF_REG_X86_R14)?,
        r15: r(PERF_REG_X86_R15)?,
    })
}

#[cfg(any(target_os = "linux", test))]
fn read_u32(payload: &[u8], pos: &mut usize) -> Result<u32, PerfDecodeError> {
    let available = payload.len().saturating_sub(*pos);
    let end = pos.checked_add(4).ok_or(PerfDecodeError::TruncatedRecord { needed: usize::MAX, available })?;
    let s = payload.get(*pos..end).ok_or(PerfDecodeError::TruncatedRecord { needed: 4, available })?;
    *pos = end;
    Ok(u32::from_le_bytes([s[0], s[1], s[2], s[3]]))
}

#[cfg(any(target_os = "linux", test))]
fn read_u64(payload: &[u8], pos: &mut usize) -> Result<u64, PerfDecodeError> {
    let available = payload.len().saturating_sub(*pos);
    let end = pos.checked_add(8).ok_or(PerfDecodeError::TruncatedRecord { needed: usize::MAX, available })?;
    let s = payload.get(*pos..end).ok_or(PerfDecodeError::TruncatedRecord { needed: 8, available })?;
    *pos = end;
    Ok(u64::from_le_bytes([s[0], s[1], s[2], s[3], s[4], s[5], s[6], s[7]]))
}

#[cfg(not(target_os = "linux"))]
pub fn run_perf_watch(
    _session: &mut LiveSession,
    _specs: &[WatchTargetSpec],
    _dependent: Vec<RuntimeDependentWatch>,
    _cfg: &WatchRunConfig<'_>,
    _mem_reader: Option<&dyn crate::live::memscan::ReadAt>,
) -> Result<(ProbeObservation, Vec<WatchTargetResult>, Vec<DependentWatchResult>), String> {
    Err("unsupported_platform: perf_event_open hardware watchpoints require Linux x86-64".to_owned())
}

#[cfg(target_os = "linux")]
pub struct ActiveWatchSampler {
    pub watch_index: usize,
    pub tid: u32,
    pub runtime_va: u64,
    pub sampler: perf_event::Sampler,
}

#[cfg(target_os = "linux")]
pub fn run_perf_watch(
    session: &mut LiveSession,
    specs: &[WatchTargetSpec],
    dependent: Vec<RuntimeDependentWatch>,
    cfg: &WatchRunConfig<'_>,
    mem_reader: Option<&dyn crate::live::memscan::ReadAt>,
) -> Result<(ProbeObservation, Vec<WatchTargetResult>, Vec<DependentWatchResult>), String> {
    use std::path::Path;
    use std::time::Instant;

    use crate::live::probe::perf::{PERF_PARANOID_PATH, format_perf_open_error, read_perf_event_paranoid};
    use crate::live::probe::tracefs::{read_tid_set, verify_exe_still_matches};
    use crate::live::procfs::refresh_session_identity;
    use crate::live::watch::{
        build_watch_results, finalize_watch_observation,
        perf_stream::{WatchDrainCtx, drain_watch_samplers, run_watch_loop},
        types::emit_watch_ready_stderr,
    };

    let proc_root = Path::new("/proc");
    verify_exe_still_matches(session, proc_root)?;
    let task_dir = proc_root.join(session.process.pid.to_string()).join("task");
    let mut initial_tids = read_tid_set(&task_dir)?;
    if let Ok(pass2) = read_tid_set(&task_dir) {
        initial_tids.extend(pass2);
    }
    if initial_tids.is_empty() {
        return Err(format!("process {} has no active threads in {}", session.process.pid, task_dir.display()));
    }
    let total_slots = specs.len() + dependent.iter().map(|d| d.spec.hardware_slots_required()).sum::<usize>();
    let required = total_slots.saturating_mul(initial_tids.len());
    if required > MAX_WATCH_SAMPLERS_PER_SESSION {
        return Err(format!(
            "target process {} requires {required} hardware watchpoint samplers ({} slots * {} threads), exceeding session cap {MAX_WATCH_SAMPLERS_PER_SESSION}",
            session.process.pid,
            total_slots,
            initial_tids.len()
        ));
    }

    let sample_type = PERF_SAMPLE_IP | PERF_SAMPLE_TID | PERF_SAMPLE_TIME | PERF_SAMPLE_REGS_INTR;
    let intr_regs_mask = XREF_WATCH_INTR_REGS_MASK;
    let mut samplers = Vec::with_capacity(required);
    for &tid in &initial_tids {
        attach_watch_samplers_for_tid(specs, &dependent, tid, sample_type, intr_regs_mask, &mut samplers)?;
    }
    let seeded_tids = initial_tids.len();
    for active in &mut samplers {
        active.sampler.enable().map_err(|e| {
            format_perf_open_error("PERF_EVENT_IOC_ENABLE", &e, read_perf_event_paranoid(Path::new(PERF_PARANOID_PATH)))
        })?;
    }
    emit_watch_ready_stderr(session.process.pid, &initial_tids, specs, &dependent);

    let mut ctx = WatchDrainCtx::with_dependent(
        session.process.pid,
        sample_type,
        intr_regs_mask,
        cfg.want_regs,
        specs,
        dependent,
        initial_tids,
    );
    ctx.keep = cfg.keep;
    let started = Instant::now();
    let stop_reason =
        run_watch_loop(session, &task_dir, &mut samplers, &mut ctx, mem_reader, cfg, started + cfg.duration);
    let elapsed_ms = u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX);

    for active in &mut samplers {
        let _ = active.sampler.disable();
    }
    drain_watch_samplers(session, &mut samplers, &mut ctx, cfg.max_events);
    drop(samplers);
    refresh_session_identity(session);

    let observation = finalize_watch_observation(&ctx, cfg, seeded_tids, elapsed_ms, stop_reason);
    let results = build_watch_results(specs, ctx.accumulators, mem_reader);
    let dep_results = ctx.dependent.into_iter().map(|d| d.into_result(mem_reader)).collect();
    Ok((observation, results, dep_results))
}

#[cfg(target_os = "linux")]
pub fn attach_watch_samplers_for_tid(
    specs: &[WatchTargetSpec],
    dependent: &[RuntimeDependentWatch],
    tid: u32,
    sample_type: u64,
    intr_regs_mask: u64,
    out: &mut Vec<ActiveWatchSampler>,
) -> Result<(), String> {
    let mut push_one = |watch_index: usize, spec: &WatchTargetSpec| -> Result<(), String> {
        let sampler = open_single_watch_sampler(spec, tid, sample_type, intr_regs_mask)?;
        out.push(ActiveWatchSampler { watch_index, tid, runtime_va: spec.runtime_va, sampler });
        Ok(())
    };
    for (watch_index, spec) in specs.iter().enumerate() {
        push_one(watch_index, spec)?;
    }
    for dep in dependent {
        if let Some(ptr_spec) = &dep.active_ptr_slot_spec {
            push_one(dep.ptr_slot_watch_index, ptr_spec)?;
        }
        if let (Some(hdr_spec), Some(hdr_idx)) = (&dep.header_slot_spec, dep.header_slot_watch_index) {
            push_one(hdr_idx, hdr_spec)?;
        }
        if let Some(leaf_spec) = &dep.active_leaf_spec {
            push_one(dep.leaf_watch_index, leaf_spec)?;
        }
    }
    Ok(())
}

#[cfg(target_os = "linux")]
pub fn open_single_watch_sampler(
    spec: &WatchTargetSpec,
    tid: u32,
    sample_type: u64,
    intr_regs_mask: u64,
) -> Result<perf_event::Sampler, String> {
    use std::path::Path;

    use perf_event::{Builder, Clock, events::Breakpoint};

    use crate::live::cli::WatchAccessMode;
    use crate::live::probe::perf::{PERF_PARANOID_PATH, format_perf_open_error, read_perf_event_paranoid};

    let pid_i32 = i32::try_from(tid).map_err(|_| format!("TID {tid} overflows pid_t"))?;
    let len_u64 = u64::from(spec.len_bytes.as_u8());
    let bp = match spec.access {
        WatchAccessMode::Write => Breakpoint::write(spec.runtime_va, len_u64),
        WatchAccessMode::Rw => Breakpoint::read_write(spec.runtime_va, len_u64),
    };
    let mut builder = Builder::new(bp);
    builder
        .observe_pid(pid_i32)
        .any_cpu()
        .inherit(false)
        .remove_on_exec(true)
        .task(true)
        .clockid(Clock::MONOTONIC)
        .sample_period(1)
        .wakeup_events(1);
    {
        let attrs = builder.attrs_mut();
        attrs.sample_type = sample_type;
        attrs.sample_regs_intr = intr_regs_mask;
    }
    let counter = builder.build().map_err(|err| {
        format_perf_open_error(
            &format!(
                "hardware_watchpoint tid={tid} addr={:#x} len={len_u64} access={}",
                spec.runtime_va,
                spec.access.as_str()
            ),
            &err,
            read_perf_event_paranoid(Path::new(PERF_PARANOID_PATH)),
        )
    })?;
    counter.sampled(RING_DATA_BYTES_PER_SAMPLER).map_err(|err| {
        format_perf_open_error(
            &format!("mmap ring tid={tid} addr={:#x}", spec.runtime_va),
            &err,
            read_perf_event_paranoid(Path::new(PERF_PARANOID_PATH)),
        )
    })
}
