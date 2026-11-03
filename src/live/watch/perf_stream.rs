/*
 * XRef — Stage L3 nonblocking perf hardware watchpoint ring drain loop and dynamic TID tracker
 * Copyright (c) 2026 Alexander Panasenko
 * Contact: alex@prod.codes
 * Author: https://prod.codes/about/
 * Project: https://github.com/alex09x/xref
 * SPDX-License-Identifier: MIT OR Apache-2.0
 */

//! Nonblocking `mmap` ring drain loop for `xref live watch`, dynamic `/proc/<pid>/task/*` thread
//! attachment (`DR0`–`DR3`), post-execution `trap_ip` attribution, and dependent-watch rebind.

use std::collections::{BTreeMap, BTreeSet};
#[cfg(target_os = "linux")]
use std::path::Path;
#[cfg(target_os = "linux")]
use std::time::{Duration, Instant};

use crate::image::Image;
#[cfg(target_os = "linux")]
use crate::live::memscan::ReadAt;
#[cfg(any(target_os = "linux", test))]
use crate::live::probe::perf_ring::PerfDecodeError;
#[cfg(target_os = "linux")]
use crate::live::probe::types::ProbeStopReason;
#[cfg(target_os = "linux")]
use crate::live::procfs::{LiveSession, refresh_session_identity};
use crate::live::types::{HexAddr, RegionEntry};
#[cfg(target_os = "linux")]
use crate::live::watch::perf::{ActiveWatchSampler, decode_watch_record};
#[cfg(any(target_os = "linux", test))]
use crate::live::watch::perf::{DecodedWatchRecord, WatchSampleEvent};
#[cfg(target_os = "linux")]
use crate::live::watch::rebind::DEPENDENT_REBIND_GAP_REASON;
#[cfg(not(target_os = "linux"))]
use crate::live::watch::rebind_runtime::RuntimeDependentWatch;
#[cfg(target_os = "linux")]
use crate::live::watch::rebind_runtime::{
    RuntimeDependentWatch, attach_pending_watch_tids, reconcile_dependent_watches,
};
use crate::live::watch::types::{MAX_WATCH_SAMPLES_PER_TARGET, WatchHitSample, WatchTargetSpec, WriterSiteEntry};
use crate::live::watch::writer::{WriterStaticCache, attribute_watch_trap_cached};

#[derive(Clone, Debug, Default)]
pub struct WatchAccumulator {
    pub accepted_hits: u64,
    pub first_timestamp_ns: Option<u64>,
    pub last_timestamp_ns: Option<u64>,
    pub writer_sites: BTreeMap<u64, WriterSiteEntry>,
    pub samples_truncated: bool,
    pub samples: Vec<WatchHitSample>,
}

pub struct WatchDrainCtx<'a> {
    pub target_pid: u32,
    pub sample_type: u64,
    pub intr_regs_mask: u64,
    pub want_regs: bool,
    pub specs: &'a [WatchTargetSpec],
    pub dependent: Vec<RuntimeDependentWatch>,
    pub pending_rebind_indices: BTreeSet<usize>,
    pub attached_tids: BTreeSet<u32>,
    pub pending_new_tids: BTreeSet<u32>,
    pub dynamically_attached_tids: usize,
    pub unattached_fork_tids: u64,
    pub excluded_other_tgid: u64,
    pub ambiguous_tid: u64,
    pub perf_lost_records: u64,
    pub decode_errors: u64,
    pub total_accepted: usize,
    pub hit_max_events: bool,
    pub coverage_gap_reasons: Vec<String>,
    pub accumulators: Vec<WatchAccumulator>,
    pub writer_cache: WriterStaticCache,
}

impl<'a> WatchDrainCtx<'a> {
    #[cfg(test)]
    #[must_use]
    pub fn new(
        target_pid: u32,
        sample_type: u64,
        intr_regs_mask: u64,
        want_regs: bool,
        specs: &'a [WatchTargetSpec],
        attached_tids: BTreeSet<u32>,
    ) -> Self {
        Self::with_dependent(target_pid, sample_type, intr_regs_mask, want_regs, specs, Vec::new(), attached_tids)
    }

    #[must_use]
    pub fn with_dependent(
        target_pid: u32,
        sample_type: u64,
        intr_regs_mask: u64,
        want_regs: bool,
        specs: &'a [WatchTargetSpec],
        dependent: Vec<RuntimeDependentWatch>,
        attached_tids: BTreeSet<u32>,
    ) -> Self {
        let mut coverage_gap_reasons = Vec::new();
        if !dependent.is_empty() {
            coverage_gap_reasons.push(DEPENDENT_REBIND_GAP_REASON.to_owned());
        }
        Self {
            target_pid,
            sample_type,
            intr_regs_mask,
            want_regs,
            specs,
            dependent,
            pending_rebind_indices: BTreeSet::new(),
            attached_tids,
            pending_new_tids: BTreeSet::new(),
            dynamically_attached_tids: 0,
            unattached_fork_tids: 0,
            excluded_other_tgid: 0,
            ambiguous_tid: 0,
            perf_lost_records: 0,
            decode_errors: 0,
            total_accepted: 0,
            hit_max_events: false,
            coverage_gap_reasons,
            accumulators: (0..specs.len()).map(|_| WatchAccumulator::default()).collect(),
            writer_cache: WriterStaticCache::default(),
        }
    }
}

#[cfg(target_os = "linux")]
pub fn run_watch_loop(
    session: &mut LiveSession,
    task_dir: &Path,
    samplers: &mut Vec<ActiveWatchSampler>,
    ctx: &mut WatchDrainCtx<'_>,
    mem_reader: Option<&dyn ReadAt>,
    max_events: usize,
    deadline: Instant,
) -> ProbeStopReason {
    use crate::live::probe::tracefs::read_tid_set;

    let mut last_recheck = Instant::now();
    loop {
        let progressed = drain_watch_samplers(session, samplers, ctx, max_events);
        if !ctx.pending_rebind_indices.is_empty() {
            reconcile_dependent_watches(session, samplers, ctx, mem_reader, false);
        }
        if ctx.total_accepted >= max_events {
            return ProbeStopReason::MaxEvents;
        }
        if Instant::now() >= deadline {
            return ProbeStopReason::DurationElapsed;
        }
        if last_recheck.elapsed() >= Duration::from_millis(25) {
            refresh_session_identity(session);
            last_recheck = Instant::now();
            if session.process.process_changed {
                return ProbeStopReason::ProcessChanged;
            }
            if !session.process.pid_alive_after {
                return ProbeStopReason::ProcessExited;
            }
            if let Ok(live_tids) = read_tid_set(task_dir) {
                crate::live::watch::rebind_runtime::sync_live_watch_tids(samplers, ctx, &live_tids);
            }
            if !ctx.dependent.is_empty() {
                reconcile_dependent_watches(session, samplers, ctx, mem_reader, true);
            }
        }
        attach_pending_watch_tids(samplers, ctx);
        if !progressed {
            let rem = deadline.saturating_duration_since(Instant::now());
            if !rem.is_zero() {
                std::thread::sleep(rem.min(Duration::from_millis(2)));
            }
        }
    }
}

#[cfg(any(target_os = "linux", test))]
pub fn push_unique_reason(reasons: &mut Vec<String>, reason: &str) {
    if !reasons.iter().any(|r| r == reason) {
        reasons.push(reason.to_owned());
    }
}

#[cfg(target_os = "linux")]
pub fn drain_watch_samplers(
    session: &LiveSession,
    samplers: &mut [ActiveWatchSampler],
    ctx: &mut WatchDrainCtx<'_>,
    max_events: usize,
) -> bool {
    let mut any_record = false;
    for active in samplers {
        loop {
            if ctx.total_accepted >= max_events || !ctx.pending_rebind_indices.is_empty() {
                if ctx.total_accepted >= max_events {
                    ctx.hit_max_events = true;
                }
                break;
            }
            let Some(rec) = active.sampler.next_record() else { break };
            any_record = true;
            let bytes = rec.to_contiguous();
            let decoded = decode_watch_record(rec.ty(), rec.misc(), &bytes, ctx.sample_type, ctx.intr_regs_mask);
            process_decoded_watch_record(
                &session.image,
                session.process.pie_slide,
                &session.regions,
                active.watch_index,
                decoded,
                ctx,
                max_events,
            );
        }
        if ctx.total_accepted >= max_events || !ctx.pending_rebind_indices.is_empty() {
            if ctx.total_accepted >= max_events {
                ctx.hit_max_events = true;
            }
            break;
        }
    }
    any_record
}

#[cfg(any(target_os = "linux", test))]
pub fn process_decoded_watch_record(
    image: &Image,
    pie_slide: i64,
    regions: &[RegionEntry],
    watch_index: usize,
    decoded: Result<DecodedWatchRecord, PerfDecodeError>,
    ctx: &mut WatchDrainCtx<'_>,
    max_events: usize,
) {
    if ctx.total_accepted >= max_events {
        ctx.hit_max_events = true;
        return;
    }
    match decoded {
        Ok(DecodedWatchRecord::Sample(ev)) => {
            handle_watch_sample(image, pie_slide, regions, watch_index, &ev, ctx, max_events);
        }
        Ok(DecodedWatchRecord::Lost { lost, .. }) => {
            ctx.perf_lost_records = ctx.perf_lost_records.saturating_add(lost);
        }
        Ok(DecodedWatchRecord::Fork { tgid, thread_id, .. }) => {
            if tgid == ctx.target_pid && !ctx.attached_tids.contains(&thread_id) {
                ctx.pending_new_tids.insert(thread_id);
            }
        }
        Ok(DecodedWatchRecord::Exit { tgid, thread_id, .. }) => {
            if tgid == ctx.target_pid {
                let was_attached = ctx.attached_tids.remove(&thread_id);
                if ctx.pending_new_tids.remove(&thread_id) && !was_attached {
                    ctx.unattached_fork_tids = ctx.unattached_fork_tids.saturating_add(1);
                    push_unique_reason(&mut ctx.coverage_gap_reasons, "short_lived_dynamic_tid_exited_before_attach");
                }
            }
        }
        Ok(DecodedWatchRecord::Other { .. }) => {}
        Err(_) => {
            ctx.decode_errors = ctx.decode_errors.saturating_add(1);
        }
    }
}

#[cfg(any(target_os = "linux", test))]
fn handle_watch_sample(
    image: &Image,
    pie_slide: i64,
    regions: &[RegionEntry],
    watch_index: usize,
    ev: &WatchSampleEvent,
    ctx: &mut WatchDrainCtx<'_>,
    max_events: usize,
) {
    match ev.tgid {
        Some(tgid) if tgid != ctx.target_pid => {
            ctx.excluded_other_tgid = ctx.excluded_other_tgid.saturating_add(1);
            return;
        }
        None => {
            ctx.ambiguous_tid = ctx.ambiguous_tid.saturating_add(1);
            return;
        }
        Some(_) => {}
    }

    if let Some((dep_idx, is_root_slot)) = ctx.dependent.iter().enumerate().find_map(|(idx, d)| {
        if d.ptr_slot_watch_index == watch_index || d.header_slot_watch_index == Some(watch_index) {
            Some((idx, true))
        } else if d.leaf_watch_index == watch_index {
            Some((idx, false))
        } else {
            None
        }
    }) {
        if is_root_slot {
            ctx.dependent[dep_idx].root_ptr_slot_hits = ctx.dependent[dep_idx].root_ptr_slot_hits.saturating_add(1);
            ctx.pending_rebind_indices.insert(dep_idx);
            return;
        }
        if ctx.pending_rebind_indices.contains(&dep_idx) {
            push_unique_reason(
                &mut ctx.coverage_gap_reasons,
                "dependent_leaf_sample_dropped_while_root_rebind_pending",
            );
            return;
        }
        let Some(leaf_spec) = ctx.dependent[dep_idx].active_leaf_spec.clone() else { return };
        if ctx.total_accepted >= max_events {
            ctx.hit_max_events = true;
            return;
        }
        ctx.total_accepted += 1;
        if ctx.total_accepted >= max_events {
            ctx.hit_max_events = true;
        }
        record_sample_into_acc(
            &mut ctx.writer_cache,
            (image, pie_slide, regions),
            &leaf_spec,
            &mut ctx.dependent[dep_idx].leaf_acc,
            ev,
            ctx.want_regs,
        );
        return;
    }

    let Some(spec) = ctx.specs.get(watch_index) else { return };
    let Some(acc) = ctx.accumulators.get_mut(watch_index) else { return };
    if ctx.total_accepted >= max_events {
        ctx.hit_max_events = true;
        return;
    }
    ctx.total_accepted += 1;
    if ctx.total_accepted >= max_events {
        ctx.hit_max_events = true;
    }
    record_sample_into_acc(&mut ctx.writer_cache, (image, pie_slide, regions), spec, acc, ev, ctx.want_regs);
}

#[cfg(any(target_os = "linux", test))]
fn record_sample_into_acc(
    writer_cache: &mut WriterStaticCache,
    target: (&Image, i64, &[RegionEntry]),
    spec: &WatchTargetSpec,
    acc: &mut WatchAccumulator,
    ev: &WatchSampleEvent,
    want_regs: bool,
) {
    let (image, pie_slide, regions) = target;
    acc.accepted_hits = acc.accepted_hits.saturating_add(1);
    if let Some(ts) = ev.timestamp_ns {
        acc.first_timestamp_ns = Some(acc.first_timestamp_ns.map_or(ts, |prev| prev.min(ts)));
        acc.last_timestamp_ns = Some(acc.last_timestamp_ns.map_or(ts, |prev| prev.max(ts)));
    }
    let trap_ip = ev.ip.unwrap_or(0);
    let attr =
        attribute_watch_trap_cached(writer_cache, image, pie_slide, regions, spec, trap_ip, ev.intr_regs.as_ref());

    acc.writer_sites.entry(trap_ip).and_modify(|site| site.hits = site.hits.saturating_add(1)).or_insert_with(|| {
        WriterSiteEntry {
            trap_runtime_ip: HexAddr(trap_ip),
            trap_static_ip: attr.trap_static_ip.map(HexAddr),
            candidate_writer_static_ip: attr.candidate_writer_static_ip.map(HexAddr),
            candidate_writer_mnemonic: attr.candidate_writer_mnemonic.clone(),
            candidate_writer_text: attr.candidate_writer_text.clone(),
            writer_function: attr.writer_function.map(HexAddr),
            writer_function_offset: attr.writer_function_offset,
            writer_symbol: attr.writer_symbol.clone(),
            confidence: attr.confidence,
            hits: 1,
            caveat: attr.caveat,
        }
    });

    if acc.samples.len() < MAX_WATCH_SAMPLES_PER_TARGET {
        acc.samples.push(WatchHitSample {
            tgid: ev.tgid,
            tid: ev.thread_id.unwrap_or(0),
            timestamp_ns: ev.timestamp_ns,
            trap_runtime_ip: HexAddr(trap_ip),
            trap_static_ip: attr.trap_static_ip.map(HexAddr),
            candidate_writer_static_ip: attr.candidate_writer_static_ip.map(HexAddr),
            candidate_writer_text: attr.candidate_writer_text,
            writer_function: attr.writer_function.map(HexAddr),
            writer_symbol: attr.writer_symbol,
            confidence: attr.confidence,
            written_value: attr.written_value,
            regs: want_regs.then_some(ev.intr_regs).flatten(),
        });
    } else {
        acc.samples_truncated = true;
    }
}
