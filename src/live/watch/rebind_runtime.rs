/*
 * XRef — Stage L3 Increment 2 runtime dependent watch state and transition applicator
 * Copyright (c) 2026 Alexander Panasenko
 * Contact: alex@prod.codes
 * Author: https://prod.codes/about/
 * Project: https://github.com/alex09x/xref
 * SPDX-License-Identifier: MIT OR Apache-2.0
 */

//! Tracks live binding state, generation counter, root/intermediate slot indices, and leaf
//! `WatchAccumulator` for `--follow` dependent watches during `xref live watch`.

#[cfg(target_os = "linux")]
use crate::live::cli::{WatchAccessMode, WatchLen};
use crate::live::memscan::ReadAt;
use crate::live::types::HexAddr;
#[cfg(any(target_os = "linux", test))]
use crate::live::types::RegionEntry;
use crate::live::watch::perf_stream::WatchAccumulator;
#[cfg(any(target_os = "linux", test))]
use crate::live::watch::rebind::evaluate_dependent_chain;
use crate::live::watch::rebind::{
    DependentBindingState, DependentWatchResult, DependentWatchSpec, EvaluatedChain, RebindEvent, RebindTransitionKind,
    RootLivenessStatus,
};
use crate::live::watch::types::WatchTargetSpec;
pub use crate::live::watch::validate::prepare_dependent_watches;

#[derive(Clone, Debug)]
pub struct RuntimeDependentWatch {
    pub spec: DependentWatchSpec,
    pub ptr_slot_spec: WatchTargetSpec,
    pub active_ptr_slot_spec: Option<WatchTargetSpec>,
    pub header_slot_spec: Option<WatchTargetSpec>,
    pub resolved_len_slot_va: Option<u64>,
    pub resolved_guard_slot_va: Option<u64>,
    pub ptr_slot_watch_index: usize,
    pub header_slot_watch_index: Option<usize>,
    pub leaf_watch_index: usize,
    pub state: DependentBindingState,
    pub liveness: RootLivenessStatus,
    pub generation: u32,
    pub active_leaf_spec: Option<WatchTargetSpec>,
    pub initial_leaf_snapshot: Option<HexAddr>,
    pub observed_len: Option<u64>,
    pub rebind_events: Vec<RebindEvent>,
    pub root_ptr_slot_hits: u64,
    pub leaf_acc: WatchAccumulator,
}

impl RuntimeDependentWatch {
    pub fn apply_evaluated(&mut self, eval: EvaluatedChain, is_initial: bool) -> bool {
        let ptr_slot_changed = self.active_ptr_slot_spec.as_ref().map(|s| s.runtime_va)
            != eval.ptr_slot_spec.as_ref().map(|s| s.runtime_va);
        if let Some(new_ptr) = &eval.ptr_slot_spec {
            self.ptr_slot_spec = new_ptr.clone();
        }
        self.active_ptr_slot_spec = eval.ptr_slot_spec;

        let (old_leaf_va, new_leaf_va) =
            (self.active_leaf_spec.as_ref().map(|s| s.runtime_va), eval.leaf_spec.as_ref().map(|s| s.runtime_va));
        let (old_len, old_state) = (self.observed_len, self.state);
        self.state = eval.state;
        self.liveness = eval.liveness;
        self.observed_len = eval.observed_len;

        if let Some(new_spec) = eval.leaf_spec {
            let new_va = new_spec.runtime_va;
            if is_initial || old_leaf_va.is_none() || old_leaf_va != Some(new_va) {
                let transition = if is_initial || old_leaf_va.is_none() {
                    if self.initial_leaf_snapshot.is_none() {
                        self.initial_leaf_snapshot = new_spec.initial_snapshot;
                    }
                    RebindTransitionKind::InitialBind
                } else {
                    RebindTransitionKind::RelocatedBuffer
                };
                self.generation = self.generation.saturating_add(1);
                self.rebind_events.push(RebindEvent {
                    generation: self.generation,
                    transition,
                    old_leaf_va: old_leaf_va.map(HexAddr),
                    new_leaf_va: Some(HexAddr(new_va)),
                    observed_len: eval.observed_len,
                    detail: eval.detail,
                });
                self.active_leaf_spec = Some(new_spec);
                return true;
            }
            if old_len.is_some() && eval.observed_len.is_some() && old_len != eval.observed_len {
                let (o, n) = (old_len.unwrap_or(0), eval.observed_len.unwrap_or(0));
                self.rebind_events.push(RebindEvent {
                    generation: self.generation,
                    transition: RebindTransitionKind::InPlaceResize,
                    old_leaf_va: old_leaf_va.map(HexAddr),
                    new_leaf_va: Some(HexAddr(new_va)),
                    observed_len: eval.observed_len,
                    detail: format!("in_place_resize old_len={o} new_len={n}"),
                });
            }
            self.active_leaf_spec = Some(new_spec);
            return ptr_slot_changed;
        }

        if old_leaf_va.is_some()
            || (is_initial && eval.state != DependentBindingState::Bound)
            || old_state != eval.state
        {
            let transition = match eval.state {
                DependentBindingState::DisarmedBoundsViolation => RebindTransitionKind::DisarmedBoundsViolation,
                DependentBindingState::DisarmedGuardMismatch => RebindTransitionKind::DisarmedGuardMismatch,
                DependentBindingState::DisarmedTornRead => RebindTransitionKind::DisarmedTornRead,
                _ => RebindTransitionKind::DisarmedNullOrUnmapped,
            };
            self.rebind_events.push(RebindEvent {
                generation: self.generation,
                transition,
                old_leaf_va: old_leaf_va.map(HexAddr),
                new_leaf_va: None,
                observed_len: eval.observed_len,
                detail: eval.detail,
            });
        }
        self.active_leaf_spec = None;
        old_leaf_va.is_some() || new_leaf_va.is_some() || ptr_slot_changed
    }

    #[cfg(any(target_os = "linux", test))]
    #[must_use]
    pub fn into_result(self, mem_reader: Option<&dyn ReadAt>) -> DependentWatchResult {
        crate::live::watch::validate::build_dependent_watch_result(self, mem_reader)
    }
}

#[cfg(any(target_os = "linux", test))]
pub trait WatchSlotSampler {
    fn watch_index(&self) -> usize;
    fn tid(&self) -> u32;
    fn runtime_va(&self) -> u64;
    fn disable(&mut self);
}

#[cfg(target_os = "linux")]
impl WatchSlotSampler for crate::live::watch::perf::ActiveWatchSampler {
    fn watch_index(&self) -> usize {
        self.watch_index
    }
    fn tid(&self) -> u32 {
        self.tid
    }
    fn runtime_va(&self) -> u64 {
        self.runtime_va
    }
    fn disable(&mut self) {
        let _ = self.sampler.disable();
    }
}

#[cfg(any(target_os = "linux", test))]
pub fn sync_live_watch_tids<S: WatchSlotSampler>(
    samplers: &mut Vec<S>,
    ctx: &mut crate::live::watch::perf_stream::WatchDrainCtx<'_>,
    live_tids: &std::collections::BTreeSet<u32>,
) {
    let mut dropped = 0_u64;
    ctx.pending_new_tids.retain(|tid| {
        let alive = live_tids.contains(tid);
        if !alive && !ctx.attached_tids.contains(tid) {
            dropped = dropped.saturating_add(1);
        }
        alive
    });
    if dropped > 0 {
        ctx.unattached_fork_tids = ctx.unattached_fork_tids.saturating_add(dropped);
        crate::live::watch::perf_stream::push_unique_reason(
            &mut ctx.coverage_gap_reasons,
            "short_lived_dynamic_tid_exited_before_attach",
        );
    }
    ctx.attached_tids.retain(|tid| live_tids.contains(tid));
    samplers.iter_mut().filter(|s| !ctx.attached_tids.contains(&s.tid())).for_each(WatchSlotSampler::disable);
    samplers.retain(|s| ctx.attached_tids.contains(&s.tid()));
    for &tid in live_tids {
        if !ctx.attached_tids.contains(&tid) {
            ctx.pending_new_tids.insert(tid);
        }
    }
}

#[cfg(any(target_os = "linux", test))]
pub fn reconcile_dependent_watch_entry<S, F>(
    dep: &mut RuntimeDependentWatch,
    regions: &[RegionEntry],
    mem_reader: Option<&dyn ReadAt>,
    samplers: &mut Vec<S>,
    attached_tids: &std::collections::BTreeSet<u32>,
    reasons: &mut Vec<String>,
    open_and_enable: &mut F,
) where
    S: WatchSlotSampler,
    F: FnMut(usize, &WatchTargetSpec, u32) -> Result<S, &'static str>,
{
    samplers.iter_mut().filter(|s| !attached_tids.contains(&s.tid())).for_each(WatchSlotSampler::disable);
    samplers.retain(|s| attached_tids.contains(&s.tid()));
    let eval = evaluate_dependent_chain(
        &dep.spec,
        regions,
        mem_reader,
        dep.ptr_slot_spec.runtime_va,
        dep.header_slot_spec.as_ref().map(|s| s.runtime_va),
        dep.resolved_len_slot_va,
        dep.resolved_guard_slot_va,
    );
    let _ = dep.apply_evaluated(eval, false);
    let ptr_ok = sync_slot_samplers_with(
        samplers,
        attached_tids,
        dep.ptr_slot_watch_index,
        dep.active_ptr_slot_spec.as_ref(),
        reasons,
        open_and_enable,
    );
    let leaf_ok = sync_slot_samplers_with(
        samplers,
        attached_tids,
        dep.leaf_watch_index,
        dep.active_leaf_spec.as_ref(),
        reasons,
        open_and_enable,
    );
    if (!ptr_ok || !leaf_ok) && dep.state == DependentBindingState::Bound {
        dep.state = DependentBindingState::RebindAttachRetryPending;
    }
}

#[cfg(any(target_os = "linux", test))]
fn sync_slot_samplers_with<S, F>(
    samplers: &mut Vec<S>,
    attached_tids: &std::collections::BTreeSet<u32>,
    watch_index: usize,
    desired: Option<&WatchTargetSpec>,
    reasons: &mut Vec<String>,
    open_and_enable: &mut F,
) -> bool
where
    S: WatchSlotSampler,
    F: FnMut(usize, &WatchTargetSpec, u32) -> Result<S, &'static str>,
{
    use crate::live::watch::perf_stream::push_unique_reason;

    let Some(spec) = desired else {
        samplers.iter_mut().filter(|s| s.watch_index() == watch_index).for_each(WatchSlotSampler::disable);
        samplers.retain(|s| s.watch_index() != watch_index);
        return true;
    };
    samplers
        .iter_mut()
        .filter(|s| s.watch_index() == watch_index && s.runtime_va() != spec.runtime_va)
        .for_each(WatchSlotSampler::disable);
    samplers.retain(|s| s.watch_index() != watch_index || s.runtime_va() == spec.runtime_va);
    let mut all_ok = true;
    for &tid in attached_tids {
        if samplers
            .iter()
            .any(|s| s.watch_index() == watch_index && s.tid() == tid && s.runtime_va() == spec.runtime_va)
        {
            continue;
        }
        match open_and_enable(watch_index, spec, tid) {
            Ok(s) => samplers.push(s),
            Err(reason) => {
                all_ok = false;
                push_unique_reason(reasons, reason);
            }
        }
    }
    all_ok
}

#[cfg(target_os = "linux")]
pub fn reconcile_dependent_watches(
    session: &mut crate::live::procfs::LiveSession,
    samplers: &mut Vec<crate::live::watch::perf::ActiveWatchSampler>,
    ctx: &mut crate::live::watch::perf_stream::WatchDrainCtx<'_>,
    mem_reader: Option<&dyn ReadAt>,
    check_all: bool,
) {
    use crate::live::watch::perf::{ActiveWatchSampler, open_single_watch_sampler};

    let indices: Vec<usize> = if check_all {
        (0..ctx.dependent.len()).collect()
    } else {
        ctx.pending_rebind_indices.iter().copied().collect()
    };
    ctx.pending_rebind_indices.clear();
    if indices.is_empty() {
        return;
    }
    let task_dir = std::path::Path::new("/proc").join(session.process.pid.to_string()).join("task");
    if let Ok(live_tids) = crate::live::probe::tracefs::read_tid_set(&task_dir) {
        sync_live_watch_tids(samplers, ctx, &live_tids);
    }
    let target_id = crate::live::procparse::TargetIdentity {
        dev_major_minor: session
            .exe_dev_ino
            .map(|(d, _)| (((d >> 8) & 0xfff) | ((d >> 32) & !0xfff), (d & 0xff) | ((d >> 12) & !0xff))),
        inode: session.exe_dev_ino.map(|(_, ino)| ino),
        pathname: None,
    };
    if let Ok(maps_raw) = std::fs::read(format!("/proc/{}/maps", session.process.pid))
        && let Ok(parsed) = crate::live::procparse::parse_maps(&maps_raw, None, &target_id)
    {
        session.regions = parsed;
    }
    for dep_idx in indices {
        let Some(dep) = ctx.dependent.get_mut(dep_idx) else { continue };
        let ptr_idx = dep.ptr_slot_watch_index;
        let mut open_fn = |widx: usize, spec: &WatchTargetSpec, tid: u32| -> Result<ActiveWatchSampler, &'static str> {
            let (open_err, en_err) = if widx == ptr_idx {
                ("dependent_ptr_slot_rebind_perf_open_failed", "dependent_ptr_slot_rebind_perf_enable_failed")
            } else {
                ("dependent_leaf_rebind_perf_open_failed", "dependent_leaf_rebind_perf_enable_failed")
            };
            let mut s =
                open_single_watch_sampler(spec, tid, ctx.sample_type, ctx.intr_regs_mask).map_err(|_| open_err)?;
            s.enable().map_err(|_| en_err)?;
            Ok(ActiveWatchSampler { watch_index: widx, tid, runtime_va: spec.runtime_va, sampler: s })
        };
        reconcile_dependent_watch_entry(
            dep,
            &session.regions,
            mem_reader,
            samplers,
            &ctx.attached_tids,
            &mut ctx.coverage_gap_reasons,
            &mut open_fn,
        );
    }
}

#[cfg(target_os = "linux")]
pub fn attach_pending_watch_tids(
    samplers: &mut Vec<crate::live::watch::perf::ActiveWatchSampler>,
    ctx: &mut crate::live::watch::perf_stream::WatchDrainCtx<'_>,
) {
    use crate::live::watch::perf::{MAX_WATCH_SAMPLERS_PER_SESSION, attach_watch_samplers_for_tid};
    use crate::live::watch::perf_stream::push_unique_reason;

    let candidates: Vec<u32> = ctx.pending_new_tids.iter().copied().collect();
    ctx.pending_new_tids.clear();
    let per_tid_slots = ctx.specs.len() + ctx.dependent.iter().map(|d| d.spec.hardware_slots_required()).sum::<usize>();
    for tid in candidates {
        if ctx.attached_tids.contains(&tid) {
            continue;
        }
        if samplers.len().saturating_add(per_tid_slots) > MAX_WATCH_SAMPLERS_PER_SESSION {
            ctx.unattached_fork_tids = ctx.unattached_fork_tids.saturating_add(1);
            push_unique_reason(&mut ctx.coverage_gap_reasons, "sampler_session_cap_exceeded_for_dynamic_tid");
            continue;
        }
        let mut tid_samplers = Vec::with_capacity(per_tid_slots);
        if attach_watch_samplers_for_tid(
            ctx.specs,
            &ctx.dependent,
            tid,
            ctx.sample_type,
            ctx.intr_regs_mask,
            &mut tid_samplers,
        )
        .is_err()
        {
            ctx.unattached_fork_tids = ctx.unattached_fork_tids.saturating_add(1);
            push_unique_reason(&mut ctx.coverage_gap_reasons, "dynamic_tid_perf_event_open_failed");
            continue;
        }
        if !tid_samplers.iter_mut().all(|a| a.sampler.enable().is_ok()) {
            tid_samplers.iter_mut().for_each(WatchSlotSampler::disable);
            ctx.unattached_fork_tids = ctx.unattached_fork_tids.saturating_add(1);
            push_unique_reason(&mut ctx.coverage_gap_reasons, "dynamic_tid_perf_enable_failed");
            continue;
        }
        samplers.extend(tid_samplers);
        ctx.attached_tids.insert(tid);
        ctx.dynamically_attached_tids = ctx.dynamically_attached_tids.saturating_add(1);
        let (acc, len) = ctx.specs.first().map_or((WatchAccessMode::Write, WatchLen::B8), |s| (s.access, s.len_bytes));
        crate::live::watch::types::emit_watch_ready_stderr(
            ctx.target_pid,
            &ctx.attached_tids,
            ctx.specs,
            &ctx.dependent,
            acc,
            len,
        );
        push_unique_reason(&mut ctx.coverage_gap_reasons, "dynamic_tid_inherit_false_pre_attach_window");
    }
}
