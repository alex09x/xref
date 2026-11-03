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

use crate::image::Image;
use crate::live::cli::{WatchAccessMode, WatchLen};
use crate::live::memscan::ReadAt;
use crate::live::types::{HexAddr, RegionEntry};
use crate::live::watch::perf_stream::WatchAccumulator;
use crate::live::watch::rebind::{
    DEPENDENT_REBIND_CAVEAT, DependentBindingState, DependentWatchResult, DependentWatchSpec, EvaluatedChain,
    RebindEvent, RebindTransitionKind, RootLivenessStatus, evaluate_dependent_chain, parse_follow_spec,
};
use crate::live::watch::types::{WatchTargetSpec, WriterSiteEntry};
use crate::live::watch::validate::{read_watch_scalar, resolve_watch_input, validate_slot_watch_target};

#[derive(Clone, Debug)]
pub struct RuntimeDependentWatch {
    pub spec: DependentWatchSpec,
    pub ptr_slot_spec: WatchTargetSpec,
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
        let old_leaf_va = self.active_leaf_spec.as_ref().map(|s| s.runtime_va);
        let new_leaf_va = eval.leaf_spec.as_ref().map(|s| s.runtime_va);
        let old_len = self.observed_len;
        let old_state = self.state;

        self.state = eval.state;
        self.liveness = eval.liveness;
        self.observed_len = eval.observed_len;

        if let Some(new_spec) = eval.leaf_spec {
            if is_initial || old_leaf_va.is_none() {
                self.generation = self.generation.saturating_add(1);
                if self.initial_leaf_snapshot.is_none() {
                    self.initial_leaf_snapshot = new_spec.initial_snapshot;
                }
                self.rebind_events.push(RebindEvent {
                    generation: self.generation,
                    transition: RebindTransitionKind::InitialBind,
                    old_leaf_va: old_leaf_va.map(HexAddr),
                    new_leaf_va: Some(HexAddr(new_spec.runtime_va)),
                    observed_len: eval.observed_len,
                    detail: eval.detail,
                });
                self.active_leaf_spec = Some(new_spec);
                return true;
            }
            if old_leaf_va != Some(new_spec.runtime_va) {
                self.generation = self.generation.saturating_add(1);
                self.rebind_events.push(RebindEvent {
                    generation: self.generation,
                    transition: RebindTransitionKind::RelocatedBuffer,
                    old_leaf_va: old_leaf_va.map(HexAddr),
                    new_leaf_va: Some(HexAddr(new_spec.runtime_va)),
                    observed_len: eval.observed_len,
                    detail: eval.detail,
                });
                self.active_leaf_spec = Some(new_spec);
                return true;
            }
            if old_len.is_some() && eval.observed_len.is_some() && old_len != eval.observed_len {
                self.rebind_events.push(RebindEvent {
                    generation: self.generation,
                    transition: RebindTransitionKind::InPlaceResize,
                    old_leaf_va: old_leaf_va.map(HexAddr),
                    new_leaf_va: Some(HexAddr(new_spec.runtime_va)),
                    observed_len: eval.observed_len,
                    detail: format!(
                        "in_place_resize old_len={} new_len={}",
                        old_len.unwrap_or(0),
                        eval.observed_len.unwrap_or(0)
                    ),
                });
            }
            self.active_leaf_spec = Some(new_spec);
            return false;
        }

        let disarmed_now = old_leaf_va.is_some()
            || (is_initial && eval.state != DependentBindingState::Bound)
            || old_state != eval.state;
        if disarmed_now {
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
        let changed_sampler = old_leaf_va.is_some() || new_leaf_va.is_some();
        self.active_leaf_spec = None;
        changed_sampler
    }

    #[must_use]
    pub fn into_result(self, mem_reader: Option<&dyn ReadAt>) -> DependentWatchResult {
        let latest_leaf_snapshot = self
            .active_leaf_spec
            .as_ref()
            .and_then(|s| mem_reader.and_then(|r| read_watch_scalar(r, s.runtime_va, s.len_bytes)));
        let mut writer_sites: Vec<WriterSiteEntry> = self.leaf_acc.writer_sites.into_values().collect();
        writer_sites.sort_by(|a, b| b.hits.cmp(&a.hits).then_with(|| a.trap_runtime_ip.cmp(&b.trap_runtime_ip)));

        DependentWatchResult {
            spec: self.spec.raw_spec.clone(),
            hardware_slots_reserved: self.spec.hardware_slots_required(),
            ptr_slot_runtime_va: HexAddr(self.ptr_slot_spec.runtime_va),
            leaf_offset: self.spec.offset,
            leaf_len_bytes: self.spec.leaf_len.as_u8(),
            leaf_access: self.spec.leaf_access.as_str(),
            binding_state: self.state,
            root_liveness: self.liveness,
            generation: self.generation,
            active_leaf_runtime_va: self.active_leaf_spec.as_ref().map(|s| HexAddr(s.runtime_va)),
            active_leaf_region: self.active_leaf_spec.as_ref().map(|s| s.region.clone()),
            observed_len: self.observed_len,
            initial_leaf_snapshot: self.initial_leaf_snapshot,
            latest_leaf_snapshot,
            rebind_coverage_gap: true,
            caveat: DEPENDENT_REBIND_CAVEAT,
            root_ptr_slot_hits: self.root_ptr_slot_hits,
            accepted_hits: self.leaf_acc.accepted_hits,
            first_timestamp_ns: self.leaf_acc.first_timestamp_ns,
            last_timestamp_ns: self.leaf_acc.last_timestamp_ns,
            rebind_events: self.rebind_events,
            writer_sites,
            samples_truncated: self.leaf_acc.samples_truncated,
            samples: self.leaf_acc.samples,
        }
    }
}

pub fn prepare_dependent_watches(
    target: (&Image, i64, &[RegionEntry]),
    defaults: (&[String], WatchLen, WatchAccessMode),
    base_watch_idx: usize,
    mem_reader: Option<&dyn ReadAt>,
) -> Result<Vec<RuntimeDependentWatch>, String> {
    let (image, pie_slide, regions) = target;
    let (follow_raw, default_len, default_access) = defaults;
    let mut out = Vec::with_capacity(follow_raw.len());
    let mut next_idx = base_watch_idx;

    for raw in follow_raw {
        let spec = parse_follow_spec(raw, default_len, default_access)?;
        let ptr_slot_spec = validate_slot_watch_target(image, pie_slide, regions, spec.ptr_slot, mem_reader)?;
        let header_slot_spec = match spec.header_ptr_slot {
            Some(hdr_in) => Some(validate_slot_watch_target(image, pie_slide, regions, hdr_in, mem_reader)?),
            None => None,
        };
        let resolved_len_slot_va = match spec.len_slot {
            Some(l_in) => Some(resolve_watch_input(image, pie_slide, regions, l_in)?.0),
            None => None,
        };
        let resolved_guard_slot_va = match spec.guard_slot {
            Some(g_in) => Some(resolve_watch_input(image, pie_slide, regions, g_in)?.0),
            None => None,
        };

        let ptr_slot_watch_index = next_idx;
        next_idx += 1;
        let header_slot_watch_index = if header_slot_spec.is_some() {
            let idx = next_idx;
            next_idx += 1;
            Some(idx)
        } else {
            None
        };
        let leaf_watch_index = next_idx;
        next_idx += 1;

        let mut rt = RuntimeDependentWatch {
            spec,
            ptr_slot_spec,
            header_slot_spec,
            resolved_len_slot_va,
            resolved_guard_slot_va,
            ptr_slot_watch_index,
            header_slot_watch_index,
            leaf_watch_index,
            state: DependentBindingState::DisarmedNullOrUnmapped,
            liveness: RootLivenessStatus::InvalidatedByNullOrBounds,
            generation: 0,
            active_leaf_spec: None,
            initial_leaf_snapshot: None,
            observed_len: None,
            rebind_events: Vec::new(),
            root_ptr_slot_hits: 0,
            leaf_acc: WatchAccumulator::default(),
        };

        let eval = evaluate_dependent_chain(
            &rt.spec,
            regions,
            mem_reader,
            rt.ptr_slot_spec.runtime_va,
            rt.header_slot_spec.as_ref().map(|s| s.runtime_va),
            rt.resolved_len_slot_va,
            rt.resolved_guard_slot_va,
        );
        let _ = rt.apply_evaluated(eval, true);
        out.push(rt);
    }

    Ok(out)
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
    use crate::live::watch::perf_stream::push_unique_reason;

    let indices: Vec<usize> = if check_all {
        (0..ctx.dependent.len()).collect()
    } else {
        ctx.pending_rebind_indices.iter().copied().collect()
    };
    ctx.pending_rebind_indices.clear();

    for dep_idx in indices {
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
        let Some(dep) = ctx.dependent.get_mut(dep_idx) else { continue };
        let eval = evaluate_dependent_chain(
            &dep.spec,
            &session.regions,
            mem_reader,
            dep.ptr_slot_spec.runtime_va,
            dep.header_slot_spec.as_ref().map(|s| s.runtime_va),
            dep.resolved_len_slot_va,
            dep.resolved_guard_slot_va,
        );
        if !dep.apply_evaluated(eval, false) {
            continue;
        }
        let leaf_idx = dep.leaf_watch_index;
        let new_leaf_spec = dep.active_leaf_spec.clone();
        for s in samplers.iter_mut().filter(|s| s.watch_index == leaf_idx) {
            let _ = s.sampler.disable();
        }
        samplers.retain(|s| s.watch_index != leaf_idx);
        if let Some(leaf_spec) = new_leaf_spec {
            for &tid in &ctx.attached_tids {
                if let Ok(mut sampler) = open_single_watch_sampler(&leaf_spec, tid, ctx.sample_type, ctx.intr_regs_mask)
                {
                    if sampler.enable().is_ok() {
                        samplers.push(ActiveWatchSampler { watch_index: leaf_idx, sampler });
                    }
                } else {
                    push_unique_reason(&mut ctx.coverage_gap_reasons, "dependent_leaf_rebind_perf_open_failed");
                }
            }
        }
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
            for active in &mut tid_samplers {
                let _ = active.sampler.disable();
            }
            drop(tid_samplers);
            ctx.unattached_fork_tids = ctx.unattached_fork_tids.saturating_add(1);
            push_unique_reason(&mut ctx.coverage_gap_reasons, "dynamic_tid_perf_enable_failed");
            continue;
        }
        samplers.extend(tid_samplers);
        ctx.attached_tids.insert(tid);
        let (ready_access, ready_len) = ctx
            .specs
            .first()
            .map(|s| (s.access, s.len_bytes))
            .or_else(|| ctx.dependent.first().map(|d| (d.spec.leaf_access, d.spec.leaf_len)))
            .unwrap_or((WatchAccessMode::Write, WatchLen::B8));
        crate::live::watch::types::emit_watch_ready_stderr(
            ctx.target_pid,
            &ctx.attached_tids,
            ctx.specs,
            &ctx.dependent,
            ready_access,
            ready_len,
        );
        push_unique_reason(&mut ctx.coverage_gap_reasons, "dynamic_tid_inherit_false_pre_attach_window");
    }
}
