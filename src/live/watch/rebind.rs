/*
 * XRef — Stage L3 Increment 2 dependent watch model (`--follow`) and rebind state machine
 * Copyright (c) 2026 Alexander Panasenko
 * Contact: alex@prod.codes
 * Author: https://prod.codes/about/
 * Project: https://github.com/alex09x/xref
 * SPDX-License-Identifier: MIT OR Apache-2.0
 */

//! Generic dependent watch model (`root / pointer_slot + offset` -> leaf target range) with
//! bounded 2-pass `/proc/<pid>/mem` consistency checks, optional bounds (`len_slot >= min_len`)
//! and owner identity (`guard_slot == guard_val`) checks, and explicit rebind/disarm transitions.

#[cfg(any(target_os = "linux", test))]
use serde::Serialize;

use crate::live::cli::{WatchAccessMode, WatchLen};
#[cfg(any(target_os = "linux", test))]
use crate::live::{
    classify::find_region,
    memscan::ReadAt,
    types::{HexAddr, RegionEntry},
    watch::{
        types::{WatchHitSample, WatchTargetSpec, WriterSiteEntry},
        validate::read_watch_scalar,
    },
};

pub const MAX_REBIND_SNAPSHOT_RETRIES: usize = 3;
pub const DEPENDENT_REBIND_GAP_REASON: &str = "dependent_watch_async_rebind_and_non_atomic_proc_mem_gap";
pub const DEPENDENT_REBIND_CAVEAT: &str = "leaf_rebind_uses_two_pass_proc_mem_read_never_sample_store_value_and_cannot_prove_allocator_lifetime_without_guard";

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DependentWatchSpec {
    pub raw_spec: String,
    pub header_ptr_slot: Option<u64>,
    pub header_offset: u64,
    pub ptr_slot: u64,
    pub offset: u64,
    pub len_slot: Option<u64>,
    pub min_len: u64,
    pub guard_slot: Option<u64>,
    pub guard_val: Option<u64>,
    pub leaf_len: WatchLen,
    pub leaf_access: WatchAccessMode,
}

impl DependentWatchSpec {
    #[must_use]
    pub const fn hardware_slots_required(&self) -> usize {
        if self.header_ptr_slot.is_some() { 3 } else { 2 }
    }
}

#[cfg(any(target_os = "linux", test))]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum DependentBindingState {
    Bound,
    DisarmedNullOrUnmapped,
    DisarmedBoundsViolation,
    DisarmedGuardMismatch,
    DisarmedTornRead,
    LostHeaderBinding,
}

#[cfg(any(target_os = "linux", test))]
impl DependentBindingState {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Bound => "bound",
            Self::DisarmedNullOrUnmapped => "disarmed_null_or_unmapped",
            Self::DisarmedBoundsViolation => "disarmed_bounds_violation",
            Self::DisarmedGuardMismatch => "disarmed_guard_mismatch",
            Self::DisarmedTornRead => "disarmed_torn_read",
            Self::LostHeaderBinding => "lost_header_binding",
        }
    }
}

#[cfg(any(target_os = "linux", test))]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RootLivenessStatus {
    AssumedLiveWithoutAllocatorProof,
    GuardVerifiedWithoutAllocatorProof,
    InvalidatedByNullOrBounds,
    InvalidatedByGuardMismatch,
    InvalidatedByTornRead,
}

#[cfg(any(target_os = "linux", test))]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RebindTransitionKind {
    InitialBind,
    InPlaceResize,
    RelocatedBuffer,
    DisarmedNullOrUnmapped,
    DisarmedBoundsViolation,
    DisarmedGuardMismatch,
    DisarmedTornRead,
}

#[cfg(any(target_os = "linux", test))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct RebindEvent {
    pub generation: u32,
    pub transition: RebindTransitionKind,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub old_leaf_va: Option<HexAddr>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub new_leaf_va: Option<HexAddr>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub observed_len: Option<u64>,
    pub detail: String,
}

#[cfg(any(target_os = "linux", test))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct DependentWatchResult {
    pub spec: String,
    pub hardware_slots_reserved: usize,
    pub ptr_slot_runtime_va: HexAddr,
    pub leaf_offset: u64,
    pub leaf_len_bytes: u8,
    pub leaf_access: &'static str,
    pub binding_state: DependentBindingState,
    pub root_liveness: RootLivenessStatus,
    pub generation: u32,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub active_leaf_runtime_va: Option<HexAddr>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub active_leaf_region: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub observed_len: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub initial_leaf_snapshot: Option<HexAddr>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub latest_leaf_snapshot: Option<HexAddr>,
    pub rebind_coverage_gap: bool,
    pub caveat: &'static str,
    pub root_ptr_slot_hits: u64,
    pub accepted_hits: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub first_timestamp_ns: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_timestamp_ns: Option<u64>,
    pub rebind_events: Vec<RebindEvent>,
    pub writer_sites: Vec<WriterSiteEntry>,
    pub samples_truncated: bool,
    pub samples: Vec<WatchHitSample>,
}

#[cfg(any(target_os = "linux", test))]
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EvaluatedChain {
    pub state: DependentBindingState,
    pub liveness: RootLivenessStatus,
    pub resolved_ptr_slot_va: u64,
    pub leaf_spec: Option<WatchTargetSpec>,
    pub observed_len: Option<u64>,
    pub detail: String,
}

#[cfg(any(target_os = "linux", test))]
impl EvaluatedChain {
    #[must_use]
    pub fn disarmed(
        state: DependentBindingState,
        liveness: RootLivenessStatus,
        resolved_ptr_slot_va: u64,
        observed_len: Option<u64>,
        detail: impl Into<String>,
    ) -> Self {
        Self { state, liveness, resolved_ptr_slot_va, leaf_spec: None, observed_len, detail: detail.into() }
    }
}

pub fn parse_follow_spec(
    raw: &str,
    default_len: WatchLen,
    default_access: WatchAccessMode,
) -> Result<DependentWatchSpec, String> {
    let (mut header_ptr_slot, mut ptr_slot, mut len_slot, mut min_len, mut guard_slot, mut guard_val) =
        (None, None, None, None, None, None);
    let (mut header_offset, mut offset) = (0_u64, 0_u64);
    for part in raw.split(',').map(str::trim).filter(|s| !s.is_empty()) {
        let (k, v) = part
            .split_once('=')
            .ok_or_else(|| format!("invalid --follow token '{part}' in '{raw}': expected key=value"))?;
        let val = crate::cli::parse_number(v.trim())
            .map_err(|e| format!("invalid numeric value for '{k}' in --follow '{raw}': {e}"))?;
        match k.trim() {
            "ptr_slot" => ptr_slot = Some(val),
            "offset" => offset = val,
            "len_slot" => len_slot = Some(val),
            "min_len" => min_len = Some(val),
            "guard_slot" => guard_slot = Some(val),
            "guard_val" => guard_val = Some(val),
            "header_ptr_slot" => header_ptr_slot = Some(val),
            "header_offset" => header_offset = val,
            other => {
                return Err(format!(
                    "unknown --follow key '{other}': supported keys are ptr_slot, offset, len_slot, min_len, guard_slot, guard_val, header_ptr_slot, header_offset"
                ));
            }
        }
    }
    let ptr_slot = ptr_slot.ok_or_else(|| format!("invalid --follow '{raw}': missing required key ptr_slot=<ADDR>"))?;
    if guard_slot.is_some() != guard_val.is_some() {
        return Err(format!("invalid --follow '{raw}': guard_slot and guard_val must be specified together"));
    }
    let min_len = min_len.unwrap_or_else(|| offset.saturating_add(u64::from(default_len.as_u8())));
    Ok(DependentWatchSpec {
        raw_spec: raw.to_owned(),
        header_ptr_slot,
        header_offset,
        ptr_slot,
        offset,
        len_slot,
        min_len,
        guard_slot,
        guard_val,
        leaf_len: default_len,
        leaf_access: default_access,
    })
}

#[cfg(any(target_os = "linux", test))]
#[derive(Clone, Copy, PartialEq, Eq)]
struct ChainPassSnapshot {
    effective_ptr_slot_va: u64,
    ptr_val: u64,
    len_val: Option<u64>,
    guard_val: Option<u64>,
}

#[cfg(any(target_os = "linux", test))]
fn read_chain_pass(
    reader: &dyn ReadAt,
    spec: &DependentWatchSpec,
    slots: (u64, Option<u64>, Option<u64>, Option<u64>),
) -> Option<ChainPassSnapshot> {
    let (base_ptr_slot_va, resolved_header_slot_va, resolved_len_slot_va, resolved_guard_slot_va) = slots;
    let effective_ptr_slot_va = if let Some(hdr_slot) = resolved_header_slot_va {
        let hdr_base = read_watch_scalar(reader, hdr_slot, WatchLen::B8)?.0;
        if hdr_base == 0 {
            return Some(ChainPassSnapshot { effective_ptr_slot_va: 0, ptr_val: 0, len_val: None, guard_val: None });
        }
        hdr_base.checked_add(spec.header_offset)?
    } else {
        base_ptr_slot_va
    };
    let guard_val = resolved_guard_slot_va.and_then(|g_va| read_watch_scalar(reader, g_va, WatchLen::B8)).map(|h| h.0);
    if resolved_guard_slot_va.is_some() && guard_val.is_none() {
        return None;
    }
    let ptr_val = read_watch_scalar(reader, effective_ptr_slot_va, WatchLen::B8)?.0;
    let len_val = resolved_len_slot_va.and_then(|l_va| read_watch_scalar(reader, l_va, WatchLen::B8)).map(|h| h.0);
    if resolved_len_slot_va.is_some() && len_val.is_none() {
        return None;
    }
    Some(ChainPassSnapshot { effective_ptr_slot_va, ptr_val, len_val, guard_val })
}

#[cfg(any(target_os = "linux", test))]
pub fn evaluate_dependent_chain(
    spec: &DependentWatchSpec,
    regions: &[RegionEntry],
    reader: Option<&dyn ReadAt>,
    base_ptr_slot_va: u64,
    resolved_header_slot_va: Option<u64>,
    resolved_len_slot_va: Option<u64>,
    resolved_guard_slot_va: Option<u64>,
) -> EvaluatedChain {
    let Some(mem) = reader else {
        return EvaluatedChain::disarmed(
            DependentBindingState::DisarmedTornRead,
            RootLivenessStatus::InvalidatedByTornRead,
            base_ptr_slot_va,
            None,
            "proc_mem_unavailable_for_dependent_chain",
        );
    };
    let slots = (base_ptr_slot_va, resolved_header_slot_va, resolved_len_slot_va, resolved_guard_slot_va);
    let pass = || read_chain_pass(mem, spec, slots);
    let Some(snap) = (0..MAX_REBIND_SNAPSHOT_RETRIES).find_map(|_| {
        let (p1, p2) = (pass()?, pass()?);
        (p1 == p2).then_some(p1)
    }) else {
        return EvaluatedChain::disarmed(
            DependentBindingState::DisarmedTornRead,
            RootLivenessStatus::InvalidatedByTornRead,
            base_ptr_slot_va,
            None,
            "two_pass_proc_mem_snapshot_inconsistent_or_unreadable",
        );
    };
    if snap.effective_ptr_slot_va == 0 {
        return EvaluatedChain::disarmed(
            DependentBindingState::LostHeaderBinding,
            RootLivenessStatus::InvalidatedByNullOrBounds,
            0,
            None,
            "header_ptr_slot_is_null",
        );
    }
    if let (Some(exp), Some(act)) = (spec.guard_val, snap.guard_val)
        && act != exp
    {
        return EvaluatedChain::disarmed(
            DependentBindingState::DisarmedGuardMismatch,
            RootLivenessStatus::InvalidatedByGuardMismatch,
            snap.effective_ptr_slot_va,
            snap.len_val,
            format!("guard_mismatch expected={exp:#x} actual={act:#x}"),
        );
    }
    if let Some(len) = snap.len_val
        && len < spec.min_len
    {
        return EvaluatedChain::disarmed(
            DependentBindingState::DisarmedBoundsViolation,
            RootLivenessStatus::InvalidatedByNullOrBounds,
            snap.effective_ptr_slot_va,
            Some(len),
            format!("len_slot={len} < min_len={}", spec.min_len),
        );
    }
    build_bound_leaf_chain(spec, regions, mem, &snap)
}

#[cfg(any(target_os = "linux", test))]
fn build_bound_leaf_chain(
    spec: &DependentWatchSpec,
    regions: &[RegionEntry],
    mem: &dyn ReadAt,
    snap: &ChainPassSnapshot,
) -> EvaluatedChain {
    let null_or_bounds = |d: String| {
        EvaluatedChain::disarmed(
            DependentBindingState::DisarmedNullOrUnmapped,
            RootLivenessStatus::InvalidatedByNullOrBounds,
            snap.effective_ptr_slot_va,
            snap.len_val,
            d,
        )
    };
    if snap.ptr_val == 0 {
        return null_or_bounds("ptr_slot_value_is_null".to_owned());
    }
    let (len_u64, Some(leaf_va)) = (u64::from(spec.leaf_len.as_u8()), snap.ptr_val.checked_add(spec.offset)) else {
        return null_or_bounds("leaf_va_overflow".to_owned());
    };
    if !leaf_va.is_multiple_of(len_u64) {
        return null_or_bounds(format!("unaligned_leaf_va={leaf_va:#x}"));
    }
    let Some(region) = find_region(regions, leaf_va) else {
        return null_or_bounds(format!("unmapped_leaf_va={leaf_va:#x}"));
    };
    if leaf_va.saturating_add(len_u64) > region.end.0
        || (spec.leaf_access == WatchAccessMode::Write && !region.perms.contains('w'))
    {
        return null_or_bounds(format!("inaccessible_leaf_region={leaf_va:#x}"));
    }
    let liveness = if spec.guard_val.is_some() {
        RootLivenessStatus::GuardVerifiedWithoutAllocatorProof
    } else {
        RootLivenessStatus::AssumedLiveWithoutAllocatorProof
    };
    let (region_str, perms, access, len_bytes) =
        (region.format_location(leaf_va), region.perms.clone(), spec.leaf_access, spec.leaf_len);
    let initial_snapshot = read_watch_scalar(mem, leaf_va, len_bytes);
    let leaf_spec = WatchTargetSpec {
        input: leaf_va,
        runtime_va: leaf_va,
        static_va: None,
        region: region_str,
        perms,
        access,
        len_bytes,
        initial_snapshot,
    };
    EvaluatedChain {
        state: DependentBindingState::Bound,
        liveness,
        resolved_ptr_slot_va: snap.effective_ptr_slot_va,
        leaf_spec: Some(leaf_spec),
        observed_len: snap.len_val,
        detail: format!("bound_leaf_va={leaf_va:#x}"),
    }
}
