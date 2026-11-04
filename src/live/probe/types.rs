/*
 * XRef — Stage L2 Linux uprobe hit counts, caller attribution, and register sampling
 * Copyright (c) 2026 Alexander Panasenko
 * Contact: alex@prod.codes
 * Author: https://prod.codes/about/
 * Project: https://github.com/alex09x/xref
 * SPDX-License-Identifier: MIT OR Apache-2.0
 */

//! Structured output contracts (`schema_version: 1`) and internal target specs for `xref live probe`.

use serde::Serialize;

use crate::live::probe::capabilities::ProbeCapabilities;
use crate::live::types::{HexAddr, ProcessMeta};

pub const MAX_REGISTER_SAMPLES_PER_PROBE: usize = 16;
pub const REGISTER_SEMANTICS_CAVEAT: &str = "raw_register_bits_do_not_prove_source_types";

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ProbeStopReason {
    DurationElapsed,
    MaxEvents,
    UntilHits,
    Interrupted,
    ProcessExited,
    ProcessChanged,
}

impl ProbeStopReason {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::DurationElapsed => "duration_elapsed",
            Self::MaxEvents => "max_events",
            Self::UntilHits => "until_hits",
            Self::Interrupted => "interrupted",
            Self::ProcessExited => "process_exited",
            Self::ProcessChanged => "process_changed",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum LostEvents {
    Known { overrun: u64, commit_overrun: u64, dropped_events: u64, perf_lost_records: u64, total: u64 },
    Unknown { reason: String },
}

impl LostEvents {
    #[must_use]
    pub const fn has_possible_loss(&self) -> bool {
        match self {
            Self::Known { total, .. } => *total > 0,
            Self::Unknown { .. } => true,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct ThreadCoverage {
    pub seeded_tids: usize,
    pub dynamically_attached_tids: usize,
    pub unattached_fork_tids: u64,
    pub event_fork_enabled: bool,
    pub record_tgid_enabled: bool,
    pub excluded_other_tgid_events: u64,
    pub ambiguous_tid_events: u64,
    pub unparsed_events: u64,
    pub partial_coverage: bool,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub partial_coverage_reasons: Vec<String>,
    pub note: &'static str,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct ProbeObservation {
    pub duration_requested_ms: u64,
    pub elapsed_ms: u64,
    pub max_events: usize,
    pub stop_reason: ProbeStopReason,
    pub truncated_by_max_events: bool,
    pub thread_coverage: ThreadCoverage,
    pub thread_changes: Vec<ThreadChange>,
    pub thread_changes_truncated: bool,
    pub every: usize,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub first: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub until_hits: Option<usize>,
    pub lost_events: LostEvents,
    pub counts_are_lower_bound: bool,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct ThreadChange {
    pub tid: u32,
    pub action: &'static str,
}

pub const MAX_THREAD_CHANGES: usize = 4096;

pub fn record_thread_change(changes: &mut Vec<ThreadChange>, truncated: &mut bool, tid: u32, action: &'static str) {
    if changes.len() < MAX_THREAD_CHANGES {
        changes.push(ThreadChange { tid, action });
    } else {
        *truncated = true;
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum UnwindEntryStatus {
    StandardRsp8RaMinus8,
    InteriorFrameOffset { base_register: &'static str, disp: i64 },
    Unavailable { detail: String },
}

impl UnwindEntryStatus {
    #[must_use]
    pub const fn summary_tag(&self) -> &'static str {
        match self {
            Self::StandardRsp8RaMinus8 => "entry_rsp+8_ra-8",
            Self::InteriorFrameOffset { .. } => "interior_cfi_offset",
            Self::Unavailable { .. } => "cfi_unavailable",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct CallerEntry {
    pub raw_return_runtime_va: HexAddr,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub return_static_va: Option<HexAddr>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub caller_function: Option<HexAddr>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub caller_symbol: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub call_site_static_va: Option<HexAddr>,
    pub call_verified: bool,
    pub hits: u64,
    pub caveat: &'static str,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct RegisterSample {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tgid: Option<u32>,
    pub tid: u32,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub timestamp_ns: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ip: Option<HexAddr>,
    pub rdi: HexAddr,
    pub rsi: HexAddr,
    pub rdx: HexAddr,
    pub rcx: HexAddr,
    pub r8: HexAddr,
    pub r9: HexAddr,
    pub rax: HexAddr,
    pub rsp: HexAddr,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rbp: Option<HexAddr>,
    pub caveat: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mark: Option<String>,
}

#[derive(Clone, Debug)]
pub struct ProbeTargetSpec {
    pub input: u64,
    pub static_va: u64,
    pub runtime_va: u64,
    pub file_offset: u64,
    pub function_start: Option<u64>,
    pub function_end: Option<u64>,
    pub function_offset: Option<u64>,
    pub symbol: Option<String>,
    pub instruction_mnemonic: String,
    pub unwind_entry_abi: UnwindEntryStatus,
    pub ra_fetch_arg: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct ProbeTargetResult {
    pub input: HexAddr,
    pub static_va: HexAddr,
    pub runtime_va: HexAddr,
    pub file_offset: HexAddr,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub function_start: Option<HexAddr>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub function_end: Option<HexAddr>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub function_offset: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub symbol: Option<String>,
    pub instruction_mnemonic: String,
    pub unwind_entry_abi: UnwindEntryStatus,
    pub accepted_hits: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub first_timestamp_ns: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_timestamp_ns: Option<u64>,
    pub callers: Vec<CallerEntry>,
    pub register_samples_truncated: bool,
    pub register_samples: Vec<RegisterSample>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub fetched_samples: Vec<FetchedSample>,
    #[serde(skip_serializing_if = "is_false")]
    pub fetched_samples_truncated: bool,
}

#[allow(clippy::trivially_copy_pass_by_ref)] // serde's skip_serializing_if callback accepts &T.
const fn is_false(value: &bool) -> bool {
    !*value
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct FetchedValue {
    pub name: String,
    pub value: HexAddr,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct FetchedSample {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub va: Option<HexAddr>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tid: Option<u32>,
    pub timestamp_ns: u64,
    pub values: Vec<FetchedValue>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ret: Option<HexAddr>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mark: Option<String>,
}

pub const MAX_FETCH_SAMPLES_PER_PROBE: usize = 128;
pub const MAX_FETCHED_VALUES_PER_SESSION: usize = 512;

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct ProbeReport {
    pub schema_version: u32,
    pub tool: &'static str,
    pub tool_version: &'static str,
    pub operation: &'static str,
    pub backend: &'static str,
    pub backend_selection: &'static str,
    pub capabilities: ProbeCapabilities,
    pub process: ProcessMeta,
    pub observation: ProbeObservation,
    pub probes: Vec<ProbeTargetResult>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub groups: Option<Vec<crate::live::probe::group::GroupEntry>>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct ProbeReadyReceipt {
    pub backend: &'static str,
    pub pid: u32,
    pub attached_tids: Vec<u32>,
    pub probes: Vec<HexAddr>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tracefs_instance: Option<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub uprobe_events: Vec<String>,
}

pub fn emit_probe_ready_stderr(
    backend: &'static str,
    pid: u32,
    tids: &std::collections::BTreeSet<u32>,
    specs: &[ProbeTargetSpec],
    tracefs_instance: Option<&str>,
    uprobe_events: &[String],
) {
    use std::io::Write;
    let receipt = ProbeReadyReceipt {
        backend,
        pid,
        attached_tids: tids.iter().copied().collect(),
        probes: specs.iter().map(|s| HexAddr(s.static_va)).collect(),
        tracefs_instance: tracefs_instance.map(str::to_owned),
        uprobe_events: uprobe_events.to_vec(),
    };
    if let Ok(json) = serde_json::to_string(&receipt) {
        let mut stderr = std::io::stderr().lock();
        let _ = writeln!(stderr, "xref: probe_ready {json}");
        let _ = stderr.flush();
    }
}
