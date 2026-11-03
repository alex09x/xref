/*
 * XRef — Shared typed live-adapter capability matrix for Stage L2/L3 binary & tracefs backends
 * Copyright (c) 2026 Alexander Panasenko
 * Contact: alex@prod.codes
 * Author: https://prod.codes/about/
 * Project: https://github.com/alex09x/xref
 * SPDX-License-Identifier: MIT OR Apache-2.0
 */

//! Exposes adapter-specific capabilities (`requested`, `available`, `collected`, `detail`)
//! without clamping results to the lowest-common-denominator intersection of backends.

use serde::Serialize;

use crate::live::probe::types::{ProbeTargetSpec, UnwindEntryStatus};

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum FieldAvailability {
    Supported,
    Unsupported,
    Unknown,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct FieldCapability {
    pub requested: bool,
    pub available: FieldAvailability,
    pub collected: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub detail: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct ProbeCapabilities {
    pub hit_counts: FieldCapability,
    pub timestamp_ns: FieldCapability,
    pub tgid_tid: FieldCapability,
    pub callers: FieldCapability,
    pub registers: FieldCapability,
    pub pid_isolated_breakpoint: FieldCapability,
    pub silent_fallback_permitted: bool,
}

#[must_use]
pub fn build_perf_capabilities(specs: &[ProbeTargetSpec], want_callers: bool, want_regs: bool) -> ProbeCapabilities {
    let any_caller_cfi = specs.iter().any(|s| !matches!(s.unwind_entry_abi, UnwindEntryStatus::Unavailable { .. }));
    let all_caller_cfi = specs.iter().all(|s| !matches!(s.unwind_entry_abi, UnwindEntryStatus::Unavailable { .. }));
    let caller_detail = if !want_callers {
        Some("not_requested".to_owned())
    } else if all_caller_cfi {
        Some("perf_sample_stack_user_plus_eh_frame_cfi_and_preceding_call_check".to_owned())
    } else if any_caller_cfi {
        Some("partial_cfi_coverage_some_targets_lack_eh_frame_unwind".to_owned())
    } else {
        Some("no_target_has_verifiable_eh_frame_unwind".to_owned())
    };

    ProbeCapabilities {
        hit_counts: FieldCapability {
            requested: true,
            available: FieldAvailability::Supported,
            collected: true,
            detail: Some("perf_record_sample_tgid_verified_with_perf_record_lost_accounting".to_owned()),
        },
        timestamp_ns: FieldCapability {
            requested: true,
            available: FieldAvailability::Supported,
            collected: true,
            detail: Some("perf_sample_time_clock_monotonic_ns".to_owned()),
        },
        tgid_tid: FieldCapability {
            requested: true,
            available: FieldAvailability::Supported,
            collected: true,
            detail: Some("perf_sample_tid_kernel_pid_tgid_and_tid".to_owned()),
        },
        callers: FieldCapability {
            requested: want_callers,
            available: if any_caller_cfi { FieldAvailability::Supported } else { FieldAvailability::Unsupported },
            collected: want_callers && any_caller_cfi,
            detail: caller_detail,
        },
        registers: FieldCapability {
            requested: want_regs,
            available: FieldAvailability::Supported,
            collected: want_regs,
            detail: Some(if want_regs {
                "perf_sample_regs_user_x86_64_raw_bits_do_not_prove_source_types".to_owned()
            } else {
                "not_requested".to_owned()
            }),
        },
        pid_isolated_breakpoint: FieldCapability {
            requested: true,
            available: FieldAvailability::Supported,
            collected: true,
            detail: Some("perf_uprobe_attaches_mm_filter_to_target_task_and_cleans_up_on_fd_close".to_owned()),
        },
        silent_fallback_permitted: false,
    }
}

#[must_use]
pub fn build_tracefs_capabilities(
    specs: &[ProbeTargetSpec],
    want_callers: bool,
    want_regs: bool,
    record_tgid_enabled: bool,
) -> ProbeCapabilities {
    let any_caller_cfi = specs.iter().any(|s| s.ra_fetch_arg.is_some());
    let all_caller_cfi = specs.iter().all(|s| s.ra_fetch_arg.is_some());
    let caller_detail = if !want_callers {
        Some("not_requested".to_owned())
    } else if all_caller_cfi {
        Some("tracefs_stack_fetcharg_plus_eh_frame_cfi_and_preceding_call_check".to_owned())
    } else if any_caller_cfi {
        Some("partial_cfi_coverage_some_targets_lack_eh_frame_unwind".to_owned())
    } else {
        Some("no_target_has_verifiable_eh_frame_unwind".to_owned())
    };

    ProbeCapabilities {
        hit_counts: FieldCapability {
            requested: true,
            available: FieldAvailability::Supported,
            collected: true,
            detail: Some("isolated_tracefs_instance_stream_with_per_cpu_stats_loss_accounting".to_owned()),
        },
        timestamp_ns: FieldCapability {
            requested: true,
            available: FieldAvailability::Supported,
            collected: true,
            detail: Some("trace_clock_mono_parsed_to_ns".to_owned()),
        },
        tgid_tid: FieldCapability {
            requested: true,
            available: if record_tgid_enabled { FieldAvailability::Supported } else { FieldAvailability::Unknown },
            collected: true,
            detail: Some(if record_tgid_enabled {
                "tracefs_record_tgid_plus_proc_task_verification".to_owned()
            } else {
                "record_tgid_unavailable_using_proc_task_tgid_lookup".to_owned()
            }),
        },
        callers: FieldCapability {
            requested: want_callers,
            available: if any_caller_cfi { FieldAvailability::Supported } else { FieldAvailability::Unsupported },
            collected: want_callers && any_caller_cfi,
            detail: caller_detail,
        },
        registers: FieldCapability {
            requested: want_regs,
            available: FieldAvailability::Supported,
            collected: want_regs,
            detail: Some(if want_regs {
                "tracefs_pt_regs_fetchargs_raw_bits_do_not_prove_source_types".to_owned()
            } else {
                "not_requested".to_owned()
            }),
        },
        pid_isolated_breakpoint: FieldCapability {
            requested: true,
            available: FieldAvailability::Unsupported,
            collected: false,
            detail: Some("trace_uprobe_registers_inode_wide_null_mm_filter_even_with_isolated_instance".to_owned()),
        },
        silent_fallback_permitted: false,
    }
}
