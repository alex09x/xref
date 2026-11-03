/*
 * XRef — Stage L3 Linux hardware data watchpoints (`DR0`–`DR3`) output contracts
 * Copyright (c) 2026 Alexander Panasenko
 * Contact: alex@prod.codes
 * Author: https://prod.codes/about/
 * Project: https://github.com/alex09x/xref
 * SPDX-License-Identifier: MIT OR Apache-2.0
 */

//! Structured output contracts (`schema_version: 1`) and internal target specs for `xref live watch`.

use serde::Serialize;

use crate::live::cli::{WatchAccessMode, WatchLen};
use crate::live::probe::capabilities::{FieldAvailability, FieldCapability};
use crate::live::probe::types::ProbeObservation;
use crate::live::types::{HexAddr, ProcessMeta};

pub const MAX_WATCH_SAMPLES_PER_TARGET: usize = 32;
pub const WATCH_SNAPSHOT_CAVEAT: &str = "latest_proc_mem_snapshot_not_store_time_value";

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct WatchCapabilities {
    pub hit_counts: FieldCapability,
    pub timestamp_ns: FieldCapability,
    pub tgid_tid: FieldCapability,
    pub trap_ip: FieldCapability,
    pub writer_instruction: FieldCapability,
    pub registers: FieldCapability,
    pub latest_memory_snapshot: FieldCapability,
    pub pid_isolated_watchpoint: FieldCapability,
    pub silent_fallback_permitted: bool,
}

#[must_use]
pub fn build_watch_capabilities(want_regs: bool, mem_snapshot_available: bool) -> WatchCapabilities {
    WatchCapabilities {
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
        trap_ip: FieldCapability {
            requested: true,
            available: FieldAvailability::Supported,
            collected: true,
            detail: Some("x86_64_data_watchpoint_traps_post_execution_at_next_instruction".to_owned()),
        },
        writer_instruction: FieldCapability {
            requested: true,
            available: FieldAvailability::Supported,
            collected: true,
            detail: Some(
                "iced_x86_local_linear_predecessor_candidate_recovery_with_intr_register_operand_decode_assumes_no_indirect_entry"
                    .to_owned(),
            ),
        },
        registers: FieldCapability {
            requested: want_regs,
            available: FieldAvailability::Supported,
            collected: want_regs,
            detail: Some(if want_regs {
                "perf_sample_regs_intr_x86_64_16_gpr_mask_at_trap_delivery".to_owned()
            } else {
                "collected_internally_for_store_value_decode_omitted_from_samples".to_owned()
            }),
        },
        latest_memory_snapshot: FieldCapability {
            requested: true,
            available: if mem_snapshot_available {
                FieldAvailability::Supported
            } else {
                FieldAvailability::Unsupported
            },
            collected: mem_snapshot_available,
            detail: Some(WATCH_SNAPSHOT_CAVEAT.to_owned()),
        },
        pid_isolated_watchpoint: FieldCapability {
            requested: true,
            available: FieldAvailability::Supported,
            collected: true,
            detail: Some("per_tid_perf_type_breakpoint_dr0_dr3_with_fd_close_cleanup".to_owned()),
        },
        silent_fallback_permitted: false,
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum WriterConfidence {
    CandidateLinearPredecessorStore,
    CandidateLinearPredecessorRead,
    AmbiguousBranchTarget,
    UnverifiedMemoryTarget,
    PredecessorNotMemoryAccess,
    OutsideKnownFunction,
    OutsideTargetExecutable,
}

impl WriterConfidence {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::CandidateLinearPredecessorStore => "candidate_linear_predecessor_store",
            Self::CandidateLinearPredecessorRead => "candidate_linear_predecessor_read",
            Self::AmbiguousBranchTarget => "ambiguous_branch_target",
            Self::UnverifiedMemoryTarget => "unverified_memory_target",
            Self::PredecessorNotMemoryAccess => "predecessor_not_memory_access",
            Self::OutsideKnownFunction => "outside_known_function",
            Self::OutsideTargetExecutable => "outside_target_executable",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum WrittenValueRecovery {
    CandidateRegisterStore { register: &'static str, width_bytes: u8, value: HexAddr, caveat: &'static str },
    CandidateImmediateStore { width_bytes: u8, value: HexAddr, caveat: &'static str },
    Unknown { reason: &'static str },
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize)]
pub struct WatchRegsSnapshot {
    pub rax: HexAddr,
    pub rbx: HexAddr,
    pub rcx: HexAddr,
    pub rdx: HexAddr,
    pub rsi: HexAddr,
    pub rdi: HexAddr,
    pub rbp: HexAddr,
    pub rsp: HexAddr,
    pub r8: HexAddr,
    pub r9: HexAddr,
    pub r10: HexAddr,
    pub r11: HexAddr,
    pub r12: HexAddr,
    pub r13: HexAddr,
    pub r14: HexAddr,
    pub r15: HexAddr,
}

impl WatchRegsSnapshot {
    #[must_use]
    pub const fn read_register(&self, reg: iced_x86::Register) -> Option<(&'static str, u64)> {
        use iced_x86::Register;
        match reg {
            Register::RAX | Register::EAX | Register::AX | Register::AL => Some(("rax", self.rax.0)),
            Register::RBX | Register::EBX | Register::BX | Register::BL => Some(("rbx", self.rbx.0)),
            Register::RCX | Register::ECX | Register::CX | Register::CL => Some(("rcx", self.rcx.0)),
            Register::RDX | Register::EDX | Register::DX | Register::DL => Some(("rdx", self.rdx.0)),
            Register::RSI | Register::ESI | Register::SI | Register::SIL => Some(("rsi", self.rsi.0)),
            Register::RDI | Register::EDI | Register::DI | Register::DIL => Some(("rdi", self.rdi.0)),
            Register::RBP | Register::EBP | Register::BP | Register::BPL => Some(("rbp", self.rbp.0)),
            Register::RSP | Register::ESP | Register::SP | Register::SPL => Some(("rsp", self.rsp.0)),
            Register::R8 | Register::R8D | Register::R8W | Register::R8L => Some(("r8", self.r8.0)),
            Register::R9 | Register::R9D | Register::R9W | Register::R9L => Some(("r9", self.r9.0)),
            Register::R10 | Register::R10D | Register::R10W | Register::R10L => Some(("r10", self.r10.0)),
            Register::R11 | Register::R11D | Register::R11W | Register::R11L => Some(("r11", self.r11.0)),
            Register::R12 | Register::R12D | Register::R12W | Register::R12L => Some(("r12", self.r12.0)),
            Register::R13 | Register::R13D | Register::R13W | Register::R13L => Some(("r13", self.r13.0)),
            Register::R14 | Register::R14D | Register::R14W | Register::R14L => Some(("r14", self.r14.0)),
            Register::R15 | Register::R15D | Register::R15W | Register::R15L => Some(("r15", self.r15.0)),
            Register::AH => Some(("ah", (self.rax.0 >> 8) & 0xff)),
            Register::BH => Some(("bh", (self.rbx.0 >> 8) & 0xff)),
            Register::CH => Some(("ch", (self.rcx.0 >> 8) & 0xff)),
            Register::DH => Some(("dh", (self.rdx.0 >> 8) & 0xff)),
            _ => None,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct WriterSiteEntry {
    pub trap_runtime_ip: HexAddr,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub trap_static_ip: Option<HexAddr>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub candidate_writer_static_ip: Option<HexAddr>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub candidate_writer_mnemonic: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub candidate_writer_text: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub writer_function: Option<HexAddr>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub writer_function_offset: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub writer_symbol: Option<String>,
    pub confidence: WriterConfidence,
    pub hits: u64,
    pub caveat: &'static str,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct WatchHitSample {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tgid: Option<u32>,
    pub tid: u32,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub timestamp_ns: Option<u64>,
    pub trap_runtime_ip: HexAddr,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub trap_static_ip: Option<HexAddr>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub candidate_writer_static_ip: Option<HexAddr>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub candidate_writer_text: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub writer_function: Option<HexAddr>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub writer_symbol: Option<String>,
    pub confidence: WriterConfidence,
    pub written_value: WrittenValueRecovery,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub regs: Option<WatchRegsSnapshot>,
}

#[derive(Clone, Debug)]
pub struct WatchTargetSpec {
    pub input: u64,
    pub runtime_va: u64,
    pub static_va: Option<u64>,
    pub region: String,
    pub perms: String,
    pub access: WatchAccessMode,
    pub len_bytes: WatchLen,
    pub initial_snapshot: Option<HexAddr>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct WatchTargetResult {
    pub input: HexAddr,
    pub runtime_va: HexAddr,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub static_va: Option<HexAddr>,
    pub region: String,
    pub perms: String,
    pub access: &'static str,
    pub len_bytes: u8,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub initial_snapshot: Option<HexAddr>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub latest_snapshot: Option<HexAddr>,
    pub snapshot_changed: Option<bool>,
    pub snapshot_caveat: &'static str,
    pub accepted_hits: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub first_timestamp_ns: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_timestamp_ns: Option<u64>,
    pub writer_sites: Vec<WriterSiteEntry>,
    pub samples_truncated: bool,
    pub samples: Vec<WatchHitSample>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct WatchReport {
    pub schema_version: u32,
    pub tool: &'static str,
    pub tool_version: &'static str,
    pub operation: &'static str,
    pub backend: &'static str,
    pub capabilities: WatchCapabilities,
    pub process: ProcessMeta,
    pub observation: ProbeObservation,
    pub watches: Vec<WatchTargetResult>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct WatchReadyReceipt {
    pub backend: &'static str,
    pub pid: u32,
    pub attached_tids: Vec<u32>,
    pub watches: Vec<HexAddr>,
    pub access: &'static str,
    pub len_bytes: u8,
}

pub fn emit_watch_ready_stderr(
    pid: u32,
    tids: &std::collections::BTreeSet<u32>,
    specs: &[WatchTargetSpec],
    access: WatchAccessMode,
    len_bytes: WatchLen,
) {
    use std::io::Write;
    let receipt = WatchReadyReceipt {
        backend: "perf_breakpoint",
        pid,
        attached_tids: tids.iter().copied().collect(),
        watches: specs.iter().map(|s| HexAddr(s.runtime_va)).collect(),
        access: access.as_str(),
        len_bytes: len_bytes.as_u8(),
    };
    if let Ok(json) = serde_json::to_string(&receipt) {
        let mut stderr = std::io::stderr().lock();
        let _ = writeln!(stderr, "xref: watch_ready {json}");
        let _ = stderr.flush();
    }
}
