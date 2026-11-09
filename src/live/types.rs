/*
 * XRef — Live Linux procfs inspection and xref-aware memory scanning
 * Copyright (c) 2026 Alexander Panasenko
 * Contact: alex@prod.codes
 * Author: https://prod.codes/about/
 * Project: https://github.com/alex09x/xref
 * SPDX-License-Identifier: MIT OR Apache-2.0
 */

//! Structured output contracts (`schema_version: 1`) and address-slide helpers for `xref live`.

use serde::{Serialize, Serializer};

pub const SCHEMA_VERSION: u32 = 1;
pub const TOOL_NAME: &str = "xref";
pub const TOOL_VERSION: &str = env!("CARGO_PKG_VERSION");

/// Hex-serialized 64-bit address/word (`"0x..."`) preserving full 64-bit precision in JSON.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, PartialOrd, Ord)]
pub struct HexAddr(pub u64);

impl From<u64> for HexAddr {
    fn from(value: u64) -> Self {
        Self(value)
    }
}

impl Serialize for HexAddr {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&format!("{:#x}", self.0))
    }
}

#[must_use]
pub fn format_signed_hex(value: i64) -> String {
    match value.cmp(&0) {
        std::cmp::Ordering::Equal => "0x0".to_owned(),
        std::cmp::Ordering::Greater => format!("+{:#x}", value.cast_unsigned()),
        std::cmp::Ordering::Less => format!("-{:#x}", value.wrapping_neg().cast_unsigned()),
    }
}

#[must_use]
pub const fn apply_slide(addr: u64, slide: i64) -> Option<u64> {
    if slide >= 0 {
        addr.checked_add(slide.cast_unsigned())
    } else {
        addr.checked_sub(slide.wrapping_neg().cast_unsigned())
    }
}

#[must_use]
pub const fn remove_slide(addr: u64, slide: i64) -> Option<u64> {
    if slide >= 0 {
        addr.checked_sub(slide.cast_unsigned())
    } else {
        addr.checked_add(slide.wrapping_neg().cast_unsigned())
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum BinaryMatch {
    ProcExeAuto,
    VerifiedBuildId,
    VerifiedSha256,
    ForcedMismatch,
}

impl BinaryMatch {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::ProcExeAuto => "proc_exe_auto",
            Self::VerifiedBuildId => "verified_build_id",
            Self::VerifiedSha256 => "verified_sha256",
            Self::ForcedMismatch => "forced_mismatch",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct ProcessMeta {
    pub pid: u32,
    pub starttime_ticks: u64,
    pub pid_alive_after: bool,
    pub process_changed: bool,
    pub binary_match: BinaryMatch,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub exe_sha256: Option<String>,
    pub pie_slide: i64,
    pub warnings: Vec<String>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ScanStatus {
    ScannableRwp,
    SkippedNonWritable,
    SkippedShared,
    SkippedDeviceOrSpecial,
    SkippedMissingVmflags,
    SkippedVmflags,
    SkippedUnclassifiedFile,
}

impl ScanStatus {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::ScannableRwp => "scannable_rwp",
            Self::SkippedNonWritable => "skipped_non_writable",
            Self::SkippedShared => "skipped_shared",
            Self::SkippedDeviceOrSpecial => "skipped_device_or_special",
            Self::SkippedMissingVmflags => "skipped_missing_vmflags",
            Self::SkippedVmflags => "skipped_vmflags",
            Self::SkippedUnclassifiedFile => "skipped_unclassified_file",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct RegionEntry {
    pub start: HexAddr,
    pub end: HexAddr,
    pub perms: String,
    pub offset: HexAddr,
    pub dev: String,
    pub inode: u64,
    pub pathname: Option<String>,
    pub vm_flags: Option<Vec<String>>,
    pub is_target_image: bool,
    pub scan_status: ScanStatus,
}

impl RegionEntry {
    #[must_use]
    pub const fn contains(&self, addr: u64) -> bool {
        addr >= self.start.0 && addr < self.end.0
    }

    #[must_use]
    pub fn format_location(&self, addr: u64) -> String {
        let off = addr.saturating_sub(self.start.0);
        self.pathname
            .as_deref()
            .map_or_else(|| format!("[anon@{:#x}]+{off:#x}", self.start.0), |name| format!("{name}+{off:#x}"))
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct MapsReport {
    pub schema_version: u32,
    pub tool: &'static str,
    pub tool_version: &'static str,
    pub operation: &'static str,
    pub process: ProcessMeta,
    pub regions: Vec<RegionEntry>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ResolveDirection {
    StaticToRuntime,
    RuntimeToStatic,
    Unmapped,
}

impl ResolveDirection {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::StaticToRuntime => "static_to_runtime",
            Self::RuntimeToStatic => "runtime_to_static",
            Self::Unmapped => "unmapped",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct ResolvedAddress {
    pub input: HexAddr,
    pub direction: ResolveDirection,
    pub static_va: Option<HexAddr>,
    pub file_offset: Option<HexAddr>,
    pub in_bss: bool,
    pub executable: bool,
    pub runtime_va: Option<HexAddr>,
    pub region: Option<String>,
    pub function_start: Option<HexAddr>,
    pub function_end: Option<HexAddr>,
    pub function_offset: Option<u64>,
    pub symbol: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct ResolveReport {
    pub schema_version: u32,
    pub tool: &'static str,
    pub tool_version: &'static str,
    pub operation: &'static str,
    pub process: ProcessMeta,
    pub addresses: Vec<ResolvedAddress>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum StopReason {
    Complete,
    MaxHits,
    MaxBytes,
    Timeout,
}

impl StopReason {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Complete => "complete",
            Self::MaxHits => "max_hits",
            Self::MaxBytes => "max_bytes",
            Self::Timeout => "timeout",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ContextWordKind {
    CodePtr,
    ExecMappingPtr,
    RelroPtrCandidate,
    StaticDataPtr,
    HeapPtr,
    StackPtr,
    AnonPtr,
    MappedPtr,
    Scalar,
    Unreadable,
}

impl ContextWordKind {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::CodePtr => "code_ptr",
            Self::ExecMappingPtr => "exec_mapping_ptr",
            Self::RelroPtrCandidate => "relro_ptr_candidate",
            Self::StaticDataPtr => "static_data_ptr",
            Self::HeapPtr => "heap_ptr",
            Self::StackPtr => "stack_ptr",
            Self::AnonPtr => "anon_ptr",
            Self::MappedPtr => "mapped_ptr",
            Self::Scalar => "scalar",
            Self::Unreadable => "unreadable",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct ContextWord {
    pub relative_offset: i64,
    pub runtime_va: HexAddr,
    pub value: Option<HexAddr>,
    pub is_match: bool,
    pub kind: ContextWordKind,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub static_va: Option<HexAddr>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub target_function: Option<HexAddr>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub function_offset: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub symbol: Option<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub candidate_targets: Vec<HexAddr>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub static_ascii_preview: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub target_region: Option<String>,
}

impl ContextWord {
    #[must_use]
    pub const fn scalar(runtime_va: u64, relative_offset: i64, is_match: bool, value: u64) -> Self {
        Self {
            relative_offset,
            runtime_va: HexAddr(runtime_va),
            value: Some(HexAddr(value)),
            is_match,
            kind: ContextWordKind::Scalar,
            static_va: None,
            target_function: None,
            function_offset: None,
            symbol: None,
            candidate_targets: Vec::new(),
            static_ascii_preview: None,
            target_region: None,
        }
    }

    #[must_use]
    pub const fn unreadable(runtime_va: u64, relative_offset: i64, is_match: bool) -> Self {
        Self {
            relative_offset,
            runtime_va: HexAddr(runtime_va),
            value: None,
            is_match,
            kind: ContextWordKind::Unreadable,
            static_va: None,
            target_function: None,
            function_offset: None,
            symbol: None,
            candidate_targets: Vec::new(),
            static_ascii_preview: None,
            target_region: None,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct MemHit {
    pub runtime_va: HexAddr,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub static_va: Option<HexAddr>,
    pub region: String,
    /// The matched word's value, for a `--range` scan.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub value: Option<HexAddr>,
    pub window_truncated: bool,
    pub context: Vec<ContextWord>,
}

/// The value range a `--range` scan matched, `[lo, hi)` over `width`-byte words.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
pub struct ScanRange {
    pub lo: HexAddr,
    pub hi: HexAddr,
    pub width: usize,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct MemscanReport {
    pub schema_version: u32,
    pub tool: &'static str,
    pub tool_version: &'static str,
    pub operation: &'static str,
    pub process: ProcessMeta,
    /// The exact sequence searched for (empty for a `--range` scan).
    pub needle_hex: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub range: Option<ScanRange>,
    pub align: usize,
    pub elapsed_ms: u64,
    pub regions_scanned: usize,
    pub regions_skipped: usize,
    pub bytes_scanned: u64,
    pub unreadable_ranges: usize,
    pub stop_reason: StopReason,
    pub hits: Vec<MemHit>,
}
