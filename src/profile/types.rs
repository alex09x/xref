/*
 * XRef — sampling profile data types
 * Copyright (c) 2026 Alexander Panasenko
 * Contact: alex@prod.codes
 * Author: https://prod.codes/about/
 * Project: https://github.com/alex09x/xref
 * SPDX-License-Identifier: MIT OR Apache-2.0
 */
use serde::{Deserialize, Serialize};

/// Identity and configuration are recorded before any samples are written.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Header {
    pub schema_version: u32,
    pub image_sha256: String,
    pub process_exe_sha256: Option<String>,
    pub binary_match: String,
    pub pie_slide: i64,
    pub exe_device_major: u64,
    pub exe_device_minor: u64,
    pub exe_inode: u64,
    pub pid: u32,
    pub starttime_ticks: u64,
    pub event: String,
    pub frequency_hz: Option<u64>,
    pub period: Option<u64>,
    pub callchain: String,
    pub started_monotonic_ns: u64,
    pub trigger_static_va: Option<u64>,
    pub trigger_window_ns: Option<u64>,
}

/// Raw data is preserved so post-processing never invents missing frames.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Sample {
    pub timestamp_ns: u64,
    pub pid: u32,
    pub tid: u32,
    /// Linux `PERF_RECORD_MISC_CPUMODE_MASK` bits for the sampled IP.
    pub cpu_mode: u16,
    pub ip: u64,
    pub period: u64,
    pub registers_mask: u64,
    pub registers: Vec<u64>,
    pub user_stack: Vec<u8>,
    pub callchain: Vec<u64>,
    pub branches: Vec<Branch>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Branch {
    pub from: u64,
    pub to: u64,
    /// Raw Linux perf branch flags; interpretation is CPU/kernel dependent.
    pub flags: u64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Mapping {
    pub timestamp_ns: u64,
    pub pid: u32,
    pub tid: u32,
    pub start: u64,
    pub length: u64,
    pub file_offset: u64,
    pub device_major: u32,
    pub device_minor: u32,
    pub inode: u64,
    pub executable: bool,
    /// Captured module hash when file identity was verified; otherwise unknown.
    pub sha256: Option<String>,
    pub path: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct Footer {
    pub timestamp_ns: u64,
    pub samples: u64,
    pub lost: u64,
    pub dropped: u64,
    /// Dynamic thread attachment and lost events can leave observation gaps.
    pub partial_coverage: bool,
    pub stop_reason: String,
    pub trigger_timestamp_ns: Option<u64>,
    pub trigger_lost: u64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Record {
    Sample(Sample),
    Mapping(Mapping),
    Lost { timestamp_ns: u64, tid: u32, count: u64 },
    Fork { timestamp_ns: u64, pid: u32, tid: u32, parent_pid: u32, parent_tid: u32 },
    Exit { timestamp_ns: u64, pid: u32, tid: u32 },
    End(Footer),
}
