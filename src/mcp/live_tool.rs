/*
 * XRef — Opt-in PID-pinned live Linux process MCP tool (`xref_live`)
 * Copyright (c) 2026 Alexander Panasenko
 * Contact: alex@prod.codes
 * Author: https://prod.codes/about/
 * Project: https://github.com/alex09x/xref
 * SPDX-License-Identifier: MIT OR Apache-2.0
 */

//! Stage L4 opt-in MCP tool `xref_live` (`xref -b <ELF> mcp --allow-live-pid <PID>`).
//! Pins a single verified Linux process (`(pid, starttime_ticks, exe_dev_ino)`) at startup,
//! forbids arbitrary PID/binary redirection, enforces tight MCP budgets, and serializes live calls.

use std::path::{Path, PathBuf};
use std::sync::{
    Arc,
    atomic::{AtomicBool, Ordering},
};

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

use crate::api::{
    Cancellation, MAX_RESPONSE_BYTES,
    types::{ApiError, ImageIdentity},
};
use crate::live::cli::{DEFAULT_MAX_BYTES, DEFAULT_MAX_PROBE_EVENTS, ProbeBackend, WatchAccessMode};
pub use crate::mcp::live_tool_exec::validate_live_query_budgets;
#[cfg(any(target_os = "linux", test))]
use crate::mcp::live_tool_exec::{classify_live_error, parse_addr_list, run_mcp_memscan, run_mcp_probe, run_mcp_watch};

pub const MAX_MCP_LIVE_ADDRS: usize = 64;
pub const MAX_MCP_LIVE_DURATION_MS: u64 = 5_000;
pub const MAX_MCP_LIVE_HITS: usize = 64;
pub const MAX_MCP_LIVE_BYTES: u64 = DEFAULT_MAX_BYTES;
pub const MAX_MCP_LIVE_EVENTS: usize = DEFAULT_MAX_PROBE_EVENTS;

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Deserialize, Serialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum LiveProbeBackend {
    #[default]
    Perf,
    Tracefs,
}

impl From<LiveProbeBackend> for ProbeBackend {
    fn from(value: LiveProbeBackend) -> Self {
        match value {
            LiveProbeBackend::Perf => Self::Perf,
            LiveProbeBackend::Tracefs => Self::Tracefs,
        }
    }
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Deserialize, Serialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum LiveWatchAccess {
    #[default]
    Write,
    Rw,
}

impl From<LiveWatchAccess> for WatchAccessMode {
    fn from(value: LiveWatchAccess) -> Self {
        match value {
            LiveWatchAccess::Write => Self::Write,
            LiveWatchAccess::Rw => Self::Rw,
        }
    }
}

#[derive(Clone, Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct LiveToolArguments {
    pub request: LiveQuery,
}

#[derive(Clone, Debug, Deserialize, JsonSchema)]
#[serde(tag = "operation", rename_all = "snake_case", deny_unknown_fields)]
pub enum LiveQuery {
    /// Sample the pinned process with a bounded hardware performance event.
    Profile { duration_ms: Option<u64>, max_events: Option<usize> },
    /// Inspect `/proc/<pid>/maps`, `/proc/<pid>/smaps`, binary match, and PIE slide of the pinned process.
    Maps {},
    /// Translate static ELF VAs and live runtime VAs bidirectionally (`1..=64` addresses).
    Resolve { addresses: Vec<String> },
    /// Scan eligible private `rw-p` regions of the pinned process (`timeout_ms <= 5000`, `max_hits <= 64`).
    Memscan {
        /// Consecutive `u64` values to find, as one little-endian sequence; or give `range`.
        #[serde(default)]
        values: Vec<String>,
        /// `[LO, HI)`: every aligned word whose value is in the range (`0x...` hex or decimal).
        #[serde(default)]
        range: Option<[String; 2]>,
        /// Word width in bytes for `range` (`4` or `8`, default 8).
        #[serde(default)]
        width: Option<usize>,
        align: Option<usize>,
        before_words: Option<usize>,
        after_words: Option<usize>,
        max_hits: Option<usize>,
        max_bytes: Option<u64>,
        timeout_ms: Option<u64>,
    },
    /// Attach bounded Linux uprobes to verified code addresses (`duration_ms <= 5000`, `max_events <= 4096`).
    Probe {
        addresses: Vec<String>,
        #[serde(default)]
        backend: LiveProbeBackend,
        #[serde(default)]
        callers: bool,
        #[serde(default)]
        regs: bool,
        duration_ms: Option<u64>,
        max_events: Option<usize>,
    },
    /// Attach bounded hardware data watchpoints (`DR0`–`DR3`, `duration_ms <= 5000`, `max_events <= 4096`).
    Watch {
        #[serde(default)]
        addresses: Vec<String>,
        #[serde(default)]
        follow: Vec<String>,
        len_bytes: Option<u8>,
        #[serde(default)]
        access: LiveWatchAccess,
        #[serde(default)]
        regs: bool,
        duration_ms: Option<u64>,
        max_events: Option<usize>,
        /// Per-hit samples kept per watch (default 32, at most `max_events`).
        #[serde(default)]
        max_samples: Option<usize>,
        /// `[LO, HI)`: keep a sample only when its recovered written value is in the range.
        #[serde(default)]
        value_range: Option<[String; 2]>,
    },
}

impl LiveQuery {
    #[must_use]
    pub const fn name(&self) -> &'static str {
        match self {
            Self::Profile { .. } => "live_profile",
            Self::Maps {} => "live_maps",
            Self::Resolve { .. } => "live_resolve",
            Self::Memscan { .. } => "live_memscan",
            Self::Probe { .. } => "live_probe",
            Self::Watch { .. } => "live_watch",
        }
    }
}

#[derive(Clone, Debug, Serialize, JsonSchema)]
pub struct PinnedProcessIdentity {
    pub pid: u32,
    pub starttime_ticks: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub exe_sha256: Option<String>,
}

#[derive(Debug, Serialize, JsonSchema)]
pub struct LiveToolResponse {
    pub schema_version: u32,
    pub tool: &'static str,
    pub tool_version: &'static str,
    pub build_revision: Option<&'static str>,
    pub image: Option<ImageIdentity>,
    pub pinned_process: PinnedProcessIdentity,
    pub operation: String,
    pub data: Option<Value>,
    pub error: Option<ApiError>,
}

impl LiveToolResponse {
    #[must_use]
    pub fn success(ctx: &LiveMcpContext, image: ImageIdentity, operation: &str, data: Value) -> Self {
        Self {
            schema_version: 1,
            tool: "xref",
            tool_version: env!("CARGO_PKG_VERSION"),
            build_revision: option_env!("XREF_BUILD_COMMIT"),
            image: Some(image),
            pinned_process: ctx.pinned_identity(),
            operation: operation.to_owned(),
            data: Some(data),
            error: None,
        }
    }

    #[must_use]
    pub fn failure(ctx: &LiveMcpContext, image: Option<ImageIdentity>, operation: &str, error: ApiError) -> Self {
        Self {
            schema_version: 1,
            tool: "xref",
            tool_version: env!("CARGO_PKG_VERSION"),
            build_revision: option_env!("XREF_BUILD_COMMIT"),
            image,
            pinned_process: ctx.pinned_identity(),
            operation: operation.to_owned(),
            data: None,
            error: Some(error),
        }
    }

    #[must_use]
    pub fn json(&self) -> Value {
        let Ok(value) = serde_json::to_value(self) else {
            return self.small_error("serialization_failed", "could not encode the live result");
        };
        if value.to_string().len() <= MAX_RESPONSE_BYTES {
            return value;
        }
        self.small_error("response_too_large", "reduce max_hits, max_events, or address count")
    }

    fn small_error(&self, code: &str, message: &str) -> Value {
        json!({
            "schema_version": 1,
            "tool": "xref",
            "tool_version": env!("CARGO_PKG_VERSION"),
            "build_revision": option_env!("XREF_BUILD_COMMIT"),
            "image": self.image,
            "pinned_process": self.pinned_process,
            "operation": self.operation,
            "data": null,
            "error": { "code": code, "message": message },
        })
    }
}

#[derive(Clone)]
pub struct LiveMcpContext {
    pub bin_path: PathBuf,
    pub pid: u32,
    pub starttime_ticks: u64,
    pub exe_dev_ino: Option<(u64, u64)>,
    pub exe_sha256: Option<String>,
    pub active_live: Arc<AtomicBool>,
}

pub struct LiveActiveGuard(pub Arc<AtomicBool>);
impl Drop for LiveActiveGuard {
    fn drop(&mut self) {
        self.0.store(false, Ordering::Release);
    }
}

impl LiveMcpContext {
    pub fn open(bin: &Path, pid: u32) -> Result<Self, String> {
        if pid == 0 {
            return Err("invalid --allow-live-pid 0: process ID must be non-zero".to_owned());
        }
        #[cfg(not(target_os = "linux"))]
        {
            let _ = crate::live::procfs::load_elf_image(bin)?;
            Err(format!("unsupported_platform: --allow-live-pid {pid} requires a Linux x86-64 host"))
        }
        #[cfg(target_os = "linux")]
        {
            use crate::live::types::BinaryMatch;
            let session = crate::live::procfs::open_session(pid, Some(bin), false)?;
            if !session.process.pid_alive_after {
                return Err(format!("process_exited: process {pid} exited during MCP startup verification"));
            }
            if session.process.process_changed {
                return Err(format!("process_changed: process {pid} identity changed during MCP startup verification"));
            }
            if !matches!(session.process.binary_match, BinaryMatch::VerifiedBuildId | BinaryMatch::VerifiedSha256) {
                return Err("binary_mismatch: --allow-live-pid requires verified --bin identity match".to_owned());
            }
            Ok(Self {
                bin_path: bin.to_path_buf(),
                pid,
                starttime_ticks: session.process.starttime_ticks,
                exe_dev_ino: session.exe_dev_ino,
                exe_sha256: session.process.exe_sha256,
                active_live: Arc::new(AtomicBool::new(false)),
            })
        }
    }

    #[cfg(test)]
    #[must_use]
    pub fn synthetic_for_test(bin_path: PathBuf, pid: u32, starttime_ticks: u64) -> Self {
        Self {
            bin_path,
            pid,
            starttime_ticks,
            exe_dev_ino: None,
            exe_sha256: None,
            active_live: Arc::new(AtomicBool::new(false)),
        }
    }

    pub fn try_acquire(&self) -> Option<LiveActiveGuard> {
        self.active_live
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .ok()
            .map(|_| LiveActiveGuard(self.active_live.clone()))
    }

    #[must_use]
    pub fn pinned_identity(&self) -> PinnedProcessIdentity {
        PinnedProcessIdentity {
            pid: self.pid,
            starttime_ticks: self.starttime_ticks,
            exe_sha256: self.exe_sha256.clone(),
        }
    }

    pub fn execute(&self, image: &ImageIdentity, query: &LiveQuery, cancel: &Cancellation) -> LiveToolResponse {
        match cancel.checkpoint().and_then(|()| self.run_inner(query, cancel)).and_then(|val| {
            cancel.checkpoint()?;
            Ok(val)
        }) {
            Ok(data) => LiveToolResponse::success(self, image.clone(), query.name(), data),
            Err(err) => LiveToolResponse::failure(self, Some(image.clone()), query.name(), err),
        }
    }

    #[cfg(all(not(target_os = "linux"), not(test)))]
    fn run_inner(&self, _query: &LiveQuery, _cancel: &Cancellation) -> Result<Value, ApiError> {
        Err(ApiError::new("unsupported_platform", "live Linux procfs inspection requires a Linux x86-64 host"))
    }

    #[cfg(any(target_os = "linux", test))]
    fn run_inner(&self, query: &LiveQuery, cancel: &Cancellation) -> Result<Value, ApiError> {
        let mut session =
            crate::live::procfs::open_pinned_session(self.pid, &self.bin_path, self.starttime_ticks, self.exe_dev_ino)
                .map_err(|e| classify_live_error(&e))?;
        match query {
            LiveQuery::Profile { duration_ms, max_events } => {
                crate::profile::mcp::run(&mut session, *duration_ms, *max_events, cancel)
            }
            LiveQuery::Maps {} => {
                let report = crate::live::types::MapsReport {
                    schema_version: crate::live::types::SCHEMA_VERSION,
                    tool: crate::live::types::TOOL_NAME,
                    tool_version: crate::live::types::TOOL_VERSION,
                    operation: "live_maps",
                    process: session.process,
                    regions: session.regions,
                };
                serde_json::to_value(report).map_err(|e| ApiError::new("serialization_failed", e.to_string()))
            }
            LiveQuery::Resolve { addresses } => {
                let addrs = parse_addr_list(addresses, 1, MAX_MCP_LIVE_ADDRS, "resolve")?;
                let resolved = addrs
                    .iter()
                    .map(|&addr| {
                        crate::live::classify::resolve_address(
                            &session.image,
                            session.process.pie_slide,
                            &session.regions,
                            addr,
                        )
                    })
                    .collect();
                crate::live::procfs::refresh_session_identity(&mut session);
                let report = crate::live::types::ResolveReport {
                    schema_version: crate::live::types::SCHEMA_VERSION,
                    tool: crate::live::types::TOOL_NAME,
                    tool_version: crate::live::types::TOOL_VERSION,
                    operation: "live_resolve",
                    process: session.process,
                    addresses: resolved,
                };
                serde_json::to_value(report).map_err(|e| ApiError::new("serialization_failed", e.to_string()))
            }
            LiveQuery::Memscan {
                values,
                range,
                width,
                align,
                before_words,
                after_words,
                max_hits,
                max_bytes,
                timeout_ms,
            } => run_mcp_memscan(
                &mut session,
                (values, range.as_ref(), *width),
                (*align, *before_words, *after_words),
                (*max_hits, *max_bytes, *timeout_ms),
                cancel,
            ),
            LiveQuery::Probe { addresses, backend, callers, regs, duration_ms, max_events } => {
                run_mcp_probe(&mut session, addresses, *backend, (*callers, *regs), (*duration_ms, *max_events), cancel)
            }
            LiveQuery::Watch {
                addresses,
                follow,
                len_bytes,
                access,
                regs,
                duration_ms,
                max_events,
                max_samples,
                value_range,
            } => run_mcp_watch(
                &mut session,
                (addresses, follow),
                (*len_bytes, *access, *regs),
                (*duration_ms, *max_events),
                crate::mcp::live_tool_exec::mcp_watch_sampling(*max_samples, value_range.as_ref())?,
                cancel,
            ),
        }
    }
}
