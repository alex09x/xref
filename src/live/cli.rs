/*
 * XRef — Live Linux procfs inspection and xref-aware memory scanning
 * Copyright (c) 2026 Alexander Panasenko
 * Contact: alex@prod.codes
 * Author: https://prod.codes/about/
 * Project: https://github.com/alex09x/xref
 * SPDX-License-Identifier: MIT OR Apache-2.0
 */

//! Command-line definitions and argument validators for `xref [--bin BIN] live SUBCOMMAND`.

use std::fmt::Write as _;
use std::path::PathBuf;

use clap::{Args, Subcommand, ValueEnum};

pub const DEFAULT_ALIGN: usize = 8;
pub const DEFAULT_BEFORE_WORDS: usize = 2;
pub const DEFAULT_AFTER_WORDS: usize = 6;
pub const MAX_CONTEXT_WORDS: usize = 16;
pub const MAX_PATTERN_WORDS: usize = 64;
pub const DEFAULT_MAX_HITS: usize = 32;
/// Per-hit samples `live watch` keeps per watch by default.
pub const DEFAULT_MAX_WATCH_SAMPLES: usize = 32;
pub const MAX_HITS_CAP: usize = 1024;
pub const DEFAULT_MAX_BYTES: u64 = 268_435_456;
pub const DEFAULT_TIMEOUT_MS: u64 = 5000;
pub const DEFAULT_PROBE_DURATION_MS: u64 = 1000;
pub const MAX_PROBE_DURATION_MS: u64 = 60_000;
pub const DEFAULT_MAX_PROBE_EVENTS: usize = 4096;
pub const MAX_PROBE_EVENTS_CAP: usize = 65_536;
pub const MAX_PROBES_PER_SESSION: usize = 16;
pub const MAX_WATCHES_PER_SESSION: usize = 4;

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, ValueEnum, serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub enum WatchAccessMode {
    /// Hardware write watchpoint (`HW_BREAKPOINT_W`).
    #[default]
    Write,
    /// Hardware read-or-write watchpoint (`HW_BREAKPOINT_RW`).
    Rw,
}

impl WatchAccessMode {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Write => "write",
            Self::Rw => "rw",
        }
    }
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, serde::Serialize)]
pub enum WatchLen {
    B1 = 1,
    B2 = 2,
    B4 = 4,
    #[default]
    B8 = 8,
}

impl WatchLen {
    #[must_use]
    pub const fn as_u8(self) -> u8 {
        match self {
            Self::B1 => 1,
            Self::B2 => 2,
            Self::B4 => 4,
            Self::B8 => 8,
        }
    }
}

pub fn parse_watch_len(text: &str) -> Result<WatchLen, String> {
    match text.trim() {
        "1" => Ok(WatchLen::B1),
        "2" => Ok(WatchLen::B2),
        "4" => Ok(WatchLen::B4),
        "8" => Ok(WatchLen::B8),
        _ => Err(format!("invalid --len {text}: allowed hardware watchpoint lengths are 1, 2, 4, or 8")),
    }
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, ValueEnum)]
pub enum ProbeBackend {
    /// Primary native `perf_event_open` + `mmap` binary ring-buffer backend.
    #[default]
    Perf,
    /// Explicit Linux `tracefs` (`uprobe_events` + isolated `instances/`) adapter.
    Tracefs,
}

impl ProbeBackend {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Perf => "perf",
            Self::Tracefs => "tracefs",
        }
    }
}

#[derive(Clone, Debug, Args)]
pub struct LiveCommand {
    #[command(subcommand)]
    pub subcommand: LiveSubcommand,
}

#[derive(Clone, Debug, Subcommand)]
pub enum LiveSubcommand {
    /// Sample CPU activity and record a bounded profile of one process.
    Profile(crate::profile::cli::LiveProfileArgs),
    /// Record ordered, thread-scoped call trace windows via Linux `tracefs` uprobes.
    Trace(crate::live::trace::cli::TraceArgs),
    /// Inspect `/proc/<pid>/maps` and `/proc/<pid>/smaps`, binary identity, and PIE slide.
    Maps {
        /// Target process ID (must be non-zero).
        #[arg(long)]
        pid: u32,
        /// Continue even if `--bin` does not match `/proc/<pid>/exe`.
        #[arg(long)]
        force_bin: bool,
        /// Emit structured `schema_version: 1` JSON output.
        #[arg(long)]
        json: bool,
    },
    /// Translate static ELF VAs and live runtime VAs bidirectionally using PIE slide and `PT_LOAD`.
    Resolve {
        /// Target process ID (must be non-zero).
        #[arg(long)]
        pid: u32,
        /// Continue even if `--bin` does not match `/proc/<pid>/exe`.
        #[arg(long)]
        force_bin: bool,
        /// Emit structured `schema_version: 1` JSON output.
        #[arg(long)]
        json: bool,
        /// Static or live runtime addresses (`0x...` hex or decimal).
        #[arg(required = true, value_name = "ADDR", value_parser = crate::cli::parse_number)]
        addrs: Vec<u64>,
    },
    /// Scan eligible private `rw-p` regions for consecutive little-endian `u64` values, or for every
    /// aligned word whose value is in a range (`--range LO HI`).
    Memscan {
        /// Target process ID (must be non-zero).
        #[arg(long)]
        pid: u32,
        /// Required byte alignment for matches (`1`, `2`, `4`, or `8`).
        #[arg(long, default_value_t = DEFAULT_ALIGN, value_parser = parse_align)]
        align: usize,
        /// Number of 8-byte words to read before each match (`0..=16`).
        #[arg(long, default_value_t = DEFAULT_BEFORE_WORDS, value_parser = parse_context_words)]
        before_words: usize,
        /// Number of 8-byte words to read after each match (`0..=16`).
        #[arg(long, default_value_t = DEFAULT_AFTER_WORDS, value_parser = parse_context_words)]
        after_words: usize,
        /// Maximum number of hits before stopping (`1..=1024`).
        #[arg(long, default_value_t = DEFAULT_MAX_HITS)]
        max_hits: usize,
        /// Maximum scannable region bytes read before stopping.
        #[arg(long, default_value_t = DEFAULT_MAX_BYTES)]
        max_bytes: u64,
        /// Cooperative inter-chunk elapsed-time budget in milliseconds.
        #[arg(long, default_value_t = DEFAULT_TIMEOUT_MS)]
        timeout_ms: u64,
        /// Continue even if `--bin` does not match `/proc/<pid>/exe`.
        #[arg(long)]
        force_bin: bool,
        /// Emit structured `schema_version: 1` JSON output.
        #[arg(long)]
        json: bool,
        /// Match every aligned word whose value is in `[LO, HI)` instead of a sequence of VALUES (for
        /// a counter whose current value is unknown); each hit prints the value found.
        #[arg(long, num_args = 2, value_names = ["LO", "HI"], value_parser = crate::cli::parse_number, conflicts_with = "values")]
        range: Option<Vec<u64>>,
        /// Word width in bytes for `--range` (`4` or `8`).
        #[arg(long, default_value_t = 8, requires = "range")]
        width: usize,
        /// Consecutive `u64` values (`0x...` hex or decimal) encoded as little-endian bytes.
        #[arg(required_unless_present = "range", value_name = "VALUES", value_parser = crate::cli::parse_number)]
        values: Vec<u64>,
    },
    /// Attach bounded Linux uprobes to verified target code addresses and count hits/callers.
    Probe {
        /// Target process ID (must be non-zero).
        #[arg(long)]
        pid: u32,
        /// Kernel tracing backend: `perf` (binary ring buffer) by default, `tracefs` when --fetch,
        /// --filter, --every, --first, --until-hits or --mark-file is given. Never silently falls
        /// back on EACCES.
        #[arg(long, value_enum)]
        backend: Option<ProbeBackend>,
        /// Explicitly request hit-count reporting (enabled by default).
        #[arg(long)]
        count: bool,
        /// Recover and verify caller return addresses using effective `.eh_frame` CFI.
        #[arg(long)]
        callers: bool,
        /// Sample argument/return registers (`rdi..r9`, `rax`, `rsp`, `rbp`) on accepted hits.
        #[arg(long)]
        regs: bool,
        /// Observation window duration in milliseconds (`0..=60000`, 0 runs until --until-hits, target exit, or SIGINT).
        #[arg(long, default_value_t = DEFAULT_PROBE_DURATION_MS)]
        duration_ms: u64,
        /// Periodic progress heartbeat interval in milliseconds (`1..=60000`).
        #[arg(long = "heartbeat-ms", value_name = "MS")]
        heartbeat_ms: Option<u64>,
        /// Group hits by key (`ret` for return site).
        #[arg(long = "group-by", value_name = "KEY")]
        group_by: Option<String>,
        /// Print one JSON object per hit (va, tid, fetch, ret, mark) as it happens, on either
        /// backend and for any duration; the last line is the full report.
        #[arg(long = "json-lines", conflicts_with = "json")]
        json_lines: bool,
        /// File to tail for mark annotations.
        #[arg(long = "mark-file", value_name = "PATH")]
        mark_file: Option<PathBuf>,
        /// Regular expression to match lines in --mark-file.
        #[arg(long = "mark-regex", value_name = "REGEX")]
        mark_regex: Option<String>,
        /// Maximum accepted probe events before stopping (`1..=65536`). Defaults to 4096, or no
        /// limit with `--duration-ms 0`, so unbounded runs end on --until-hits, exit or SIGINT.
        #[arg(long)]
        max_events: Option<usize>,
        /// Tracefs uprobe fetch argument (`NAME=+OFFSET(%reg):u64`); repeatable, tracefs backend only.
        /// Registers are whole 64-bit registers in tracefs names (`%di %si %dx %cx %r8 %r9 %ax %bx
        /// %bp %sp %r10..%r15`); `%rdi`-style names are accepted and written as `%di`. Sub-registers
        /// (`%eax`, `%r8d`) are rejected: use the full register with `:u32` (e.g. `len=+8(%di):u64`).
        #[arg(long = "fetch", value_name = "NAME=EXPR")]
        fetch: Vec<String>,
        /// Tracefs numeric value predicate (`rdi == 0x...` or `NAME > N`); repeatable.
        #[arg(long = "filter", value_name = "PREDICATE")]
        filter: Vec<String>,
        /// Record every Nth matching tracefs event per probe (`1..=1000000`).
        #[arg(long, default_value_t = 1)]
        every: usize,
        /// Stop recording after the first N matching events per probe (`1..=65536`).
        #[arg(long)]
        first: Option<usize>,
        /// Stop the session after this many accepted hits across probes (`1..=65536`).
        #[arg(long)]
        until_hits: Option<usize>,
        /// Rejects unverified mismatches; accepted for CLI symmetry with `maps`/`resolve`.
        #[arg(long)]
        force_bin: bool,
        /// Emit structured `schema_version: 1` JSON output.
        #[arg(long)]
        json: bool,
        /// Target static or runtime code addresses (`0x...` hex or decimal).
        #[arg(required = true, value_name = "ADDR", value_parser = crate::cli::parse_number)]
        addrs: Vec<u64>,
    },
    /// Attach bounded hardware data watchpoints (`DR0`–`DR3`) and attribute store instructions.
    Watch {
        /// Target process ID (must be non-zero).
        #[arg(long)]
        pid: u32,
        /// Hardware watchpoint length in bytes (`1`, `2`, `4`, or `8`).
        #[arg(long, default_value = "8", value_parser = parse_watch_len)]
        len: WatchLen,
        /// Hardware breakpoint access mode (`write` or `rw`).
        #[arg(long, value_enum, default_value_t = WatchAccessMode::Write)]
        access: WatchAccessMode,
        /// Include raw 16-GPR `PERF_SAMPLE_REGS_INTR` snapshot in per-hit samples.
        #[arg(long)]
        regs: bool,
        /// Observation window duration in milliseconds (`1..=60000`).
        #[arg(long, default_value_t = DEFAULT_PROBE_DURATION_MS)]
        duration_ms: u64,
        /// Maximum accepted watch events before stopping (`1..=65536`).
        #[arg(long, default_value_t = DEFAULT_MAX_PROBE_EVENTS)]
        max_events: usize,
        /// Per-hit samples kept per watch (`1..=65536`); every accepted hit still counts toward its
        /// writer site, which also reports the least and greatest written value.
        #[arg(long, default_value_t = DEFAULT_MAX_WATCH_SAMPLES)]
        max_samples: usize,
        /// Keep a sample only when its recovered written value is in `[LO, HI)`; a hit whose value
        /// could not be recovered is kept with its trap registers.
        #[arg(long, num_args = 2, value_names = ["LO", "HI"], value_parser = crate::cli::parse_number)]
        value_range: Option<Vec<u64>>,
        /// Print every hit passing --value-range as one JSON line when it happens (also past
        /// --max-samples); the last line is the full report.
        #[arg(long = "json-lines", conflicts_with = "json")]
        json_lines: bool,
        /// Continue even if `--bin` does not match `/proc/<pid>/exe`.
        #[arg(long)]
        force_bin: bool,
        /// Emit structured `schema_version: 1` JSON output.
        #[arg(long)]
        json: bool,
        /// Follow a pointer-backed dependent watch (`ptr_slot=<ADDR>[,offset=<OFF>][,len_slot=<ADDR>,min_len=<BYTES>][,guard_slot=<ADDR>,guard_val=<U64>][,header_ptr_slot=<ADDR>,header_offset=<OFF>]`).
        #[arg(long = "follow", value_name = "SPEC")]
        follow: Vec<String>,
        /// Target static or runtime data addresses (`0x...` hex or decimal, sharing `1..=4` total `DR0`–`DR3` slots).
        #[arg(value_name = "ADDR", value_parser = crate::cli::parse_number)]
        addrs: Vec<u64>,
    },
    #[command(hide = true)]
    TracefsWatchdog {
        #[arg(long)]
        tracefs_root: PathBuf,
        #[arg(long)]
        instance: String,
        #[arg(long = "event")]
        events: Vec<String>,
        #[arg(long)]
        parent_test_hold: bool,
    },
}

impl LiveCommand {
    #[cfg(all(test, target_os = "linux"))]
    #[must_use]
    pub const fn maps(pid: u32, force_bin: bool, json: bool) -> Self {
        Self { subcommand: LiveSubcommand::Maps { pid, force_bin, json } }
    }

    #[cfg(all(test, target_os = "linux"))]
    #[must_use]
    pub const fn resolve(pid: u32, force_bin: bool, json: bool, addrs: Vec<u64>) -> Self {
        Self { subcommand: LiveSubcommand::Resolve { pid, force_bin, json, addrs } }
    }
}

pub fn parse_align(text: &str) -> Result<usize, String> {
    let align = text.parse::<usize>().map_err(|err| format!("invalid --align {text}: {err}"))?;
    validate_align(align)?;
    Ok(align)
}

pub fn validate_align(align: usize) -> Result<(), String> {
    if matches!(align, 1 | 2 | 4 | 8) {
        Ok(())
    } else {
        Err(format!("invalid --align {align}: allowed values are 1, 2, 4, or 8"))
    }
}

pub fn parse_context_words(text: &str) -> Result<usize, String> {
    let words = text.parse::<usize>().map_err(|err| format!("invalid context word count {text}: {err}"))?;
    validate_context_words(words, "context words")?;
    Ok(words)
}

pub fn validate_context_words(words: usize, flag: &str) -> Result<(), String> {
    if words <= MAX_CONTEXT_WORDS { Ok(()) } else { Err(format!("{flag} {words} exceeds maximum {MAX_CONTEXT_WORDS}")) }
}

#[must_use]
pub fn encode_values_le(values: &[u64]) -> Vec<u8> {
    let mut needle = Vec::with_capacity(values.len().saturating_mul(8));
    for &word in values {
        needle.extend_from_slice(&word.to_le_bytes());
    }
    needle
}

#[must_use]
pub fn format_bytes_hex(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(2 + bytes.len().saturating_mul(2));
    out.push_str("0x");
    for &byte in bytes {
        let _ = write!(out, "{byte:02x}");
    }
    out
}

/// The probe backend: the one given, else `tracefs` when a tracefs-only option is used, else
/// `perf`.
#[cfg(any(target_os = "linux", test))]
#[must_use]
pub fn resolve_probe_backend(given: Option<ProbeBackend>, tracefs_only_options: bool) -> ProbeBackend {
    given.unwrap_or(if tracefs_only_options { ProbeBackend::Tracefs } else { ProbeBackend::Perf })
}
