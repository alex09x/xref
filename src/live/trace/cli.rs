/*
 * XRef — CLI options and bounded validation for live trace windows
 * Copyright (c) 2026 Alexander Panasenko
 * Contact: alex@prod.codes
 * Author: https://prod.codes/about/
 * Project: https://github.com/alex09x/xref
 * SPDX-License-Identifier: MIT OR Apache-2.0
 */

use clap::{ArgAction, Args};

use crate::live::cli::{
    DEFAULT_MAX_PROBE_EVENTS, DEFAULT_PROBE_DURATION_MS, MAX_PROBE_DURATION_MS, MAX_PROBE_EVENTS_CAP,
};

pub const DEFAULT_MAX_TRACE_WINDOWS: usize = 64;
pub const MAX_TRACE_WINDOWS_CAP: usize = 4096;
pub const MAX_TRACE_STARTS: usize = 64;
pub const MAX_TRACE_PROBES: usize = 256;
pub const MAX_TRACE_DEPTH: usize = 16;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TraceLimits {
    pub duration_ms: u64,
    pub max_windows: usize,
    pub max_events: usize,
}

#[derive(Clone, Debug, Args)]
pub struct TraceArgs {
    /// Target process ID (must be non-zero).
    #[arg(long)]
    pub pid: u32,
    /// Start address opening a thread-scoped trace window (`0x...` hex or decimal; repeatable).
    #[arg(long = "start", required = true, value_name = "VA", value_parser = crate::cli::parse_number)]
    pub start: Vec<u64>,
    /// Numeric predicate gating window creation on `--start` fetches (`FIELD <OP> INTEGER`; repeatable).
    #[arg(long = "start-filter", value_name = "PRED")]
    pub start_filter: Vec<String>,
    /// Close an active window on the matching return of this `--start` function (`0x...` or decimal).
    #[arg(long = "stop-return", value_name = "VA", value_parser = crate::cli::parse_number)]
    pub stop_return: Vec<u64>,
    /// Close an active window when its thread reaches this address (`0x...` or decimal).
    #[arg(long = "stop", value_name = "VA", value_parser = crate::cli::parse_number)]
    pub stop: Vec<u64>,
    /// Comma-separated or repeated function entry addresses to trace (`VA,VA,...`).
    #[arg(long = "functions", value_delimiter = ',', value_name = "VA", value_parser = crate::cli::parse_number)]
    pub functions: Vec<u64>,
    /// Expand static call sites and post-call return sites from function `FN` (`0x...` or symbol).
    #[arg(long = "callees-of", value_name = "FN")]
    pub callees_of: Vec<String>,
    /// Static callee expansion depth for `--callees-of` (`1..=16`, defaults to `1`).
    #[arg(long, value_name = "N")]
    pub depth: Option<usize>,
    /// Fetch expression(s) attached to `--start` probes (`NAME=EXPR[,NAME=EXPR...]`).
    #[arg(long = "fetch", value_name = "NAME=EXPR")]
    pub fetch: Vec<String>,
    /// Attach entry/call-site fetch expressions at `VA` (`--fetch-at VA "NAME=EXPR,..."`).
    #[arg(
        long = "fetch-at",
        num_args = 2,
        value_names = ["VA", "NAME=EXPR,..."],
        action = ArgAction::Append
    )]
    pub fetch_at: Vec<String>,
    /// Attach return fetch expressions for `VA` (`--fetch-ret VA "NAME=EXPR,..."`).
    #[arg(
        long = "fetch-ret",
        num_args = 2,
        value_names = ["VA", "NAME=EXPR,..."],
        action = ArgAction::Append
    )]
    pub fetch_ret: Vec<String>,
    /// Stop and detach after completing this many trace windows (`1..=4096`).
    #[arg(long = "max-windows", value_name = "N")]
    pub max_windows: Option<usize>,
    /// Stop and detach after recording this many trace events (`1..=65536`).
    #[arg(long = "max-events", value_name = "N")]
    pub max_events: Option<usize>,
    /// Observation duration in milliseconds (`0` runs until limits, target exit, or `SIGINT`).
    #[arg(long = "duration-ms", value_name = "MS")]
    pub duration_ms: Option<u64>,
    /// Rejects unverified binary mismatches; accepted for CLI symmetry with other `live` commands.
    #[arg(long)]
    pub force_bin: bool,
    /// Emit structured `schema_version: 1` JSON output.
    #[arg(long)]
    pub json: bool,
}

impl TraceArgs {
    #[must_use]
    pub fn effective_limits(&self) -> TraceLimits {
        let has_explicit_bound = self.max_windows.is_some() || self.max_events.is_some();
        let duration_ms = self.duration_ms.unwrap_or(if has_explicit_bound { 0 } else { DEFAULT_PROBE_DURATION_MS });
        let max_windows = self.max_windows.unwrap_or_else(|| {
            if duration_ms == 0 || self.max_events.is_some() {
                MAX_TRACE_WINDOWS_CAP
            } else {
                DEFAULT_MAX_TRACE_WINDOWS
            }
        });
        let max_events = self.max_events.unwrap_or_else(|| {
            if duration_ms == 0 || self.max_windows.is_some() { MAX_PROBE_EVENTS_CAP } else { DEFAULT_MAX_PROBE_EVENTS }
        });
        TraceLimits { duration_ms, max_windows, max_events }
    }

    pub fn validate(&self) -> Result<(), String> {
        if self.pid == 0 {
            return Err("invalid --pid 0: process ID must be non-zero".to_owned());
        }
        if self.start.is_empty() || self.start.len() > MAX_TRACE_STARTS {
            return Err(format!("trace requires 1..={MAX_TRACE_STARTS} --start <VA> targets"));
        }
        if self.stop_return.is_empty() == self.stop.is_empty() {
            return Err("trace requires either --stop-return <VA> or --stop <VA> (not both)".to_owned());
        }
        if self.functions.len() > MAX_TRACE_PROBES {
            return Err(format!("--functions accepts at most {MAX_TRACE_PROBES} addresses"));
        }
        if self.callees_of.is_empty() && self.depth.is_some() {
            return Err("--depth requires --callees-of".to_owned());
        }
        if let Some(depth) = self.depth
            && (depth == 0 || depth > MAX_TRACE_DEPTH)
        {
            return Err(format!("--depth {depth} must be in 1..={MAX_TRACE_DEPTH}"));
        }
        if let Some(max_windows) = self.max_windows
            && (max_windows == 0 || max_windows > MAX_TRACE_WINDOWS_CAP)
        {
            return Err(format!("--max-windows {max_windows} must be in 1..={MAX_TRACE_WINDOWS_CAP}"));
        }
        if let Some(max_events) = self.max_events
            && (max_events == 0 || max_events > MAX_PROBE_EVENTS_CAP)
        {
            return Err(format!("--max-events {max_events} must be in 1..={MAX_PROBE_EVENTS_CAP}"));
        }
        let has_explicit_bound = self.max_windows.is_some() || self.max_events.is_some();
        if !has_explicit_bound
            && let Some(ms) = self.duration_ms
            && ms > MAX_PROBE_DURATION_MS
        {
            return Err(format!(
                "--duration-ms {ms} must be in 0..={MAX_PROBE_DURATION_MS} unless bounded by --max-windows or --max-events"
            ));
        }

        let start_fetches = split_many_fetch_lists(&self.fetch)?;
        let fetch_at = parse_targeted_fetches(&self.fetch_at, "--fetch-at")?;
        let fetch_ret = parse_targeted_fetches(&self.fetch_ret, "--fetch-ret")?;

        #[cfg(any(target_os = "linux", test))]
        {
            let _ = crate::live::probe::fetch::parse_fetch_args(&start_fetches)?;
            for (_, specs) in &fetch_at {
                let _ = crate::live::probe::fetch::parse_fetch_args(specs)?;
            }
            for (_, specs) in &fetch_ret {
                let _ = crate::live::probe::fetch::parse_fetch_args(specs)?;
            }
            if self.start_filter.len() > 16 {
                return Err("--start-filter accepts at most 16 predicates".to_owned());
            }
            for pred in &self.start_filter {
                let _ = crate::live::probe::filter::ValueFilter::parse(pred)?;
            }
        }
        #[cfg(not(any(target_os = "linux", test)))]
        let _ = (start_fetches, fetch_at, fetch_ret);

        Ok(())
    }
}

pub fn split_fetch_list(raw: &str) -> Result<Vec<String>, String> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return Err("fetch specification must not be empty".to_owned());
    }
    let mut out = Vec::new();
    for item in trimmed.split(',') {
        let part = item.trim();
        if part.is_empty() {
            return Err(format!("empty fetch item in {raw:?}"));
        }
        out.push(part.to_owned());
    }
    Ok(out)
}

pub fn split_many_fetch_lists(raw_list: &[String]) -> Result<Vec<String>, String> {
    let mut out = Vec::new();
    for raw in raw_list {
        out.extend(split_fetch_list(raw)?);
    }
    Ok(out)
}

pub fn parse_targeted_fetches(pairs: &[String], flag_name: &str) -> Result<Vec<(u64, Vec<String>)>, String> {
    if !pairs.len().is_multiple_of(2) {
        return Err(format!("{flag_name} requires <VA> <NAME=EXPR,...> pairs"));
    }
    let mut out = Vec::with_capacity(pairs.len() / 2);
    for pair in pairs.chunks_exact(2) {
        let va = crate::cli::parse_number(&pair[0])
            .map_err(|e| format!("invalid {flag_name} address {:?}: {e}", pair[0]))?;
        let specs = split_fetch_list(&pair[1])?;
        out.push((va, specs));
    }
    Ok(out)
}
