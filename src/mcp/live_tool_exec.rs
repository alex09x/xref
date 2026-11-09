/*
 * XRef — Stage L4 opt-in `xref_live` MCP execution and budget validators
 * Copyright (c) 2026 Alexander Panasenko
 * Contact: alex@prod.codes
 * Author: https://prod.codes/about/
 * Project: https://github.com/alex09x/xref
 * SPDX-License-Identifier: MIT OR Apache-2.0
 */

//! Budget validators and execution dispatchers for `xref_live` (`maps`, `resolve`, `memscan`, `probe`, `watch`).

use std::time::Duration;

use serde_json::Value;

use crate::api::{Cancellation, types::ApiError};
use crate::cli::parse_number;
use crate::live::cli::{
    DEFAULT_AFTER_WORDS, DEFAULT_ALIGN, DEFAULT_BEFORE_WORDS, DEFAULT_MAX_HITS, DEFAULT_PROBE_DURATION_MS,
    MAX_CONTEXT_WORDS, MAX_PATTERN_WORDS, MAX_PROBES_PER_SESSION, MAX_WATCHES_PER_SESSION, ProbeBackend,
    WatchAccessMode, WatchLen, encode_values_le, format_bytes_hex, validate_align, validate_context_words,
};
use crate::mcp::live_tool::{
    LiveProbeBackend, LiveQuery, LiveWatchAccess, MAX_MCP_LIVE_ADDRS, MAX_MCP_LIVE_BYTES, MAX_MCP_LIVE_DURATION_MS,
    MAX_MCP_LIVE_EVENTS, MAX_MCP_LIVE_HITS,
};

pub fn validate_live_query_budgets(query: &LiveQuery) -> Result<(), ApiError> {
    match query {
        LiveQuery::Profile { duration_ms, max_events } => validate_duration_and_events(*duration_ms, *max_events),
        LiveQuery::Maps {} => Ok(()),
        LiveQuery::Resolve { addresses } => {
            let _ = parse_addr_list(addresses, 1, MAX_MCP_LIVE_ADDRS, "resolve")?;
            Ok(())
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
        } => {
            let _ = memscan_pattern(values, range.as_ref(), *width)?;
            validate_align(align.unwrap_or(DEFAULT_ALIGN)).map_err(|e| ApiError::new("invalid_request", e))?;
            validate_context_words(before_words.unwrap_or(DEFAULT_BEFORE_WORDS), "before_words")
                .map_err(|e| ApiError::new("invalid_request", e))?;
            validate_context_words(after_words.unwrap_or(DEFAULT_AFTER_WORDS), "after_words")
                .map_err(|e| ApiError::new("invalid_request", e))?;
            let hits = max_hits.unwrap_or(DEFAULT_MAX_HITS);
            if hits == 0 || hits > MAX_MCP_LIVE_HITS {
                return Err(ApiError::new(
                    "invalid_request",
                    format!("max_hits {hits} must be in 1..={MAX_MCP_LIVE_HITS} for MCP live_memscan"),
                ));
            }
            let bytes = max_bytes.unwrap_or(MAX_MCP_LIVE_BYTES);
            if bytes == 0 || bytes > MAX_MCP_LIVE_BYTES {
                return Err(ApiError::new(
                    "invalid_request",
                    format!("max_bytes {bytes} must be in 1..={MAX_MCP_LIVE_BYTES} for MCP live_memscan"),
                ));
            }
            let timeout = timeout_ms.unwrap_or(MAX_MCP_LIVE_DURATION_MS);
            if timeout == 0 || timeout > MAX_MCP_LIVE_DURATION_MS {
                return Err(ApiError::new(
                    "invalid_request",
                    format!("timeout_ms {timeout} must be in 1..={MAX_MCP_LIVE_DURATION_MS} for MCP live_memscan"),
                ));
            }
            Ok(())
        }
        LiveQuery::Probe { addresses, duration_ms, max_events, .. } => {
            let _ = parse_addr_list(addresses, 1, MAX_PROBES_PER_SESSION, "probe")?;
            validate_duration_and_events(*duration_ms, *max_events)
        }
        LiveQuery::Watch {
            addresses,
            follow,
            len_bytes,
            access,
            duration_ms,
            max_events,
            max_samples,
            value_range,
            ..
        } => {
            let _ = mcp_watch_sampling(*max_samples, value_range.as_ref())?;
            let len = parse_mcp_watch_len(*len_bytes)?;
            let addrs = parse_addr_list(addresses, 0, MAX_WATCHES_PER_SESSION, "watch")?;
            let mut total_slots = addrs.len();
            for spec_str in follow {
                let parsed =
                    crate::live::watch::rebind::parse_follow_spec(spec_str, len, WatchAccessMode::from(*access))
                        .map_err(|e| ApiError::new("invalid_request", e))?;
                total_slots = total_slots.saturating_add(parsed.hardware_slots_required());
            }
            if total_slots == 0 || total_slots > MAX_WATCHES_PER_SESSION {
                return Err(ApiError::new(
                    "invalid_request",
                    format!(
                        "watch requires 1..={MAX_WATCHES_PER_SESSION} total hardware watchpoint slots across addresses and follow (requested {total_slots})"
                    ),
                ));
            }
            validate_duration_and_events(*duration_ms, *max_events)
        }
    }
}

fn validate_duration_and_events(duration_ms: Option<u64>, max_events: Option<usize>) -> Result<(), ApiError> {
    let dur = duration_ms.unwrap_or(DEFAULT_PROBE_DURATION_MS);
    if dur == 0 || dur > MAX_MCP_LIVE_DURATION_MS {
        return Err(ApiError::new(
            "invalid_request",
            format!("duration_ms {dur} must be in 1..={MAX_MCP_LIVE_DURATION_MS} for MCP live tool"),
        ));
    }
    let ev = max_events.unwrap_or(MAX_MCP_LIVE_EVENTS);
    if ev == 0 || ev > MAX_MCP_LIVE_EVENTS {
        return Err(ApiError::new(
            "invalid_request",
            format!("max_events {ev} must be in 1..={MAX_MCP_LIVE_EVENTS} for MCP live tool"),
        ));
    }
    Ok(())
}

pub fn parse_mcp_watch_len(len_bytes: Option<u8>) -> Result<WatchLen, ApiError> {
    match len_bytes.unwrap_or(8) {
        1 => Ok(WatchLen::B1),
        2 => Ok(WatchLen::B2),
        4 => Ok(WatchLen::B4),
        8 => Ok(WatchLen::B8),
        other => Err(ApiError::new(
            "invalid_request",
            format!("invalid len_bytes {other}: allowed hardware watchpoint lengths are 1, 2, 4, or 8"),
        )),
    }
}

pub fn parse_addr_list(raw: &[String], min: usize, max: usize, label: &str) -> Result<Vec<u64>, ApiError> {
    if raw.len() < min || raw.len() > max {
        return Err(ApiError::new(
            "invalid_request",
            format!("{label} requires {min}..={max} entries (got {})", raw.len()),
        ));
    }
    let mut out = Vec::with_capacity(raw.len());
    for item in raw {
        let val = parse_number(item.trim())
            .map_err(|e| ApiError::new("invalid_address", format!("invalid {label} entry {item:?}: {e}")))?;
        out.push(val);
    }
    Ok(out)
}

pub fn classify_live_error(err: &str) -> ApiError {
    for code in [
        "cancelled",
        "process_exited",
        "process_changed",
        "binary_mismatch",
        "permission_denied",
        "unsupported_platform",
        "unsupported_uprobe_pmu",
    ] {
        if let Some(rest) = err.strip_prefix(&format!("{code}:")) {
            return ApiError::new(code, rest.trim());
        }
    }
    ApiError::new("live_failed", err)
}

/// The memscan pattern: exactly one of a value sequence (`values`) or a value range (`range`, with
/// `width`).
pub fn memscan_pattern(
    values: &[String],
    range: Option<&[String; 2]>,
    width: Option<usize>,
) -> Result<(Vec<u64>, Option<crate::live::memscan_range::ValueRange>), ApiError> {
    match range {
        None if width.is_some() => Err(ApiError::new("invalid_request", "width applies only to range")),
        None => Ok((parse_addr_list(values, 1, MAX_PATTERN_WORDS, "memscan values")?, None)),
        Some(_) if !values.is_empty() => Err(ApiError::new("invalid_request", "give values or range, not both")),
        Some([lo, hi]) => {
            let bound = |text: &str| parse_number(text).map_err(|e| ApiError::new("invalid_request", e));
            let range = crate::live::memscan_range::ValueRange::new(bound(lo)?, bound(hi)?, width.unwrap_or(8))
                .map_err(|e| ApiError::new("invalid_request", e))?;
            Ok((Vec::new(), Some(range)))
        }
    }
}

#[cfg(any(target_os = "linux", test))]
pub fn run_mcp_memscan(
    session: &mut crate::live::procfs::LiveSession,
    pattern: (&[String], Option<&[String; 2]>, Option<usize>),
    context: (Option<usize>, Option<usize>, Option<usize>),
    budgets: (Option<usize>, Option<u64>, Option<u64>),
    cancel: &Cancellation,
) -> Result<Value, ApiError> {
    let (align_opt, before_opt, after_opt) = context;
    let (max_hits_opt, max_bytes_opt, timeout_opt) = budgets;
    let (values, range) = memscan_pattern(pattern.0, pattern.1, pattern.2)?;
    let align = align_opt.unwrap_or(DEFAULT_ALIGN);
    let before_words = before_opt.unwrap_or(DEFAULT_BEFORE_WORDS);
    let after_words = after_opt.unwrap_or(DEFAULT_AFTER_WORDS);
    if before_words > MAX_CONTEXT_WORDS || after_words > MAX_CONTEXT_WORDS {
        return Err(ApiError::new("invalid_request", format!("context words must be in 0..={MAX_CONTEXT_WORDS}")));
    }
    let mem_file = crate::live::procfs::open_process_mem(session.process.pid, session.process.starttime_ticks)
        .map_err(|e| classify_live_error(&e))?;
    let needle = encode_values_le(&values);
    let cfg = crate::live::memscan::ScanConfig {
        align,
        before_words,
        after_words,
        max_hits: max_hits_opt.unwrap_or(DEFAULT_MAX_HITS),
        max_bytes: max_bytes_opt.unwrap_or(MAX_MCP_LIVE_BYTES),
        timeout: Duration::from_millis(timeout_opt.unwrap_or(MAX_MCP_LIVE_DURATION_MS)),
    };
    let pattern =
        range.map_or(crate::live::memscan_range::Pattern::Bytes(&needle), crate::live::memscan_range::Pattern::Range);
    let outcome = crate::live::memscan::scan_memory_pattern(
        &mem_file,
        &session.image,
        session.process.pie_slide,
        &session.regions,
        pattern,
        &cfg,
        Some(cancel.flag()),
    )
    .map_err(|e| classify_live_error(&e))?;
    crate::live::procfs::refresh_session_identity(session);
    let report = crate::live::types::MemscanReport {
        schema_version: crate::live::types::SCHEMA_VERSION,
        tool: crate::live::types::TOOL_NAME,
        tool_version: crate::live::types::TOOL_VERSION,
        operation: "live_memscan",
        process: session.process.clone(),
        needle_hex: format_bytes_hex(&needle),
        range: range.map(|r| crate::live::types::ScanRange {
            lo: crate::live::types::HexAddr(r.lo),
            hi: crate::live::types::HexAddr(r.hi),
            width: r.width,
        }),
        align,
        elapsed_ms: outcome.elapsed_ms,
        regions_scanned: outcome.regions_scanned,
        regions_skipped: outcome.regions_skipped,
        bytes_scanned: outcome.bytes_scanned,
        unreadable_ranges: outcome.unreadable_ranges,
        stop_reason: outcome.stop_reason,
        hits: outcome.hits,
    };
    serde_json::to_value(report).map_err(|e| ApiError::new("serialization_failed", e.to_string()))
}

#[cfg(any(target_os = "linux", test))]
pub fn run_mcp_probe(
    session: &mut crate::live::procfs::LiveSession,
    addresses: &[String],
    backend: LiveProbeBackend,
    capture: (bool, bool),
    budgets: (Option<u64>, Option<usize>),
    cancel: &Cancellation,
) -> Result<Value, ApiError> {
    let addrs = parse_addr_list(addresses, 1, MAX_PROBES_PER_SESSION, "probe")?;
    crate::live::probe::validate::validate_session_for_probe(session).map_err(|e| classify_live_error(&e))?;
    let specs = crate::live::probe::validate::validate_probe_targets(
        &session.image,
        session.process.pie_slide,
        &session.regions,
        &addrs,
    )
    .map_err(|e| ApiError::new("invalid_request", e))?;
    let cfg = crate::live::probe::tracefs::ProbeRunConfig {
        duration: Duration::from_millis(budgets.0.unwrap_or(DEFAULT_PROBE_DURATION_MS)),
        max_events: budgets.1.unwrap_or(MAX_MCP_LIVE_EVENTS),
        want_callers: capture.0,
        want_regs: capture.1,
        fetches: Vec::new(),
        filters: Vec::new(),
        every: 1,
        first: None,
        until_hits: None,
        heartbeat_ms: None,
        mark_file: None,
        mark_regex: None,
        stream_json: false,
        spawn_watchdog: true,
        cancel: Some(cancel.flag()),
    };
    let backend_enum = ProbeBackend::from(backend);
    let (obs, probes) = match backend_enum {
        ProbeBackend::Perf => crate::live::probe::perf::run_perf_probe(session, &specs, &cfg),
        ProbeBackend::Tracefs => crate::live::probe::tracefs::run_tracefs_probe(session, &specs, &cfg),
    }
    .map_err(|e| classify_live_error(&e))?;
    let report = crate::live::probe::build_probe_report(
        backend_enum,
        session.process.clone(),
        obs,
        probes,
        &specs,
        cfg.want_callers,
        cfg.want_regs,
    );
    serde_json::to_value(report).map_err(|e| ApiError::new("serialization_failed", e.to_string()))
}

/// The samples a watch keeps: `max_samples` (default 32, `1..=MAX_MCP_LIVE_EVENTS`) and the
/// written-value range `[LO, HI)` a kept sample must have.
pub fn mcp_watch_sampling(
    max_samples: Option<usize>,
    value_range: Option<&[String; 2]>,
) -> Result<(usize, Option<(u64, u64)>), ApiError> {
    let max = max_samples.unwrap_or(crate::live::cli::DEFAULT_MAX_WATCH_SAMPLES);
    if max == 0 || max > MAX_MCP_LIVE_EVENTS {
        return Err(ApiError::new("invalid_request", format!("max_samples must be in 1..={MAX_MCP_LIVE_EVENTS}")));
    }
    let range = value_range
        .map(|[lo, hi]| {
            let bound = |text: &str| parse_number(text).map_err(|e| ApiError::new("invalid_request", e));
            let (lo, hi) = (bound(lo)?, bound(hi)?);
            if lo >= hi {
                return Err(ApiError::new("invalid_request", "value_range LO must be below HI"));
            }
            Ok((lo, hi))
        })
        .transpose()?;
    Ok((max, range))
}

#[cfg(any(target_os = "linux", test))]
pub fn run_mcp_watch(
    session: &mut crate::live::procfs::LiveSession,
    targets: (&[String], &[String]),
    mode: (Option<u8>, LiveWatchAccess, bool),
    budgets: (Option<u64>, Option<usize>),
    sampling: (usize, Option<(u64, u64)>),
    cancel: &Cancellation,
) -> Result<Value, ApiError> {
    let len = parse_mcp_watch_len(mode.0)?;
    let access = WatchAccessMode::from(mode.1);
    let addrs = parse_addr_list(targets.0, 0, MAX_WATCHES_PER_SESSION, "watch")?;
    crate::live::watch::validate::validate_session_for_watch(session).map_err(|e| classify_live_error(&e))?;
    let mem_file = crate::live::procfs::open_process_mem(session.process.pid, session.process.starttime_ticks).ok();
    let mem_reader: Option<&dyn crate::live::memscan::ReadAt> =
        mem_file.as_ref().map(|f| f as &dyn crate::live::memscan::ReadAt);
    let specs = crate::live::watch::validate::validate_watch_targets(
        &session.image,
        session.process.pie_slide,
        &session.regions,
        &addrs,
        len,
        access,
        mem_reader,
    )
    .map_err(|e| ApiError::new("invalid_request", e))?;
    let dependent = crate::live::watch::rebind_runtime::prepare_dependent_watches(
        (&session.image, session.process.pie_slide, &session.regions),
        (targets.1, len, access),
        specs.len(),
        mem_reader,
    )
    .map_err(|e| ApiError::new("invalid_request", e))?;
    let cfg = crate::live::watch::perf::WatchRunConfig {
        duration: Duration::from_millis(budgets.0.unwrap_or(DEFAULT_PROBE_DURATION_MS)),
        max_events: budgets.1.unwrap_or(MAX_MCP_LIVE_EVENTS),
        want_regs: mode.2,
        cancel: Some(cancel.flag()),
        keep: crate::live::watch::samples::SampleKeep { max: sampling.0, value_range: sampling.1, stream: false },
    };
    let (obs, watches, dep_results) =
        crate::live::watch::perf::run_perf_watch(session, &specs, dependent, &cfg, mem_reader)
            .map_err(|e| classify_live_error(&e))?;
    let report = crate::live::watch::build_watch_report_with_dependent(
        session.process.clone(),
        obs,
        watches,
        dep_results,
        mode.2,
        mem_file.is_some(),
    );
    serde_json::to_value(report).map_err(|e| ApiError::new("serialization_failed", e.to_string()))
}
