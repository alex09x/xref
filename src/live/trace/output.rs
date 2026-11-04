/*
 * XRef — report schema, text renderer, and JSON output for live trace windows
 * Copyright (c) 2026 Alexander Panasenko
 * Contact: alex@prod.codes
 * Author: https://prod.codes/about/
 * Project: https://github.com/alex09x/xref
 * SPDX-License-Identifier: MIT OR Apache-2.0
 */

use std::error::Error;
use std::fmt::Write as _;
use std::io::Write;

use serde::Serialize;

use crate::live::probe::types::{FetchedValue, LostEvents};
use crate::live::trace::plan::ReturnMode;
use crate::live::types::{HexAddr, ProcessMeta, SCHEMA_VERSION, TOOL_NAME, TOOL_VERSION, format_signed_hex};

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum TraceStopReason {
    MaxWindows,
    MaxEvents,
    DurationElapsed,
    Interrupted,
    ProcessExited,
    ProcessChanged,
}

impl TraceStopReason {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::MaxWindows => "max_windows",
            Self::MaxEvents => "max_events",
            Self::DurationElapsed => "duration_elapsed",
            Self::Interrupted => "interrupted",
            Self::ProcessExited => "process_exited",
            Self::ProcessChanged => "process_changed",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum TraceWindowStatus {
    Complete,
    Incomplete,
    Truncated,
}

impl TraceWindowStatus {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Complete => "complete",
            Self::Incomplete => "incomplete",
            Self::Truncated => "truncated",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum TraceEventKind {
    Entry,
    Return,
    Stop,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct TraceEvent {
    pub seq: usize,
    pub kind: TraceEventKind,
    pub depth: usize,
    pub target_va: HexAddr,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub symbol: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub call_site_va: Option<HexAddr>,
    pub call_site_verified: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub caller_va: Option<HexAddr>,
    pub tail_call: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub timestamp_ns: Option<u64>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub fetches: Vec<FetchedValue>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct TraceWindow {
    pub window_id: usize,
    pub tid: u32,
    pub start_va: HexAddr,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub stop_va: Option<HexAddr>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub start_timestamp_ns: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub end_timestamp_ns: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub duration_ns: Option<u64>,
    pub status: TraceWindowStatus,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub incomplete_reason: Option<&'static str>,
    pub possible_loss: bool,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub start_fetches: Vec<FetchedValue>,
    pub events: Vec<TraceEvent>,
}

#[derive(Clone, Debug, Serialize)]
pub struct TraceSummary {
    pub windows: usize,
    pub complete_windows: usize,
    pub incomplete_windows: usize,
    pub events: usize,
    pub lost: Option<u64>,
    pub lost_events: LostEvents,
    pub stop_reason: TraceStopReason,
    pub return_mode: &'static str,
    pub elapsed_ms: u64,
    pub unparsed_events: u64,
    pub excluded_other_tgid_events: u64,
    pub ambiguous_tid_events: u64,
}

#[derive(Clone, Debug, Serialize)]
pub struct TraceReport {
    pub schema_version: u32,
    pub tool: &'static str,
    pub tool_version: &'static str,
    pub operation: &'static str,
    pub backend: &'static str,
    pub process: ProcessMeta,
    pub summary: TraceSummary,
    pub windows: Vec<TraceWindow>,
}

#[allow(clippy::too_many_arguments)]
#[must_use]
pub fn build_trace_report(
    process: ProcessMeta,
    windows: Vec<TraceWindow>,
    events: usize,
    lost_events: LostEvents,
    stop_reason: TraceStopReason,
    return_mode: ReturnMode,
    elapsed_ms: u64,
    unparsed_events: u64,
    excluded_other_tgid_events: u64,
    ambiguous_tid_events: u64,
) -> TraceReport {
    let complete_windows = windows.iter().filter(|w| w.status == TraceWindowStatus::Complete).count();
    let incomplete_windows = windows.len().saturating_sub(complete_windows);
    let lost = match &lost_events {
        LostEvents::Known { total, .. } => Some(*total),
        LostEvents::Unknown { .. } => None,
    };
    TraceReport {
        schema_version: SCHEMA_VERSION,
        tool: TOOL_NAME,
        tool_version: TOOL_VERSION,
        operation: "live_trace",
        backend: "tracefs",
        process,
        summary: TraceSummary {
            windows: windows.len(),
            complete_windows,
            incomplete_windows,
            events,
            lost,
            lost_events,
            stop_reason,
            return_mode: return_mode.as_str(),
            elapsed_ms,
            unparsed_events,
            excluded_other_tgid_events,
            ambiguous_tid_events,
        },
        windows,
    }
}

pub fn write_trace_json(report: &TraceReport, out: &mut dyn Write) -> Result<(), Box<dyn Error>> {
    serde_json::to_writer(&mut *out, report)?;
    writeln!(out)?;
    Ok(())
}

pub fn write_trace_text(report: &TraceReport, out: &mut dyn Write) -> std::io::Result<()> {
    writeln!(
        out,
        "pid {}  match {}  slide {}  backend {}  return_mode {}",
        report.process.pid,
        report.process.binary_match.as_str(),
        format_signed_hex(report.process.pie_slide),
        report.backend,
        report.summary.return_mode,
    )?;
    for warn in &report.process.warnings {
        writeln!(out, "warning: {warn}")?;
    }
    for win in &report.windows {
        let mut hdr = format!(
            "window {}  tid {}  start {:#x}  status {}",
            win.window_id,
            win.tid,
            win.start_va.0,
            win.status.as_str(),
        );
        if let Some(stop_va) = win.stop_va {
            let _ = write!(hdr, "  stop {:#x}", stop_va.0);
        }
        if let Some(reason) = win.incomplete_reason {
            let _ = write!(hdr, " ({reason})");
        }
        if win.possible_loss {
            hdr.push_str("  [possible_loss]");
        }
        append_fetches(&mut hdr, &win.start_fetches);
        writeln!(out, "{hdr}")?;

        for ev in &win.events {
            let indent = "  ".repeat(ev.depth);
            let mut line = format!("  {:2}  {indent}", ev.depth);
            match ev.kind {
                TraceEventKind::Entry => {
                    let _ = write!(line, "> {:#x}", ev.target_va.0);
                    if let Some(cs) = ev.call_site_va {
                        let _ = write!(line, " @{:#x}", cs.0);
                    }
                }
                TraceEventKind::Return => {
                    let _ = write!(line, "< {:#x}", ev.target_va.0);
                }
                TraceEventKind::Stop => {
                    let _ = write!(line, "= {:#x} [stop]", ev.target_va.0);
                }
            }
            if let Some(sym) = &ev.symbol {
                let _ = write!(line, " ({sym})");
            }
            if ev.tail_call {
                line.push_str(" [tail]");
            }
            append_fetches(&mut line, &ev.fetches);
            writeln!(out, "{line}")?;
        }
    }
    let lost_str = match &report.summary.lost_events {
        LostEvents::Known { total, .. } => total.to_string(),
        LostEvents::Unknown { reason } => format!("unknown ({reason})"),
    };
    writeln!(
        out,
        "summary: windows={} events={} lost={lost_str} stop={} elapsed_ms={}",
        report.summary.windows,
        report.summary.events,
        report.summary.stop_reason.as_str(),
        report.summary.elapsed_ms,
    )
}

fn append_fetches(buf: &mut String, fetches: &[FetchedValue]) {
    if !fetches.is_empty() {
        buf.push_str("  ");
        for (idx, fv) in fetches.iter().enumerate() {
            if idx > 0 {
                buf.push(' ');
            }
            let _ = write!(buf, "{}={:#x}", fv.name, fv.value.0);
        }
    }
}
