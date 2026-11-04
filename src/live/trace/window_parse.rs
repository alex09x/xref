/*
 * XRef — tracefs uprobe/uretprobe line normalizer and pure batch runners
 * Copyright (c) 2026 Alexander Panasenko
 * Contact: alex@prod.codes
 * Author: https://prod.codes/about/
 * Project: https://github.com/alex09x/xref
 * SPDX-License-Identifier: MIT OR Apache-2.0
 */

#[cfg(test)]
use crate::image::Image;
use crate::live::probe::trace_parse::{ParsedTraceEvent, parse_uprobe_trace_line};
use crate::live::probe::types::FetchedValue;
#[cfg(test)]
use crate::live::trace::output::TraceStopReason;
use crate::live::trace::output::{TraceWindow, TraceWindowStatus};
use crate::live::trace::plan::RoleFetch;
#[cfg(test)]
use crate::live::trace::plan::TracePlan;
use crate::live::trace::window::ActiveWindow;
#[cfg(test)]
use crate::live::trace::window::{TraceEngineOutput, TraceWindowEngine};
use crate::live::types::HexAddr;
#[cfg(test)]
use crate::live::types::RegionEntry;

#[must_use]
pub fn parse_trace_line(line: &str, event_prefix: &str) -> Option<ParsedTraceEvent> {
    if let Some(ev) = parse_uprobe_trace_line(line, event_prefix) {
        return Some(ev);
    }
    let marker = format!(": {event_prefix}");
    let marker_pos = line.find(&marker)?;
    let after_prefix = &line[marker_pos + marker.len()..];
    let (idx_str, after_event) = after_prefix.split_once(": (")?;
    let (ip_pair, tail) = after_event.split_once(')')?;
    let (caller_ip, func_ip) = ip_pair.split_once(" <- ")?;
    let prefix = &line[..marker_pos + marker.len() + idx_str.len()];
    let extra_ra = if tail.contains(" ra=") { String::new() } else { format!(" ra={}", caller_ip.trim()) };
    let normalized = format!("{prefix}: ({}){tail}{extra_ra}", func_ip.trim());
    parse_uprobe_trace_line(&normalized, event_prefix)
}

#[cfg(test)]
#[allow(clippy::too_many_arguments)]
#[must_use]
pub fn process_trace_lines(
    image: &Image,
    pie_slide: i64,
    regions: &[RegionEntry],
    plan: &TracePlan,
    event_prefix: &str,
    target_pid: Option<u32>,
    max_windows: usize,
    max_events: usize,
    lines: &[&str],
) -> TraceEngineOutput {
    let mut engine = TraceWindowEngine::new(image, pie_slide, regions, plan, max_windows, max_events);
    let mut unparsed_lines = 0_u64;
    for &line in lines {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }
        let Some(ev) = parse_trace_line(trimmed, event_prefix) else {
            unparsed_lines = unparsed_lines.saturating_add(1);
            continue;
        };
        if let (Some(pid), Some(tgid)) = (target_pid, ev.tgid)
            && pid != tgid
        {
            continue;
        }
        engine.push_event(ev);
    }
    let (windows, total_events, stop_reason) = engine.finish(TraceStopReason::DurationElapsed, false);
    TraceEngineOutput { windows, total_events, stop_reason, unparsed_lines }
}

#[cfg(test)]
#[must_use]
pub fn process_parsed_events(
    image: &Image,
    pie_slide: i64,
    regions: &[RegionEntry],
    plan: &TracePlan,
    max_windows: usize,
    max_events: usize,
    events: &[ParsedTraceEvent],
) -> TraceEngineOutput {
    let mut engine = TraceWindowEngine::new(image, pie_slide, regions, plan, max_windows, max_events);
    for ev in events {
        engine.push_event(ev.clone());
    }
    let (windows, total_events, stop_reason) = engine.finish(TraceStopReason::DurationElapsed, false);
    TraceEngineOutput { windows, total_events, stop_reason, unparsed_lines: 0 }
}

pub(super) fn extract_fetches(ev: &ParsedTraceEvent, fetches: &[RoleFetch]) -> Vec<FetchedValue> {
    fetches
        .iter()
        .filter_map(|rf| {
            ev.fetch_values
                .get(&rf.kernel_name)
                .map(|&v| FetchedValue { name: rf.user_name.clone(), value: HexAddr(v) })
        })
        .collect()
}

pub(super) fn finalize_window(
    win: ActiveWindow,
    stop_va: Option<HexAddr>,
    status: TraceWindowStatus,
    possible_loss: bool,
) -> TraceWindow {
    let end_ts = win.last_timestamp_ns.or(win.start_timestamp_ns);
    let duration_ns = match (win.start_timestamp_ns, end_ts) {
        (Some(s), Some(e)) => Some(e.saturating_sub(s)),
        _ => None,
    };
    TraceWindow {
        window_id: win.window_id,
        tid: win.tid,
        start_va: HexAddr(win.start_va),
        stop_va,
        start_timestamp_ns: win.start_timestamp_ns,
        end_timestamp_ns: end_ts,
        duration_ns,
        status,
        incomplete_reason: win.incomplete_reason,
        possible_loss,
        start_fetches: win.start_fetches,
        events: win.events,
    }
}
