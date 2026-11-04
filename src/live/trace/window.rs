/*
 * XRef — pure thread-scoped window state machine and monotonic ordering
 * Copyright (c) 2026 Alexander Panasenko
 * Contact: alex@prod.codes
 * Author: https://prod.codes/about/
 * Project: https://github.com/alex09x/xref
 * SPDX-License-Identifier: MIT OR Apache-2.0
 */

use std::collections::BTreeMap;

use crate::image::Image;
use crate::live::probe::trace_parse::ParsedTraceEvent;
use crate::live::probe::types::FetchedValue;
use crate::live::trace::output::{TraceEvent, TraceEventKind, TraceStopReason, TraceWindow, TraceWindowStatus};
use crate::live::trace::plan::{PlannedProbe, ProbeAction, TracePlan};
pub use crate::live::trace::window_parse::parse_trace_line;
use crate::live::trace::window_parse::{extract_fetches, finalize_window};
#[cfg(test)]
pub use crate::live::trace::window_parse::{process_parsed_events, process_trace_lines};
use crate::live::types::{HexAddr, RegionEntry, remove_slide};

const REORDER_SLACK_NS: u64 = 5_000_000;
const MAX_REORDER_BUFFER: usize = 8192;

#[cfg(test)]
#[derive(Debug)]
pub struct TraceEngineOutput {
    pub windows: Vec<TraceWindow>,
    pub total_events: usize,
    pub stop_reason: TraceStopReason,
    pub unparsed_lines: u64,
}

pub(super) struct OpenFrame {
    pub callee_va: u64,
    pub call_site_va: Option<u64>,
    pub depth: usize,
}

pub(super) struct ActiveWindow {
    pub window_id: usize,
    pub tid: u32,
    pub start_va: u64,
    pub has_stop_return: bool,
    pub start_timestamp_ns: Option<u64>,
    pub last_timestamp_ns: Option<u64>,
    pub start_fetches: Vec<FetchedValue>,
    pub depth: usize,
    pub frames: Vec<OpenFrame>,
    pub incomplete: bool,
    pub incomplete_reason: Option<&'static str>,
    pub events: Vec<TraceEvent>,
}

pub struct TraceWindowEngine<'a> {
    pub(super) image: &'a Image,
    pub(super) pie_slide: i64,
    pub(super) regions: &'a [RegionEntry],
    pub(super) plan: &'a TracePlan,
    pub(super) max_windows: usize,
    pub(super) max_events: usize,
    next_arrival_seq: u64,
    max_seen_ts: u64,
    pending: BTreeMap<(u64, u64), ParsedTraceEvent>,
    pub(super) active: BTreeMap<u32, ActiveWindow>,
    pub(super) completed: Vec<TraceWindow>,
    pub(super) opened_windows: usize,
    pub(super) total_events: usize,
    pub(super) stop_reason: Option<TraceStopReason>,
}

impl<'a> TraceWindowEngine<'a> {
    #[must_use]
    pub const fn new(
        image: &'a Image,
        pie_slide: i64,
        regions: &'a [RegionEntry],
        plan: &'a TracePlan,
        max_windows: usize,
        max_events: usize,
    ) -> Self {
        Self {
            image,
            pie_slide,
            regions,
            plan,
            max_windows,
            max_events,
            next_arrival_seq: 0,
            max_seen_ts: 0,
            pending: BTreeMap::new(),
            active: BTreeMap::new(),
            completed: Vec::new(),
            opened_windows: 0,
            total_events: 0,
            stop_reason: None,
        }
    }

    #[must_use]
    pub const fn stop_reason(&self) -> Option<TraceStopReason> {
        self.stop_reason
    }

    pub fn push_event(&mut self, ev: ParsedTraceEvent) {
        if self.stop_reason.is_some() {
            return;
        }
        let ts = ev.timestamp_ns.unwrap_or(0);
        self.max_seen_ts = self.max_seen_ts.max(ts);
        let seq = self.next_arrival_seq;
        self.next_arrival_seq = self.next_arrival_seq.saturating_add(1);
        self.pending.insert((ts, seq), ev);
        while self.stop_reason.is_none() {
            let should_pop = self.pending.first_key_value().is_some_and(|(&(head_ts, _), _)| {
                head_ts.saturating_add(REORDER_SLACK_NS) <= self.max_seen_ts || self.pending.len() > MAX_REORDER_BUFFER
            });
            if !should_pop {
                break;
            }
            if let Some((_, ready)) = self.pending.pop_first() {
                self.apply_ordered_event(&ready);
            }
        }
    }

    pub fn flush_ready_all(&mut self) {
        while self.stop_reason.is_none() {
            let Some((_, ready)) = self.pending.pop_first() else { break };
            self.apply_ordered_event(&ready);
        }
    }

    #[must_use]
    pub fn finish(
        mut self,
        fallback_stop: TraceStopReason,
        possible_loss: bool,
    ) -> (Vec<TraceWindow>, usize, TraceStopReason) {
        self.flush_ready_all();
        let reason = self.stop_reason.unwrap_or(fallback_stop);
        let active_left = std::mem::take(&mut self.active);
        for (_, mut win) in active_left {
            let (status, why) = if reason == TraceStopReason::MaxEvents {
                (TraceWindowStatus::Truncated, "max_events_reached")
            } else {
                (TraceWindowStatus::Incomplete, "trace_stopped_before_window_end")
            };
            win.incomplete_reason.get_or_insert(why);
            self.completed.push(finalize_window(win, None, status, possible_loss));
        }
        for win in &mut self.completed {
            if possible_loss {
                win.possible_loss = true;
            }
        }
        self.completed.sort_by_key(|w| w.window_id);
        (self.completed, self.total_events, reason)
    }

    fn apply_ordered_event(&mut self, ev: &ParsedTraceEvent) {
        let Some(probe) = self.plan.probes.get(ev.probe_index) else { return };
        for action in &probe.actions {
            if self.stop_reason.is_some() {
                break;
            }
            self.apply_action(probe, action, ev);
        }
    }

    #[allow(clippy::too_many_lines)]
    fn apply_action(&mut self, probe: &PlannedProbe, action: &ProbeAction, ev: &ParsedTraceEvent) {
        match action {
            ProbeAction::CallSiteReturn { call_site_va, callee_va, fetches, .. } => {
                let Some(win) = self.active.get_mut(&ev.tid) else { return };
                let Some(pos) =
                    win.frames.iter().rposition(|f| f.call_site_va == Some(*call_site_va) && f.callee_va == *callee_va)
                else {
                    return;
                };
                if pos + 1 < win.frames.len() {
                    win.incomplete = true;
                    win.incomplete_reason.get_or_insert("missed_inner_return");
                }
                let depth = win.frames[pos].depth;
                win.frames.truncate(pos);
                win.depth = depth;
                self.push_window_event(
                    ev.tid,
                    TraceEventKind::Return,
                    depth,
                    *callee_va,
                    Some(HexAddr(*call_site_va)),
                    true,
                    None,
                    false,
                    ev.timestamp_ns,
                    extract_fetches(ev, fetches),
                );
            }
            ProbeAction::FunctionReturn { fn_va, is_stop_return, fetches } => {
                self.handle_function_return(*fn_va, *is_stop_return, fetches, ev);
            }
            ProbeAction::StopAt { stop_va, fetches } => {
                self.handle_stop_at(*stop_va, fetches, ev);
            }
            ProbeAction::StartWindow { start_va, has_stop_return, fetches } => {
                self.handle_start_window(probe, *start_va, *has_stop_return, fetches, ev);
            }
            ProbeAction::FunctionEntry { fn_va, fetches } => {
                let Some(depth) = self.active.get(&ev.tid).map(|w| w.depth) else { return };
                let (cs, verified, caller) = self.resolve_entry_caller(probe, ev);
                if let Some(win) = self.active.get_mut(&ev.tid) {
                    win.frames.push(OpenFrame { callee_va: *fn_va, call_site_va: cs.map(|h| h.0), depth });
                    win.depth = depth.saturating_add(1);
                }
                self.push_window_event(
                    ev.tid,
                    TraceEventKind::Entry,
                    depth,
                    *fn_va,
                    cs,
                    verified,
                    caller,
                    false,
                    ev.timestamp_ns,
                    extract_fetches(ev, fetches),
                );
            }
            ProbeAction::CallSiteEntry { caller_fn, call_site_va, callee_va, is_tail_call, fetches } => {
                let Some(depth) = self.active.get(&ev.tid).map(|w| w.depth) else { return };
                let verified = ev.hit_ip == 0 || remove_slide(ev.hit_ip, self.pie_slide) == Some(*call_site_va);
                if !*is_tail_call && let Some(win) = self.active.get_mut(&ev.tid) {
                    win.frames.push(OpenFrame { callee_va: *callee_va, call_site_va: Some(*call_site_va), depth });
                    win.depth = depth.saturating_add(1);
                }
                self.push_window_event(
                    ev.tid,
                    TraceEventKind::Entry,
                    depth,
                    *callee_va,
                    Some(HexAddr(*call_site_va)),
                    verified,
                    Some(HexAddr(*caller_fn)),
                    *is_tail_call,
                    ev.timestamp_ns,
                    extract_fetches(ev, fetches),
                );
            }
        }
    }
}
