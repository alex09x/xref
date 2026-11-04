/*
 * XRef — per-thread window state transitions and budget enforcement
 * Copyright (c) 2026 Alexander Panasenko
 * Contact: alex@prod.codes
 * Author: https://prod.codes/about/
 * Project: https://github.com/alex09x/xref
 * SPDX-License-Identifier: MIT OR Apache-2.0
 */

use std::collections::BTreeMap;

use crate::live::probe::caller::attribute_caller;
use crate::live::probe::trace_parse::ParsedTraceEvent;
use crate::live::probe::types::FetchedValue;
use crate::live::trace::output::{TraceEvent, TraceEventKind, TraceStopReason, TraceWindowStatus};
use crate::live::trace::plan::{PlannedProbe, RoleFetch};
use crate::live::trace::window::{ActiveWindow, OpenFrame, TraceWindowEngine};
use crate::live::trace::window_parse::{extract_fetches, finalize_window};
use crate::live::types::HexAddr;

impl TraceWindowEngine<'_> {
    pub(super) fn handle_start_window(
        &mut self,
        probe: &PlannedProbe,
        start_va: u64,
        has_stop_return: bool,
        fetches: &[RoleFetch],
        ev: &ParsedTraceEvent,
    ) {
        if let Some(depth) =
            self.active.get(&ev.tid).filter(|w| w.has_stop_return && w.start_va == start_va).map(|w| w.depth)
        {
            let (cs, verified, caller) = self.resolve_entry_caller(probe, ev);
            if let Some(win) = self.active.get_mut(&ev.tid) {
                win.frames.push(OpenFrame { callee_va: start_va, call_site_va: cs.map(|h| h.0), depth });
                win.depth = depth.saturating_add(1);
            }
            self.push_window_event(
                ev.tid,
                TraceEventKind::Entry,
                depth,
                start_va,
                cs,
                verified,
                caller,
                false,
                ev.timestamp_ns,
                extract_fetches(ev, fetches),
            );
            return;
        }
        // A start rejected by --start-filter must not disturb a window that is already open (#116 review).
        let start_fetches = extract_fetches(ev, fetches);
        let value_map: BTreeMap<&str, u64> = start_fetches.iter().map(|fv| (fv.name.as_str(), fv.value.0)).collect();
        if !self
            .plan
            .start_filters
            .iter()
            .all(|flt| value_map.get(flt.field.as_str()).is_some_and(|&v| flt.op.test(v, flt.value)))
        {
            return;
        }
        if let Some(mut unclosed) = self.active.remove(&ev.tid) {
            unclosed.incomplete_reason.get_or_insert("restarted_before_stop");
            self.completed.push(finalize_window(unclosed, None, TraceWindowStatus::Truncated, false));
            self.check_post_close_limits();
            if self.stop_reason.is_some() {
                return;
            }
        }
        if self.opened_windows >= self.max_windows {
            return;
        }
        if self.total_events >= self.max_events {
            self.stop_reason = Some(TraceStopReason::MaxEvents);
            return;
        }

        self.opened_windows = self.opened_windows.saturating_add(1);
        let window_id = self.opened_windows;
        let (cs, verified, caller) = self.resolve_entry_caller(probe, ev);
        let entry_ev = TraceEvent {
            seq: 0,
            kind: TraceEventKind::Entry,
            depth: 0,
            target_va: HexAddr(start_va),
            symbol: self.plan.symbols.get(&start_va).cloned(),
            call_site_va: cs,
            call_site_verified: verified,
            caller_va: caller,
            tail_call: false,
            timestamp_ns: ev.timestamp_ns,
            fetches: start_fetches.clone(),
        };
        self.total_events = self.total_events.saturating_add(1);
        self.active.insert(
            ev.tid,
            ActiveWindow {
                window_id,
                tid: ev.tid,
                start_va,
                has_stop_return,
                start_timestamp_ns: ev.timestamp_ns,
                last_timestamp_ns: ev.timestamp_ns,
                start_fetches,
                depth: 1,
                frames: Vec::new(),
                incomplete: false,
                incomplete_reason: None,
                events: vec![entry_ev],
            },
        );
        self.check_active_event_budget();
    }

    pub(super) fn handle_function_return(
        &mut self,
        fn_va: u64,
        is_stop_return: bool,
        fetches: &[RoleFetch],
        ev: &ParsedTraceEvent,
    ) {
        let Some(has_frame) = self.active.get(&ev.tid).map(|w| w.frames.iter().rposition(|f| f.callee_va == fn_va))
        else {
            return;
        };
        if let Some(pos) = has_frame {
            let mut ret_depth = 0;
            if let Some(win) = self.active.get_mut(&ev.tid) {
                if pos + 1 < win.frames.len() {
                    win.incomplete = true;
                    win.incomplete_reason.get_or_insert("missed_inner_return");
                }
                ret_depth = win.frames[pos].depth;
                win.frames.truncate(pos);
                win.depth = ret_depth;
            }
            self.push_window_event(
                ev.tid,
                TraceEventKind::Return,
                ret_depth,
                fn_va,
                None,
                false,
                None,
                false,
                ev.timestamp_ns,
                extract_fetches(ev, fetches),
            );
        } else if is_stop_return && self.active.get(&ev.tid).is_some_and(|w| w.has_stop_return && w.start_va == fn_va) {
            if let Some(win) = self.active.get_mut(&ev.tid) {
                if !win.frames.is_empty() {
                    win.incomplete = true;
                    win.incomplete_reason.get_or_insert("unclosed_inner_frames_at_return");
                }
                let seq = win.events.len();
                win.last_timestamp_ns = ev.timestamp_ns.or(win.last_timestamp_ns);
                win.events.push(TraceEvent {
                    seq,
                    kind: TraceEventKind::Return,
                    depth: 0,
                    target_va: HexAddr(fn_va),
                    symbol: self.plan.symbols.get(&fn_va).cloned(),
                    call_site_va: None,
                    call_site_verified: false,
                    caller_va: None,
                    tail_call: false,
                    timestamp_ns: ev.timestamp_ns,
                    fetches: extract_fetches(ev, fetches),
                });
                self.total_events = self.total_events.saturating_add(1);
            }
            if let Some(win) = self.active.remove(&ev.tid) {
                let status = if win.incomplete { TraceWindowStatus::Incomplete } else { TraceWindowStatus::Complete };
                self.completed.push(finalize_window(win, Some(HexAddr(fn_va)), status, false));
            }
            self.check_post_close_limits();
        }
    }

    pub(super) fn handle_stop_at(&mut self, stop_va: u64, fetches: &[RoleFetch], ev: &ParsedTraceEvent) {
        if !self.active.contains_key(&ev.tid) {
            return;
        }
        if !fetches.is_empty() && self.total_events < self.max_events {
            if let Some(win) = self.active.get_mut(&ev.tid) {
                let seq = win.events.len();
                win.last_timestamp_ns = ev.timestamp_ns.or(win.last_timestamp_ns);
                win.events.push(TraceEvent {
                    seq,
                    kind: TraceEventKind::Stop,
                    depth: 0,
                    target_va: HexAddr(stop_va),
                    symbol: self.plan.symbols.get(&stop_va).cloned(),
                    call_site_va: None,
                    call_site_verified: true,
                    caller_va: None,
                    tail_call: false,
                    timestamp_ns: ev.timestamp_ns,
                    fetches: extract_fetches(ev, fetches),
                });
                self.total_events = self.total_events.saturating_add(1);
            }
        } else if let Some(win) = self.active.get_mut(&ev.tid) {
            win.last_timestamp_ns = ev.timestamp_ns.or(win.last_timestamp_ns);
        }
        if let Some(win) = self.active.remove(&ev.tid) {
            let status = if win.incomplete { TraceWindowStatus::Incomplete } else { TraceWindowStatus::Complete };
            self.completed.push(finalize_window(win, Some(HexAddr(stop_va)), status, false));
        }
        self.check_post_close_limits();
    }

    pub(super) fn resolve_entry_caller(
        &self,
        probe: &PlannedProbe,
        ev: &ParsedTraceEvent,
    ) -> (Option<HexAddr>, bool, Option<HexAddr>) {
        let Some(raw_ra) = ev.return_addr else { return (None, false, None) };
        let entry = attribute_caller(self.image, self.pie_slide, self.regions, &probe.effective_unwind, raw_ra, 1);
        (entry.call_site_static_va, entry.call_verified, entry.caller_function)
    }

    #[allow(clippy::too_many_arguments)]
    pub(super) fn push_window_event(
        &mut self,
        tid: u32,
        kind: TraceEventKind,
        depth: usize,
        target_va: u64,
        call_site_va: Option<HexAddr>,
        call_site_verified: bool,
        caller_va: Option<HexAddr>,
        tail_call: bool,
        timestamp_ns: Option<u64>,
        fetches: Vec<FetchedValue>,
    ) {
        if self.total_events >= self.max_events {
            self.check_active_event_budget();
            return;
        }
        let symbol = self.plan.symbols.get(&target_va).cloned();
        if let Some(win) = self.active.get_mut(&tid) {
            let seq = win.events.len();
            win.last_timestamp_ns = timestamp_ns.or(win.last_timestamp_ns);
            win.events.push(TraceEvent {
                seq,
                kind,
                depth,
                target_va: HexAddr(target_va),
                symbol,
                call_site_va,
                call_site_verified,
                caller_va,
                tail_call,
                timestamp_ns,
                fetches,
            });
            self.total_events = self.total_events.saturating_add(1);
        }
        self.check_active_event_budget();
    }

    pub(super) fn check_post_close_limits(&mut self) {
        if self.completed.len() >= self.max_windows && self.active.is_empty() {
            self.stop_reason = Some(TraceStopReason::MaxWindows);
        } else if self.total_events >= self.max_events {
            self.truncate_all_active("max_events_reached");
            self.stop_reason = Some(TraceStopReason::MaxEvents);
        }
    }

    fn check_active_event_budget(&mut self) {
        if self.total_events >= self.max_events {
            self.truncate_all_active("max_events_reached");
            self.stop_reason = Some(TraceStopReason::MaxEvents);
        }
    }

    fn truncate_all_active(&mut self, reason: &'static str) {
        let active_left = std::mem::take(&mut self.active);
        for (_, mut win) in active_left {
            win.incomplete_reason.get_or_insert(reason);
            self.completed.push(finalize_window(win, None, TraceWindowStatus::Truncated, false));
        }
    }
}
