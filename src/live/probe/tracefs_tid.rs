/*
 * XRef — tracefs probe TID ownership and change tracking
 * Copyright (c) 2026 Alexander Panasenko
 *
 * Contact: alex@prod.codes
 * Author: https://prod.codes/about/
 * Project: https://github.com/alex09x/xref
 * SPDX-License-Identifier: MIT OR Apache-2.0
 */

use std::path::Path;

use super::trace_parse::ParsedTraceEvent;
use super::tracefs_stream::StreamState;

pub(super) fn accept_tid_for_target(ev: &ParsedTraceEvent, proc_root: &Path, state: &mut StreamState) -> bool {
    if let Some(tgid) = ev.tgid {
        if tgid == state.target_pid {
            record_observed_tid(state, ev.tid);
            return true;
        }
        state.excluded_other_tgid = state.excluded_other_tgid.saturating_add(1);
        return false;
    }
    if state.known_tids.contains(&ev.tid) {
        return true;
    }
    if state.other_tgid_tids.contains(&ev.tid) {
        state.excluded_other_tgid = state.excluded_other_tgid.saturating_add(1);
        return false;
    }
    let task_path = proc_root.join(state.target_pid.to_string()).join("task").join(ev.tid.to_string());
    if task_path.exists() {
        record_observed_tid(state, ev.tid);
        return true;
    }
    let status_path = proc_root.join(ev.tid.to_string()).join("status");
    if let Ok(status) = std::fs::read_to_string(status_path)
        && let Some(tgid) = status.lines().find_map(|line| line.strip_prefix("Tgid:")?.trim().parse::<u32>().ok())
    {
        if tgid == state.target_pid {
            record_observed_tid(state, ev.tid);
            return true;
        }
        state.other_tgid_tids.insert(ev.tid);
        state.excluded_other_tgid = state.excluded_other_tgid.saturating_add(1);
        return false;
    }
    state.ambiguous_tid = state.ambiguous_tid.saturating_add(1);
    false
}

fn record_observed_tid(state: &mut StreamState, tid: u32) {
    if state.known_tids.insert(tid) {
        super::types::record_thread_change(
            &mut state.thread_changes,
            &mut state.thread_changes_truncated,
            tid,
            "observed",
        );
        eprintln!("xref: tid_observed {tid}");
    }
}
