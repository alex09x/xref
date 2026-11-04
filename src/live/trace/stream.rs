/*
 * XRef — nonblocking trace_pipe streaming and final drain for live trace
 * Copyright (c) 2026 Alexander Panasenko
 * Contact: alex@prod.codes
 * Author: https://prod.codes/about/
 * Project: https://github.com/alex09x/xref
 * SPDX-License-Identifier: MIT OR Apache-2.0
 */

use std::fs::File;
use std::io::{self, Read};
use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Instant;

use crate::live::probe::trace_parse::StreamingTraceLineBuffer;
use crate::live::probe::tracefs_stream::{StreamState, sleep_or_recheck};
use crate::live::probe::tracefs_tid::accept_tid_for_target;
use crate::live::procfs::LiveSession;
use crate::live::trace::output::TraceStopReason;
use crate::live::trace::window::{TraceWindowEngine, parse_trace_line};

#[allow(clippy::too_many_arguments)]
pub fn stream_trace_pipe(
    session: &mut LiveSession,
    trace_pipe_fd: &mut File,
    line_buf: &mut StreamingTraceLineBuffer,
    tid_state: &mut StreamState,
    engine: &mut TraceWindowEngine<'_>,
    proc_root: &Path,
    event_prefix: &str,
    cancel: Option<&AtomicBool>,
    deadline: Option<Instant>,
) -> TraceStopReason {
    let mut chunk = [0_u8; 8192];
    let mut last_recheck = Instant::now();
    loop {
        if cancel.is_some_and(|flag| flag.load(Ordering::Relaxed)) {
            return TraceStopReason::Interrupted;
        }
        if let Some(reason) = engine.stop_reason() {
            return reason;
        }
        if deadline.is_some_and(|dl| Instant::now() >= dl) {
            return TraceStopReason::DurationElapsed;
        }
        match trace_pipe_fd.read(&mut chunk) {
            Ok(n) if n > 0 => {
                line_buf.push_chunk(&chunk[..n], |line| {
                    ingest_trace_line(line, event_prefix, proc_root, tid_state, engine);
                });
            }
            Ok(_) => {
                engine.flush_ready_all();
                if let Some(reason) = engine.stop_reason() {
                    return reason;
                }
                sleep_or_recheck(session, &mut last_recheck, deadline);
            }
            Err(err) if err.kind() == io::ErrorKind::WouldBlock => {
                engine.flush_ready_all();
                if let Some(reason) = engine.stop_reason() {
                    return reason;
                }
                sleep_or_recheck(session, &mut last_recheck, deadline);
            }
            Err(err) if err.kind() == io::ErrorKind::Interrupted => return TraceStopReason::Interrupted,
            Err(_) => return TraceStopReason::DurationElapsed,
        }
        if session.process.process_changed {
            return TraceStopReason::ProcessChanged;
        }
        if !session.process.pid_alive_after {
            return TraceStopReason::ProcessExited;
        }
    }
}

pub fn drain_remaining_trace_pipe(
    trace_pipe_fd: &mut File,
    line_buf: &mut StreamingTraceLineBuffer,
    tid_state: &mut StreamState,
    engine: &mut TraceWindowEngine<'_>,
    proc_root: &Path,
    event_prefix: &str,
) {
    let mut chunk = [0_u8; 8192];
    while engine.stop_reason().is_none() {
        match trace_pipe_fd.read(&mut chunk) {
            Ok(n) if n > 0 => {
                line_buf.push_chunk(&chunk[..n], |line| {
                    ingest_trace_line(line, event_prefix, proc_root, tid_state, engine);
                });
            }
            _ => break,
        }
    }
    line_buf.finish(|line| ingest_trace_line(line, event_prefix, proc_root, tid_state, engine));
}

pub fn ingest_trace_line(
    line: &str,
    event_prefix: &str,
    proc_root: &Path,
    tid_state: &mut StreamState,
    engine: &mut TraceWindowEngine<'_>,
) {
    if engine.stop_reason().is_some() {
        return;
    }
    let Some(ev) = parse_trace_line(line, event_prefix) else {
        tid_state.unparsed_lines = tid_state.unparsed_lines.saturating_add(1);
        return;
    };
    if !accept_tid_for_target(&ev, proc_root, tid_state) {
        return;
    }
    engine.push_event(ev);
}
