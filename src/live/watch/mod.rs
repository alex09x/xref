/*
 * XRef — Stage L3 hardware data watchpoints (`DR0`–`DR3`) command orchestration and rendering
 * Copyright (c) 2026 Alexander Panasenko
 * Contact: alex@prod.codes
 * Author: https://prod.codes/about/
 * Project: https://github.com/alex09x/xref
 * SPDX-License-Identifier: MIT OR Apache-2.0
 */

//! Stage L3 `xref live watch`: hardware data watchpoints (`HW_BREAKPOINT_W` / `HW_BREAKPOINT_RW`),
//! cached per-FDE post-execution `trap_ip` attribution to candidate linear-predecessor store/read
//! instructions, candidate store-operand decoding via `PERF_SAMPLE_REGS_INTR`, and before/after
//! `/proc/<pid>/mem` snapshots.

pub mod perf;
pub mod perf_stream;
#[cfg(test)]
mod tests;
pub mod types;
pub mod validate;
pub mod writer;

use std::error::Error;
use std::io::Write;
use std::path::Path;
use std::time::Duration;

use crate::live::cli::{WatchAccessMode, WatchLen};
use crate::live::memscan::ReadAt;
use crate::live::probe::types::{LostEvents, ProbeObservation};
#[cfg(target_os = "linux")]
use crate::live::probe::types::{ProbeStopReason, ThreadCoverage};
use crate::live::procfs::{open_process_mem, open_session};
use crate::live::types::{HexAddr, ProcessMeta, SCHEMA_VERSION, TOOL_NAME, TOOL_VERSION, format_signed_hex};
use crate::live::watch::perf::{WatchRunConfig, run_perf_watch};
use crate::live::watch::perf_stream::WatchAccumulator;
#[cfg(target_os = "linux")]
use crate::live::watch::perf_stream::WatchDrainCtx;
use crate::live::watch::types::{
    WATCH_SNAPSHOT_CAVEAT, WatchReport, WatchTargetResult, WatchTargetSpec, WriterSiteEntry, WrittenValueRecovery,
    build_watch_capabilities,
};
use crate::live::watch::validate::{read_watch_scalar, validate_session_for_watch, validate_watch_targets};

pub struct WatchCliArgs<'a> {
    pub pid: u32,
    pub addrs: &'a [u64],
    pub len_bytes: WatchLen,
    pub access: WatchAccessMode,
    pub regs: bool,
    pub duration_ms: u64,
    pub max_events: usize,
    pub force_bin: bool,
    pub json: bool,
}

pub fn execute_watch(bin: Option<&Path>, args: &WatchCliArgs<'_>, out: &mut dyn Write) -> Result<(), Box<dyn Error>> {
    let mut session = open_session(args.pid, bin, args.force_bin)?;
    validate_session_for_watch(&session)?;
    let mem_file = open_process_mem(args.pid, session.process.starttime_ticks).ok();
    let mem_reader: Option<&dyn ReadAt> = mem_file.as_ref().map(|f| f as &dyn ReadAt);

    let specs = validate_watch_targets(
        &session.image,
        session.process.pie_slide,
        &session.regions,
        args.addrs,
        args.len_bytes,
        args.access,
        mem_reader,
    )?;
    let cfg = WatchRunConfig {
        duration: Duration::from_millis(args.duration_ms),
        max_events: args.max_events,
        want_regs: args.regs,
    };
    let (observation, watches) = run_perf_watch(&mut session, &specs, &cfg, mem_reader)?;
    let report = build_watch_report(session.process, observation, watches, args.regs, mem_file.is_some());
    if args.json {
        serde_json::to_writer(&mut *out, &report)?;
        writeln!(out)?;
    } else {
        write_watch_table(&report, out)?;
    }
    Ok(())
}

#[must_use]
pub fn build_watch_report(
    process: ProcessMeta,
    observation: ProbeObservation,
    watches: Vec<WatchTargetResult>,
    want_regs: bool,
    mem_snapshot_available: bool,
) -> WatchReport {
    WatchReport {
        schema_version: SCHEMA_VERSION,
        tool: TOOL_NAME,
        tool_version: TOOL_VERSION,
        operation: "live_watch",
        backend: "perf_breakpoint",
        capabilities: build_watch_capabilities(want_regs, mem_snapshot_available),
        process,
        observation,
        watches,
    }
}

pub fn write_watch_table(report: &WatchReport, out: &mut dyn Write) -> std::io::Result<()> {
    write_watch_header(&report.process, out)?;
    let loss_str = match &report.observation.lost_events {
        LostEvents::Known { total, .. } => format!("{total}"),
        LostEvents::Unknown { .. } => "unknown".to_owned(),
    };
    let bound_note = if report.observation.counts_are_lower_bound { " (lower_bound)" } else { "" };
    writeln!(
        out,
        "backend {}  pid_isolated_wp {}  elapsed {}ms/{}ms  stop {}  seeded_tids {}  dyn_tids {}  excluded_tgid {}  lost {loss_str}{bound_note}",
        report.backend,
        report.capabilities.pid_isolated_watchpoint.collected,
        report.observation.elapsed_ms,
        report.observation.duration_requested_ms,
        report.observation.stop_reason.as_str(),
        report.observation.thread_coverage.seeded_tids,
        report.observation.thread_coverage.dynamically_attached_tids,
        report.observation.thread_coverage.excluded_other_tgid_events,
    )?;
    for w in &report.watches {
        let static_str = w.static_va.map_or_else(|| "-".to_owned(), |v| format!("{:#x}", v.0));
        let init_str = w.initial_snapshot.map_or_else(|| "-".to_owned(), |v| format!("{:#x}", v.0));
        let latest_str = w.latest_snapshot.map_or_else(|| "-".to_owned(), |v| format!("{:#x}", v.0));
        writeln!(
            out,
            "watch runtime {:#x}  static {static_str}  len {}B  access {}  region {} ({})  init {init_str}  latest {latest_str}  hits {}",
            w.runtime_va.0, w.len_bytes, w.access, w.region, w.perms, w.accepted_hits,
        )?;
        for site in &w.writer_sites {
            let trap_s = site.trap_static_ip.map_or_else(|| "-".to_owned(), |v| format!("{:#x}", v.0));
            let writer_s = site.candidate_writer_static_ip.map_or_else(|| "-".to_owned(), |v| format!("{:#x}", v.0));
            let fn_s = site.writer_function.map_or_else(|| "-".to_owned(), |v| format!("{:#x}", v.0));
            let sym = site.writer_symbol.as_deref().unwrap_or("-");
            let text = site.candidate_writer_text.as_deref().unwrap_or("-");
            writeln!(
                out,
                "  writer {writer_s} (trap {:#x} / static {trap_s})  fn {fn_s} ({sym})  insn \"{text}\"  conf {}  hits {}  [{}]",
                site.trap_runtime_ip.0,
                site.confidence.as_str(),
                site.hits,
                site.caveat,
            )?;
        }
        for sample in &w.samples {
            let val_desc = match &sample.written_value {
                WrittenValueRecovery::CandidateRegisterStore { register, width_bytes, value, .. } => {
                    format!("candidate_reg:{register}({width_bytes}B)={:#x}", value.0)
                }
                WrittenValueRecovery::CandidateImmediateStore { width_bytes, value, .. } => {
                    format!("candidate_imm({width_bytes}B)={:#x}", value.0)
                }
                WrittenValueRecovery::Unknown { reason } => format!("unknown({reason})"),
            };
            let writer_s = sample.candidate_writer_static_ip.map_or_else(|| "-".to_owned(), |v| format!("{:#x}", v.0));
            writeln!(
                out,
                "  sample tid {}  writer {writer_s}  trap {:#x}  value {val_desc}",
                sample.tid, sample.trap_runtime_ip.0,
            )?;
        }
    }
    Ok(())
}

fn write_watch_header(proc_meta: &ProcessMeta, out: &mut dyn Write) -> std::io::Result<()> {
    writeln!(
        out,
        "pid {}  starttime {}  match {}  pie_slide {}  alive {}  changed {}",
        proc_meta.pid,
        proc_meta.starttime_ticks,
        proc_meta.binary_match.as_str(),
        format_signed_hex(proc_meta.pie_slide),
        proc_meta.pid_alive_after,
        proc_meta.process_changed,
    )?;
    for warning in &proc_meta.warnings {
        writeln!(out, "warning: {warning}")?;
    }
    Ok(())
}

#[cfg(target_os = "linux")]
#[must_use]
pub fn finalize_watch_observation(
    ctx: &WatchDrainCtx<'_>,
    cfg: &WatchRunConfig,
    seeded_tids: usize,
    elapsed_ms: u64,
    stop_reason: ProbeStopReason,
) -> ProbeObservation {
    let lost_events = if ctx.decode_errors > 0 {
        LostEvents::Unknown { reason: format!("{} malformed perf watch ring record(s)", ctx.decode_errors) }
    } else {
        LostEvents::Known {
            overrun: 0,
            commit_overrun: 0,
            dropped_events: 0,
            perf_lost_records: ctx.perf_lost_records,
            total: ctx.perf_lost_records,
        }
    };
    let truncated_by_max_events =
        stop_reason == ProbeStopReason::MaxEvents || ctx.hit_max_events || ctx.total_accepted >= cfg.max_events;
    let effective_stop = if truncated_by_max_events && stop_reason == ProbeStopReason::DurationElapsed {
        ProbeStopReason::MaxEvents
    } else {
        stop_reason
    };
    let dynamically_attached_tids = ctx.attached_tids.len().saturating_sub(seeded_tids);
    let pending_unattached =
        u64::try_from(ctx.pending_new_tids.iter().filter(|tid| !ctx.attached_tids.contains(tid)).count()).unwrap_or(0);
    let unattached_fork_tids = ctx.unattached_fork_tids.saturating_add(pending_unattached);

    let mut reasons = ctx.coverage_gap_reasons.clone();
    if dynamically_attached_tids > 0 && !reasons.iter().any(|r| r == "dynamic_tid_inherit_false_pre_attach_window") {
        reasons.push("dynamic_tid_inherit_false_pre_attach_window".to_owned());
    }
    if unattached_fork_tids > 0 && !reasons.iter().any(|r| r.contains("dynamic_tid") || r.contains("unattached")) {
        reasons.push("unattached_fork_tids".to_owned());
    }
    if ctx.decode_errors > 0 {
        reasons.push("malformed_perf_ring_records".to_owned());
    }
    let partial_coverage =
        unattached_fork_tids > 0 || dynamically_attached_tids > 0 || ctx.ambiguous_tid > 0 || ctx.decode_errors > 0;
    let counts_are_lower_bound = lost_events.has_possible_loss() || truncated_by_max_events || partial_coverage;

    ProbeObservation {
        duration_requested_ms: u64::try_from(cfg.duration.as_millis()).unwrap_or(u64::MAX),
        elapsed_ms,
        max_events: cfg.max_events,
        stop_reason: effective_stop,
        truncated_by_max_events,
        thread_coverage: ThreadCoverage {
            seeded_tids,
            dynamically_attached_tids,
            unattached_fork_tids,
            event_fork_enabled: true,
            record_tgid_enabled: true,
            excluded_other_tgid_events: ctx.excluded_other_tgid,
            ambiguous_tid_events: ctx.ambiguous_tid,
            unparsed_events: ctx.decode_errors,
            partial_coverage,
            partial_coverage_reasons: reasons,
            note: "per_tid_perf_breakpoint_dr0_dr3_mmap_ring_plus_fork_record_and_proc_task_attach",
        },
        lost_events,
        counts_are_lower_bound,
    }
}

#[must_use]
pub fn build_watch_results(
    specs: &[WatchTargetSpec],
    accumulators: Vec<WatchAccumulator>,
    mem_reader: Option<&dyn ReadAt>,
) -> Vec<WatchTargetResult> {
    specs
        .iter()
        .zip(accumulators)
        .map(|(spec, acc)| {
            let latest_snapshot = mem_reader.and_then(|r| read_watch_scalar(r, spec.runtime_va, spec.len_bytes));
            let snapshot_changed = match (spec.initial_snapshot, latest_snapshot) {
                (Some(before), Some(after)) => Some(before != after),
                _ => None,
            };
            let mut writer_sites: Vec<WriterSiteEntry> = acc.writer_sites.into_values().collect();
            writer_sites.sort_by(|a, b| b.hits.cmp(&a.hits).then_with(|| a.trap_runtime_ip.cmp(&b.trap_runtime_ip)));

            WatchTargetResult {
                input: HexAddr(spec.input),
                runtime_va: HexAddr(spec.runtime_va),
                static_va: spec.static_va.map(HexAddr),
                region: spec.region.clone(),
                perms: spec.perms.clone(),
                access: spec.access.as_str(),
                len_bytes: spec.len_bytes.as_u8(),
                initial_snapshot: spec.initial_snapshot,
                latest_snapshot,
                snapshot_changed,
                snapshot_caveat: WATCH_SNAPSHOT_CAVEAT,
                accepted_hits: acc.accepted_hits,
                first_timestamp_ns: acc.first_timestamp_ns,
                last_timestamp_ns: acc.last_timestamp_ns,
                writer_sites,
                samples_truncated: acc.samples_truncated,
                samples: acc.samples,
            }
        })
        .collect()
}
