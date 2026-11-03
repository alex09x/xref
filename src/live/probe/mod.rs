/*
 * XRef — Stage L2 Linux uprobe command orchestration and human/JSON report rendering
 * Copyright (c) 2026 Alexander Panasenko
 * Contact: alex@prod.codes
 * Author: https://prod.codes/about/
 * Project: https://github.com/alex09x/xref
 * SPDX-License-Identifier: MIT OR Apache-2.0
 */

//! Stage L2 `xref live probe`: native `perf_event_open` binary ring buffer (default) and explicit
//! `tracefs` adapter, `.eh_frame`-verified caller attribution, register samples, and capability matrix.

pub mod caller;
pub mod capabilities;
pub mod perf;
pub mod perf_ring;
#[cfg(target_os = "linux")]
pub mod perf_stream;
#[cfg(test)]
mod tests;
#[cfg(test)]
mod tests_elf;
#[cfg(test)]
mod tests_perf;
pub mod trace_parse;
pub mod tracefs;
pub mod tracefs_cleanup;
pub mod tracefs_stream;
pub mod types;
pub mod validate;

use std::error::Error;
use std::io::Write;
use std::path::Path;
use std::time::Duration;

use crate::live::cli::ProbeBackend;
use crate::live::probe::capabilities::{build_perf_capabilities, build_tracefs_capabilities};
use crate::live::probe::perf::run_perf_probe;
use crate::live::probe::tracefs::{ProbeRunConfig, run_tracefs_probe};
use crate::live::probe::types::{LostEvents, ProbeObservation, ProbeReport, ProbeTargetResult, ProbeTargetSpec};
use crate::live::probe::validate::{validate_probe_targets, validate_session_for_probe};
use crate::live::procfs::open_session;
use crate::live::types::{ProcessMeta, SCHEMA_VERSION, TOOL_NAME, TOOL_VERSION, format_signed_hex};

#[derive(Clone, Copy, Debug)]
pub struct ProbeCapture {
    pub callers: bool,
    pub regs: bool,
}

pub struct ProbeCliArgs<'a> {
    pub pid: u32,
    pub backend: ProbeBackend,
    pub addrs: &'a [u64],
    pub capture: ProbeCapture,
    pub duration_ms: u64,
    pub max_events: usize,
    pub force_bin: bool,
    pub json: bool,
}

pub fn execute_probe(bin: Option<&Path>, args: &ProbeCliArgs<'_>, out: &mut dyn Write) -> Result<(), Box<dyn Error>> {
    let mut session = open_session(args.pid, bin, args.force_bin)?;
    validate_session_for_probe(&session)?;
    let specs = validate_probe_targets(&session.image, session.process.pie_slide, &session.regions, args.addrs)?;
    let cfg = ProbeRunConfig {
        duration: Duration::from_millis(args.duration_ms),
        max_events: args.max_events,
        want_callers: args.capture.callers,
        want_regs: args.capture.regs,
        spawn_watchdog: true,
        cancel: None,
    };
    let (observation, probes) = match args.backend {
        ProbeBackend::Perf => run_perf_probe(&mut session, &specs, &cfg)?,
        ProbeBackend::Tracefs => run_tracefs_probe(&mut session, &specs, &cfg)?,
    };
    let report =
        build_probe_report(args.backend, session.process, observation, probes, &specs, cfg.want_callers, cfg.want_regs);
    if args.json {
        serde_json::to_writer(&mut *out, &report)?;
        writeln!(out)?;
    } else {
        write_probe_table(&report, out)?;
    }
    Ok(())
}

#[must_use]
pub fn build_probe_report(
    backend: ProbeBackend,
    process: ProcessMeta,
    observation: ProbeObservation,
    probes: Vec<ProbeTargetResult>,
    specs: &[ProbeTargetSpec],
    want_callers: bool,
    want_regs: bool,
) -> ProbeReport {
    let capabilities = match backend {
        ProbeBackend::Perf => build_perf_capabilities(specs, want_callers, want_regs),
        ProbeBackend::Tracefs => {
            build_tracefs_capabilities(specs, want_callers, want_regs, observation.thread_coverage.record_tgid_enabled)
        }
    };
    ProbeReport {
        schema_version: SCHEMA_VERSION,
        tool: TOOL_NAME,
        tool_version: TOOL_VERSION,
        operation: "live_probe",
        backend: backend.as_str(),
        backend_selection: "explicit_or_default_no_silent_fallback",
        capabilities,
        process,
        observation,
        probes,
    }
}

pub fn write_probe_table(report: &ProbeReport, out: &mut dyn Write) -> std::io::Result<()> {
    write_probe_header(&report.process, out)?;
    let loss_str = match &report.observation.lost_events {
        LostEvents::Known { total, .. } => format!("{total}"),
        LostEvents::Unknown { .. } => "unknown".to_owned(),
    };
    let bound_note = if report.observation.counts_are_lower_bound { " (lower_bound)" } else { "" };
    writeln!(
        out,
        "backend {}  pid_isolated_bp {}  elapsed {}ms/{}ms  stop {}  seeded_tids {}  dyn_tids {}  excluded_tgid {}  lost {loss_str}{bound_note}",
        report.backend,
        report.capabilities.pid_isolated_breakpoint.collected,
        report.observation.elapsed_ms,
        report.observation.duration_requested_ms,
        report.observation.stop_reason.as_str(),
        report.observation.thread_coverage.seeded_tids,
        report.observation.thread_coverage.dynamically_attached_tids,
        report.observation.thread_coverage.excluded_other_tgid_events,
    )?;
    for probe in &report.probes {
        let fn_str = probe.function_start.map_or_else(|| "-".to_owned(), |f| format!("{:#x}", f.0));
        let sym = probe.symbol.as_deref().unwrap_or("-");
        writeln!(
            out,
            "probe static {:#x}  runtime {:#x}  file {:#x}  insn {:6}  cfi {:18}  fn {fn_str} ({sym})  hits {}",
            probe.static_va.0,
            probe.runtime_va.0,
            probe.file_offset.0,
            probe.instruction_mnemonic,
            probe.unwind_entry_abi.summary_tag(),
            probe.accepted_hits,
        )?;
        for caller in &probe.callers {
            let ret_s = caller.return_static_va.map_or_else(|| "-".to_owned(), |v| format!("{:#x}", v.0));
            let cfn = caller.caller_function.map_or_else(|| "-".to_owned(), |v| format!("{:#x}", v.0));
            let site = caller.call_site_static_va.map_or_else(|| "-".to_owned(), |v| format!("{:#x}", v.0));
            writeln!(
                out,
                "  caller ra {:#x} (static {ret_s})  fn {cfn}  call_site {site}  verified {}  hits {}  [{}]",
                caller.raw_return_runtime_va.0, caller.call_verified, caller.hits, caller.caveat,
            )?;
        }
        for reg in &probe.register_samples {
            let rbp_str = reg.rbp.map_or_else(|| "-".to_owned(), |v| format!("{:#x}", v.0));
            writeln!(
                out,
                "  regs tid {}  rdi {:#x}  rsi {:#x}  rdx {:#x}  rcx {:#x}  r8 {:#x}  r9 {:#x}  rax {:#x}  rsp {:#x}  rbp {rbp_str}  [{}]",
                reg.tid,
                reg.rdi.0,
                reg.rsi.0,
                reg.rdx.0,
                reg.rcx.0,
                reg.r8.0,
                reg.r9.0,
                reg.rax.0,
                reg.rsp.0,
                reg.caveat,
            )?;
        }
    }
    Ok(())
}

fn write_probe_header(proc_meta: &ProcessMeta, out: &mut dyn Write) -> std::io::Result<()> {
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
