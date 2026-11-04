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
pub(super) mod fetch;
pub mod filter;
pub mod group;
pub mod mark;
pub mod output;
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
#[cfg(test)]
mod tests_sampling;
pub mod trace_parse;
pub mod tracefs;
pub mod tracefs_cleanup;
mod tracefs_filter;
pub mod tracefs_setup;
pub mod tracefs_stream;
mod tracefs_tid;
pub mod types;
pub mod validate;

pub use output::write_probe_table;

use std::error::Error;
use std::io::Write;
use std::path::Path;
use std::time::Duration;

use crate::live::cli::ProbeBackend;
use crate::live::probe::capabilities::{build_perf_capabilities, build_tracefs_capabilities};
use crate::live::probe::perf::run_perf_probe;
use crate::live::probe::tracefs::{ProbeRunConfig, run_tracefs_probe};
use crate::live::probe::types::{ProbeObservation, ProbeReport, ProbeTargetResult, ProbeTargetSpec};
use crate::live::probe::validate::{validate_probe_targets, validate_session_for_probe};
use crate::live::procfs::open_session;
use crate::live::types::{ProcessMeta, SCHEMA_VERSION, TOOL_NAME, TOOL_VERSION};

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
    pub heartbeat_ms: Option<u64>,
    pub group_by: Option<&'a str>,
    pub mark_file: Option<&'a Path>,
    pub mark_regex: Option<&'a str>,
    pub max_events: usize,
    pub fetch: &'a [String],
    pub filter: &'a [String],
    pub every: usize,
    pub first: Option<usize>,
    pub until_hits: Option<usize>,
    pub force_bin: bool,
    pub json: bool,
    pub cancel: Option<&'a std::sync::atomic::AtomicBool>,
}

/// Static preflight (#96): a `--filter` on a function-entry probe is checked against what every
/// direct call site passes; a filter no caller can satisfy is reported before attaching.
fn warn_unsatisfiable_entry_filters(image: &crate::image::Image, specs: &[ProbeTargetSpec], filters: &[String]) {
    for spec in specs {
        let va = spec.static_va;
        if spec.function_start != Some(va) {
            continue;
        }
        for filter in filters {
            if let Ok(report) = crate::args::filter_preflight(image, va, filter)
                && report.unsatisfiable_at_all_sites
            {
                eprintln!(
                    "xref: warning: filter '{filter}' is unsatisfiable at all {} direct call sites of {va:#x} (see `xref args {va:#x} --filter '{filter}'`)",
                    report.sites.len()
                );
            }
        }
    }
}

pub fn execute_probe(bin: Option<&Path>, args: &ProbeCliArgs<'_>, out: &mut dyn Write) -> Result<(), Box<dyn Error>> {
    let mut session = open_session(args.pid, bin, args.force_bin)?;
    validate_session_for_probe(&session)?;
    let specs = validate_probe_targets(&session.image, session.process.pie_slide, &session.regions, args.addrs)?;
    let fetches = fetch::parse_fetch_args(args.fetch)?;
    let fetch_names = fetches.iter().map(|arg| arg.name.clone()).collect::<Vec<_>>();
    let filters = filter::parse_filters(args.filter, args.capture.regs, &fetch_names)?;
    if args.backend != ProbeBackend::Tracefs
        && (!fetches.is_empty()
            || !filters.is_empty()
            || args.every != 1
            || args.first.is_some()
            || args.until_hits.is_some())
    {
        return Err("advanced probe fetch, filter, and sampling options require the tracefs backend".into());
    }
    if args.backend != ProbeBackend::Tracefs && args.mark_file.is_some() {
        return Err("--mark-file/--mark-regex require --backend tracefs".into());
    }
    if args.mark_file.is_some() && args.fetch.is_empty() && !args.capture.regs {
        // Marks are stored on captured samples; without --fetch or --regs there is nothing to stamp.
        return Err("--mark-file needs --fetch or --regs: marks are attached to captured samples".into());
    }
    warn_unsatisfiable_entry_filters(&session.image, &specs, args.filter);
    let parsed_group_by = args.group_by.map(group::parse_group_by).transpose()?;
    let want_callers = args.capture.callers || parsed_group_by.is_some();
    let cfg = ProbeRunConfig {
        duration: Duration::from_millis(args.duration_ms),
        max_events: args.max_events,
        want_callers,
        want_regs: args.capture.regs,
        fetches,
        filters,
        every: args.every,
        first: args.first,
        until_hits: args.until_hits,
        spawn_watchdog: true,
        cancel: args.cancel,
        heartbeat_ms: args.heartbeat_ms,
        mark_file: args.mark_file.map(Path::to_path_buf),
        mark_regex: args.mark_regex.map(str::to_owned),
        // Only the tracefs stream emits per-hit JSON lines; perf keeps the final report.
        stream_json: args.duration_ms == 0 && args.json && args.backend == ProbeBackend::Tracefs,
    };
    let (observation, probes) = match args.backend {
        ProbeBackend::Perf => run_perf_probe(&mut session, &specs, &cfg)?,
        ProbeBackend::Tracefs => run_tracefs_probe(&mut session, &specs, &cfg)?,
    };
    let mut report =
        build_probe_report(args.backend, session.process, observation, probes, &specs, cfg.want_callers, cfg.want_regs);
    if parsed_group_by.is_some() {
        report.groups = Some(group::build_group_histogram_from_probes(&report.probes));
    }
    if cfg.stream_json {
        // Hits were already streamed; finish with the group histogram when requested.
        if let Some(ref groups) = report.groups {
            serde_json::to_writer(&mut *out, &groups)?;
            writeln!(out)?;
        }
    } else if args.json {
        serde_json::to_writer(&mut *out, &report)?;
        writeln!(out)?;
    } else {
        write_probe_table(&report, out)?;
        if let Some(ref groups) = report.groups {
            group::write_group_histogram(groups, out)?;
        }
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
        groups: None,
    }
}
