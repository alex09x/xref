/*
 * XRef — Live Linux procfs inspection and xref-aware memory scanning
 * Copyright (c) 2026 Alexander Panasenko
 * Contact: alex@prod.codes
 * Author: https://prod.codes/about/
 * Project: https://github.com/alex09x/xref
 * SPDX-License-Identifier: MIT OR Apache-2.0
 */

//! Stage L1–L2 live Linux process inspection (`maps`, `resolve`, `memscan`, `probe`).

#[cfg(any(target_os = "linux", test))]
pub mod classify;
pub mod cli;
#[cfg(any(target_os = "linux", test))]
pub mod memscan;
#[cfg(any(target_os = "linux", test))]
pub mod probe;
pub mod procfs;
#[cfg(any(target_os = "linux", test))]
pub mod procparse;
#[cfg(test)]
mod tests;
#[cfg(all(test, target_os = "linux"))]
mod tests_linux;
#[cfg(test)]
mod tests_review;
#[cfg(any(target_os = "linux", test))]
pub mod types;
pub mod watch;

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
pub use probe::filter::ValueFilter as ProfileValueFilter;
#[cfg(any(target_os = "linux", test))]
pub use probe::{fetch::parse_fetch_args as parse_profile_fetches, filter::parse_filters as parse_profile_filters};

use std::error::Error;
use std::io::Write;
use std::path::Path;
#[cfg(any(target_os = "linux", test))]
use std::time::Duration;

#[cfg(any(target_os = "linux", test))]
use crate::live::classify::resolve_address;
use crate::live::cli::LiveCommand;
#[cfg(any(target_os = "linux", test))]
use crate::live::cli::{LiveSubcommand, encode_values_le, format_bytes_hex};
#[cfg(any(target_os = "linux", test))]
use crate::live::memscan::{ScanConfig, scan_memory};
#[cfg(any(target_os = "linux", test))]
use crate::live::probe::{ProbeCliArgs, execute_probe, tracefs_cleanup::run_watchdog_entrypoint};
#[cfg(any(target_os = "linux", test))]
use crate::live::procfs::{open_process_mem, open_session, refresh_session_identity};
#[cfg(any(target_os = "linux", test))]
use crate::live::types::{
    ContextWord, ContextWordKind, MapsReport, MemscanReport, ProcessMeta, ResolveDirection, ResolveReport,
    SCHEMA_VERSION, ScanStatus, TOOL_NAME, TOOL_VERSION, format_signed_hex,
};
#[cfg(any(target_os = "linux", test))]
use crate::live::watch::{WatchCliArgs, execute_watch};

#[cfg(all(not(target_os = "linux"), not(test)))]
pub fn run(bin: Option<&Path>, cmd: &LiveCommand, _out: &mut dyn Write) -> Result<(), Box<dyn Error>> {
    cmd.validate()?;
    if let Some(path) = bin {
        let _ = procfs::load_elf_image(path)?;
    }
    Err(format!("unsupported_platform: live Linux procfs inspection (pid {}) requires a Linux x86-64 host", cmd.pid())
        .into())
}

#[cfg(any(target_os = "linux", test))]
#[allow(clippy::too_many_lines)]
pub fn run(bin: Option<&Path>, cmd: &LiveCommand, out: &mut dyn Write) -> Result<(), Box<dyn Error>> {
    cmd.validate()?;
    match &cmd.subcommand {
        LiveSubcommand::Profile(args) => crate::profile::live_cli::run(bin, args, out)?,
        LiveSubcommand::Maps { pid, force_bin, json } => {
            let session = open_session(*pid, bin, *force_bin)?;
            let report = MapsReport {
                schema_version: SCHEMA_VERSION,
                tool: TOOL_NAME,
                tool_version: TOOL_VERSION,
                operation: "live_maps",
                process: session.process,
                regions: session.regions,
            };
            if *json {
                serde_json::to_writer(&mut *out, &report)?;
                writeln!(out)?;
            } else {
                write_maps_table(&report, out)?;
            }
        }
        LiveSubcommand::Resolve { pid, force_bin, json, addrs } => {
            let mut session = open_session(*pid, bin, *force_bin)?;
            let addresses = addrs
                .iter()
                .map(|&addr| resolve_address(&session.image, session.process.pie_slide, &session.regions, addr))
                .collect();
            refresh_session_identity(&mut session);
            let report = ResolveReport {
                schema_version: SCHEMA_VERSION,
                tool: TOOL_NAME,
                tool_version: TOOL_VERSION,
                operation: "live_resolve",
                process: session.process,
                addresses,
            };
            if *json {
                serde_json::to_writer(&mut *out, &report)?;
                writeln!(out)?;
            } else {
                write_resolve_table(&report, out)?;
            }
        }
        LiveSubcommand::Memscan { .. } => {
            run_memscan_subcommand(bin, &cmd.subcommand, out)?;
        }
        LiveSubcommand::Probe {
            pid,
            backend,
            count: _,
            callers,
            regs,
            duration_ms,
            heartbeat_ms,
            group_by,
            mark_file,
            mark_regex,
            max_events,
            fetch,
            filter,
            every,
            first,
            until_hits,
            force_bin,
            json,
            addrs,
        } => {
            // SIGINT/SIGTERM end the observation through the loops' cancel flag so the report (and
            // --group-by histogram) is still printed; a second signal terminates immediately, and the
            // tracefs watchdog removes probes if the process dies.
            let interrupted = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
            #[cfg(target_os = "linux")]
            for signal in [signal_hook::consts::SIGINT, signal_hook::consts::SIGTERM] {
                signal_hook::flag::register_conditional_shutdown(signal, 1, std::sync::Arc::clone(&interrupted))?;
                signal_hook::flag::register(signal, std::sync::Arc::clone(&interrupted))?;
            }
            let args = ProbeCliArgs {
                pid: *pid,
                backend: *backend,
                addrs,
                capture: crate::live::probe::ProbeCapture { callers: *callers, regs: *regs },
                duration_ms: *duration_ms,
                heartbeat_ms: *heartbeat_ms,
                group_by: group_by.as_deref(),
                mark_file: mark_file.as_deref(),
                mark_regex: mark_regex.as_deref(),
                max_events: *max_events,
                fetch,
                filter,
                every: *every,
                first: *first,
                until_hits: *until_hits,
                force_bin: *force_bin,
                json: *json,
                cancel: Some(&interrupted),
            };
            execute_probe(bin, &args, out)?;
        }
        LiveSubcommand::Watch { pid, len, access, regs, duration_ms, max_events, force_bin, json, follow, addrs } => {
            let args = WatchCliArgs {
                pid: *pid,
                addrs,
                follow,
                len_bytes: *len,
                access: *access,
                regs: *regs,
                duration_ms: *duration_ms,
                max_events: *max_events,
                force_bin: *force_bin,
                json: *json,
            };
            execute_watch(bin, &args, out)?;
        }
        LiveSubcommand::TracefsWatchdog { tracefs_root, instance, events, parent_test_hold } => {
            run_watchdog_entrypoint(tracefs_root, instance, events, *parent_test_hold);
        }
    }
    Ok(())
}

#[cfg(any(target_os = "linux", test))]
fn run_memscan_subcommand(bin: Option<&Path>, sub: &LiveSubcommand, out: &mut dyn Write) -> Result<(), Box<dyn Error>> {
    let LiveSubcommand::Memscan {
        pid,
        align,
        before_words,
        after_words,
        max_hits,
        max_bytes,
        timeout_ms,
        force_bin,
        json,
        values,
    } = sub
    else {
        return Ok(());
    };
    let mut session = open_session(*pid, bin, *force_bin)?;
    let mem_file = open_process_mem(*pid, session.process.starttime_ticks)?;
    let needle = encode_values_le(values);
    let cfg = ScanConfig {
        align: *align,
        before_words: *before_words,
        after_words: *after_words,
        max_hits: *max_hits,
        max_bytes: *max_bytes,
        timeout: Duration::from_millis(*timeout_ms),
    };
    let outcome = scan_memory(&mem_file, &session.image, session.process.pie_slide, &session.regions, &needle, &cfg)?;
    refresh_session_identity(&mut session);
    let report = MemscanReport {
        schema_version: SCHEMA_VERSION,
        tool: TOOL_NAME,
        tool_version: TOOL_VERSION,
        operation: "live_memscan",
        process: session.process,
        needle_hex: format_bytes_hex(&needle),
        align: *align,
        elapsed_ms: outcome.elapsed_ms,
        regions_scanned: outcome.regions_scanned,
        regions_skipped: outcome.regions_skipped,
        bytes_scanned: outcome.bytes_scanned,
        unreadable_ranges: outcome.unreadable_ranges,
        stop_reason: outcome.stop_reason,
        hits: outcome.hits,
    };
    if *json {
        serde_json::to_writer(&mut *out, &report)?;
        writeln!(out)?;
    } else {
        write_memscan_table(&report, out)?;
    }
    Ok(())
}

#[cfg(any(target_os = "linux", test))]
fn write_process_header(proc_meta: &ProcessMeta, out: &mut dyn Write) -> std::io::Result<()> {
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

#[cfg(any(target_os = "linux", test))]
fn write_maps_table(report: &MapsReport, out: &mut dyn Write) -> std::io::Result<()> {
    write_process_header(&report.process, out)?;
    let mut scannable = 0_usize;
    for r in &report.regions {
        if r.scan_status == ScanStatus::ScannableRwp {
            scannable += 1;
        }
        let tag = if r.is_target_image { "target" } else { "-" };
        let path = r.pathname.as_deref().unwrap_or("[anon]");
        writeln!(
            out,
            "{:#014x}..{:#014x}  {}  off {:#010x}  {:26}  {:6}  {path}",
            r.start.0,
            r.end.0,
            r.perms,
            r.offset.0,
            r.scan_status.as_str(),
            tag,
        )?;
    }
    writeln!(out, "{} regions ({scannable} scannable_rwp)", report.regions.len())
}

#[cfg(any(target_os = "linux", test))]
fn write_resolve_table(report: &ResolveReport, out: &mut dyn Write) -> std::io::Result<()> {
    write_process_header(&report.process, out)?;
    for entry in &report.addresses {
        if entry.direction == ResolveDirection::Unmapped {
            writeln!(out, "{:#x}  unmapped", entry.input.0)?;
            continue;
        }
        let s_str = entry.static_va.map_or_else(|| "-".to_owned(), |v| format!("{:#x}", v.0));
        let r_str = entry.runtime_va.map_or_else(|| "-".to_owned(), |v| format!("{:#x}", v.0));
        let f_str = if entry.in_bss {
            "bss".to_owned()
        } else {
            entry.file_offset.map_or_else(|| "-".to_owned(), |v| format!("{:#x}", v.0))
        };
        let sym = entry.symbol.as_deref().unwrap_or("-");
        let reg = entry.region.as_deref().unwrap_or("-");
        writeln!(
            out,
            "{:#x}  {:17}  static {s_str}  runtime {r_str}  file {f_str}  sym {sym}  {reg}",
            entry.input.0,
            entry.direction.as_str(),
        )?;
    }
    Ok(())
}

#[cfg(any(target_os = "linux", test))]
fn write_memscan_table(report: &MemscanReport, out: &mut dyn Write) -> std::io::Result<()> {
    write_process_header(&report.process, out)?;
    writeln!(
        out,
        "needle {}  align {}  elapsed {}ms  regions {}/{}  bytes {:#x}  unreadable {}  stop {}  hits {}",
        report.needle_hex,
        report.align,
        report.elapsed_ms,
        report.regions_scanned,
        report.regions_scanned + report.regions_skipped,
        report.bytes_scanned,
        report.unreadable_ranges,
        report.stop_reason.as_str(),
        report.hits.len(),
    )?;
    for hit in &report.hits {
        let trunc_note = if hit.window_truncated { "  [window_truncated]" } else { "" };
        writeln!(out, "hit {:#x}  {}{trunc_note}", hit.runtime_va.0, hit.region)?;
        for word in &hit.context {
            write_context_word_line(word, out)?;
        }
    }
    Ok(())
}

#[cfg(any(target_os = "linux", test))]
fn write_context_word_line(word: &ContextWord, out: &mut dyn Write) -> std::io::Result<()> {
    let mark = if word.is_match { '*' } else { ' ' };
    let rel = format_signed_hex(word.relative_offset);
    let val_str = word.value.map_or_else(|| "<unreadable>      ".to_owned(), |v| format!("{:#018x}", v.0));
    let detail = match word.kind {
        ContextWordKind::CodePtr => {
            let fn_s = word.target_function.map_or_else(|| "-".to_owned(), |f| format!("{:#x}", f.0));
            let off_s = word.function_offset.unwrap_or(0);
            let sym = word.symbol.as_deref().unwrap_or("-");
            format!("fn {fn_s}+{off_s:#x}  {sym}")
        }
        ContextWordKind::RelroPtrCandidate => {
            let targets: Vec<String> = word.candidate_targets.iter().map(|t| format!("{:#x}", t.0)).collect();
            format!("candidates [{}]", targets.join(", "))
        }
        ContextWordKind::StaticDataPtr => {
            let prev = word.static_ascii_preview.as_deref().unwrap_or("");
            if prev.is_empty() { String::new() } else { format!("{prev:?}") }
        }
        ContextWordKind::ExecMappingPtr
        | ContextWordKind::HeapPtr
        | ContextWordKind::StackPtr
        | ContextWordKind::AnonPtr
        | ContextWordKind::MappedPtr => word.target_region.clone().unwrap_or_default(),
        ContextWordKind::Scalar | ContextWordKind::Unreadable => String::new(),
    };
    writeln!(out, "  {rel:>6}{mark} {:#018x}  {val_str}  {:19}  {detail}", word.runtime_va.0, word.kind.as_str())
}
pub mod cli_validate;
