/*
 * XRef — Stage L2 probe output formatting and rendering
 * Copyright (c) 2026 Alexander Panasenko
 * Contact: alex@prod.codes
 * Author: https://prod.codes/about/
 * Project: https://github.com/alex09x/xref
 * SPDX-License-Identifier: MIT OR Apache-2.0
 */

use std::collections::BTreeMap;
use std::io::Write;

use serde::Serialize;

use crate::live::probe::caller::attribute_caller;
use crate::live::probe::tracefs_stream::ProbeAccumulator;
use crate::live::probe::types::{LostEvents, ProbeReport, ProbeTargetResult, ProbeTargetSpec};
use crate::live::procfs::LiveSession;
use crate::live::types::{HexAddr, ProcessMeta, format_signed_hex};

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct HitJson {
    pub va: HexAddr,
    pub tid: u32,
    pub fetch: BTreeMap<String, HexAddr>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ret: Option<HexAddr>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mark: Option<String>,
}

#[must_use]
pub fn format_hit_json(
    va: u64,
    tid: u32,
    fetch_values: &BTreeMap<String, u64>,
    ret: Option<u64>,
    mark: Option<&str>,
) -> String {
    let hit = HitJson {
        va: HexAddr(va),
        tid,
        fetch: fetch_values.iter().map(|(k, &v)| (k.clone(), HexAddr(v))).collect(),
        ret: ret.map(HexAddr),
        mark: mark.map(str::to_owned),
    };
    serde_json::to_string(&hit).unwrap_or_else(|_| "{}".to_owned())
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
    let multiple_probes = report.probes.len() > 1;
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
            let mark_str = reg.mark.as_deref().map_or_else(String::new, |m| format!("  mark {m:?}"));
            writeln!(
                out,
                "  regs tid {}  rdi {:#x}  rsi {:#x}  rdx {:#x}  rcx {:#x}  r8 {:#x}  r9 {:#x}  rax {:#x}  rsp {:#x}  rbp {rbp_str}  [{}]{mark_str}",
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
        for sample in &probe.fetched_samples {
            let values = sample
                .values
                .iter()
                .map(|value| format!("{}={:#x}", value.name, value.value.0))
                .collect::<Vec<_>>()
                .join(" ");
            let mark_str = sample.mark.as_deref().map_or_else(String::new, |m| format!("  mark {m:?}"));
            if multiple_probes {
                writeln!(out, "  fetch va {:#x}  ts {}  {values}{mark_str}", probe.static_va.0, sample.timestamp_ns)?;
            } else {
                writeln!(out, "  fetch ts {}  {values}{mark_str}", sample.timestamp_ns)?;
            }
        }
        if probe.fetched_samples_truncated {
            writeln!(out, "  fetch values truncated by bounded report budget")?;
        }
    }
    Ok(())
}

pub fn write_probe_header(proc_meta: &ProcessMeta, out: &mut dyn Write) -> std::io::Result<()> {
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

pub fn build_probe_results(
    session: &mut LiveSession,
    specs: &[ProbeTargetSpec],
    accumulators: Vec<ProbeAccumulator>,
    want_callers: bool,
) -> Vec<ProbeTargetResult> {
    let mut out = Vec::with_capacity(specs.len());
    for (spec, acc) in specs.iter().zip(accumulators) {
        if want_callers && spec.ra_fetch_arg.is_none() {
            let warn = format!("caller_recovery_unavailable_at_{:#x}", spec.static_va);
            if !session.process.warnings.contains(&warn) {
                session.process.warnings.push(warn);
            }
        }
        let mut callers: Vec<_> = acc
            .caller_counts
            .into_iter()
            .map(|(ra, hits)| {
                attribute_caller(
                    &session.image,
                    session.process.pie_slide,
                    &session.regions,
                    &spec.unwind_entry_abi,
                    ra,
                    hits,
                )
            })
            .collect();
        callers.sort_by(|a, b| b.hits.cmp(&a.hits).then_with(|| a.raw_return_runtime_va.cmp(&b.raw_return_runtime_va)));

        out.push(ProbeTargetResult {
            input: HexAddr(spec.input),
            static_va: HexAddr(spec.static_va),
            runtime_va: HexAddr(spec.runtime_va),
            file_offset: HexAddr(spec.file_offset),
            function_start: spec.function_start.map(HexAddr),
            function_end: spec.function_end.map(HexAddr),
            function_offset: spec.function_offset,
            symbol: spec.symbol.clone(),
            instruction_mnemonic: spec.instruction_mnemonic.clone(),
            unwind_entry_abi: spec.unwind_entry_abi.clone(),
            accepted_hits: acc.accepted_hits,
            first_timestamp_ns: acc.first_timestamp_ns,
            last_timestamp_ns: acc.last_timestamp_ns,
            callers,
            register_samples_truncated: acc.reg_samples_truncated,
            register_samples: acc.reg_samples,
            fetched_samples: acc.fetched_samples,
            fetched_samples_truncated: acc.fetched_samples_truncated,
        });
    }
    out
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::unreadable_literal)]
mod tests {
    use std::collections::BTreeMap;

    use super::format_hit_json;

    #[test]
    fn formats_hit_json_with_and_without_ret_and_mark() {
        let mut fetches = BTreeMap::new();
        fetches.insert("amount".to_owned(), 0x2a);
        fetches.insert("size".to_owned(), 0x10);

        let json_full = format_hit_json(0x401000, 1234, &fetches, Some(0x402000), Some("step 1"));
        let parsed: serde_json::Value = serde_json::from_str(&json_full).unwrap();
        assert_eq!(parsed["va"], "0x401000");
        assert_eq!(parsed["tid"], 1234);
        assert_eq!(parsed["fetch"]["amount"], "0x2a");
        assert_eq!(parsed["fetch"]["size"], "0x10");
        assert_eq!(parsed["ret"], "0x402000");
        assert_eq!(parsed["mark"], "step 1");

        let json_minimal = format_hit_json(0x401000, 1234, &fetches, None, None);
        let parsed_min: serde_json::Value = serde_json::from_str(&json_minimal).unwrap();
        assert_eq!(parsed_min["va"], "0x401000");
        assert_eq!(parsed_min["tid"], 1234);
        assert!(parsed_min.get("ret").is_none());
        assert!(parsed_min.get("mark").is_none());
    }
}
