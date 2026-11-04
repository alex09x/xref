/*
 * XRef — static probe set planner for live trace windows
 * Copyright (c) 2026 Alexander Panasenko
 * Contact: alex@prod.codes
 * Author: https://prod.codes/about/
 * Project: https://github.com/alex09x/xref
 * SPDX-License-Identifier: MIT OR Apache-2.0
 */

use std::collections::{BTreeMap, BTreeSet};

use crate::image::Image;
use crate::live::classify::resolve_address;
use crate::live::probe::fetch::{FetchArg, parse_fetch_args};
use crate::live::probe::filter::{ValueFilter, parse_filters};
use crate::live::probe::trace_parse::format_uprobe_definition_with_fetches;
use crate::live::probe::types::{ProbeTargetSpec, UnwindEntryStatus};
use crate::live::trace::cli::{MAX_TRACE_PROBES, TraceArgs, split_many_fetch_lists};
use crate::live::trace::plan_helpers::{
    assign_kernel_fetches, build_fetch_map, effective_entry_unwind, expand_callees_of, record_symbol,
    take_dual_fetches, take_single_fetches, validate_all_unique_vas, verify_all_fetches_matched,
};
use crate::live::types::RegionEntry;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ReturnMode {
    CallSite,
    UretprobeBestEffort,
    MixedUretprobeBestEffort,
}

impl ReturnMode {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::CallSite => "callsite",
            Self::UretprobeBestEffort => "uretprobe_best_effort",
            Self::MixedUretprobeBestEffort => "mixed_uretprobe_best_effort",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RoleFetch {
    pub user_name: String,
    pub kernel_name: String,
    pub expression: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ProbeAction {
    CallSiteReturn { caller_fn: u64, call_site_va: u64, callee_va: u64, fetches: Vec<RoleFetch> },
    FunctionReturn { fn_va: u64, is_stop_return: bool, fetches: Vec<RoleFetch> },
    StopAt { stop_va: u64, fetches: Vec<RoleFetch> },
    StartWindow { start_va: u64, has_stop_return: bool, fetches: Vec<RoleFetch> },
    FunctionEntry { fn_va: u64, fetches: Vec<RoleFetch> },
    CallSiteEntry { caller_fn: u64, call_site_va: u64, callee_va: u64, is_tail_call: bool, fetches: Vec<RoleFetch> },
}

#[derive(Clone, Debug)]
pub struct PlannedProbe {
    pub is_retprobe: bool,
    pub spec: ProbeTargetSpec,
    pub effective_unwind: UnwindEntryStatus,
    pub ra_fetch_arg: Option<String>,
    pub kernel_fetches: Vec<FetchArg>,
    pub kernel_filters: Vec<ValueFilter>,
    pub actions: Vec<ProbeAction>,
}

impl PlannedProbe {
    #[must_use]
    pub fn uprobe_definition(&self, group: &str, event_name: &str, exec_path: &str) -> String {
        let ra = if self.is_retprobe { None } else { self.ra_fetch_arg.as_deref() };
        let def = format_uprobe_definition_with_fetches(
            group,
            event_name,
            exec_path,
            self.spec.file_offset,
            ra,
            false,
            &self.kernel_fetches,
        );
        if self.is_retprobe { def.replacen("p:", "r:", 1) } else { def }
    }
}

#[derive(Clone, Debug)]
pub struct TracePlan {
    pub probes: Vec<PlannedProbe>,
    pub start_filters: Vec<ValueFilter>,
    pub return_mode: ReturnMode,
    pub symbols: BTreeMap<u64, String>,
}

#[allow(clippy::too_many_lines)]
pub fn build_trace_plan(
    image: &Image,
    pie_slide: i64,
    regions: &[RegionEntry],
    args: &TraceArgs,
) -> Result<TracePlan, String> {
    let resolve_va = |input: u64, label: &str| -> Result<u64, String> {
        resolve_address(image, pie_slide, regions, input)
            .static_va
            .map(|h| h.0)
            .ok_or_else(|| format!("{label} address {input:#x} does not map into the target ELF executable"))
    };

    let start_set = args.start.iter().map(|&v| resolve_va(v, "--start")).collect::<Result<BTreeSet<_>, _>>()?;
    let stop_return_set =
        args.stop_return.iter().map(|&v| resolve_va(v, "--stop-return")).collect::<Result<BTreeSet<_>, _>>()?;
    for &sr in &stop_return_set {
        if !start_set.contains(&sr) {
            return Err(format!(
                "--stop-return {sr:#x} must match one of the --start addresses (use --stop {sr:#x} for an arbitrary stop PC)"
            ));
        }
    }
    let stop_set = args.stop.iter().map(|&v| resolve_va(v, "--stop")).collect::<Result<BTreeSet<_>, _>>()?;
    let fn_set = args
        .functions
        .iter()
        .map(|&v| resolve_va(v, "--functions"))
        .collect::<Result<BTreeSet<_>, _>>()?
        .into_iter()
        .filter(|va| !start_set.contains(va))
        .collect::<BTreeSet<_>>();

    let edges = expand_callees_of(image, pie_slide, regions, &args.callees_of, args.depth.unwrap_or(1))?;
    let global_start_fetches = parse_fetch_args(&split_many_fetch_lists(&args.fetch)?)?;
    let fetch_at_map = build_fetch_map(image, pie_slide, regions, &args.fetch_at, "--fetch-at")?;
    let fetch_ret_map = build_fetch_map(image, pie_slide, regions, &args.fetch_ret, "--fetch-ret")?;
    let mut used_at = BTreeSet::new();
    let mut used_ret = BTreeSet::new();

    let mut normal_actions: BTreeMap<u64, Vec<(u8, ProbeAction)>> = BTreeMap::new();
    let mut ret_actions: BTreeMap<u64, Vec<ProbeAction>> = BTreeMap::new();
    let mut symbols = BTreeMap::new();
    let mut has_callsite_returns = false;

    for edge in &edges {
        record_symbol(image, edge.caller_fn, &mut symbols);
        record_symbol(image, edge.callee_va, &mut symbols);
        if fn_set.contains(&edge.callee_va)
            || (start_set.contains(&edge.callee_va) && stop_return_set.contains(&edge.callee_va))
        {
            continue;
        }
        let entry_fetches = take_dual_fetches(&fetch_at_map, edge.call_site_va, edge.callee_va, &mut used_at)?;
        normal_actions.entry(edge.call_site_va).or_default().push((
            4,
            ProbeAction::CallSiteEntry {
                caller_fn: edge.caller_fn,
                call_site_va: edge.call_site_va,
                callee_va: edge.callee_va,
                is_tail_call: edge.is_tail_call,
                fetches: entry_fetches,
            },
        ));
        if let Some(ret_va) = edge.return_site_va {
            has_callsite_returns = true;
            let ret_fetches = take_dual_fetches(&fetch_ret_map, ret_va, edge.callee_va, &mut used_ret)?;
            normal_actions.entry(ret_va).or_default().push((
                0,
                ProbeAction::CallSiteReturn {
                    caller_fn: edge.caller_fn,
                    call_site_va: edge.call_site_va,
                    callee_va: edge.callee_va,
                    fetches: ret_fetches,
                },
            ));
        }
    }

    for &stop_va in &stop_set {
        record_symbol(image, stop_va, &mut symbols);
        let fetches = take_single_fetches(&fetch_at_map, stop_va, &[], &mut used_at)?;
        normal_actions.entry(stop_va).or_default().push((1, ProbeAction::StopAt { stop_va, fetches }));
    }

    let mut start_filters = Vec::new();
    for &start_va in &start_set {
        record_symbol(image, start_va, &mut symbols);
        let fetches = take_single_fetches(&fetch_at_map, start_va, &global_start_fetches, &mut used_at)?;
        let names = fetches.iter().map(|f| f.user_name.clone()).collect::<Vec<_>>();
        start_filters = parse_filters(&args.start_filter, false, &names)?;
        let has_stop_return = stop_return_set.contains(&start_va);
        normal_actions
            .entry(start_va)
            .or_default()
            .push((2, ProbeAction::StartWindow { start_va, has_stop_return, fetches }));
        if has_stop_return {
            let rf = take_single_fetches(&fetch_ret_map, start_va, &[], &mut used_ret)?;
            ret_actions.entry(start_va).or_default().push(ProbeAction::FunctionReturn {
                fn_va: start_va,
                is_stop_return: true,
                fetches: rf,
            });
        }
    }

    for &fn_va in &fn_set {
        record_symbol(image, fn_va, &mut symbols);
        let ef = take_single_fetches(&fetch_at_map, fn_va, &[], &mut used_at)?;
        normal_actions.entry(fn_va).or_default().push((3, ProbeAction::FunctionEntry { fn_va, fetches: ef }));
        let rf = take_single_fetches(&fetch_ret_map, fn_va, &[], &mut used_ret)?;
        ret_actions.entry(fn_va).or_default().push(ProbeAction::FunctionReturn {
            fn_va,
            is_stop_return: false,
            fetches: rf,
        });
    }

    verify_all_fetches_matched(&fetch_at_map, &used_at, "--fetch-at")?;
    verify_all_fetches_matched(&fetch_ret_map, &used_ret, "--fetch-ret")?;

    let unique_vas = normal_actions.keys().chain(ret_actions.keys()).copied().collect::<BTreeSet<_>>();
    let total_probes = normal_actions.len().saturating_add(ret_actions.len());
    if total_probes == 0 || total_probes > MAX_TRACE_PROBES {
        return Err(format!("trace plan requires 1..={MAX_TRACE_PROBES} uprobes (planned {total_probes})"));
    }
    let spec_map = validate_all_unique_vas(image, pie_slide, regions, &unique_vas)?;

    let mut probes = Vec::with_capacity(total_probes);
    for (va, mut ordered) in normal_actions {
        ordered.sort_by_key(|(rank, _)| *rank);
        let mut actions = ordered.into_iter().map(|(_, a)| a).collect::<Vec<_>>();
        let kernel_fetches = assign_kernel_fetches(&mut actions)?;
        let spec = spec_map.get(&va).cloned().ok_or_else(|| format!("missing validated spec for {va:#x}"))?;
        let needs_ra =
            actions.iter().any(|a| matches!(a, ProbeAction::StartWindow { .. } | ProbeAction::FunctionEntry { .. }));
        let (effective_unwind, ra_fetch_arg) =
            if needs_ra { effective_entry_unwind(&spec) } else { (spec.unwind_entry_abi.clone(), None) };
        let kernel_filters = if matches!(actions.as_slice(), [ProbeAction::StartWindow { has_stop_return: false, .. }])
        {
            start_filters.clone()
        } else {
            Vec::new()
        };
        probes.push(PlannedProbe {
            is_retprobe: false,
            spec,
            effective_unwind,
            ra_fetch_arg,
            kernel_fetches,
            kernel_filters,
            actions,
        });
    }
    let has_uretprobes = !ret_actions.is_empty();
    for (va, mut actions) in ret_actions {
        let kernel_fetches = assign_kernel_fetches(&mut actions)?;
        let spec = spec_map.get(&va).cloned().ok_or_else(|| format!("missing validated spec for {va:#x}"))?;
        probes.push(PlannedProbe {
            is_retprobe: true,
            effective_unwind: spec.unwind_entry_abi.clone(),
            spec,
            ra_fetch_arg: None,
            kernel_fetches,
            kernel_filters: Vec::new(),
            actions,
        });
    }

    let return_mode = match (has_callsite_returns, has_uretprobes) {
        (_, false) => ReturnMode::CallSite,
        (false, true) => ReturnMode::UretprobeBestEffort,
        (true, true) => ReturnMode::MixedUretprobeBestEffort,
    };
    Ok(TracePlan { probes, start_filters, return_mode, symbols })
}
