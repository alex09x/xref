/*
 * XRef — static call-site expansion and fetch binding helpers for live trace
 * Copyright (c) 2026 Alexander Panasenko
 * Contact: alex@prod.codes
 * Author: https://prod.codes/about/
 * Project: https://github.com/alex09x/xref
 * SPDX-License-Identifier: MIT OR Apache-2.0
 */

use std::collections::{BTreeMap, BTreeSet, VecDeque};

use iced_x86::FlowControl;

use crate::commands::function;
use crate::graph::{call_target, resolve_addr};
use crate::image::Image;
use crate::listing::is_call;
use crate::live::classify::{lookup_symbol, resolve_address};
use crate::live::cli::MAX_PROBES_PER_SESSION;
use crate::live::probe::fetch::{FetchArg, MAX_FETCH_ARGS, parse_fetch_args};
use crate::live::probe::types::{ProbeTargetSpec, UnwindEntryStatus};
use crate::live::probe::validate::{validate_probe_targets, verify_instruction_boundary};
use crate::live::trace::cli::parse_targeted_fetches;
use crate::live::trace::plan::{ProbeAction, RoleFetch};
use crate::live::types::RegionEntry;
use crate::scan::decode;

pub struct StaticCallEdge {
    pub caller_fn: u64,
    pub call_site_va: u64,
    pub return_site_va: Option<u64>,
    pub callee_va: u64,
    pub is_tail_call: bool,
}

pub fn expand_callees_of(
    image: &Image,
    pie_slide: i64,
    regions: &[RegionEntry],
    specs: &[String],
    max_depth: usize,
) -> Result<Vec<StaticCallEdge>, String> {
    let mut queue = VecDeque::new();
    for spec in specs {
        let root_va = if let Ok(num) = crate::cli::parse_number(spec) {
            resolve_address(image, pie_slide, regions, num)
                .static_va
                .map(|h| h.0)
                .ok_or_else(|| format!("--callees-of address {num:#x} does not map into the target ELF executable"))?
        } else {
            resolve_addr(image, spec).map_err(|e| e.to_string())?
        };
        let root_fn = function(image, root_va).map_err(|e| format!("--callees-of {spec}: {e}"))?;
        queue.push_back((root_fn, 0_usize));
    }

    let mut visited = BTreeSet::new();
    let mut edges = Vec::new();
    while let Some((caller_range, level)) = queue.pop_front() {
        if level >= max_depth || !visited.insert(caller_range.start) {
            continue;
        }
        let code = image
            .code(&caller_range)
            .ok_or_else(|| format!("function {:#x}..{:#x} outside image", caller_range.start, caller_range.end))?;
        decode(code, caller_range.start, |instr| {
            if !is_call(instr, &caller_range) {
                return;
            }
            let Some(raw_target) = call_target(image, instr) else { return };
            let callee_fn = image.function_at(raw_target);
            let callee_va = callee_fn.as_ref().map_or(raw_target, |f| f.start);
            let is_regular_call = matches!(instr.flow_control(), FlowControl::Call | FlowControl::IndirectCall);
            let next_ip = instr.next_ip();
            let return_site_va =
                if is_regular_call && next_ip < caller_range.end && verify_instruction_boundary(image, next_ip).is_ok()
                {
                    Some(next_ip)
                } else {
                    None
                };
            edges.push(StaticCallEdge {
                caller_fn: caller_range.start,
                call_site_va: instr.ip(),
                return_site_va,
                callee_va,
                is_tail_call: !is_regular_call,
            });
            if level + 1 < max_depth
                && let Some(cf) = callee_fn
                && cf.start == raw_target
            {
                queue.push_back((cf, level + 1));
            }
        });
    }
    Ok(edges)
}

pub fn build_fetch_map(
    image: &Image,
    pie_slide: i64,
    regions: &[RegionEntry],
    pairs: &[String],
    flag_name: &str,
) -> Result<BTreeMap<u64, Vec<FetchArg>>, String> {
    let parsed_pairs = parse_targeted_fetches(pairs, flag_name)?;
    let mut map: BTreeMap<u64, Vec<FetchArg>> = BTreeMap::new();
    for (input_va, specs) in parsed_pairs {
        let static_va = resolve_address(image, pie_slide, regions, input_va)
            .static_va
            .map(|h| h.0)
            .ok_or_else(|| format!("{flag_name} address {input_va:#x} does not map into the target ELF executable"))?;
        let args = parse_fetch_args(&specs)?;
        let entry = map.entry(static_va).or_default();
        for arg in args {
            if entry.iter().any(|existing| existing.name == arg.name) {
                return Err(format!("duplicate {flag_name} name {:?} for {static_va:#x}", arg.name));
            }
            entry.push(arg);
        }
        if entry.len() > MAX_FETCH_ARGS {
            return Err(format!("{flag_name} for {static_va:#x} exceeds {MAX_FETCH_ARGS} arguments"));
        }
    }
    Ok(map)
}

pub fn take_single_fetches(
    map: &BTreeMap<u64, Vec<FetchArg>>,
    va: u64,
    base: &[FetchArg],
    used: &mut BTreeSet<u64>,
) -> Result<Vec<RoleFetch>, String> {
    let mut combined = Vec::new();
    for arg in base {
        push_unique_role_fetch(&mut combined, arg, va)?;
    }
    if let Some(extra) = map.get(&va) {
        used.insert(va);
        for arg in extra {
            push_unique_role_fetch(&mut combined, arg, va)?;
        }
    }
    Ok(combined)
}

pub fn take_dual_fetches(
    map: &BTreeMap<u64, Vec<FetchArg>>,
    site_va: u64,
    callee_va: u64,
    used: &mut BTreeSet<u64>,
) -> Result<Vec<RoleFetch>, String> {
    let mut combined = Vec::new();
    for va in if site_va == callee_va { vec![site_va] } else { vec![callee_va, site_va] } {
        if let Some(list) = map.get(&va) {
            used.insert(va);
            for arg in list {
                push_unique_role_fetch(&mut combined, arg, site_va)?;
            }
        }
    }
    Ok(combined)
}

fn push_unique_role_fetch(out: &mut Vec<RoleFetch>, arg: &FetchArg, va: u64) -> Result<(), String> {
    if let Some(prev) = out.iter().find(|f| f.user_name == arg.name) {
        if prev.expression != arg.expression {
            return Err(format!("conflicting fetch definitions for {:?} at {va:#x}", arg.name));
        }
        return Ok(());
    }
    out.push(RoleFetch {
        user_name: arg.name.clone(),
        kernel_name: arg.name.clone(),
        expression: arg.expression.clone(),
    });
    if out.len() > MAX_FETCH_ARGS {
        return Err(format!("probe at {va:#x} exceeds {MAX_FETCH_ARGS} fetch arguments"));
    }
    Ok(())
}

pub fn verify_all_fetches_matched(
    map: &BTreeMap<u64, Vec<FetchArg>>,
    used: &BTreeSet<u64>,
    flag_name: &str,
) -> Result<(), String> {
    for &va in map.keys() {
        if !used.contains(&va) {
            return Err(format!("{flag_name} target {va:#x} does not match any traced probe in the plan"));
        }
    }
    Ok(())
}

pub fn validate_all_unique_vas(
    image: &Image,
    pie_slide: i64,
    regions: &[RegionEntry],
    unique_vas: &BTreeSet<u64>,
) -> Result<BTreeMap<u64, ProbeTargetSpec>, String> {
    let ordered = unique_vas.iter().copied().collect::<Vec<_>>();
    let mut seen_offsets = BTreeSet::new();
    let mut out = BTreeMap::new();
    for chunk in ordered.chunks(MAX_PROBES_PER_SESSION) {
        let specs = validate_probe_targets(image, pie_slide, regions, chunk)?;
        for spec in specs {
            if !seen_offsets.insert(spec.file_offset) {
                return Err(format!(
                    "duplicate probe target at file offset {:#x} (static {:#x})",
                    spec.file_offset, spec.static_va
                ));
            }
            out.insert(spec.static_va, spec);
        }
    }
    Ok(out)
}

pub fn assign_kernel_fetches(actions: &mut [ProbeAction]) -> Result<Vec<FetchArg>, String> {
    let mut kernel_fetches: Vec<FetchArg> = Vec::new();
    for action in actions {
        let fetches = match action {
            ProbeAction::CallSiteReturn { fetches, .. }
            | ProbeAction::FunctionReturn { fetches, .. }
            | ProbeAction::StopAt { fetches, .. }
            | ProbeAction::StartWindow { fetches, .. }
            | ProbeAction::FunctionEntry { fetches, .. }
            | ProbeAction::CallSiteEntry { fetches, .. } => fetches,
        };
        for rf in fetches {
            if let Some(existing) = kernel_fetches.iter().find(|kf| kf.expression == rf.expression) {
                rf.kernel_name.clone_from(&existing.name);
            } else if !kernel_fetches.iter().any(|kf| kf.name == rf.user_name) {
                rf.kernel_name.clone_from(&rf.user_name);
                kernel_fetches.push(FetchArg { name: rf.kernel_name.clone(), expression: rf.expression.clone() });
            } else {
                let alias = format!("_xf_{}", kernel_fetches.len());
                rf.kernel_name.clone_from(&alias);
                kernel_fetches.push(FetchArg { name: alias, expression: rf.expression.clone() });
            }
            if kernel_fetches.len() > MAX_FETCH_ARGS {
                return Err(format!("merged probe exceeds {MAX_FETCH_ARGS} uprobe fetch arguments"));
            }
        }
    }
    Ok(kernel_fetches)
}

pub fn effective_entry_unwind(spec: &ProbeTargetSpec) -> (UnwindEntryStatus, Option<String>) {
    if spec.ra_fetch_arg.is_some() {
        return (spec.unwind_entry_abi.clone(), spec.ra_fetch_arg.clone());
    }
    if let UnwindEntryStatus::Unavailable { detail } = &spec.unwind_entry_abi
        && matches!(detail.as_str(), "missing_eh_frame" | "elf_reparse_failed" | "no_fde_for_address")
        && (spec.function_offset == Some(0) || spec.symbol.is_some())
    {
        return (UnwindEntryStatus::StandardRsp8RaMinus8, Some("+0(%sp):u64".to_owned()));
    }
    (spec.unwind_entry_abi.clone(), None)
}

pub fn record_symbol(image: &Image, va: u64, symbols: &mut BTreeMap<u64, String>) {
    if !symbols.contains_key(&va)
        && let Some(sym) = lookup_symbol(image, va).or_else(|| crate::runtime::plt_import(image, va).map(str::to_owned))
    {
        symbols.insert(va, sym);
    }
}
