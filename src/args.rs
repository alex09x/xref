/*
 * XRef — Call-site argument recovery and filter preflight orchestration
 * Copyright (c) 2026 Alexander Panasenko
 * Contact: alex@prod.codes
 * Author: https://prod.codes/about/
 * Project: https://github.com/alex09x/xref
 * SPDX-License-Identifier: MIT OR Apache-2.0
 */

//! Call-site constant and symbolic argument recovery (`args`) for System V AMD64 register and stack slots.

use std::collections::{BTreeSet, HashSet};
use std::io::Write;
use std::ops::Range;

use iced_x86::{FlowControl, OpKind};
use rayon::prelude::*;

use crate::commands::Res;
use crate::graph::{call_target, resolve_addr};
use crate::image::Image;
use crate::listing::is_call;
use crate::locations::{Location, locations};
use crate::scan::{branch_target, decode};

mod preflight;
mod resolve;
#[cfg(test)]
mod tests;
mod tracker;

#[allow(unused_imports)]
pub use preflight::{CallSitePreflight, CompareOp, Preflight, SiteStatus, SiteVerdict, ValueFilter, filter_preflight};
#[allow(unused_imports)]
pub use resolve::{ResolvedArg, resolve_arg_in_block};
pub use tracker::Tracker;

fn analyze_caller(
    image: &Image,
    locs: &[Location],
    f: &Range<u64>,
    bytes: &[u8],
    target: u64,
    max_stack: usize,
) -> Vec<(u64, Range<u64>, Vec<String>)> {
    let mut has_call = false;
    let mut leaders = BTreeSet::new();
    decode(bytes, f.start, |instruction| {
        if is_call(instruction, f) && call_target(image, instruction) == Some(target) {
            has_call = true;
        }
        if let Some(dest) = branch_target(instruction)
            && f.contains(&dest)
        {
            leaders.insert(dest);
        }
    });
    if !has_call {
        return Vec::new();
    }

    let mut all_insns = Vec::new();
    decode(bytes, f.start, |ins| all_insns.push(*ins));

    let mut tracker = Tracker::new();
    let mut sites = Vec::new();
    let mut block_start_idx = 0;
    let mut prior_writes = HashSet::new();

    for (idx, ins) in all_insns.iter().enumerate() {
        if leaders.contains(&ins.ip()) {
            tracker.pushed.clear();
            block_start_idx = idx;
        }

        if is_call(ins, f) && call_target(image, ins) == Some(target) {
            let block_insns = &all_insns[block_start_idx..idx];
            let mut snapshot = tracker.snapshot(max_stack);
            preflight::enhance_snapshot_with_block_resolutions(
                image,
                locs,
                block_insns,
                &prior_writes,
                &mut snapshot,
            );
            sites.push((ins.ip(), f.clone(), snapshot));
        }

        if matches!(ins.flow_control(), FlowControl::Call | FlowControl::IndirectCall) {
            for r in tracker::VOLATILE {
                tracker.regs.remove(&r);
            }
            tracker.pushed.clear();
            block_start_idx = idx.saturating_add(1);
            continue;
        }

        if matches!(
            ins.flow_control(),
            FlowControl::UnconditionalBranch
                | FlowControl::ConditionalBranch
                | FlowControl::IndirectBranch
                | FlowControl::Return
                | FlowControl::Interrupt
        ) {
            block_start_idx = idx.saturating_add(1);
        }

        if ins.op0_kind() == OpKind::Register {
            prior_writes.insert(ins.op0_register().full_register());
        }

        tracker.step(image, locs, ins, max_stack);
    }

    sites
}

pub fn args(
    image: &Image,
    spec: &str,
    max_stack: usize,
    filter: Option<&str>,
    out: &mut dyn Write,
) -> Res {
    let raw = resolve_addr(image, spec)?;
    let target = image.function_at(raw).map_or(raw, |f| f.start);

    if let Some(filter_expr) = filter {
        let report = filter_preflight(image, target, filter_expr)?;
        report.print(out)?;
        return Ok(());
    }

    let all_locs = locations(image);
    let mut sites: Vec<(u64, Range<u64>, Vec<String>)> = image
        .functions
        .par_iter()
        .filter_map(|f| Some((f, image.code(f)?)))
        .flat_map_iter(|(f, bytes)| analyze_caller(image, &all_locs, f, bytes, target, max_stack))
        .collect();
    sites.sort_by_key(|(ip, ..)| *ip);
    for (ip, f, items) in &sites {
        let joined = items.join("  ");
        let (start, end) = (f.start, f.end);
        writeln!(out, "{ip:#x}  in {start:#x}..{end:#x}  {joined}")?;
    }
    writeln!(out, "{} call sites", sites.len())?;
    Ok(())
}
