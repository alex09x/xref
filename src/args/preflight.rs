/*
 * XRef — Live-probe style argument filter preflight and site evaluation
 * Copyright (c) 2026 Alexander Panasenko
 * Contact: alex@prod.codes
 * Author: https://prod.codes/about/
 * Project: https://github.com/alex09x/xref
 * SPDX-License-Identifier: MIT OR Apache-2.0
 */

use std::collections::{BTreeSet, HashSet};
use std::io::Write;
use std::ops::Range;

use iced_x86::{FlowControl, Instruction, OpKind, Register};
use rayon::prelude::*;

use super::resolve::resolve_arg_in_block;
use super::tracker::{Tracker, VOLATILE};
use crate::expr::{ABI_ARGS, reg_name};
use crate::graph::call_target;
use crate::image::Image;
use crate::listing::is_call;
use crate::locations::{Location, locations};
use crate::scan::{branch_target, decode};

#[cfg(any(target_os = "linux", test))]
pub use crate::live::probe::filter::{CompareOp, ValueFilter};

// `live::probe` is Linux-only outside tests; the filter grammar itself is platform-neutral,
// so non-Linux builds compile the same source file here for static preflight.
#[cfg(not(any(target_os = "linux", test)))]
#[path = "../live/probe/filter.rs"]
mod probe_filter;
#[cfg(not(any(target_os = "linux", test)))]
pub use probe_filter::{CompareOp, ValueFilter};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SiteVerdict {
    Satisfiable,
    Unsatisfiable,
    Unknown,
}

impl SiteVerdict {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Satisfiable => "satisfiable",
            Self::Unsatisfiable => "unsatisfiable",
            Self::Unknown => "unknown",
        }
    }

    #[allow(dead_code)]
    #[must_use]
    pub const fn is_satisfiable(self) -> bool { matches!(self, Self::Satisfiable) }

    #[allow(dead_code)]
    #[must_use]
    pub const fn is_unsatisfiable(self) -> bool { matches!(self, Self::Unsatisfiable) }

    #[allow(dead_code)]
    #[must_use]
    pub const fn is_unknown(self) -> bool { matches!(self, Self::Unknown) }
}

#[allow(dead_code)]
pub type SiteStatus = SiteVerdict;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CallSitePreflight {
    pub ip: u64,
    pub caller: Range<u64>,
    pub verdict: SiteVerdict,
    pub args: Vec<String>,
}

impl CallSitePreflight {
    #[allow(dead_code)]
    #[must_use]
    pub const fn status(&self) -> SiteVerdict { self.verdict }

    #[allow(dead_code)]
    #[must_use]
    pub const fn is_satisfiable(&self) -> bool { self.verdict.is_satisfiable() }

    #[allow(dead_code)]
    #[must_use]
    pub const fn is_unsatisfiable(&self) -> bool { self.verdict.is_unsatisfiable() }

    #[allow(dead_code)]
    #[must_use]
    pub const fn is_unknown(&self) -> bool { self.verdict.is_unknown() }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Preflight {
    pub function_va: u64,
    pub filter: String,
    pub sites: Vec<CallSitePreflight>,
    pub unsatisfiable_at_all_sites: bool,
}

impl Preflight {
    #[allow(dead_code)]
    #[must_use]
    pub const fn is_unsatisfiable_at_all_sites(&self) -> bool {
        self.unsatisfiable_at_all_sites
    }

    pub fn print(&self, out: &mut dyn Write) -> std::io::Result<()> {
        for site in &self.sites {
            let (start, end) = (site.caller.start, site.caller.end);
            let ip = site.ip;
            let verdict = site.verdict.as_str();
            let joined = site.args.join("  ");
            if joined.is_empty() {
                writeln!(out, "{ip:#x}  in {start:#x}..{end:#x}  {verdict}")?;
            } else {
                writeln!(out, "{ip:#x}  in {start:#x}..{end:#x}  {verdict}  {joined}")?;
            }
        }
        let total = self.sites.len();
        let unsat = self.sites.iter().filter(|s| s.verdict == SiteVerdict::Unsatisfiable).count();
        let sat = self.sites.iter().filter(|s| s.verdict == SiteVerdict::Satisfiable).count();
        let unk = self.sites.iter().filter(|s| s.verdict == SiteVerdict::Unknown).count();
        if self.unsatisfiable_at_all_sites {
            writeln!(out, "unsatisfiable at all {total} call sites")?;
        } else {
            writeln!(out, "{total} call sites ({unsat} unsatisfiable, {sat} satisfiable, {unk} unknown)")?;
        }
        Ok(())
    }
}

pub fn parse_reg_name(name: &str) -> Option<Register> {
    match name {
        "rdi" => Some(Register::RDI),
        "rsi" => Some(Register::RSI),
        "rdx" => Some(Register::RDX),
        "rcx" => Some(Register::RCX),
        "r8" => Some(Register::R8),
        "r9" => Some(Register::R9),
        "rax" => Some(Register::RAX),
        "rsp" => Some(Register::RSP),
        "rbp" => Some(Register::RBP),
        _ => None,
    }
}

pub fn filter_preflight(image: &Image, function_va: u64, filter_expr: &str) -> Result<Preflight, String> {
    let filter = ValueFilter::parse(filter_expr)?;
    let target_reg = parse_reg_name(&filter.field);
    let all_locs = locations(image);

    let mut sites: Vec<CallSitePreflight> = image
        .functions
        .par_iter()
        .filter_map(|f| Some((f, image.code(f)?)))
        .flat_map_iter(|(f, bytes)| evaluate_caller_sites(image, &all_locs, f, bytes, function_va, &filter, target_reg))
        .collect();

    sites.sort_by_key(|s| s.ip);
    let unsatisfiable_at_all_sites =
        !sites.is_empty() && sites.iter().all(|s| s.verdict == SiteVerdict::Unsatisfiable);

    Ok(Preflight {
        function_va,
        filter: filter_expr.to_owned(),
        sites,
        unsatisfiable_at_all_sites,
    })
}

fn evaluate_caller_sites(
    image: &Image,
    locs: &[Location],
    f: &Range<u64>,
    bytes: &[u8],
    target: u64,
    filter: &ValueFilter,
    target_reg: Option<Register>,
) -> Vec<CallSitePreflight> {
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

    let mut sites = Vec::new();
    let mut tracker = Tracker::new();
    let mut block_start_idx = 0;
    let mut prior_writes = HashSet::new();

    for (idx, ins) in all_insns.iter().enumerate() {
        if leaders.contains(&ins.ip()) {
            tracker.pushed.clear();
            block_start_idx = idx;
        }

        if is_call(ins, f) && call_target(image, ins) == Some(target) {
            let block_insns = &all_insns[block_start_idx..idx];
            let mut resolved_snapshot = tracker.snapshot(4);
            enhance_snapshot_with_block_resolutions(
                image,
                locs,
                block_insns,
                &prior_writes,
                &mut resolved_snapshot,
            );

            let verdict = target_reg.map_or(SiteVerdict::Unknown, |reg| {
                resolve_arg_in_block(image, locs, block_insns, &prior_writes, reg).map_or(
                    SiteVerdict::Unknown,
                    |resolved| {
                        resolved.const_val.map_or(SiteVerdict::Unknown, |c| {
                            if filter.op.test(c, filter.value) {
                                SiteVerdict::Satisfiable
                            } else {
                                SiteVerdict::Unsatisfiable
                            }
                        })
                    },
                )
            });

            sites.push(CallSitePreflight {
                ip: ins.ip(),
                caller: f.clone(),
                verdict,
                args: resolved_snapshot,
            });
        }

        if matches!(ins.flow_control(), FlowControl::Call | FlowControl::IndirectCall) {
            for r in VOLATILE {
                tracker.regs.remove(&r);
                // A call clobbers volatile registers: they no longer hold the caller's incoming arguments.
                prior_writes.insert(r);
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

        tracker.step(image, locs, ins, 4);
    }

    sites
}

pub fn enhance_snapshot_with_block_resolutions(
    image: &Image,
    locs: &[Location],
    block_insns: &[Instruction],
    prior_writes: &HashSet<Register>,
    snapshot: &mut Vec<String>,
) {
    for &reg in &ABI_ARGS {
        let name = reg_name(reg);
        let prefix = format!("{name}=");
        if let Some(pos) = snapshot.iter().position(|s| s.starts_with(&prefix)) {
            let current_val = &snapshot[pos][prefix.len()..];
            if current_val.contains("(dynamic)")
                && let Some(resolved) = resolve_arg_in_block(image, locs, block_insns, prior_writes, reg)
            {
                snapshot[pos] = format!("{name}={}", resolved.expr);
            }
        } else if let Some(resolved) = resolve_arg_in_block(image, locs, block_insns, prior_writes, reg) {
            let item = format!("{name}={}", resolved.expr);
            let insert_pos = snapshot
                .iter()
                .position(|s| s.starts_with("stack"))
                .unwrap_or(snapshot.len());
            snapshot.insert(insert_pos, item);
        }
    }
}
