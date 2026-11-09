/*
 * XRef — Call sites passing a constant argument, binary-wide
 * Copyright (c) 2026 Alexander Panasenko
 * Contact: alex@prod.codes
 * Author: https://prod.codes/about/
 * Project: https://github.com/alex09x/xref
 * SPDX-License-Identifier: MIT OR Apache-2.0
 */

//! `callargs N`: every call site where an argument holds the constant N, grouped by callee and
//! argument position, with the other constants that callee receives there. A callee taking N and
//! a handful of other small numbers in one position is a status-, reason- or tag-taking helper
//! (#151): the producer of an enum value may pass it rather than store it.

pub mod copy;
mod copy_in;
pub mod flow;
pub mod forward;
mod frame;
pub mod pointer;
pub mod records;
pub mod scan;
mod spill;
#[cfg(test)]
mod tests;
#[cfg(test)]
mod tests_records;

use std::collections::{BTreeMap, BTreeSet, HashSet};
use std::io::Write;

use crate::commands::Res;
use crate::graph::resolve_addr;
use crate::image::Image;
use crate::listing::describe_code;
pub use scan::Slot;
use scan::{Call, calls};

/// Distinct constants named per group; the rest are counted.
const CONSTANTS_SHOWN: usize = 16;

pub struct CallArgsOptions {
    pub value: u64,
    pub slot: Option<Slot>,
    pub callee: Option<String>,
    /// Call sites listed; every group is summarized.
    pub limit: usize,
}

struct Group<'a> {
    callee: u64,
    slot: Slot,
    sites: Vec<&'a Call>,
    total: usize,
    constants: BTreeMap<u64, usize>,
}

pub fn callargs(image: &Image, options: &CallArgsOptions, out: &mut dyn Write) -> Res {
    let callee = match &options.callee {
        Some(spec) => {
            let raw = resolve_addr(image, spec)?;
            Some(image.function_at(raw).map_or(raw, |f| f.start))
        }
        None => None,
    };
    let wanted = |slot: Slot, value: u64| value == options.value && options.slot.is_none_or(|s| s == slot);
    let matching = calls(image, &|target, args| {
        callee.is_none_or(|c| c == target) && args.iter().any(|&(slot, value)| wanted(slot, value))
    });
    let pairs: BTreeSet<(u64, Slot)> = matching
        .iter()
        .flat_map(|call| {
            call.args.iter().filter(|&&(slot, value)| wanted(slot, value)).map(|&(slot, _)| (call.callee, slot))
        })
        .collect();
    let callees: HashSet<u64> = pairs.iter().map(|(target, _)| *target).collect();
    let every = calls(image, &|target, _| callees.contains(&target));
    let mut groups: Vec<Group> = pairs
        .iter()
        .map(|&(target, slot)| {
            let all: Vec<&Call> = every.iter().filter(|call| call.callee == target).collect();
            let mut constants = BTreeMap::new();
            for call in &all {
                for &(_, value) in call.args.iter().filter(|(s, _)| *s == slot) {
                    *constants.entry(value).or_insert(0) += 1;
                }
            }
            let sites = matching
                .iter()
                .filter(|call| call.callee == target && call.args.contains(&(slot, options.value)))
                .collect();
            Group { callee: target, slot, sites, total: all.len(), constants }
        })
        .collect();
    // Callees receiving many different constants in the position stand out first.
    groups.sort_by_key(|g| (std::cmp::Reverse(g.constants.len()), g.callee, g.slot));
    let mut listed = 0;
    let mut sites = 0;
    for group in &groups {
        sites += group.sites.len();
        writeln!(
            out,
            "callee {}  {}: {} of {} call sites pass {:#x}; constants there: {}",
            describe_code(image, group.callee),
            group.slot,
            group.sites.len(),
            group.total,
            options.value,
            constants(&group.constants)
        )?;
        for call in &group.sites {
            if listed >= options.limit {
                break;
            }
            listed += 1;
            let args: Vec<String> = call.args.iter().map(|(slot, value)| format!("{slot}={value:#x}")).collect();
            let kind = if call.tail { "jump" } else { "call" };
            writeln!(
                out,
                "  {:#x}  in {:#x}..{:#x}  {kind}  {}",
                call.ip,
                call.function.start,
                call.function.end,
                args.join("  ")
            )?;
        }
    }
    writeln!(out, "{sites} call sites pass {:#x} to {} callee arguments", options.value, groups.len())?;
    if listed < sites {
        writeln!(out, "{} call sites not listed (--limit {})", sites - listed, options.limit)?;
    }
    writeln!(
        out,
        "constants are those set in the call's straight-line run: mov reg, imm; xor reg, reg; copies of such \
         registers; mov [rsp+8k], imm; push imm"
    )?;
    Ok(())
}

fn constants(counts: &BTreeMap<u64, usize>) -> String {
    let mut named: Vec<String> =
        counts.iter().take(CONSTANTS_SHOWN).map(|(value, count)| format!("{value:#x} ×{count}")).collect();
    if counts.len() > CONSTANTS_SHOWN {
        named.push(format!("+{} more", counts.len() - CONSTANTS_SHOWN));
    }
    named.join(", ")
}
