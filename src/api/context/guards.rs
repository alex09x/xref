/*
 * XRef Code — evidence-producing binary analysis
 * Copyright (c) 2026 Alexander Panasenko
 * Contact: alex@prod.codes
 * Author: https://prod.codes/about/
 * Project: https://github.com/alex09x/xref
 * SPDX-License-Identifier: MIT OR Apache-2.0
 */
use super::super::{ApiError, Cancellation};
use super::{flow::Flow, types::Guard};
use iced_x86::{FlowControl, Instruction};
use std::collections::BTreeSet;

fn flag_defs(insns: &[Instruction], flow: &Flow, branch: usize, budget: &mut usize) -> (Vec<usize>, bool) {
    let mask = insns[branch].rflags_read();
    if mask == 0 {
        return (vec![], true);
    }
    let mut pending: Vec<_> = flow.predecessors[branch].iter().map(|&i| (i, mask)).collect();
    let mut seen = BTreeSet::new();
    let mut defs = BTreeSet::new();
    let mut complete = branch != 0;
    while let Some((i, needed)) = pending.pop() {
        if *budget == 0 || defs.len() >= 16 {
            return (defs.into_iter().collect(), false);
        }
        *budget -= 1;
        if !seen.insert((i, needed)) {
            continue;
        }
        let ins = &insns[i];
        let modifies = ins.rflags_modified();
        let produced = modifies & needed;
        if produced != 0 {
            defs.insert(i);
            // Calls can alter flags even if the decoder does not list writes.
            if ins.rflags_undefined() & produced != 0 {
                complete = false;
            }
        }
        if matches!(ins.flow_control(), FlowControl::Call | FlowControl::IndirectCall) {
            defs.insert(i);
            complete = false;
            continue;
        }
        let rest = needed & !modifies;
        if rest == 0 {
            continue;
        }
        if i == 0 || flow.predecessors[i].is_empty() {
            complete = false;
        }
        pending.extend(flow.predecessors[i].iter().map(|&p| (p, rest)));
    }
    (defs.into_iter().collect(), complete)
}
pub(super) fn guards(
    insns: &[Instruction],
    flow: &Flow,
    call: usize,
    cancel: &Cancellation,
) -> Result<(Vec<Guard>, Vec<usize>, bool), ApiError> {
    cancel.checkpoint()?;
    if flow.incomplete {
        return Ok((vec![], vec![], false));
    }
    let mut out = vec![];
    let mut evidence = BTreeSet::new();
    let mut budget = 200_000;
    match flow.reaches(0, call, None, &mut budget) {
        Some(true) => {}
        Some(false) => return Ok((vec![], vec![], true)),
        None => return Ok((vec![], vec![], false)),
    }
    let mut complete = true;
    for (i, ins) in insns.iter().enumerate() {
        cancel.checkpoint()?;
        if ins.flow_control() != FlowControl::ConditionalBranch {
            continue;
        }
        if out.len() == 16 {
            complete = false;
            break;
        }
        if flow.reaches(0, call, Some(i), &mut budget) != Some(false) {
            if budget == 0 {
                complete = false;
                break;
            }
            continue;
        }
        let target = flow.successors[i].iter().copied().find(|&n| insns[n].ip() == ins.near_branch_target());
        let fall = flow.successors[i].iter().copied().find(|&n| insns[n].ip() == ins.next_ip());
        let (Some(target), Some(fall)) = (target, fall) else {
            complete = false;
            continue;
        };
        let t = flow.reaches(target, call, Some(i), &mut budget);
        let f = flow.reaches(fall, call, Some(i), &mut budget);
        let edge = match (t, f) {
            (Some(true), Some(false)) => "taken",
            (Some(false), Some(true)) => "fallthrough",
            (Some(_), Some(_)) => continue,
            _ => {
                complete = false;
                break;
            }
        };
        let (defs, flags_complete) = flag_defs(insns, flow, i, &mut budget);
        evidence.insert(i);
        evidence.extend(defs.iter().copied());
        out.push(Guard {
            branch_address: format!("{:#x}", ins.ip()),
            required_edge: edge,
            flag_definition_addresses: defs.iter().map(|&j| format!("{:#x}", insns[j].ip())).collect(),
            flag_definitions_complete: flags_complete,
        });
    }
    Ok((out, evidence.into_iter().collect(), complete))
}
