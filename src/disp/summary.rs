/*
 * XRef Code — Displacement search intersections
 * Copyright (c) 2026 Alexander Panasenko
 * Contact: alex@prod.codes
 * Author: https://prod.codes/about/
 * Project: https://github.com/alex09x/xref
 * SPDX-License-Identifier: MIT OR Apache-2.0
 */

use crate::scan::DispHit;
use iced_x86::Register;
use std::collections::{HashMap, HashSet};
use std::ops::Range;

#[derive(Clone, Copy, PartialEq, Eq, Hash)]
enum Basis {
    Raw(Register),
    Anchor(i64),
}

struct Access {
    ip: u64,
    offset: u64,
    basis: Basis,
    stack: bool,
}

pub struct Summary {
    pub function: Range<u64>,
    pub count: usize,
    pub counts: Vec<(u64, usize)>,
    pub stack_hits: usize,
    pub anchors: Vec<i64>,
    rank: u8,
}

fn summarize_one(function: Range<u64>, list: &[Access], values: &[u64]) -> Option<Summary> {
    let raw_offsets: HashSet<u64> =
        list.iter().filter_map(|a| matches!(a.basis, Basis::Raw(_)).then_some(a.offset)).collect();
    let raw_all = values.iter().all(|v| raw_offsets.contains(v));
    let mut by_basis: HashMap<Basis, HashSet<u64>> = HashMap::new();
    for access in list {
        by_basis.entry(access.basis).or_default().insert(access.offset);
    }
    let complete: HashSet<Basis> = by_basis
        .into_iter()
        .filter_map(|(basis, offsets)| values.iter().all(|v| offsets.contains(v)).then_some(basis))
        .collect();
    let mut anchors: Vec<i64> = complete
        .iter()
        .filter_map(|basis| match basis {
            Basis::Anchor(frame) => Some(*frame),
            Basis::Raw(_) => None,
        })
        .collect();
    anchors.sort_unstable();
    if !raw_all && anchors.is_empty() {
        return None;
    }
    let active: Vec<&Access> = list
        .iter()
        .filter(|a| match a.basis {
            Basis::Raw(_) => raw_all,
            Basis::Anchor(_) => complete.contains(&a.basis),
        })
        .collect();
    let count = active.iter().map(|a| a.ip).collect::<HashSet<_>>().len();
    let stack_hits = active.iter().filter(|a| a.stack).map(|a| a.ip).collect::<HashSet<_>>().len();
    let counts = values
        .iter()
        .map(|&v| (v, active.iter().filter(|a| a.offset == v).map(|a| a.ip).collect::<HashSet<_>>().len()))
        .collect();
    let rank = if !anchors.is_empty() {
        0
    } else if !complete.is_empty() {
        1
    } else {
        2
    };
    Some(Summary { function, count, counts, stack_hits, anchors, rank })
}

pub fn summarize(hits: Vec<DispHit>, values: &[u64]) -> Vec<Summary> {
    let mut by_fn: HashMap<u64, (Range<u64>, Vec<Access>)> = HashMap::new();
    for hit in hits {
        let (_, list) = by_fn.entry(hit.hit.function.start).or_insert_with(|| (hit.hit.function.clone(), Vec::new()));
        if values.contains(&hit.offset) {
            list.push(Access { ip: hit.hit.ip, offset: hit.offset, basis: Basis::Raw(hit.base), stack: hit.stack });
        }
        for field in hit.anchors {
            list.push(Access {
                ip: hit.hit.ip,
                offset: field.offset,
                basis: Basis::Anchor(field.frame_offset),
                stack: true,
            });
        }
    }
    let mut out: Vec<Summary> =
        by_fn.into_values().filter_map(|(function, list)| summarize_one(function, &list, values)).collect();
    out.sort_by_key(|s| (s.rank, s.function.start));
    out
}

#[cfg(test)]
mod tests {
    use super::summarize;
    use crate::scan::{DispHit, Hit, StackFieldMatch};
    use iced_x86::Register;

    fn hit(ip: u64, offset: u64, base: Register, anchors: &[(u64, i64)]) -> DispHit {
        let start = ip & !0xfff;
        DispHit {
            hit: Hit { ip, function: start..start + 0x100, memory: None, text: String::new() },
            offset,
            base,
            stack: base == Register::RSP,
            anchors: anchors.iter().map(|&(offset, frame_offset)| StackFieldMatch { offset, frame_offset }).collect(),
        }
    }

    #[test]
    fn stack_anchor_summary_deduplicates_instruction_provenance() {
        let out = summarize(
            vec![hit(0x1000, 0x18, Register::RSP, &[(0x18, 0)]), hit(0x1004, 0x28, Register::RSP, &[(0x28, 0)])],
            &[0x18, 0x28],
        );
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].count, 2);
        assert_eq!(out[0].stack_hits, 2);
        assert_eq!(out[0].counts, vec![(0x18, 1), (0x28, 1)]);
    }

    #[test]
    fn stack_anchor_summary_prioritizes_full_anchors_and_omits_partial_counts() {
        let out = summarize(
            vec![
                hit(0x1000, 0x18, Register::RBX, &[]),
                hit(0x1004, 0x28, Register::RDX, &[]),
                hit(0x1008, 0x58, Register::RSP, &[(0x18, 0x40)]), // incomplete anchor
                hit(0x2000, 0x58, Register::RSP, &[(0x18, 0x40)]),
                hit(0x2004, 0x68, Register::RSP, &[(0x28, 0x40)]),
            ],
            &[0x18, 0x28],
        );
        assert_eq!(out.len(), 2);
        assert_eq!(out[0].function.start, 0x2000);
        assert_eq!(out[0].anchors, vec![0x40]);
        assert_eq!(out[1].function.start, 0x1000);
        assert_eq!(out[1].count, 2);
        assert_eq!(out[1].stack_hits, 0);
    }
}
