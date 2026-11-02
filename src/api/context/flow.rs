/*
 * XRef Code — evidence-producing binary analysis
 * Copyright (c) 2026 Alexander Panasenko
 * Contact: alex@prod.codes
 * Author: https://prod.codes/about/
 * Project: https://github.com/alex09x/xref
 * SPDX-License-Identifier: MIT OR Apache-2.0
 */
use crate::{image::Slot, scan};
use iced_x86::{FlowControl, Instruction};
use std::collections::{BTreeMap, VecDeque};

pub(super) struct Flow {
    pub successors: Vec<Vec<usize>>,
    pub predecessors: Vec<Vec<usize>>,
    pub incomplete: bool,
}
impl Flow {
    pub fn new(insns: &[Instruction], image: &crate::image::Image, function: &std::ops::Range<u64>) -> Self {
        let indexes: BTreeMap<_, _> = insns.iter().enumerate().map(|(i, ins)| (ins.ip(), i)).collect();
        let mut successors = vec![vec![]; insns.len()];
        let mut incomplete = insns.iter().any(Instruction::is_invalid);
        for (i, ins) in insns.iter().enumerate() {
            let next = indexes.get(&ins.next_ip()).copied();
            match ins.flow_control() {
                FlowControl::Next | FlowControl::Call | FlowControl::IndirectCall => {
                    if let Some(n) = next {
                        successors[i].push(n);
                    }
                }
                FlowControl::ConditionalBranch | FlowControl::UnconditionalBranch => {
                    if let Some(&t) = scan::branch_target(ins).and_then(|ip| indexes.get(&ip)) {
                        successors[i].push(t);
                    } else if ins.flow_control() == FlowControl::ConditionalBranch
                        || scan::branch_target(ins).is_none_or(|ip| function.contains(&ip))
                    {
                        incomplete = true;
                    }
                    if ins.flow_control() == FlowControl::ConditionalBranch
                        && let Some(n) = next
                        && !successors[i].contains(&n)
                    {
                        successors[i].push(n);
                    }
                }
                FlowControl::Return | FlowControl::Exception if !ins.is_invalid() => {}
                FlowControl::IndirectBranch => {
                    let slot =
                        ins.is_ip_rel_memory_operand().then(|| image.slot(ins.ip_rel_memory_address())).flatten();
                    match slot {
                        Some(Slot::Pointer(ip)) if function.contains(&ip) => {
                            if let Some(&target) = indexes.get(&ip) {
                                successors[i].push(target);
                            } else {
                                incomplete = true;
                            }
                        }
                        Some(Slot::Import(_) | Slot::Pointer(_)) => {}
                        None => {
                            incomplete = true;
                        }
                    }
                }
                _ => {
                    incomplete = true;
                }
            }
        }
        let mut predecessors = vec![vec![]; insns.len()];
        for (i, edges) in successors.iter().enumerate() {
            for &to in edges {
                predecessors[to].push(i);
            }
        }
        Self { successors, predecessors, incomplete }
    }
    pub fn reaches(&self, start: usize, target: usize, avoid: Option<usize>, budget: &mut usize) -> Option<bool> {
        let mut seen = vec![false; self.successors.len()];
        let mut queue = VecDeque::from([start]);
        while let Some(i) = queue.pop_front() {
            if *budget == 0 {
                return None;
            }
            *budget -= 1;
            if Some(i) == avoid || seen[i] {
                continue;
            }
            if i == target {
                return Some(true);
            }
            seen[i] = true;
            queue.extend(self.successors[i].iter().copied());
        }
        Some(false)
    }
}
