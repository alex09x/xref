/*
 * xref — Ultra blazing fast cross-references of an x86-64 ELF binary
 * Copyright (c) 2026 Alexander Panasenko
 *
 * Contact: alex@prod.codes
 * Author: https://prod.codes/about/
 * Project: https://github.com/alex09x/xref
 * SPDX-License-Identifier: MIT OR Apache-2.0
 */

//! Indirect calls in the call graph: `call reg` resolved through the slot the register was loaded
//! from, and the report of the indirect calls `path` could not follow.

use std::io::Write;

use iced_x86::Instruction;

use super::CallGraph;
use crate::commands::Res;

/// Registers holding a value just loaded from an IP-relative slot (`mov r12, [rip+X]`), so a
/// later `call r12` resolves through that slot. A write to the register forgets it; a call
/// forgets the caller-saved registers.
#[derive(Default)]
pub(super) struct SlotLoads {
    loads: Vec<(iced_x86::Register, u64, usize)>,
    seq: usize,
}

/// Instructions between the slot load and the call (code order, not control flow).
const SLOT_LOAD_WINDOW: usize = 256;

impl SlotLoads {
    /// The slot a `call reg` reads through, when that register still holds a slot load.
    pub(super) fn call_slot(&self, instruction: &Instruction) -> Option<u64> {
        (instruction.flow_control() == iced_x86::FlowControl::IndirectCall
            && instruction.op0_kind() == iced_x86::OpKind::Register)
            .then(|| instruction.op0_register().full_register())
            .and_then(|reg| {
                self.loads
                    .iter()
                    .find(|(r, _, at)| *r == reg && self.seq - at <= SLOT_LOAD_WINDOW)
                    .map(|&(_, slot, _)| slot)
            })
    }

    pub(super) fn step(&mut self, instruction: &Instruction) {
        use iced_x86::{FlowControl, Mnemonic, OpKind, Register};
        self.seq += 1;
        if matches!(instruction.flow_control(), FlowControl::Call | FlowControl::IndirectCall) {
            let callee_saved =
                [Register::RBX, Register::RBP, Register::R12, Register::R13, Register::R14, Register::R15];
            self.loads.retain(|(r, _, _)| callee_saved.contains(r));
            return;
        }
        if instruction.op_count() == 0 || instruction.op0_kind() != OpKind::Register {
            return;
        }
        if matches!(instruction.mnemonic(), Mnemonic::Cmp | Mnemonic::Test | Mnemonic::Bt) {
            return;
        }
        let reg = instruction.op0_register().full_register();
        self.loads.retain(|(r, _, _)| *r != reg);
        if instruction.mnemonic() == Mnemonic::Mov
            && instruction.is_ip_rel_memory_operand()
            && instruction.op0_register().size() == 8
        {
            self.loads.push((reg, instruction.ip_rel_memory_address(), self.seq));
        }
    }
}

/// Indirect calls listed per `path` report when no chain was found.
const UNFOLLOWED_SHOWN: usize = 8;

/// Why "0 paths" is not "unreachable": the indirect calls with no static target in the part of
/// the graph reachable from `from`, nearest first. Any of them may lead to the target.
pub(super) fn write_unfollowed(graph: &CallGraph, from: u64, depth: usize, out: &mut dyn Write) -> Res {
    let reach = graph.reachable(from, depth.saturating_sub(1));
    let mut sites: Vec<(usize, u64, u64)> = reach
        .iter()
        .flat_map(|(&f, &d)| graph.unresolved.get(&f).into_iter().flatten().map(move |&ip| (d, f, ip)))
        .collect();
    sites.sort_unstable();
    let functions = sites.iter().map(|&(_, f, _)| f).collect::<std::collections::BTreeSet<_>>().len();
    writeln!(
        out,
        "reachable from {from:#x} within {} hops: {} functions; {} indirect calls with no static target in {functions} of them were not followed (dyn trait vtables, closures, function pointers), so a chain may still exist",
        depth.saturating_sub(1),
        reach.len(),
        sites.len(),
    )?;
    for &(d, f, ip) in sites.iter().take(UNFOLLOWED_SHOWN) {
        writeln!(out, "  unfollowed {ip:#x} in {f:#x} (hop {d})")?;
    }
    if sites.len() > UNFOLLOWED_SHOWN {
        writeln!(out, "  ... {} more", sites.len() - UNFOLLOWED_SHOWN)?;
    }
    Ok(())
}

#[cfg(test)]
mod unfollowed_tests {
    use std::collections::HashMap;

    use super::{SlotLoads, write_unfollowed};
    use crate::graph::CallGraph;

    fn slot_of_last_call(bytes: &[u8]) -> Option<u64> {
        let mut loads = SlotLoads::default();
        let mut last = None;
        for insn in iced_x86::Decoder::with_ip(64, bytes, 0x1000, iced_x86::DecoderOptions::NONE) {
            if insn.flow_control() == iced_x86::FlowControl::IndirectCall {
                last = loads.call_slot(&insn);
            }
            loads.step(&insn);
        }
        last
    }

    #[test]
    fn call_through_a_register_resolves_to_the_slot_it_was_loaded_from() {
        // mov r12,[rip+0x100]; mov edi,1; call r12  -> slot 0x1107
        let load = [0x4c, 0x8b, 0x25, 0x00, 0x01, 0x00, 0x00];
        let call_r12 = [0x41, 0xff, 0xd4];
        let mut code = load.to_vec();
        code.extend([0xbf, 1, 0, 0, 0]);
        code.extend(call_r12);
        assert_eq!(slot_of_last_call(&code), Some(0x1107));
        // an intervening call keeps callee-saved r12
        let mut kept = load.to_vec();
        kept.extend([0xe8, 0, 0, 0, 0]);
        kept.extend(call_r12);
        assert_eq!(slot_of_last_call(&kept), Some(0x1107));
        // mov r12, rax forgets it
        let mut over = load.to_vec();
        over.extend([0x49, 0x89, 0xc4]);
        over.extend(call_r12);
        assert_eq!(slot_of_last_call(&over), None);
        // mov rax,[rip+..]; call; call rax: rax is caller-saved
        let mut clobbered = vec![0x48, 0x8b, 0x05, 0, 1, 0, 0, 0xe8, 0, 0, 0, 0];
        clobbered.extend([0xff, 0xd0]);
        assert_eq!(slot_of_last_call(&clobbered), None);
    }

    #[test]
    fn zero_paths_names_the_unfollowed_indirect_calls_nearest_first() {
        // 0x100 -> 0x200 -> 0x300; 0x200 and 0x300 have unresolved indirect calls.
        let graph = CallGraph {
            callees: HashMap::from([(0x100, vec![(0x110, 0x200)]), (0x200, vec![(0x210, 0x300)])]),
            callers: HashMap::new(),
            unresolved: HashMap::from([(0x200, vec![0x220]), (0x300, vec![0x320, 0x330]), (0x900, vec![0x910])]),
        };
        assert_eq!(graph.reachable(0x100, 1), HashMap::from([(0x100, 0), (0x200, 1)]));
        let mut out = Vec::new();
        assert!(write_unfollowed(&graph, 0x100, 3, &mut out).is_ok());
        let text = String::from_utf8_lossy(&out);
        assert!(
            text.contains("within 2 hops: 3 functions; 3 indirect calls with no static target in 2 of them"),
            "{text}"
        );
        assert!(text.contains("  unfollowed 0x220 in 0x200 (hop 1)\n  unfollowed 0x320 in 0x300 (hop 2)"), "{text}");
        assert!(!text.contains("0x910"), "{text}");
    }
}
