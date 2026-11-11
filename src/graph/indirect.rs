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
    info: Option<iced_x86::InstructionInfoFactory>,
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
        if matches!(instruction.flow_control(), FlowControl::Return | FlowControl::Exception | FlowControl::Interrupt) {
            // The function or this path ends; the next code in order starts elsewhere.
            self.loads.clear();
            return;
        }
        // After a call, or a jump to code reached from elsewhere, only callee-saved registers
        // keep their value (a slot load before a loop is still live inside it).
        if matches!(
            instruction.flow_control(),
            FlowControl::Call
                | FlowControl::IndirectCall
                | FlowControl::UnconditionalBranch
                | FlowControl::IndirectBranch
        ) {
            let callee_saved =
                [Register::RBX, Register::RBP, Register::R12, Register::R13, Register::R14, Register::R15];
            self.loads.retain(|(r, _, _)| callee_saved.contains(r));
            return;
        }
        if self.loads.is_empty() && instruction.mnemonic() != Mnemonic::Mov {
            return;
        }
        // Every register the instruction may write, explicit or implicit (xchg, mul, cmov, pop…).
        let info = self.info.get_or_insert_with(iced_x86::InstructionInfoFactory::new).info(instruction);
        let written: Vec<Register> = info
            .used_registers()
            .iter()
            .filter(|u| {
                matches!(
                    u.access(),
                    iced_x86::OpAccess::Write
                        | iced_x86::OpAccess::ReadWrite
                        | iced_x86::OpAccess::CondWrite
                        | iced_x86::OpAccess::ReadCondWrite
                )
            })
            .map(|u| u.register().full_register())
            .collect();
        self.loads.retain(|(r, _, _)| !written.contains(r));
        if instruction.mnemonic() == Mnemonic::Mov
            && instruction.op0_kind() == OpKind::Register
            && instruction.is_ip_rel_memory_operand()
            && instruction.op0_register().size() == 8
        {
            self.loads.push((
                instruction.op0_register().full_register(),
                instruction.ip_rel_memory_address(),
                self.seq,
            ));
        }
    }
}

/// Indirect calls listed per `path` report when no chain was found.
const UNFOLLOWED_SHOWN: usize = 8;

/// Why "0 paths" is not "unreachable": the indirect calls with no static target in the part of
/// the graph reachable from `from`, nearest first. Any of them may lead to the target.
pub(super) fn write_unfollowed(graph: &CallGraph, from: u64, depth: usize, out: &mut dyn Write) -> Res {
    if depth == 0 {
        return Ok(());
    }
    let reach = graph.reachable(from, depth - 1);
    let mut sites: Vec<(usize, u64, u64)> = reach
        .iter()
        .flat_map(|(&f, &d)| graph.unresolved.get(&f).into_iter().flatten().map(move |&ip| (d, f, ip)))
        .collect();
    sites.sort_unstable();
    let hops = depth - 1;
    if sites.is_empty() {
        writeln!(
            out,
            "reachable from {from:#x} within {hops} hops: {} functions; 0 indirect calls with no static target",
            reach.len()
        )?;
        return Ok(());
    }
    let functions = sites.iter().map(|&(_, f, _)| f).collect::<std::collections::BTreeSet<_>>().len();
    writeln!(
        out,
        "reachable from {from:#x} within {hops} hops: {} functions; {} indirect calls with no static target in {functions} of them were not followed (dyn trait vtables, closures, function pointers), so a chain may still exist",
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

/// Where a function's address is taken: data slots holding it, and code loading it.
type Refs = (Vec<u64>, Vec<u64>);

/// The other side of a missing chain: the functions that reach `to` within the depth whose
/// address is taken (held in a pointer slot or vtable record, or loaded by code with `lea`),
/// nearest to `to` first. An indirect call can only enter that part of the graph through one.
pub(super) fn write_entries(
    image: &crate::image::Image,
    graph: &CallGraph,
    to_dist: &std::collections::HashMap<u64, usize>,
    to: u64,
    out: &mut dyn Write,
) -> Res {
    let mut held: std::collections::BTreeMap<u64, Refs> = std::collections::BTreeMap::new();
    for &(slot, target) in &image.pointers {
        // A slot code only calls through is already an edge; one read as data, or never named by
        // `rip`-relative code (a vtable record), lets the pointer reach an indirect call.
        let through_edges_only = graph.slots_called.contains(&slot) && !graph.slots_read.contains(&slot);
        if to_dist.contains_key(&target) && !through_edges_only {
            held.entry(target).or_default().0.push(slot);
        }
    }
    for (target, sites) in &graph.taken {
        if to_dist.contains_key(target) {
            held.entry(*target).or_default().1.extend(sites);
        }
    }
    let mut entries: Vec<(usize, u64, Refs)> = held.into_iter().map(|(f, refs)| (to_dist[&f], f, refs)).collect();
    entries.sort_unstable();
    let max = to_dist.values().copied().max().unwrap_or(0);
    if entries.is_empty() {
        writeln!(
            out,
            "reaching {to:#x} within {max} hops: {} functions, none with its address taken (in data or by code); an indirect call cannot enter there, so no chain of that depth exists",
            to_dist.len()
        )?;
        return Ok(());
    }
    writeln!(
        out,
        "reaching {to:#x} within {max} hops: {} functions; {} have their address taken, the only places an unfollowed indirect call can enter:",
        to_dist.len(),
        entries.len()
    )?;
    for (d, f, (slots, code)) in entries.iter().take(UNFOLLOWED_SHOWN) {
        let mut how = Vec::new();
        if let Some(slot) = slots.first() {
            how.push(format!(
                "held at {slot:#x}{}",
                if slots.len() > 1 { format!(" (+{})", slots.len() - 1) } else { String::new() }
            ));
        }
        if let Some(site) = code.first() {
            how.push(format!(
                "loaded at {site:#x}{}",
                if code.len() > 1 { format!(" (+{})", code.len() - 1) } else { String::new() }
            ));
        }
        writeln!(out, "  entry {f:#x} ({d} hops to {to:#x}), {}", how.join(", "))?;
    }
    if entries.len() > UNFOLLOWED_SHOWN {
        writeln!(out, "  ... {} more", entries.len() - UNFOLLOWED_SHOWN)?;
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
        // xchg r12, rax writes r12 implicitly as its second operand
        let mut swapped = load.to_vec();
        swapped.extend([0x49, 0x94]);
        swapped.extend(call_r12);
        assert_eq!(slot_of_last_call(&swapped), None);
        // a ret or ud2 ends the path; a jump keeps callee-saved r12 (a loop around the call)
        for boundary in [vec![0xc3], vec![0x0f, 0x0b]] {
            let mut crossed = load.to_vec();
            crossed.extend(boundary);
            crossed.extend(call_r12);
            assert_eq!(slot_of_last_call(&crossed), None);
        }
        let mut looped = load.to_vec();
        looped.extend([0xeb, 0x00]);
        looped.extend(call_r12);
        assert_eq!(slot_of_last_call(&looped), Some(0x1107));
        let mut jumped_rax = vec![0x48, 0x8b, 0x05, 0, 1, 0, 0, 0xeb, 0x00, 0xff, 0xd0];
        assert_eq!(slot_of_last_call(&jumped_rax), None);
        jumped_rax.clear();
        // mov rax,[rip+..]; call; call rax: rax is caller-saved
        let mut clobbered = vec![0x48, 0x8b, 0x05, 0, 1, 0, 0, 0xe8, 0, 0, 0, 0];
        clobbered.extend([0xff, 0xd0]);
        assert_eq!(slot_of_last_call(&clobbered), None);
    }

    #[test]
    fn the_target_side_names_functions_an_indirect_call_can_enter() {
        use super::write_entries;
        let image = crate::image::Image {
            data: vec![0xc3; 0x10],
            segments: vec![crate::image::Segment { va: 0x1000, offset: 0, size: 0x10 }],
            functions: Vec::new(),
            pointers: vec![(0x8000, 0x300), (0x8008, 0x999), (0x8010, 0x200)],
            imports: Vec::new(),
            symbols: Vec::new(),
            metadata: crate::image_format::Metadata::default(),
        };
        let graph = CallGraph {
            callees: HashMap::new(),
            callers: HashMap::new(),
            unresolved: HashMap::new(),
            taken: HashMap::from([(0x200, vec![0x5010])]),
            slots_called: std::collections::HashSet::from([0x8000, 0x8010]),
            slots_read: std::collections::HashSet::from([0x8000]),
        };
        let dist = HashMap::from([(0x100, 0), (0x200, 1), (0x300, 2)]);
        let mut out = Vec::new();
        assert!(write_entries(&image, &graph, &dist, 0x100, &mut out).is_ok());
        let text = String::from_utf8_lossy(&out);
        assert!(text.contains("3 functions; 2 have their address taken"), "{text}");
        assert!(
            text.contains(
                "  entry 0x200 (1 hops to 0x100), loaded at 0x5010\n  entry 0x300 (2 hops to 0x100), held at 0x8000"
            ),
            "{text}"
        );
        let mut none = Vec::new();
        assert!(write_entries(&image, &graph, &HashMap::from([(0x100, 0)]), 0x100, &mut none).is_ok());
        assert!(String::from_utf8_lossy(&none).contains("none with its address taken"));
    }

    #[test]
    fn zero_paths_names_the_unfollowed_indirect_calls_nearest_first() {
        // 0x100 -> 0x200 -> 0x300; 0x200 and 0x300 have unresolved indirect calls.
        let graph = CallGraph {
            callees: HashMap::from([(0x100, vec![(0x110, 0x200)]), (0x200, vec![(0x210, 0x300)])]),
            callers: HashMap::new(),
            unresolved: HashMap::from([(0x200, vec![0x220]), (0x300, vec![0x320, 0x330]), (0x900, vec![0x910])]),
            taken: HashMap::new(),
            slots_called: std::collections::HashSet::new(),
            slots_read: std::collections::HashSet::new(),
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
        let mut none = Vec::new();
        assert!(write_unfollowed(&graph, 0x900, 2, &mut none).is_ok());
        assert_eq!(
            String::from_utf8_lossy(&none),
            "reachable from 0x900 within 1 hops: 1 functions; 1 indirect calls with no static target in 1 of them were not followed (dyn trait vtables, closures, function pointers), so a chain may still exist\n  unfollowed 0x910 in 0x900 (hop 0)\n"
        );
        let empty = CallGraph {
            callees: HashMap::new(),
            callers: HashMap::new(),
            unresolved: HashMap::new(),
            taken: HashMap::new(),
            slots_called: std::collections::HashSet::new(),
            slots_read: std::collections::HashSet::new(),
        };
        let mut quiet = Vec::new();
        assert!(write_unfollowed(&empty, 0x100, 3, &mut quiet).is_ok());
        assert_eq!(
            String::from_utf8_lossy(&quiet),
            "reachable from 0x100 within 2 hops: 1 functions; 0 indirect calls with no static target\n"
        );
        let mut zero = Vec::new();
        assert!(write_unfollowed(&graph, 0x100, 0, &mut zero).is_ok() && zero.is_empty());
    }
}
