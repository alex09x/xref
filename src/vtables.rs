/*
 * XRef — Indirect calls through constant records chosen by branch (vtables)
 * Copyright (c) 2026 Alexander Panasenko
 * Contact: alex@prod.codes
 * Author: https://prod.codes/about/
 * Project: https://github.com/alex09x/xref
 * SPDX-License-Identifier: MIT OR Apache-2.0
 */

//! A dispatcher picks one of several constant records (`lea rax, [rip + vtable_N]` on each
//! branch) and calls a function pointer at a fixed offset of it: `call [rax + 0x18]`, `mov rcx,
//! [rax + 0x18]; call rcx`, or the same as a tail jump. In a PIE the pointer is 0 in the file and
//! filled by an `R_X86_64_RELATIVE` relocation, which `Image::slot` resolves. The registers (and
//! `[rsp+d]` slots) that hold such an address on every path are propagated over the function's
//! blocks; at the call, each address gives a target in code, with the condition of the branch
//! that set it when that is a plain `cmp x, imm; je` (`condition`).

mod condition;
mod table;

use std::collections::{BTreeMap, BTreeSet};
use std::ops::Range;

use iced_x86::{FlowControl, Instruction, InstructionInfoFactory, Mnemonic, OpAccess, OpKind, Register};

use crate::callargs::flow::{Join, function_code, settled, targets, written};
use crate::callargs::scan::VOLATILE;
use crate::image::{Image, Slot};
use crate::listing::is_call;
use crate::tables::tables;
pub use table::table;

/// One possible target of an indirect call.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Target {
    /// The record (`vtable_N`) and the slot read from it.
    pub record: u64,
    pub slot: u64,
    pub function: u64,
    /// Where the record's address was taken.
    pub set_at: u64,
    /// `edi == 3` when that happens on the taken side of a `cmp edi, 3; je`.
    pub when: Option<String>,
}

/// An indirect call or tail jump whose pointer comes from one of known records.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Dispatch {
    pub ip: u64,
    /// The offset of the function pointer in the records (`[rax - 8]` is -8).
    pub offset: i64,
    pub targets: Vec<Target>,
}

/// Record addresses with where each was taken: `(record, set_at)`.
type Picks = BTreeSet<(u64, u64)>;

/// Per indirect call: the pointer's offset in the records, and the records it may read.
type Found = BTreeMap<u64, (i64, Picks)>;

/// Where record addresses are: sets per register and `[rsp+d]` slot (8 bytes each), and
/// function pointers loaded from them (`mov rcx, [rax + 0x18]`).
#[derive(Clone, Default, PartialEq, Eq)]
struct Records {
    regs: BTreeMap<Register, Picks>,
    /// `rsp` relative to its entry value, while every path agrees on it.
    frame: Option<i64>,
    slots: BTreeMap<i64, Picks>,
    loaded: BTreeMap<Register, (Picks, i64)>,
}

impl Join for Records {
    /// A register (or slot) holds a record address after a join only when every path set it to
    /// one: then its records are those of all paths. A path that leaves it unknown drops it.
    fn join(&mut self, other: &Self) -> bool {
        let before = self.clone();
        self.regs.retain(|register, set| {
            other.regs.get(register).is_some_and(|more| {
                set.extend(more);
                true
            })
        });
        self.slots.retain(|slot, set| {
            other.slots.get(slot).is_some_and(|more| {
                set.extend(more);
                true
            })
        });
        self.loaded.retain(|register, (set, offset)| {
            other.loaded.get(register).is_some_and(|(more, at)| {
                set.extend(more);
                at == offset
            })
        });
        if self.frame != other.frame {
            self.frame = None;
            self.slots.clear();
        }
        *self != before
    }
}

/// The function and its jump tables, for the steps.
struct Context<'a> {
    image: &'a Image,
    f: &'a Range<u64>,
    /// Instructions near a jump table's dispatch: their indirect jump is a `switch`, no call.
    switches: Vec<u64>,
}

impl Context<'_> {
    fn switch(&self, ins: &Instruction) -> bool {
        self.switches.iter().any(|dispatch| *dispatch <= ins.ip() && ins.ip() - dispatch <= 32)
    }

    /// A call, a tail jump, or an indirect jump that is no `switch`.
    fn calls(&self, ins: &Instruction) -> bool {
        is_call(ins, self.f) || (ins.flow_control() == FlowControl::IndirectBranch && !self.switch(ins))
    }
}

/// The indirect calls and tail jumps of the function starting at `start` that read a function
/// pointer out of constant records, in address order.
pub fn dispatches(image: &Image, start: u64) -> Vec<Dispatch> {
    let Some((f, code)) = function_code(image, start) else { return Vec::new() };
    let found_tables = tables(image, &f);
    let context = Context { image, f: &f, switches: found_tables.iter().map(|t| t.dispatch).collect() };
    let arms: BTreeSet<u64> = found_tables.iter().flat_map(|t| t.arms.iter().copied()).collect();
    let mut found: Found = BTreeMap::new();
    let mut factory = InstructionInfoFactory::new();
    let entry = Records { frame: Some(0), ..Records::default() };
    // The sets only settle at the fixpoint: calls are recorded in the settled pass.
    settled(image, &f, &code, 0, entry, |ins, records, record| {
        step(&context, ins, records, &mut factory, record.then_some(&mut found));
    });
    let leaders = targets(image, &f, &code);
    found
        .into_iter()
        .filter_map(|(ip, (offset, set))| {
            let targets: Vec<Target> = set
                .into_iter()
                .filter_map(|(record, set_at)| {
                    let slot = record.checked_add_signed(offset)?;
                    let function = match image.slot(slot)? {
                        Slot::Pointer(target) => target,
                        Slot::Import(_) => return None,
                    };
                    // A relocated pointer to data (a string, another record) is no call target.
                    executable(image, function).then(|| Target {
                        record,
                        slot,
                        function,
                        set_at,
                        when: condition::condition(&code, &leaders, &arms, set_at),
                    })
                })
                .collect();
            (!targets.is_empty()).then_some(Dispatch { ip, offset, targets })
        })
        .collect()
}

/// `address` lies in a segment that is (`code`) or is not executable; any address when the
/// image has no load segments (synthetic images).
fn in_segment(image: &Image, address: u64, code: bool) -> bool {
    image.metadata.load_segments.is_empty()
        || image.metadata.load_segments.iter().any(|segment| {
            segment.executable == code
                && address >= segment.va
                && address < segment.va.saturating_add(segment.file_size)
        })
}

fn executable(image: &Image, address: u64) -> bool {
    in_segment(image, address, true)
}

/// A constant address in a data segment that is not code: where records live.
fn record_address(image: &Image, ins: &Instruction) -> Option<u64> {
    if ins.mnemonic() != Mnemonic::Lea || !ins.is_ip_rel_memory_operand() || ins.op0_register().size() != 8 {
        return None;
    }
    let address = ins.ip_rel_memory_address();
    in_segment(image, address, false).then_some(address)
}

fn step(
    context: &Context<'_>,
    ins: &Instruction,
    records: &mut Records,
    factory: &mut InstructionInfoFactory,
    found: Option<&mut Found>,
) {
    if context.calls(ins) {
        let pointer = match ins.op0_kind() {
            // `call [rax + 0x18]`, `jmp [rax + 0x18]`
            OpKind::Memory if ins.memory_index() == Register::None && !ins.is_ip_rel_memory_operand() => records
                .regs
                .get(&ins.memory_base().full_register())
                .map(|set| (ins.memory_displacement64().cast_signed(), set.clone())),
            // `mov rcx, [rax + 0x18]; call rcx`
            OpKind::Register => {
                records.loaded.get(&ins.op0_register().full_register()).map(|(set, d)| (*d, set.clone()))
            }
            _ => None,
        };
        if let (Some((offset, set)), Some(found)) = (pointer, found) {
            let entry = found.entry(ins.ip()).or_insert_with(|| (offset, BTreeSet::new()));
            if entry.0 == offset {
                entry.1.extend(set);
            }
        }
        for volatile in VOLATILE {
            records.regs.remove(&volatile);
            records.loaded.remove(&volatile);
        }
        // The callee's frame runs below `rsp`: slots there are gone.
        match records.frame {
            Some(frame) => records.slots.retain(|slot, _| *slot >= frame),
            None => records.slots.clear(),
        }
        return;
    }
    let gained = gained(context.image, ins, records);
    let rsp_written = written(factory, ins).contains(&Register::RSP);
    stack(ins, records, factory, rsp_written);
    for register in written(factory, ins) {
        if register != Register::RSP {
            records.regs.remove(&register);
            records.loaded.remove(&register);
        }
    }
    match gained {
        Some(Gained::Records(register, set)) => {
            records.regs.insert(register, set);
        }
        Some(Gained::Loaded(register, set, offset)) => {
            records.loaded.insert(register, (set, offset));
        }
        None => {}
    }
}

enum Gained {
    Records(Register, Picks),
    Loaded(Register, Picks, i64),
}

/// What `ins` puts in its destination register: a record address, a copy of record addresses, a
/// reload of a slot holding them, or a function pointer loaded out of them.
fn gained(image: &Image, ins: &Instruction, records: &Records) -> Option<Gained> {
    if ins.op_count() != 2 || ins.op0_kind() != OpKind::Register || ins.op0_register().size() != 8 {
        return None;
    }
    let destination = ins.op0_register().full_register();
    if destination == Register::RSP {
        return None;
    }
    if let Some(address) = record_address(image, ins) {
        return Some(Gained::Records(destination, BTreeSet::from([(address, ins.ip())])));
    }
    if ins.mnemonic() != Mnemonic::Mov {
        return None;
    }
    match ins.op1_kind() {
        OpKind::Register => {
            records.regs.get(&ins.op1_register().full_register()).cloned().map(|set| Gained::Records(destination, set))
        }
        OpKind::Memory if ins.memory_index() == Register::None && ins.memory_size().size() == 8 => {
            let base = ins.memory_base().full_register();
            let displacement = ins.memory_displacement64().cast_signed();
            if base == Register::RSP {
                let slot = records.frame?.checked_add(displacement)?;
                return records.slots.get(&slot).cloned().map(|set| Gained::Records(destination, set));
            }
            records.regs.get(&base).cloned().map(|set| Gained::Loaded(destination, set, displacement))
        }
        _ => None,
    }
}

/// `[rsp+d]` slots and `rsp` itself. Any write overlapping a slot empties it (wide stores,
/// `push`, partial writes); an unplaceable write off `rsp` or a string store empties all. An
/// 8-byte `mov [rsp+d], reg` of record addresses fills one. `push`/`pop reg`/`sub`/`add rsp, imm`
/// move the frame; any other `rsp` write (`leave`, `pop rsp`, `and rsp`, `xchg`) loses it.
fn stack(ins: &Instruction, records: &mut Records, factory: &mut InstructionInfoFactory, rsp_written: bool) {
    if matches!(ins.op0_kind(), OpKind::MemoryESDI | OpKind::MemoryESEDI | OpKind::MemoryESRDI) {
        records.slots.clear();
    }
    for used in factory.info(ins).used_memory() {
        if used.base() != Register::RSP
            || !matches!(
                used.access(),
                OpAccess::Write | OpAccess::CondWrite | OpAccess::ReadWrite | OpAccess::ReadCondWrite
            )
        {
            continue;
        }
        let at = records
            .frame
            .filter(|_| used.index() == Register::None)
            .and_then(|frame| frame.checked_add(used.displacement().cast_signed()));
        let Some(at) = at else {
            records.slots.clear();
            continue;
        };
        let end = at.saturating_add_unsigned(used.memory_size().size().max(1) as u64);
        records.slots.retain(|slot, _| slot.saturating_add(8) <= at || *slot >= end);
    }
    if ins.mnemonic() == Mnemonic::Mov
        && ins.op0_kind() == OpKind::Memory
        && ins.memory_base() == Register::RSP
        && ins.memory_index() == Register::None
        && ins.op1_kind() == OpKind::Register
        && ins.op1_register().size() == 8
        && let Some(slot) = records.frame.and_then(|frame| frame.checked_add(ins.memory_displacement64().cast_signed()))
        && let Some(set) = records.regs.get(&ins.op1_register().full_register())
    {
        records.slots.insert(slot, set.clone());
    }
    if !rsp_written {
        return;
    }
    let rsp_immediate = ins.op_count() == 2
        && ins.op0_kind() == OpKind::Register
        && ins.op0_register() == Register::RSP
        && matches!(ins.op1_kind(), OpKind::Immediate8to64 | OpKind::Immediate32to64);
    let pops_rsp = ins.op_count() == 1 && ins.op0_kind() == OpKind::Register && ins.op0_register() == Register::RSP;
    let moved = match ins.mnemonic() {
        Mnemonic::Sub if rsp_immediate => ins.immediate(1).cast_signed().checked_neg(),
        Mnemonic::Add if rsp_immediate => Some(ins.immediate(1).cast_signed()),
        Mnemonic::Push | Mnemonic::Pop if !pops_rsp && ins.stack_pointer_increment() != 0 => {
            Some(i64::from(ins.stack_pointer_increment()))
        }
        _ => None,
    };
    records.frame = records.frame.zip(moved).and_then(|(frame, moved)| frame.checked_add(moved));
    if records.frame.is_none() {
        records.slots.clear();
    }
}

/// The targets as `0x1100 (when edi == 3), 0x1120, ...` for `c` and `calls`.
pub fn describe(dispatch: &Dispatch) -> String {
    let mut targets: Vec<String> = Vec::new();
    for t in &dispatch.targets {
        let text = t
            .when
            .as_ref()
            .map_or_else(|| format!("{:#x}", t.function), |when| format!("{:#x} (when {when})", t.function));
        // Several records may share a method (a default implementation): list it once.
        if !targets.contains(&text) {
            targets.push(text);
        }
    }
    let mut records: Vec<u64> = dispatch.targets.iter().map(|t| t.record).collect();
    records.dedup();
    let sign = if dispatch.offset < 0 { "-" } else { "+" };
    let offset = format!("{sign}{:#x}", dispatch.offset.unsigned_abs());
    let tables = if records.len() == 1 {
        format!("via record {:#x}{offset}", records[0])
    } else {
        format!("via {} records {offset}", records.len())
    };
    format!("{{{}}} {tables}", targets.join(", "))
}

#[cfg(test)]
mod tests;
