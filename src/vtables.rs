/*
 * XRef — Indirect calls through constant records chosen by branch (vtables)
 * Copyright (c) 2026 Alexander Panasenko
 * Contact: alex@prod.codes
 * Author: https://prod.codes/about/
 * Project: https://github.com/alex09x/xref
 * SPDX-License-Identifier: MIT OR Apache-2.0
 */

//! A dispatcher picks one of several constant records (`lea rax, [rip + vtable_N]` on each
//! branch) and calls a function pointer at a fixed offset of it: `call [rax + 0x18]`, or
//! `mov rcx, [rax + 0x18]; call rcx`. In a PIE the pointer is 0 in the file and filled by an
//! `R_X86_64_RELATIVE` relocation, which `Image::slot` resolves. The registers (and `[rsp+d]`
//! slots) that may hold such an address are propagated over the function's blocks; at the call,
//! each address gives a target, with the condition of the branch that set it when it is a plain
//! `cmp x, imm; je`.

use std::collections::{BTreeMap, BTreeSet};
use std::ops::Range;

use iced_x86::{ConditionCode, FlowControl, Instruction, InstructionInfoFactory, Mnemonic, OpKind, Register};

use crate::callargs::flow::{Join, function_code, settled, targets, written};
use crate::callargs::scan::VOLATILE;
use crate::image::{Image, Slot};
use crate::listing::is_call;
use crate::scan;

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
    /// The offset of the function pointer in the records.
    pub offset: u64,
    pub targets: Vec<Target>,
}

/// Where record addresses may be: `(record, set_at)` sets per register and frame slot, and
/// function pointers loaded from them (`mov rcx, [rax + 0x18]`).
#[derive(Clone, Default, PartialEq, Eq)]
struct Records {
    regs: BTreeMap<Register, BTreeSet<(u64, u64)>>,
    /// `rsp` relative to its entry value, while every path agrees on it.
    frame: Option<i64>,
    slots: BTreeMap<i64, BTreeSet<(u64, u64)>>,
    loaded: BTreeMap<Register, (BTreeSet<(u64, u64)>, u64)>,
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
        }
        *self != before
    }
}

/// Record addresses with where each was taken: `(record, set_at)`.
type Picks = BTreeSet<(u64, u64)>;

/// Per indirect call: the pointer's offset in the records, and the records it may read.
type Found = BTreeMap<u64, (u64, Picks)>;

/// The indirect calls of the function starting at `start` that read a function pointer out of
/// constant records, in address order.
pub fn dispatches(image: &Image, start: u64) -> Vec<Dispatch> {
    let Some((f, code)) = function_code(image, start) else { return Vec::new() };
    let mut found: Found = BTreeMap::new();
    let mut factory = InstructionInfoFactory::new();
    let entry = Records { frame: Some(0), ..Records::default() };
    // The sets only settle at the fixpoint: calls are recorded in the settled pass.
    settled(image, &f, &code, 0, entry, |ins, records, record| {
        step(image, &f, ins, records, &mut factory, record.then_some(&mut found));
    });
    let leaders = targets(image, &f, &code);
    found
        .into_iter()
        .filter_map(|(ip, (offset, set))| {
            let targets: Vec<Target> = set
                .into_iter()
                .filter_map(|(record, set_at)| {
                    let slot = record.checked_add(offset)?;
                    let target = match image.slot(slot)? {
                        Slot::Pointer(target) => target,
                        Slot::Import(_) => return None,
                    };
                    Some(Target { record, slot, function: target, set_at, when: condition(&code, &leaders, set_at) })
                })
                .collect();
            (!targets.is_empty()).then_some(Dispatch { ip, offset, targets })
        })
        .collect()
}

/// A constant address in a data segment that is not code: where records live.
fn record_address(image: &Image, ins: &Instruction) -> Option<u64> {
    if ins.mnemonic() != Mnemonic::Lea || !ins.is_ip_rel_memory_operand() || ins.op0_register().size() != 8 {
        return None;
    }
    let address = ins.ip_rel_memory_address();
    let data = image.metadata.load_segments.iter().any(|segment| {
        !segment.executable && address >= segment.va && address < segment.va.saturating_add(segment.file_size)
    });
    (data || image.metadata.load_segments.is_empty()).then_some(address)
}

fn step(
    image: &Image,
    f: &Range<u64>,
    ins: &Instruction,
    records: &mut Records,
    factory: &mut InstructionInfoFactory,
    found: Option<&mut Found>,
) {
    if is_call(ins, f) || ins.flow_control() == FlowControl::IndirectCall {
        let pointer = match ins.op0_kind() {
            // `call [rax + 0x18]`
            OpKind::Memory if ins.memory_index() == Register::None => records
                .regs
                .get(&ins.memory_base().full_register())
                .map(|set| (ins.memory_displacement64(), set.clone())),
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
        return;
    }
    let gained = gained(image, ins, records);
    stack(ins, records);
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
    Records(Register, BTreeSet<(u64, u64)>),
    Loaded(Register, BTreeSet<(u64, u64)>, u64),
}

/// What `ins` puts in its destination register: a record address, a copy of record addresses, a
/// reload of a slot holding them, or a function pointer loaded out of them.
fn gained(image: &Image, ins: &Instruction, records: &Records) -> Option<Gained> {
    if ins.op_count() != 2 || ins.op0_kind() != OpKind::Register || ins.op0_register().size() != 8 {
        return None;
    }
    let destination = ins.op0_register().full_register();
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
        OpKind::Memory if ins.memory_index() == Register::None => {
            let base = ins.memory_base().full_register();
            if base == Register::RSP {
                let slot = records.frame?.checked_add(ins.memory_displacement64().cast_signed())?;
                return records.slots.get(&slot).cloned().map(|set| Gained::Records(destination, set));
            }
            records.regs.get(&base).cloned().map(|set| Gained::Loaded(destination, set, ins.memory_displacement64()))
        }
        _ => None,
    }
}

/// `[rsp+d]` slots: a store of record addresses fills one, any other write over it empties it;
/// `push`/`pop`/`sub`/`add rsp, imm` move the frame, any other `rsp` write loses it.
fn stack(ins: &Instruction, records: &mut Records) {
    if ins.op_count() > 0 && ins.op0_kind() == OpKind::Memory && ins.memory_base() == Register::RSP {
        let slot = records
            .frame
            .filter(|_| ins.memory_index() == Register::None)
            .and_then(|frame| frame.checked_add(ins.memory_displacement64().cast_signed()));
        match slot {
            Some(slot) => {
                records.slots.remove(&slot);
                if ins.mnemonic() == Mnemonic::Mov
                    && ins.op1_kind() == OpKind::Register
                    && let Some(set) = records.regs.get(&ins.op1_register().full_register())
                {
                    records.slots.insert(slot, set.clone());
                }
            }
            None => records.slots.clear(),
        }
    }
    let rsp_immediate = ins.op_count() == 2
        && ins.op0_kind() == OpKind::Register
        && ins.op0_register() == Register::RSP
        && matches!(ins.op1_kind(), OpKind::Immediate8to64 | OpKind::Immediate32to64);
    let moved = match ins.mnemonic() {
        Mnemonic::Sub if rsp_immediate => ins.immediate(1).cast_signed().checked_neg(),
        Mnemonic::Add if rsp_immediate => Some(ins.immediate(1).cast_signed()),
        Mnemonic::Push | Mnemonic::Pop if ins.stack_pointer_increment() != 0 => {
            Some(i64::from(ins.stack_pointer_increment()))
        }
        _ if ins.op_count() > 0 && ins.op0_kind() == OpKind::Register && ins.op0_register() == Register::RSP => None,
        _ => return,
    };
    records.frame = records.frame.zip(moved).and_then(|(frame, moved)| frame.checked_add(moved));
}

/// `x == imm` when the block holding `set_at` is entered only through the taken side of a
/// `cmp x, imm; je`, or by falling through a `cmp x, imm; jne`.
fn condition(code: &[Instruction], leaders: &BTreeSet<u64>, set_at: u64) -> Option<String> {
    let at = code.iter().position(|ins| ins.ip() == set_at)?;
    let mut first = at;
    while first > 0 && !leaders.contains(&code[first].ip()) && code[first - 1].flow_control() == FlowControl::Next {
        first -= 1;
    }
    let start = code[first].ip();
    let branches: Vec<usize> = (0..code.len())
        .filter(|&i| code[i].flow_control() == FlowControl::ConditionalBranch && code[i].near_branch_target() == start)
        .collect();
    let falls = first > 0 && code[first - 1].flow_control() == FlowControl::ConditionalBranch;
    let jumps_in = code
        .iter()
        .any(|ins| ins.near_branch_target() == start && matches!(ins.flow_control(), FlowControl::UnconditionalBranch));
    let comparison = |branch: usize| {
        let cmp = code.get(branch.checked_sub(1)?)?;
        (cmp.mnemonic() == Mnemonic::Cmp
            && matches!(
                cmp.op1_kind(),
                OpKind::Immediate8to32
                    | OpKind::Immediate32
                    | OpKind::Immediate8
                    | OpKind::Immediate8to64
                    | OpKind::Immediate32to64
                    | OpKind::Immediate16
                    | OpKind::Immediate8to16
            ))
        .then(|| scan::format(cmp))
        .and_then(|text| text.strip_prefix("cmp ").map(str::to_owned))
        .and_then(|text| text.split_once(", ").map(|(a, b)| format!("{a} == {b}")))
    };
    match (branches.as_slice(), falls, jumps_in) {
        // Only the taken side of one `je` leads here.
        ([branch], false, false) if code[*branch].condition_code() == ConditionCode::e => comparison(*branch),
        // Only the fallthrough of a `jne` leads here.
        ([], true, false) if code[first - 1].condition_code() == ConditionCode::ne => comparison(first - 1),
        _ => None,
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
    let tables = if records.len() == 1 {
        format!("via record {:#x}+{:#x}", records[0], dispatch.offset)
    } else {
        format!("via {} records +{:#x}", records.len(), dispatch.offset)
    };
    format!("{{{}}} {tables}", targets.join(", "))
}

/// `xref table ADDR --stride N --count K`: `K` records of `N` bytes from `ADDR`, each 8-byte field
/// with what fills it: a relocated pointer (to a function, an import, data), or the file's bytes.
pub fn table(
    image: &Image,
    address: u64,
    stride: u64,
    count: u64,
    out: &mut dyn std::io::Write,
) -> crate::commands::Res {
    if stride == 0 || !stride.is_multiple_of(8) {
        return Err("--stride must be a positive multiple of 8".into());
    }
    for index in 0..count {
        let record =
            address.checked_add(index.checked_mul(stride).ok_or("table too large")?).ok_or("table too large")?;
        writeln!(out, "record {index} at {record:#x}")?;
        for offset in (0..stride).step_by(8) {
            let place = record + offset;
            let filled = match image.slot(place) {
                Some(Slot::Pointer(target)) => format!("-> {}", crate::listing::describe_code(image, target)),
                Some(Slot::Import(name)) => format!("-> {name} (import)"),
                None => image.read(place, 8).map_or_else(
                    || "(outside the image)".to_owned(),
                    |bytes| format!("{:#x}", u64::from_le_bytes(bytes.try_into().unwrap_or_default())),
                ),
            };
            writeln!(out, "  +{offset:#04x}  {filled}")?;
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests;
