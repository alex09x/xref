/*
 * XRef — Where a function stores a value it receives in an argument register
 * Copyright (c) 2026 Alexander Panasenko
 * Contact: alex@prod.codes
 * Author: https://prod.codes/about/
 * Project: https://github.com/alex09x/xref
 * SPDX-License-Identifier: MIT OR Apache-2.0
 */

//! Stores of an incoming argument. The places that may hold it are propagated over the function's
//! basic blocks (`flow::propagate`): the argument register, copies wide enough to keep the stored
//! width (callee-saved ones survive calls), and `[rsp+d]` slots it was spilled to, reloaded later.
//! Any write of a register drops it, a call drops the volatile ones and the slots below `rsp`, and
//! a write over a spill slot drops the slot. A value passed on in an argument register is followed
//! up to `depth` calls deeper; each (function, argument) pair is visited once, so recursion ends.
//! A stack object holding the value that is copied whole (`memcpy`, `rep movs`) is followed into
//! the copy's destination (`copy`, `pointer`).

use std::collections::{BTreeMap, HashMap, HashSet};
use std::ops::Range;

use iced_x86::{Instruction, InstructionInfoFactory, Mnemonic, OpKind, Register};

use super::copy::{Copied, CopyOp, Dest, copy_op};
use super::flow::{bit, function_code, high_byte, propagate, written};
use super::frame::{FrameUse, Held};
use super::pointer::{aliases_at, readers};
use super::scan::{Slot, VOLATILE};
use crate::expr::ABI_ARGS;
use crate::graph::call_target;
use crate::image::Image;
use crate::listing::is_call;
use crate::scan;

/// Functions walked for one argument at most, however wide the forwarding fans out.
const MAX_FUNCTIONS: usize = 64;
/// Calls a copied value's destination is followed into to find its readers.
const READER_DEPTH: usize = 2;

/// One hop of a forwarding path: the function the value was passed to, in which argument, and the
/// call that passed it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Step {
    pub function: u64,
    pub slot: Slot,
    pub call: u64,
}

#[derive(Clone)]
pub struct ArgStore {
    pub ip: u64,
    pub text: String,
    pub base: Register,
    pub indexed: bool,
    pub displacement: u64,
    /// The functions the value was passed on to, ending with the one that stores it; empty when
    /// the callee stores it itself.
    pub via: Vec<Step>,
    /// A frame store that `FrameUse::stack_object` accepts (never read back, under a frame
    /// address the function takes); false for spills, outgoing stack arguments and other stores.
    pub in_stack_object: bool,
    /// The stack object was copied whole, and the value with it.
    pub copy: Option<Copied>,
    /// Addressed off the frame: `rsp`, or a frame pointer (`rbp` after `mov rbp, rsp`).
    pub frame: bool,
}

impl ArgStore {
    /// A field of an object the function builds on its own stack, not a spill.
    pub const fn stack_object(&self) -> bool {
        self.in_stack_object
    }

    /// A store at `displacement` of an object that is not the stack frame.
    pub const fn at_object_offset(&self, displacement: u64) -> bool {
        self.object_field() && self.displacement == displacement
    }

    /// A field of an object: not the stack frame or a global, and no index register (an element
    /// of a buffer).
    pub const fn object_field(&self) -> bool {
        !self.frame
            && !self.indexed
            && !matches!(self.base, Register::RSP | Register::RBP | Register::RIP | Register::None)
    }
}

/// `width`-byte stores of the value the function starting at `callee` receives in `slot`, and of
/// the functions it is passed on to, up to `depth` calls deeper, nearest first.
pub fn arg_stores(image: &Image, callee: u64, slot: Slot, width: usize, depth: usize) -> Vec<ArgStore> {
    let mut seen: HashSet<(u64, Slot)> = HashSet::from([(callee, slot)]);
    let mut level: Vec<Hop> = vec![(callee, slot, Vec::new())];
    let mut found = Vec::new();
    for remaining in (0..=depth).rev() {
        let mut next = Vec::new();
        for (function, argument, via) in level {
            let Some((stores, passed)) = walk(image, function, argument, width, remaining > 0) else { continue };
            found.extend(stores.into_iter().map(|mut store| {
                store.via.clone_from(&via);
                store
            }));
            for ((target, slot), call) in passed {
                if seen.len() < MAX_FUNCTIONS && seen.insert((target, slot)) {
                    let mut path = via.clone();
                    path.push(Step { function: target, slot, call });
                    next.push((target, slot, path));
                }
            }
        }
        level = next;
    }
    found
}

/// A function to walk, the argument holding the value, and the path that reached it.
type Hop = (u64, Slot, Vec<Step>);

/// The stores of one function, and the (callee, argument) pairs it passes the value on to, with
/// the first call passing each.
type Walked = (Vec<ArgStore>, BTreeMap<(u64, Slot), u64>);

/// A copy of a stack object holding the value, seen while walking.
struct CopyEvent {
    store: u64,
    at: u64,
    op: CopyOp,
    size: u64,
    offset: u64,
    dest: Dest,
}

/// The stores in one function and the (callee, argument) pairs it passes the value on to.
fn walk(image: &Image, callee: u64, slot: Slot, width: usize, forward: bool) -> Option<Walked> {
    let start = slot.register().and_then(bit)?;
    let (f, code) = function_code(image, callee)?;
    let mut walk = Walk {
        image,
        f: &f,
        width,
        forward,
        stores: BTreeMap::new(),
        frame_slots: HashMap::new(),
        frame_use: FrameUse::default(),
        passed: BTreeMap::new(),
        copies: Vec::new(),
    };
    let mut factory = InstructionInfoFactory::new();
    propagate(image, &f, &code, 0, Held::entry(start), |ins, held| walk.transfer(ins, held, &mut factory));
    let Walk { mut stores, frame_slots, frame_use, passed, copies, .. } = walk;
    for (ip, store) in &mut stores {
        store.in_stack_object =
            frame_slots.get(ip).copied().flatten().is_some_and(|slot| frame_use.stack_object(slot, width as u64));
    }
    for event in copies {
        let Some(store) = stores.get_mut(&event.store).filter(|store| store.copy.is_none()) else { continue };
        let index = code.iter().position(|ins| ins.ip() == event.at).unwrap_or_default();
        let mut holders = aliases_at(image, &f, &code, index, event.op.destination);
        if event.op.call {
            holders =
                holders & !VOLATILE.iter().fold(0, |m, r| m | bit(*r).unwrap_or(0)) | bit(Register::RAX).unwrap_or(0);
        } else {
            // `rep movs` advances rdi and rsi and clears rcx.
            holders &=
                !(bit(Register::RDI).unwrap_or(0) | bit(Register::RSI).unwrap_or(0) | bit(Register::RCX).unwrap_or(0));
        }
        let found = readers(image, &f, &code, index + 1, holders, event.offset, width, READER_DEPTH);
        store.in_stack_object = true;
        store.copy = Some(Copied {
            ip: event.at,
            how: event.op.how,
            size: event.size,
            offset: event.offset,
            dest: event.dest,
            readers: found,
        });
    }
    Some((stores.into_values().collect(), passed))
}

struct Walk<'a> {
    image: &'a Image,
    f: &'a Range<u64>,
    width: usize,
    forward: bool,
    stores: BTreeMap<u64, ArgStore>,
    /// The entry-relative slot of each unindexed `[rsp+d]` store, when every path agrees on it.
    frame_slots: HashMap<u64, Option<i64>>,
    frame_use: FrameUse,
    passed: BTreeMap<(u64, Slot), u64>,
    copies: Vec<CopyEvent>,
}

impl Walk<'_> {
    /// A register that holds the value at `width` bytes or more (never a high byte).
    fn holds(&self, register: Register, held: &Held) -> bool {
        !high_byte(register) && register.size() >= self.width && bit(register).is_some_and(|b| (held.regs & b) != 0)
    }

    fn transfer(&mut self, ins: &Instruction, held: &mut Held, factory: &mut InstructionInfoFactory) {
        self.frame_use.record(ins, held, factory);
        self.copied(ins, held);
        if is_call(ins, self.f) {
            if self.forward
                && let Some(target) = call_target(self.image, ins)
            {
                for (index, argument) in ABI_ARGS.iter().enumerate() {
                    if self.holds(*argument, held) {
                        self.passed.entry((target, Slot::Reg(index))).or_insert_with(|| ins.ip());
                    }
                }
            }
            for volatile in VOLATILE {
                held.regs &= !bit(volatile).unwrap_or(0);
                held.forget(volatile);
            }
            held.after_call();
            return;
        }
        let memory = ins.op_count() > 0 && ins.op0_kind() == OpKind::Memory;
        if memory
            && ins.mnemonic() == Mnemonic::Mov
            && ins.op1_kind() == OpKind::Register
            && self.holds(ins.op1_register(), held)
            && ins.memory_size().size() == self.width
        {
            self.stores.entry(ins.ip()).or_insert_with(|| ArgStore {
                ip: ins.ip(),
                text: scan::format(ins),
                base: ins.memory_base().full_register(),
                indexed: ins.memory_index() != Register::None,
                displacement: ins.memory_displacement64(),
                via: Vec::new(),
                in_stack_object: false,
                copy: None,
                frame: false,
            });
            if ins.memory_base() == Register::RSP || held.on_frame(ins) {
                if let Some(store) = self.stores.get_mut(&ins.ip()) {
                    store.frame = true;
                }
                let slot = held.slot(ins).filter(|_| ins.memory_index() == Register::None);
                let known = self.frame_slots.entry(ins.ip()).or_insert(slot);
                if *known != slot {
                    *known = None;
                }
            }
        }
        let gained = self.gained(ins, held);
        let learned = held.learned(ins);
        let restored = restored_rsp(ins, held);
        self.frame_writes(ins, held, memory);
        for register in written(factory, ins) {
            if register != Register::RSP {
                held.regs &= !bit(register).unwrap_or(0);
                held.forget(register);
            }
        }
        if let Some(Restored(frame)) = restored {
            held.frame = frame;
        } else {
            self.frame_moves(ins, held, factory);
        }
        held.regs |= gained;
        held.learn(learned);
    }

    /// A whole-object copy whose source is a frame address and whose size is a constant: each
    /// spill slot of the value inside the copied range moves with it.
    fn copied(&mut self, ins: &Instruction, held: &Held) {
        let Some(op) = copy_op(self.image, ins) else { return };
        let (Some(&source), Some(&count)) = (held.addrs.get(&op.source), held.consts.get(&op.count)) else { return };
        let Some(size) = count.checked_mul(op.unit) else { return };
        let end = source.saturating_add_unsigned(size);
        let dest = held.params.get(&op.destination).map_or(Dest::Computed, |index| Dest::Param(*index));
        for &slot in held.spills.range(source..end).map(|(slot, _)| slot) {
            let Some(store) = self.frame_slots.iter().find(|(_, at)| **at == Some(slot)).map(|(ip, _)| *ip) else {
                continue;
            };
            let op = CopyOp { how: op.how.clone(), ..op };
            self.copies.push(CopyEvent { store, at: ins.ip(), op, size, offset: slot.abs_diff(source), dest });
        }
    }

    /// The register `ins` loads the value into: a wide-enough copy of a holding register, or a
    /// reload of a spill slot.
    fn gained(&self, ins: &Instruction, held: &Held) -> u16 {
        if !matches!(ins.mnemonic(), Mnemonic::Mov | Mnemonic::Movzx | Mnemonic::Movsx | Mnemonic::Movsxd)
            || ins.op0_kind() != OpKind::Register
            || high_byte(ins.op0_register())
            || ins.op0_register().size() < self.width
        {
            return 0;
        }
        let source = match ins.op1_kind() {
            OpKind::Register => self.holds(ins.op1_register(), held),
            OpKind::Memory => {
                held.on_frame(ins)
                    && ins.memory_size().size() >= self.width
                    && held.slot(ins).is_some_and(|slot| held.spills.contains_key(&slot))
            }
            _ => false,
        };
        if source { bit(ins.op0_register()).unwrap_or(0) } else { 0 }
    }

    /// Stack writes: a spill of the value adds a slot, any other write over a slot drops it.
    fn frame_writes(&self, ins: &Instruction, held: &mut Held, memory: bool) {
        if matches!(ins.op0_kind(), OpKind::MemoryESDI | OpKind::MemoryESEDI | OpKind::MemoryESRDI) {
            // `stos`/`movs` may write the frame.
            held.spills.clear();
            return;
        }
        if !memory || (ins.memory_base() != Register::RSP && held.frame_base(ins.memory_base()).is_none()) {
            return;
        }
        if ins.memory_index() != Register::None {
            held.spills.clear();
            return;
        }
        let Some(slot) = held.slot(ins) else { return };
        let size = ins.memory_size().size().max(1) as u64;
        held.overwrite(slot, size);
        if ins.mnemonic() == Mnemonic::Mov && ins.op1_kind() == OpKind::Register && self.holds(ins.op1_register(), held)
        {
            held.spills.insert(slot, size);
        }
    }

    /// Moves of `rsp`: `push`/`pop` (a pushed holding register is a spill, a pop of one a
    /// reload), `sub`/`add rsp, imm`; any other write (`pop rsp`, `and rsp`, `leave`) loses the frame.
    fn frame_moves(&self, ins: &Instruction, held: &mut Held, factory: &mut InstructionInfoFactory) {
        let step = i64::from(ins.stack_pointer_increment());
        let immediate = ins.op_count() == 2
            && ins.op0_kind() == OpKind::Register
            && ins.op0_register() == Register::RSP
            && matches!(ins.op1_kind(), OpKind::Immediate8to64 | OpKind::Immediate32to64);
        let pops_rsp = ins.op_count() == 1
            && ins.op0_kind() == OpKind::Register
            && ins.op0_register().full_register() == Register::RSP;
        let moved = match ins.mnemonic() {
            Mnemonic::Sub if immediate => ins.immediate(1).cast_signed().checked_neg(),
            Mnemonic::Add if immediate => Some(ins.immediate(1).cast_signed()),
            Mnemonic::Push | Mnemonic::Pop if step != 0 && !pops_rsp => Some(step),
            _ if pops_rsp || written(factory, ins).contains(&Register::RSP) => None,
            _ => return,
        };
        let Some(after) = held.frame.zip(moved).and_then(|(frame, moved)| frame.checked_add(moved)) else {
            held.lose_frame();
            return;
        };
        let before = held.frame.unwrap_or_default();
        match ins.mnemonic() {
            Mnemonic::Push => {
                held.overwrite(after, step.unsigned_abs());
                if ins.op0_kind() == OpKind::Register && step == -8 && self.holds(ins.op0_register(), held) {
                    held.spills.insert(after, 8);
                }
            }
            Mnemonic::Pop if ins.op0_kind() == OpKind::Register && step == 8 && held.spills.contains_key(&before) => {
                held.regs |= bit(ins.op0_register()).unwrap_or(0);
            }
            _ => {}
        }
        held.frame = Some(after);
    }
}

/// `rsp` set back from a frame pointer: the frame it gets, `None` when the pointer's frame address is
/// unknown.
struct Restored(Option<i64>);

/// `leave` (`mov rsp, rbp; pop rbp`) or `mov rsp, reg`, read before `ins` writes anything.
fn restored_rsp(ins: &Instruction, held: &Held) -> Option<Restored> {
    match ins.mnemonic() {
        Mnemonic::Leave => Some(Restored(held.addrs.get(&Register::RBP).and_then(|rbp| rbp.checked_add(8)))),
        Mnemonic::Mov
            if ins.op_count() == 2
                && ins.op0_kind() == OpKind::Register
                && ins.op0_register() == Register::RSP
                && ins.op1_kind() == OpKind::Register =>
        {
            Some(Restored(held.addrs.get(&ins.op1_register().full_register()).copied()))
        }
        _ => None,
    }
}
