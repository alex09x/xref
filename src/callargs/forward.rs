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

use std::collections::{BTreeMap, HashSet};
use std::ops::Range;

use iced_x86::{FlowControl, Instruction, InstructionInfoFactory, Mnemonic, OpKind, Register};

mod stack;

use super::copy::{Copied, CopyOp, Dest, copy_op};
use super::flow::{bit, function_code, high_byte, settled, written};
use super::frame::{FrameUse, Held};
use super::pointer::{Field, aliases_at, readers};
use super::scan::{STACK_SLOTS, Slot, VOLATILE};
use crate::expr::ABI_ARGS;
use crate::graph::call_target;
use crate::image::Image;
use crate::listing::is_call;
use crate::scan;
use stack::{Restored, restored_rsp};

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

    /// A field of an object: not the stack frame (`rsp`, or a frame pointer such as `rbp` after
    /// `mov rbp, rsp`; `rbp` holding anything else is an ordinary base), not a global, and no
    /// index register (an element of a buffer).
    pub const fn object_field(&self) -> bool {
        !self.frame && !self.indexed && !matches!(self.base, Register::RSP | Register::RIP | Register::None)
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
    /// Spill slots of the value inside the copied range, entry-relative.
    slots: Vec<i64>,
    /// The copied range starts here, entry-relative.
    source: i64,
    at: u64,
    op: CopyOp,
    size: u64,
    dest: Dest,
    /// A tail jump to the copy routine: nothing runs after it in this function.
    tail: bool,
}

/// The stores in one function and the (callee, argument) pairs it passes the value on to.
fn walk(image: &Image, callee: u64, slot: Slot, width: usize, forward: bool) -> Option<Walked> {
    // A register argument, or `stack{k}`: `[rsp + 8 + 8k]` at entry, above the return address.
    let start = match slot {
        Slot::Reg(_) => Held::entry(slot.register().and_then(bit)?),
        Slot::Stack(k) => {
            let mut held = Held::entry(0);
            held.spills.insert(8 * (i64::try_from(k).ok()? + 1), 8);
            held
        }
    };
    let (f, code) = function_code(image, callee)?;
    let mut walk = Walk {
        image,
        f: &f,
        width,
        forward,
        stores: BTreeMap::new(),
        frame_slots: BTreeMap::new(),
        frame_use: FrameUse::default(),
        passed: BTreeMap::new(),
        copies: Vec::new(),
    };
    let mut factory = InstructionInfoFactory::new();
    // Must-facts (frame addresses, constants, parameters) are only final after the fixpoint, so
    // stores, copies and forwarded calls are recorded in the settled pass.
    settled(image, &f, &code, 0, start, |ins, held, record| {
        walk.transfer(ins, held, &mut factory, record);
    });
    let Walk { mut stores, frame_slots, frame_use, passed, copies, .. } = walk;
    // A variadic prologue spills rsi..r9 and xmm0..xmm7 into its register-save area, which
    // `va_arg` reads through a computed pointer: those stores look unread but are no object.
    // It saves both xmm6 and xmm7 into the frame (legacy or VEX moves); a function that merely
    // stores xmm7 somewhere is not one.
    let saves = |register: Register| {
        code.iter().any(|ins| {
            matches!(ins.mnemonic(), Mnemonic::Movaps | Mnemonic::Movups | Mnemonic::Vmovaps | Mnemonic::Vmovups)
                && ins.op0_kind() == OpKind::Memory
                && matches!(ins.memory_base(), Register::RSP | Register::RBP)
                && ins.memory_index() == Register::None
                && ins.op1_kind() == OpKind::Register
                && ins.op1_register() == register
        })
    };
    let variadic = saves(Register::XMM6) && saves(Register::XMM7);
    for (ip, store) in stores.iter_mut().filter(|_| !variadic) {
        store.in_stack_object =
            frame_slots.get(ip).copied().flatten().is_some_and(|slot| frame_use.stack_object(slot, width as u64));
    }
    for event in copies {
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
        for (ip, store) in &mut stores {
            let Some(slot) = frame_slots.get(ip).copied().flatten().filter(|slot| event.slots.contains(slot)) else {
                continue;
            };
            if store.copy.is_some() {
                continue;
            }
            let offset = slot.abs_diff(event.source);
            // Nothing in this function runs after a tail jump to the copy routine.
            let found = if event.tail {
                Vec::new()
            } else {
                readers(image, &f, &code, index + 1, holders, Field { offset, width, size: event.size }, READER_DEPTH)
            };
            store.in_stack_object = true;
            store.copy = Some(Copied {
                ip: event.at,
                how: event.op.how.clone(),
                size: event.size,
                offset,
                dest: event.dest,
                readers: found,
            });
        }
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
    frame_slots: BTreeMap<u64, Option<i64>>,
    frame_use: FrameUse,
    passed: BTreeMap<(u64, Slot), u64>,
    copies: Vec<CopyEvent>,
}

impl Walk<'_> {
    /// A register that holds the value at `width` bytes or more (never a high byte).
    fn holds(&self, register: Register, held: &Held) -> bool {
        !high_byte(register) && register.size() >= self.width && bit(register).is_some_and(|b| (held.regs & b) != 0)
    }

    fn transfer(&mut self, ins: &Instruction, held: &mut Held, factory: &mut InstructionInfoFactory, record: bool) {
        if record {
            self.frame_use.record(ins, held, factory);
            self.copied(ins, held);
        }
        if is_call(ins, self.f) {
            if record {
                self.frame_use.call(held);
            }
            if record
                && self.forward
                && let Some(target) = call_target(self.image, ins)
            {
                for (index, argument) in ABI_ARGS.iter().enumerate() {
                    if self.holds(*argument, held) {
                        self.passed.entry((target, Slot::Reg(index))).or_insert_with(|| ins.ip());
                    }
                }
                // Outgoing stack arguments: `stack{k}` is `[rsp + 8k]` at a `call`, and
                // `[rsp + 8(k + 1)]` at a tail jump, whose `[rsp]` already holds a return address.
                let tail = !matches!(ins.flow_control(), FlowControl::Call | FlowControl::IndirectCall);
                for k in 0..STACK_SLOTS {
                    let offset =
                        held.frame.and_then(|frame| frame.checked_add(8 * (i64::try_from(k).ok()? + i64::from(tail))));
                    if offset.is_some_and(|offset| held.spills.contains_key(&offset)) {
                        self.passed.entry((target, Slot::Stack(k))).or_insert_with(|| ins.ip());
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
        if record
            && memory
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
            if held.may_be_frame(ins) {
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
        let frame_pointer = held.frame_pointer(ins);
        let restored = restored_rsp(ins, held);
        self.frame_writes(ins, held, memory);
        for register in written(factory, ins) {
            if register != Register::RSP {
                held.regs &= !bit(register).unwrap_or(0);
                held.forget(register);
            }
        }
        if let Some(Restored(frame)) = restored {
            held.set_frame(frame);
        } else {
            self.frame_moves(ins, held, factory);
        }
        held.regs |= gained;
        held.learn(learned);
        if let Some(register) = frame_pointer {
            held.frame_ptrs |= bit(register).unwrap_or(0);
        }
    }

    /// A whole-object copy whose source is a frame address and whose size is a constant: each
    /// spill slot of the value inside the copied range moves with it.
    fn copied(&mut self, ins: &Instruction, held: &Held) {
        let Some(op) = copy_op(self.image, ins) else { return };
        let (Some(&source), Some(&count)) = (held.addrs.get(&op.source), held.consts.get(&op.count)) else { return };
        let Some(size) = count.checked_mul(op.unit) else { return };
        let end = source.saturating_add_unsigned(size);
        let dest = held.params.get(&op.destination).map_or(Dest::Computed, |index| Dest::Param(*index));
        // Slots whose whole value lies in the copied range; the stores that wrote them are matched
        // after the walk, when every store is known.
        let slots: Vec<i64> = held
            .spills
            .range(source..end)
            .filter(|(slot, _)| slot.saturating_add_unsigned(self.width as u64) <= end)
            .map(|(slot, _)| *slot)
            .collect();
        if slots.is_empty() {
            return;
        }
        let tail = !matches!(ins.flow_control(), FlowControl::Call | FlowControl::IndirectCall);
        self.copies.push(CopyEvent { slots, source, at: ins.ip(), op, size, dest, tail });
    }
}
