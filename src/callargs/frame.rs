/*
 * XRef — Stack-frame state for following an argument through a function
 * Copyright (c) 2026 Alexander Panasenko
 * Contact: alex@prod.codes
 * Author: https://prod.codes/about/
 * Project: https://github.com/alex09x/xref
 * SPDX-License-Identifier: MIT OR Apache-2.0
 */

//! Offsets are relative to `rsp` at the function's entry. [`Held`] is where the followed value may
//! be at one point (registers and spill slots); [`FrameUse`] is what the whole function does with
//! its frame (reads and addresses taken), which tells a spill from a field of an object built on
//! the stack.

use std::collections::BTreeMap;

use iced_x86::{Instruction, InstructionInfoFactory, Mnemonic, OpAccess, OpKind, Register};

use super::flow::Join;
use crate::expr::ABI_ARGS;

/// What one instruction tells about its destination register.
#[derive(Clone, Copy)]
pub struct Learned {
    register: Register,
    addr: Option<i64>,
    constant: Option<u64>,
    param: Option<usize>,
}

impl Learned {
    /// The entry-relative frame address the destination gets, if it gets one.
    pub const fn frame_address(self) -> Option<i64> {
        self.addr
    }
}

/// Where the value may be at a point of the function, and what is known about other registers
/// there (a must-fact on every path: the maps keep only entries all paths agree on).
#[derive(Clone, PartialEq, Eq)]
pub struct Held {
    /// General-purpose registers holding it, as a `flow::bit` mask.
    pub regs: u16,
    /// `rsp` relative to its value at entry, while every path agrees on it.
    pub frame: Option<i64>,
    /// Spill slots holding it: entry-relative stack offset → bytes written there.
    pub spills: BTreeMap<i64, u64>,
    /// Registers holding a frame address (`lea reg, [rsp+d]`): its entry-relative offset.
    pub addrs: BTreeMap<Register, i64>,
    /// Registers holding a constant (`mov edx, 0x2c8`).
    pub consts: BTreeMap<Register, u64>,
    /// Registers still holding an incoming argument: its index in `rdi..r9`.
    pub params: BTreeMap<Register, usize>,
}

impl Join for Held {
    /// Joins `other` into `self`; true when `self` changed.
    fn join(&mut self, other: &Self) -> bool {
        let before = self.clone();
        self.regs |= other.regs;
        // Slots are entry-relative, so they hold on every path whatever `rsp` is now.
        for (offset, size) in &other.spills {
            // The wider write, so that a later partial overwrite of its upper bytes drops it.
            self.spills.entry(*offset).and_modify(|known| *known = (*known).max(*size)).or_insert(*size);
        }
        if self.frame != other.frame {
            // Paths disagree on `rsp`: `[rsp+d]` can no longer be placed (a frame pointer still can).
            self.lose_frame();
        }
        self.addrs.retain(|register, at| other.addrs.get(register) == Some(at));
        self.consts.retain(|register, value| other.consts.get(register) == Some(value));
        self.params.retain(|register, index| other.params.get(register) == Some(index));
        *self != before
    }
}

impl Held {
    pub fn entry(regs: u16) -> Self {
        Self {
            regs,
            frame: Some(0),
            spills: BTreeMap::new(),
            addrs: BTreeMap::new(),
            consts: BTreeMap::new(),
            params: ABI_ARGS.iter().enumerate().map(|(index, register)| (*register, index)).collect(),
        }
    }

    /// `rsp` is unknown from here: `[rsp+d]` cannot be placed. Slots and frame-pointer registers
    /// (`mov rbp, rsp` before `and rsp, -32`) are entry-relative and stay valid.
    pub const fn lose_frame(&mut self) {
        self.frame = None;
    }

    /// The entry-relative address a base register holds: `rsp` itself, or a frame pointer
    /// (`mov rbp, rsp`, `lea rbx, [rsp+0x20]`).
    pub fn frame_base(&self, base: Register) -> Option<i64> {
        if base == Register::RSP { self.frame } else { self.addrs.get(&base).copied() }
    }

    /// An unindexed memory operand of `ins` addressed off the frame.
    pub fn on_frame(&self, ins: &Instruction) -> bool {
        ins.memory_index() == Register::None && self.frame_base(ins.memory_base()).is_some()
    }

    /// Drops what is known about a full register that is written.
    pub fn forget(&mut self, register: Register) {
        self.addrs.remove(&register);
        self.consts.remove(&register);
        self.params.remove(&register);
    }

    /// The facts `ins` gives its destination register, read before `ins` writes anything:
    /// `lea reg, [rsp+d]`, a 64-bit register copy, `mov reg, imm`, `xor reg, reg`.
    pub fn learned(&self, ins: &Instruction) -> Option<Learned> {
        if ins.op_count() != 2 || ins.op0_kind() != OpKind::Register {
            return None;
        }
        let destination = ins.op0_register();
        let register = destination.full_register();
        // `rsp` itself is the frame (`Held::frame`), never a register fact.
        if register == Register::RSP {
            return None;
        }
        let same = ins.op1_kind() == OpKind::Register && ins.op1_register() == destination;
        let nothing = Learned { register, addr: None, constant: None, param: None };
        match ins.mnemonic() {
            Mnemonic::Lea if destination.size() == 8 && self.on_frame(ins) => {
                Some(Learned { addr: self.slot(ins), ..nothing })
            }
            Mnemonic::Mov if ins.op1_kind() == OpKind::Register && destination.size() == 8 => {
                let source = ins.op1_register();
                // `mov rdi, rsp`: the frame's address, like `lea rdi, [rsp]`.
                let frame = if source == Register::RSP { self.frame } else { None };
                (source.size() == 8).then(|| Learned {
                    addr: frame.or_else(|| self.addrs.get(&source).copied()),
                    constant: self.consts.get(&source).copied(),
                    param: self.params.get(&source).copied(),
                    ..nothing
                })
            }
            Mnemonic::Mov
                if destination.size() >= 4
                    && matches!(
                        ins.op1_kind(),
                        OpKind::Immediate32 | OpKind::Immediate64 | OpKind::Immediate32to64
                    ) =>
            {
                let value = ins.immediate(1);
                let constant = if destination.size() == 4 { value & 0xffff_ffff } else { value };
                Some(Learned { constant: Some(constant), ..nothing })
            }
            Mnemonic::Xor | Mnemonic::Sub if same && destination.size() >= 4 => {
                Some(Learned { constant: Some(0), ..nothing })
            }
            _ => None,
        }
    }

    /// Records facts from [`Held::learned`] after the instruction's writes were forgotten.
    pub fn learn(&mut self, learned: Option<Learned>) {
        let Some(Learned { register, addr, constant, param }) = learned else { return };
        if let Some(addr) = addr {
            self.addrs.insert(register, addr);
        }
        if let Some(constant) = constant {
            self.consts.insert(register, constant);
        }
        if let Some(param) = param {
            self.params.insert(register, param);
        }
    }

    /// The slot `[rsp + displacement]` of `ins` as an entry-relative offset.
    pub fn slot(&self, ins: &Instruction) -> Option<i64> {
        self.frame_base(ins.memory_base()).and_then(|base| base.checked_add(ins.memory_displacement64().cast_signed()))
    }

    /// Forgets the spills `[offset, offset + size)` overlaps.
    pub fn overwrite(&mut self, offset: i64, size: u64) {
        let end = offset.saturating_add_unsigned(size);
        self.spills.retain(|start, len| start.saturating_add_unsigned(*len) <= offset || *start >= end);
    }

    /// A call pushes its return address and runs the callee's frame below `rsp`: slots there are gone.
    pub fn after_call(&mut self) {
        if let Some(frame) = self.frame {
            self.spills.retain(|offset, _| *offset >= frame);
        }
    }
}

/// How the function uses its frame, over every path.
#[derive(Default)]
pub struct FrameUse {
    /// `[rsp+d]` ranges read (explicitly, by `pop`, or as a source of any instruction).
    reads: Vec<(i64, u64)>,
    /// A direct frame read after the walk lost the frame: it may read anything back.
    unplaced_read: bool,
    /// Frame addresses handed to a call in an argument register (`lea rdi, [rsp+d]; call f`,
    /// `memcpy(dst, &obj, n)`): where an object built on the stack leaves the function.
    anchors: Vec<i64>,
    /// Every frame address the function forms (`lea reg, [rbp-d]`, `mov reg, rsp`): each starts
    /// an object of its own, so an object passed to a call ends below the next one.
    taken: Vec<i64>,
}

impl FrameUse {
    /// A call: the frame addresses its argument registers hold.
    pub fn call(&mut self, held: &Held) {
        self.anchors.extend(ABI_ARGS.iter().filter_map(|argument| held.addrs.get(argument).copied()));
    }

    /// Records the frame reads of `ins`, with the frame before it.
    pub fn record(&mut self, ins: &Instruction, held: &Held, factory: &mut InstructionInfoFactory) {
        if let Some(learned) = held.learned(ins).and_then(Learned::frame_address) {
            self.taken.push(learned);
        }
        if ins.mnemonic() == Mnemonic::Lea {
            return;
        }
        for used in factory.info(ins).used_memory() {
            // A frame read: off `rsp`, or off a register holding a frame address.
            let base = held.frame_base(used.base());
            let off_frame = base.is_some() || used.base() == Register::RSP;
            let read = matches!(
                used.access(),
                OpAccess::Read | OpAccess::CondRead | OpAccess::ReadWrite | OpAccess::ReadCondWrite
            );
            // An indexed read (`[rsp + rax*8 + 0x128]`) walks an array on the stack: an object
            // either way, never the reload of a spill, which reads its slot directly.
            if !off_frame || !read || used.index() != Register::None {
                continue;
            }
            let size = used.memory_size().size().max(1) as u64;
            match base.and_then(|base| base.checked_add(used.displacement().cast_signed())) {
                Some(slot) => self.reads.push((slot, size)),
                // `[rsp+d]` after the walk lost `rsp`.
                None => self.unplaced_read = true,
            }
        }
        if ins.mnemonic() == Mnemonic::Pop
            && let Some(frame) = held.frame
        {
            self.reads.push((frame, 8));
        }
    }

    /// A `width`-byte store at `slot` is a field of an object built on the stack: the function
    /// never reads those bytes back (not a spill), and passes a call the address of an object
    /// that reaches them: at or below the slot, with no other frame address formed in between
    /// (that would start another object, like a `&str` whose address goes into format arguments).
    pub fn stack_object(&self, slot: i64, width: u64) -> bool {
        let end = slot.saturating_add_unsigned(width);
        !self.unplaced_read
            && !self.reads.iter().any(|&(at, size)| at < end && slot < at.saturating_add_unsigned(size))
            && self
                .anchors
                .iter()
                .any(|&anchor| anchor <= slot && !self.taken.iter().any(|&other| anchor < other && other <= slot))
    }
}
