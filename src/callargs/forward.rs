/*
 * XRef — Where a function stores a value it receives in an argument register
 * Copyright (c) 2026 Alexander Panasenko
 * Contact: alex@prod.codes
 * Author: https://prod.codes/about/
 * Project: https://github.com/alex09x/xref
 * SPDX-License-Identifier: MIT OR Apache-2.0
 */

//! Stores of an incoming argument: the register (and its copies) is followed through the function
//! in code order, without regard to branches, until it is overwritten or a call clobbers it. A
//! value passed on to another function in an argument register is followed one call deeper.

use std::collections::{BTreeSet, HashSet};

use iced_x86::{Instruction, Mnemonic, OpKind, Register};

use super::scan::{Slot, VOLATILE, reads_only};
use crate::expr::ABI_ARGS;
use crate::graph::call_target;
use crate::image::Image;
use crate::listing::is_call;
use crate::scan::{self, decode};

#[derive(Clone)]
pub struct ArgStore {
    pub ip: u64,
    pub text: String,
    pub base: Register,
    pub indexed: bool,
    pub displacement: u64,
    /// The function the value was passed on to, and in which argument, when the store is there.
    pub via: Option<(u64, Slot)>,
}

impl ArgStore {
    /// A store at `displacement` of an object that is not the stack frame.
    pub const fn at_object_offset(&self, displacement: u64) -> bool {
        !self.indexed && self.displacement == displacement && !self.in_frame()
    }

    /// A store to the stack frame (or a global): a spill or a local, not a field of an object.
    pub const fn in_frame(&self) -> bool {
        matches!(self.base, Register::RSP | Register::RBP | Register::RIP | Register::None)
    }
}

/// `width`-byte stores of the value the function starting at `callee` receives in `slot`, and,
/// with `forward`, of the functions it passes the value on to.
pub fn arg_stores(image: &Image, callee: u64, slot: Slot, width: usize, forward: bool) -> Vec<ArgStore> {
    let Some(register) = slot.register() else { return Vec::new() };
    let Some(f) = image.function_at(callee).filter(|f| f.start == callee) else { return Vec::new() };
    let Some(bytes) = image.code(&f) else { return Vec::new() };
    let mut tracked: HashSet<Register> = HashSet::from([register]);
    let mut found = Vec::new();
    let mut passed = BTreeSet::new();
    decode(bytes, f.start, |ins| {
        if tracked.is_empty() {
            return;
        }
        if is_call(ins, &f) {
            if forward && let Some(target) = call_target(image, ins).filter(|t| *t != callee) {
                for (index, argument) in ABI_ARGS.iter().enumerate() {
                    if tracked.contains(argument) {
                        passed.insert((target, Slot::Reg(index)));
                    }
                }
            }
            for volatile in VOLATILE {
                tracked.remove(&volatile);
            }
            return;
        }
        if let Some(store) = stored(ins, &tracked, width) {
            found.push(store);
            return;
        }
        follow(ins, &mut tracked);
    });
    for (target, argument) in passed {
        for mut store in arg_stores(image, target, argument, width, false) {
            store.via = Some((target, argument));
            found.push(store);
        }
    }
    found
}

fn stored(ins: &Instruction, tracked: &HashSet<Register>, width: usize) -> Option<ArgStore> {
    (ins.mnemonic() == Mnemonic::Mov
        && ins.op0_kind() == OpKind::Memory
        && ins.op1_kind() == OpKind::Register
        && tracked.contains(&ins.op1_register().full_register())
        && ins.memory_size().size() == width)
        .then(|| ArgStore {
            ip: ins.ip(),
            text: scan::format(ins),
            base: ins.memory_base().full_register(),
            indexed: ins.memory_index() != Register::None,
            displacement: ins.memory_displacement64(),
            via: None,
        })
}

/// Copies of a tracked register join it; any other write of a tracked register drops it.
fn follow(ins: &Instruction, tracked: &mut HashSet<Register>) {
    let mnemonic = ins.mnemonic();
    if matches!(
        mnemonic,
        Mnemonic::Mul | Mnemonic::Imul | Mnemonic::Div | Mnemonic::Idiv | Mnemonic::Cqo | Mnemonic::Cdq
    ) {
        tracked.remove(&Register::RAX);
        tracked.remove(&Register::RDX);
    }
    if matches!(mnemonic, Mnemonic::Xchg | Mnemonic::Xadd) && ins.op1_kind() == OpKind::Register {
        tracked.remove(&ins.op1_register().full_register());
    }
    if ins.op_count() == 0 || ins.op0_kind() != OpKind::Register || reads_only(mnemonic) {
        return;
    }
    let destination = ins.op0_register().full_register();
    let copy = matches!(mnemonic, Mnemonic::Mov | Mnemonic::Movzx | Mnemonic::Movsx | Mnemonic::Movsxd)
        && ins.op1_kind() == OpKind::Register
        && tracked.contains(&ins.op1_register().full_register());
    if copy {
        tracked.insert(destination);
    } else {
        tracked.remove(&destination);
    }
}
