/*
 * XRef — Loops that walk fixed-size records with a pointer stepped by the record size
 * Copyright (c) 2026 Alexander Panasenko
 * Contact: alex@prod.codes
 * Author: https://prod.codes/about/
 * Project: https://github.com/alex09x/xref
 * SPDX-License-Identifier: MIT OR Apache-2.0
 */

use std::ops::Range;

use iced_x86::{FlowControl, Instruction, InstructionInfoFactory, Mnemonic, OpKind, Register};

use crate::callargs::flow::{GPRS, bit, written};
use crate::callargs::scan::VOLATILE;

/// A loop's span, the registers it steps by the stride, and the phase of each at the loop.
pub(super) type Stepped = (Range<u64>, u16, [u64; 16]);

/// Instructions scanned back from a loop for its pointer's setup.
const SETUP_WINDOW: usize = 32;

/// Loops (a backward branch to `target`, the span up to it) and the registers each steps by the
/// stride with every write of theirs inside it (`add rbx, 0x2c8`): a call inside the loop drops
/// the volatile ones. A stepped pointer's phase comes from its setup before the loop: `lea rbx,
/// [rdi+8]` walks the records 8 bytes in, `add rbx, 0x2c8` one record ahead (phase 0).
pub(super) fn stepped_loops(code: &[Instruction], f: &Range<u64>, stride: u64) -> Vec<Stepped> {
    let mut factory = InstructionInfoFactory::new();
    let mut loops = Vec::new();
    for back in code {
        let Some(target) = crate::scan::branch_target(back).filter(|t| f.contains(t) && *t <= back.ip()) else {
            continue;
        };
        let span = target..back.next_ip();
        let (mut steps, mut other) = (0u16, 0u16);
        for ins in code.iter().filter(|ins| span.contains(&ins.ip())) {
            if steps_by(ins, stride) {
                steps |= bit(ins.op0_register()).unwrap_or(0);
                continue;
            }
            for register in written(&mut factory, ins) {
                other |= bit(register).unwrap_or(0);
            }
            if matches!(ins.flow_control(), FlowControl::Call | FlowControl::IndirectCall) {
                other |= VOLATILE.iter().fold(0, |mask, r| mask | bit(*r).unwrap_or(0));
            }
        }
        let regs = steps & !other;
        if regs != 0 {
            let head = code.iter().position(|ins| ins.ip() == target).unwrap_or(0);
            let mut phases = [0u64; 16];
            for (index, register) in GPRS.iter().enumerate() {
                if regs & (1 << index) != 0 {
                    phases[index] = setup_phase(code, head, *register, stride);
                }
            }
            loops.push((span, regs, phases));
        }
    }
    loops
}

/// The phase `register` has at `code[head]`: the constant its setup just before adds to the
/// address it starts from (`mov rbx, [rdi+8]; add rbx, 0x2c8`; `lea rbx, [rdi+8]`), taken to be an
/// element's start; 0 when the setup is not seen.
fn setup_phase(code: &[Instruction], head: usize, register: Register, stride: u64) -> u64 {
    let mut factory = InstructionInfoFactory::new();
    let mut added = 0i64;
    for ins in code[head.saturating_sub(SETUP_WINDOW)..head].iter().rev() {
        if !matches!(ins.flow_control(), FlowControl::Next | FlowControl::ConditionalBranch) {
            break;
        }
        if !written(&mut factory, ins).contains(&register) {
            continue;
        }
        let to_register = ins.op_count() == 2 && ins.op0_kind() == OpKind::Register && ins.op0_register() == register;
        let immediate = matches!(ins.op1_kind(), OpKind::Immediate8to64 | OpKind::Immediate32to64);
        match ins.mnemonic() {
            Mnemonic::Add if to_register && immediate => added = added.wrapping_add(ins.immediate(1).cast_signed()),
            Mnemonic::Sub if to_register && immediate => added = added.wrapping_sub(ins.immediate(1).cast_signed()),
            Mnemonic::Lea if to_register && ins.memory_index() == Register::None => {
                added = added.wrapping_add(ins.memory_displacement64().cast_signed());
                if ins.memory_base() != register {
                    break;
                }
            }
            // A copy of a pointer, or one loaded (a Vec's buffer).
            Mnemonic::Mov if to_register && matches!(ins.op1_kind(), OpKind::Register | OpKind::Memory) => break,
            // Set some other way: no known start.
            _ => return 0,
        }
    }
    u64::try_from(i128::from(added).rem_euclid(i128::from(stride.max(1)))).unwrap_or(0)
}

/// `add reg, stride` or `lea reg, [reg + stride]` on a 64-bit register.
fn steps_by(ins: &Instruction, stride: u64) -> bool {
    if ins.op_count() < 2 || ins.op0_kind() != OpKind::Register || ins.op0_register().size() != 8 {
        return false;
    }
    // `add rsp, 0x2c8` frees a frame of that size; it walks no records.
    if matches!(ins.op0_register(), Register::RSP | Register::RBP) {
        return false;
    }
    match ins.mnemonic() {
        Mnemonic::Add => {
            matches!(ins.op1_kind(), OpKind::Immediate32to64 | OpKind::Immediate8to64) && ins.immediate(1) == stride
        }
        Mnemonic::Lea => {
            ins.memory_base() == ins.op0_register()
                && ins.memory_index() == Register::None
                && ins.memory_displacement64() == stride
        }
        _ => false,
    }
}
