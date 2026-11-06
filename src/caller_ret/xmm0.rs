/*
 * xref — Ultra blazing fast cross-references of an x86-64 ELF binary
 * Copyright (c) 2026 Alexander Panasenko
 *
 * Contact: alex@prod.codes
 * Author: https://prod.codes/about/
 * Project: https://github.com/alex09x/xref
 * SPDX-License-Identifier: MIT OR Apache-2.0
 */

//! Does a caller use `xmm0` after a call? The float counterpart of the `rax` consumption check:
//! a scalar float left in `xmm0` at `ret` is a return value only if some caller reads it.

use std::ops::Range;

use iced_x86::{Instruction, InstructionInfoFactory, OpAccess, Register};

use super::RegFate;
use super::trace::trace_reg_after;
use crate::sig::xmm::xmm_zero_idiom;

/// One instruction's effect on `xmm0`: read (any width), fully overwritten, or untouched.
/// A merging write (`movsd xmm0, xmm1`, `cvtsi2sd xmm0, rax`) reads the upper lanes and counts as
/// a read, which keeps the check conservative.
fn insn_xmm0_step(factory: &mut InstructionInfoFactory, ins: &Instruction) -> Option<RegFate> {
    if xmm_zero_idiom(ins) == Some(0) {
        return Some(RegFate::Killed);
    }
    let mut wrote = false;
    for u in factory.info(ins).used_registers() {
        if u.register().full_register() == Register::ZMM0 {
            match u.access() {
                OpAccess::Read | OpAccess::CondRead | OpAccess::ReadWrite | OpAccess::ReadCondWrite => {
                    return Some(RegFate::Read(8));
                }
                OpAccess::Write => wrote = true,
                _ => {}
            }
        }
    }
    wrote.then_some(RegFate::Killed)
}

/// What happens to `xmm0` after the call that returns to `entry_ip`. A following call may take
/// `xmm0` as its first float argument, so it counts as a read; `ret` and paths the walk cannot
/// follow give `Unknown`.
pub(super) fn trace_xmm0_after(
    factory: &mut InstructionInfoFactory,
    func_bytes: &[u8],
    func: &Range<u64>,
    entry_ip: u64,
) -> RegFate {
    trace_reg_after(factory, func_bytes, func, entry_ip, insn_xmm0_step, Some(RegFate::Read(8)))
}

#[cfg(test)]
mod tests {
    use iced_x86::InstructionInfoFactory;

    use super::{RegFate, trace_xmm0_after};

    fn fate(code: &[u8]) -> RegFate {
        let func = 0x1000..0x1000 + code.len() as u64;
        trace_xmm0_after(&mut InstructionInfoFactory::new(), code, &func, 0x1000)
    }

    #[test]
    fn f64_abi_caller_xmm0_use_after_call() {
        // movsd xmm0, [rsp]; ret: reloaded before any read.
        assert!(fate(&[0xf2, 0x0f, 0x10, 0x04, 0x24, 0xc3]) == RegFate::Killed);
        // pxor xmm0, xmm0; ret: the zero idiom does not read the old value.
        assert!(fate(&[0x66, 0x0f, 0xef, 0xc0, 0xc3]) == RegFate::Killed);
        // movsd [rdi], xmm0: the result is stored.
        assert!(fate(&[0xf2, 0x0f, 0x11, 0x07, 0xc3]) == RegFate::Read(8));
        // call: the next callee may take xmm0 as its first float argument.
        assert!(fate(&[0xe8, 0, 0, 0, 0, 0xc3]) == RegFate::Read(8));
        // ret: forwarded to this function's own caller, undecided here.
        assert!(fate(&[0xc3]) == RegFate::Unknown);
        // A branch where one path stores xmm0 and the other reloads it: a read.
        // je +5; movsd xmm0, [rsp]; ret; movsd [rdi], xmm0; ret
        let code = [0x74, 0x06, 0xf2, 0x0f, 0x10, 0x04, 0x24, 0xc3, 0xf2, 0x0f, 0x11, 0x07, 0xc3];
        assert!(fate(&code) == RegFate::Read(8));
    }
}
