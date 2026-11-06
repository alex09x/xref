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
use crate::graph::call_target;
use crate::image::Image;
use crate::sig::xmm::xmm_zero_idiom;

/// One instruction's effect on `xmm0`: read (any width), fully overwritten, or untouched.
/// A merging write (`movsd xmm0, xmm1`, `cvtsi2sd xmm0, rax`) reads the upper lanes and counts as
/// a read.
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

/// What happens to `xmm0` after the call that returns to `entry_ip`, and the direct targets of
/// calls reached before `xmm0` is read or overwritten. Such a call reads `xmm0` only if its callee
/// takes a float first argument, which is decided later and only when it matters; an indirect call
/// is not counted as a read. `ret` and paths the walk cannot follow give `Unknown`: undecided,
/// neither a read nor proof that the value is unused.
pub(super) fn trace_xmm0_after(
    image: &Image,
    factory: &mut InstructionInfoFactory,
    func_bytes: &[u8],
    func: &Range<u64>,
    entry_ip: u64,
) -> (RegFate, Vec<u64>) {
    let mut next_calls = Vec::new();
    let fate = trace_reg_after(factory, func_bytes, func, entry_ip, insn_xmm0_step, &mut |ins| {
        next_calls.extend(call_target(image, ins));
    });
    (fate, next_calls)
}

#[cfg(test)]
mod tests {
    use iced_x86::InstructionInfoFactory;

    use super::{RegFate, trace_xmm0_after};
    use crate::image::{Image, Segment};

    fn fate(code: &[u8]) -> (RegFate, Vec<u64>) {
        let img = Image {
            data: code.to_vec(),
            segments: vec![Segment { va: 0x1000, offset: 0, size: code.len() }],
            ..Image::default()
        };
        let func = 0x1000..0x1000 + code.len() as u64;
        trace_xmm0_after(&img, &mut InstructionInfoFactory::new(), code, &func, 0x1000)
    }

    #[test]
    fn f64_abi_caller_xmm0_use_after_call() {
        // movsd xmm0, [rsp]; ret: reloaded before any read.
        assert!(fate(&[0xf2, 0x0f, 0x10, 0x04, 0x24, 0xc3]).0 == RegFate::Killed);
        // pxor xmm0, xmm0; ret: the zero idiom does not read the old value.
        assert!(fate(&[0x66, 0x0f, 0xef, 0xc0, 0xc3]).0 == RegFate::Killed);
        // movsd [rdi], xmm0: the result is stored.
        assert!(fate(&[0xf2, 0x0f, 0x11, 0x07, 0xc3]).0 == RegFate::Read(8));
        // call 0x1005: not a read by itself; the callee is recorded for a later float-param check.
        let (f, next) = fate(&[0xe8, 0, 0, 0, 0, 0xc3]);
        assert!(f == RegFate::Killed && next == vec![0x1005]);
        // ret: forwarded to this function's own caller, undecided here.
        assert!(fate(&[0xc3]).0 == RegFate::Unknown);
        // A branch where one path stores xmm0 and the other reloads it: a read.
        // je +6; movsd xmm0, [rsp]; ret; movsd [rdi], xmm0; ret
        let code = [0x74, 0x06, 0xf2, 0x0f, 0x10, 0x04, 0x24, 0xc3, 0xf2, 0x0f, 0x11, 0x07, 0xc3];
        assert!(fate(&code).0 == RegFate::Read(8));
    }
}
