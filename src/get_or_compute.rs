/*
 * xref — Ultra blazing fast cross-references of an x86-64 ELF binary
 * Copyright (c) 2026 Alexander Panasenko
 *
 * Contact: alex@prod.codes
 * Author: https://prod.codes/about/
 * Project: https://github.com/alex09x/xref
 * SPDX-License-Identifier: MIT OR Apache-2.0
 */

//! Get-or-compute functions: `map.entry(key).or_insert_with(|| compute())`, `OnceCell::get_or_init`.
//! Such a function tests a tag first (`cmp dword ptr [rdi], 1; jne vacant`); one side returns the
//! existing value without calling anything, the other calls the compute function and hands its
//! result straight to the insert (`mov rdx, rax; call insert`). The caller's pseudo-C then names
//! the compute function, which is otherwise reached only through the callee.

use std::ops::Range;

use iced_x86::{FlowControl, Instruction, Mnemonic, OpKind, Register};

use crate::expr::ABI_ARGS;
use crate::graph::call_target;
use crate::image::Image;
use crate::scan::decode;

/// Instructions from the entry searched for the tag test.
const TAG_WINDOW: usize = 16;

/// Instructions followed along one side of the tag test.
const WALK_STEPS: usize = 48;

/// Instructions from the compute call to the insert call.
const INSERT_WINDOW: usize = 24;

/// The compute and insert calls of a get-or-compute function: the call targets (`None` for a
/// compute call through a register) and the addresses of the two calls.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct GetOrCompute {
    pub compute: Option<u64>,
    pub compute_at: u64,
    pub insert: u64,
    pub insert_at: u64,
}

/// Where one side of a branch leads in straight-line code (conditional branches fall through).
enum Walk {
    /// A `ret` with no call on the way: the value was already there.
    Returns,
    /// The first call on the way, by listing index.
    Calls(usize),
    Unknown,
}

fn is_call(instruction: &Instruction, function: &Range<u64>) -> bool {
    match instruction.flow_control() {
        FlowControl::Call | FlowControl::IndirectCall => true,
        FlowControl::UnconditionalBranch => !function.contains(&instruction.near_branch_target()),
        _ => false,
    }
}

fn walk(listing: &[Instruction], function: &Range<u64>, mut at: usize) -> Walk {
    // A side that stores to memory builds a value (an empty Vec) rather than finding one.
    let mut stores = false;
    for _ in 0..WALK_STEPS {
        let Some(instruction) = listing.get(at) else { return Walk::Unknown };
        if is_call(instruction, function) {
            return Walk::Calls(at);
        }
        if instruction.op_count() > 0
            && instruction.op0_kind() == OpKind::Memory
            && instruction.mnemonic() != Mnemonic::Push
            && crate::disp::is_mem_write(instruction, 0)
        {
            stores = true;
        }
        match instruction.flow_control() {
            FlowControl::Return if stores => return Walk::Unknown,
            FlowControl::Return => return Walk::Returns,
            FlowControl::UnconditionalBranch => {
                match listing.binary_search_by_key(&instruction.near_branch_target(), Instruction::ip) {
                    Ok(next) => at = next,
                    Err(_) => return Walk::Unknown,
                }
            }
            FlowControl::Next | FlowControl::ConditionalBranch => at += 1,
            _ => return Walk::Unknown,
        }
    }
    Walk::Unknown
}

/// The call after `compute` (by listing index) that takes its result in an argument register.
fn insert_after(listing: &[Instruction], function: &Range<u64>, compute: usize) -> Option<usize> {
    let mut holders = vec![Register::RAX];
    for (index, instruction) in listing.iter().enumerate().skip(compute + 1).take(INSERT_WINDOW) {
        if is_call(instruction, function) {
            return holders.iter().any(|held| ABI_ARGS.contains(held)).then_some(index);
        }
        // A check of the result (`test rax, rax; je fail`) falls through to the insert.
        if !matches!(instruction.flow_control(), FlowControl::Next | FlowControl::ConditionalBranch) {
            return None;
        }
        if instruction.op_count() == 0
            || instruction.op0_kind() != OpKind::Register
            || matches!(instruction.mnemonic(), Mnemonic::Cmp | Mnemonic::Test)
        {
            continue;
        }
        let written = instruction.op0_register().full_register();
        let copied = instruction.mnemonic() == Mnemonic::Mov
            && instruction.op1_kind() == OpKind::Register
            && holders.contains(&instruction.op1_register().full_register());
        holders.retain(|held| *held != written);
        if copied {
            holders.push(written);
        }
    }
    None
}

/// Whether `function` is a get-or-compute function, and its compute and insert calls.
#[must_use]
pub fn detect(image: &Image, function: &Range<u64>) -> Option<GetOrCompute> {
    let code = image.code(function)?;
    let mut listing = Vec::new();
    decode(code, function.start, |instruction| listing.push(*instruction));
    // The tag test: the first `cmp`/`test` + conditional branch near the entry, before any call.
    let head =
        listing.iter().take(TAG_WINDOW).position(|i| is_call(i, function) || i.flow_control() != FlowControl::Next);
    let branch = head.filter(|&at| {
        at > 0
            && listing[at].flow_control() == FlowControl::ConditionalBranch
            && matches!(listing[at - 1].mnemonic(), Mnemonic::Cmp | Mnemonic::Test)
    })?;
    let taken = listing.binary_search_by_key(&listing[branch].near_branch_target(), Instruction::ip).ok()?;
    let ((Walk::Returns, Walk::Calls(compute)) | (Walk::Calls(compute), Walk::Returns)) =
        (walk(&listing, function, branch + 1), walk(&listing, function, taken))
    else {
        return None;
    };
    let insert = insert_after(&listing, function, compute)?;
    // The insert is code of the program (a map or cell insert), not an import such as `memcpy`.
    let insert_target = call_target(image, &listing[insert]).filter(|&at| image.function_at(at).is_some())?;
    Some(GetOrCompute {
        compute: call_target(image, &listing[compute]),
        compute_at: listing[compute].ip(),
        insert: insert_target,
        insert_at: listing[insert].ip(),
    })
}

#[cfg(test)]
#[path = "get_or_compute_tests.rs"]
mod tests;
