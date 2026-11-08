/*
 * XRef — The branch condition that chooses a record in a dispatcher
 * Copyright (c) 2026 Alexander Panasenko
 * Contact: alex@prod.codes
 * Author: https://prod.codes/about/
 * Project: https://github.com/alex09x/xref
 * SPDX-License-Identifier: MIT OR Apache-2.0
 */

use std::collections::BTreeSet;

use iced_x86::{ConditionCode, FlowControl, Instruction, Mnemonic, OpKind};

use crate::scan;

/// `x == imm` when the block holding `set_at` is entered only through the taken side of one
/// `cmp x, imm; je`, or only by falling through a `cmp x, imm; jne`. A block that is also reached
/// from the instruction above it, by an unconditional jump, as a jump-table arm, or at the
/// function's entry has no single condition.
pub fn condition(code: &[Instruction], leaders: &BTreeSet<u64>, arms: &BTreeSet<u64>, set_at: u64) -> Option<String> {
    let at = code.iter().position(|ins| ins.ip() == set_at)?;
    let mut first = at;
    while first > 0 && !leaders.contains(&code[first].ip()) && code[first - 1].flow_control() == FlowControl::Next {
        first -= 1;
    }
    let start = code[first].ip();
    let branches: Vec<usize> = (0..code.len())
        .filter(|&i| code[i].flow_control() == FlowControl::ConditionalBranch && code[i].near_branch_target() == start)
        .collect();
    // Padding after a `ret` or `jmp` (`nop`, `int3`) is never reached; what falls in, if anything,
    // is the instruction before it.
    let mut above_at = first;
    while above_at > 0 && matches!(code[above_at - 1].mnemonic(), Mnemonic::Nop | Mnemonic::Int3) {
        above_at -= 1;
    }
    let above = (above_at > 0).then(|| code[above_at - 1].flow_control());
    let jumps_in = arms.contains(&start)
        || code
            .iter()
            .any(|ins| ins.flow_control() == FlowControl::UnconditionalBranch && ins.near_branch_target() == start);
    if jumps_in {
        return None;
    }
    // The `cmp` must be what sets the flags: the branch is not itself a block start.
    let comparison = |branch: usize| {
        if leaders.contains(&code[branch].ip()) {
            return None;
        }
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
    match (branches.as_slice(), above) {
        // Only the taken side of one `je` leads here: nothing falls in from above.
        (
            [branch],
            Some(
                FlowControl::UnconditionalBranch
                | FlowControl::Return
                | FlowControl::IndirectBranch
                | FlowControl::Interrupt
                | FlowControl::Exception,
            ),
        ) if code[*branch].condition_code() == ConditionCode::e => comparison(*branch),
        // Only the fallthrough of a `jne` leads here.
        ([], Some(FlowControl::ConditionalBranch)) if code[above_at - 1].condition_code() == ConditionCode::ne => {
            comparison(above_at - 1)
        }
        _ => None,
    }
}
