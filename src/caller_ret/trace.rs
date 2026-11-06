/*
 * xref — Ultra blazing fast cross-references of an x86-64 ELF binary
 * Copyright (c) 2026 Alexander Panasenko
 *
 * Contact: alex@prod.codes
 * Author: https://prod.codes/about/
 * Project: https://github.com/alex09x/xref
 * SPDX-License-Identifier: MIT OR Apache-2.0
 */

//! Bounded walk over the code after a call site: the fate of one result register on every path.

use std::ops::Range;

use iced_x86::{FlowControl, Instruction, InstructionInfoFactory};

use super::RegFate;
use crate::listing::is_call;
use crate::scan::{branch_target, decode};

/// Walks the code after a call site until each path reads or overwrites a register.
/// `step` decides one instruction. A following call ends the path without a read (it clobbers the
/// result registers); `on_call` sees it, so a caller can ask later whether that callee takes the
/// register as an argument.
pub(super) fn trace_reg_after(
    factory: &mut InstructionInfoFactory,
    func_bytes: &[u8],
    func: &Range<u64>,
    entry_ip: u64,
    step: fn(&mut InstructionInfoFactory, &Instruction) -> Option<RegFate>,
    on_call: &mut dyn FnMut(&Instruction),
) -> RegFate {
    let mut visited: Vec<u64> = Vec::new();
    let mut queue: Vec<u64> = vec![entry_ip];
    let (mut any_unknown, mut max_read) = (false, 0u8);

    while let Some(start_ip) = queue.pop() {
        if !func.contains(&start_ip) || visited.len() >= 24 {
            any_unknown = true;
            continue;
        }
        if visited.contains(&start_ip) {
            continue;
        }
        visited.push(start_ip);
        let bytes = &func_bytes[usize::try_from(start_ip - func.start).unwrap_or(0)..];
        let (mut steps, mut done, mut block_read) = (0usize, false, 0u8);
        decode(bytes, start_ip, |ins| {
            if done {
                return;
            }
            steps += 1;
            if steps > 32 {
                (any_unknown, done) = (true, true);
                return;
            }
            if let Some(step_fate) = step(factory, ins) {
                done = true;
                if let RegFate::Read(sz) = step_fate {
                    block_read = sz;
                }
                return;
            }
            match ins.flow_control() {
                FlowControl::Next => {}
                FlowControl::Call | FlowControl::IndirectCall => {
                    done = true;
                    on_call(ins);
                }
                FlowControl::Interrupt | FlowControl::Exception => done = true,
                FlowControl::UnconditionalBranch => {
                    done = true;
                    if is_call(ins, func) {
                        any_unknown = true;
                    } else {
                        queue.extend(branch_target(ins));
                    }
                }
                FlowControl::ConditionalBranch => {
                    done = true;
                    queue.push(ins.next_ip());
                    queue.extend(branch_target(ins));
                }
                _ => (any_unknown, done) = (true, true),
            }
        });
        if block_read > 0 {
            max_read = max_read.max(block_read);
            if max_read == 8 {
                return RegFate::Read(8);
            }
            continue;
        }
        if !done {
            any_unknown = true;
        }
    }
    if max_read > 0 {
        RegFate::Read(if any_unknown { 8 } else { max_read })
    } else if any_unknown {
        RegFate::Unknown
    } else {
        RegFate::Killed
    }
}
