/*
 * XRef — CFG-meet facts for serialized input-relative fields
 * Copyright (c) 2026 Alexander Panasenko
 * Contact: alex@prod.codes
 * Author: https://prod.codes/about/
 * Project: https://github.com/alex09x/xref
 * SPDX-License-Identifier: MIT OR Apache-2.0
 */
use super::{
    model::CallWitness,
    step::{self, reads, writes},
    values::{ARG_ROOT_COUNT, LOAD_ROOT_START, MAX_LOAD_ROOTS, MAX_ROOTS, State, Value},
};
use crate::{api::FunctionFlow, expr::ABI_ARGS, image::Image, listing, scan};
use iced_x86::{Instruction, InstructionInfoFactory, Mnemonic, OpAccess, OpKind};
use std::{collections::VecDeque, ops::Range};

pub(super) const MAX_FUNCTION_BYTES: usize = 32768;

/// Largest function analysed under `max_instructions`: 8 bytes per instruction, at least
/// [`MAX_FUNCTION_BYTES`] (so the default 4096 keeps the 32 KiB limit).
#[must_use]
pub(super) const fn function_byte_limit(max_instructions: usize) -> usize {
    let bytes = max_instructions.saturating_mul(8);
    if bytes > MAX_FUNCTION_BYTES { bytes } else { MAX_FUNCTION_BYTES }
}
pub(super) const MAX_INSTRUCTIONS: usize = 4096;
const MAX_STEPS: usize = 131_072;
const MAX_CALLS: usize = 256;
const MAX_ACCESSES: usize = 512;

#[derive(Clone)]
pub(super) struct CallFact {
    pub index: usize,
    pub instruction: Instruction,
    pub destination: Option<u64>,
    pub arguments: [Option<Value>; 6],
    pub argument_spills: [Option<Value>; 6],
    pub escaped_stack: bool,
    pub witness: CallWitness,
}

#[derive(Clone)]
pub(super) struct AccessFact {
    pub index: usize,
    pub argument: usize,
    pub offset: i64,
    pub width: usize,
    pub instruction: Instruction,
    pub kind: &'static str,
    pub write: bool,
}

pub(super) struct Facts {
    pub range: Range<u64>,
    pub calls: Vec<CallFact>,
    pub accesses: Vec<AccessFact>,
    pub local_used: u8,
    pub limited: bool,
    pub stack_assumption: bool,
    pub flow: FunctionFlow,
    pub colons: Vec<(usize, Instruction)>,
    /// `(root, offset)` slots whose loaded 8-byte value is later used as a memory base in this function:
    /// the slot holds a pointer, not a scalar (#76 writer ranking).
    pub dereferenced: Vec<(usize, i64)>,
}

const MAX_DEREFERENCED: usize = 64;

/// The `(root, offset)` an 8-byte register load reads, mirroring when `step::load` mints a load root.
fn load_root_origin(instruction: &Instruction, state: &State) -> Option<(usize, i64)> {
    if !matches!(instruction.mnemonic(), Mnemonic::Mov | Mnemonic::Movzx | Mnemonic::Movsx | Mnemonic::Movsxd)
        || instruction.op0_kind() != OpKind::Register
        || instruction.op1_kind() != OpKind::Memory
        || instruction.memory_size().size() != 8
        || instruction.op0_register().size() != 8
    {
        return None;
    }
    match state.address(instruction)? {
        Value::Input { argument, offset } if argument < MAX_ROOTS => Some((argument, offset)),
        _ => None,
    }
}

/// Origin of each load-root slot. Load roots are numbered by instruction index modulo
/// `MAX_LOAD_ROOTS`, so several loads can share a slot while their pointers are all live. A slot is
/// attributed only when every load minting it reads the same `(root, offset)`; otherwise it is `None`
/// and a dereference through it marks nothing (#118 review: no penalty under ambiguity).
fn unique_load_origins(
    instructions: &[Instruction],
    states: &[Option<State>],
) -> [Option<(usize, i64)>; MAX_LOAD_ROOTS] {
    let mut seen = [None::<Option<(usize, i64)>>; MAX_LOAD_ROOTS];
    for (index, (instruction, state)) in instructions.iter().zip(states).enumerate() {
        let Some(state) = state else { continue };
        if let Some(origin) = load_root_origin(instruction, state) {
            let slot = &mut seen[index % MAX_LOAD_ROOTS];
            *slot = match *slot {
                None => Some(Some(origin)),
                Some(Some(previous)) if previous == origin => Some(Some(origin)),
                _ => Some(None),
            };
        }
    }
    seen.map(Option::flatten)
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum AnalysisFailure {
    NoCode,
    FunctionByteLimit,
    InstructionBudgetExceeded,
    UnsupportedFlow,
    DataflowUnavailable,
}

fn solve(image: &Image, instructions: &[Instruction], flow: &FunctionFlow) -> Option<Vec<Option<State>>> {
    let mut states = vec![None; instructions.len()];
    if states.is_empty() {
        return Some(states);
    }
    states[0] = Some(State::initial());
    let mut queue = VecDeque::from([0]);
    let mut queued = vec![false; instructions.len()];
    queued[0] = true;
    let mut steps = 0;
    let mut factory = InstructionInfoFactory::new();
    while let Some(index) = queue.pop_front() {
        queued[index] = false;
        steps += 1;
        if steps > MAX_STEPS {
            return None;
        }
        let Some(input) = &states[index] else { continue };
        let output = step::transfer(image, &instructions[index], input, &mut factory, index);
        for &next in &flow.successors[index] {
            let missing = states[next].is_none();
            let destination = states[next].get_or_insert_with(|| output.clone());
            let changed = missing || destination.meet(&output);
            if changed && !queued[next] {
                queue.push_back(next);
                queued[next] = true;
            }
        }
    }
    Some(states)
}

fn zero_idiom(instruction: &Instruction) -> bool {
    matches!(instruction.mnemonic(), Mnemonic::Xor | Mnemonic::Sub)
        && instruction.op0_kind() == OpKind::Register
        && instruction.op1_kind() == OpKind::Register
        && instruction.op0_register() == instruction.op1_register()
}

fn access(
    index: usize,
    instruction: &Instruction,
    state: &State,
    factory: &mut InstructionInfoFactory,
) -> Option<AccessFact> {
    let operand = (0..instruction.op_count()).find(|&index| instruction.op_kind(index) == OpKind::Memory)?;
    let Value::Input { argument, offset } = state.address(instruction)? else { return None };
    if argument >= MAX_ROOTS {
        return None;
    }
    let address = instruction.mnemonic() == Mnemonic::Lea;
    let mode = factory.info(instruction).op_access(operand);
    if !address && !reads(mode) && !writes(mode) {
        return None;
    }
    let kind = if address {
        "address"
    } else if mode == OpAccess::ReadCondWrite {
        "read_conditional_write"
    } else if mode == OpAccess::CondWrite {
        "conditional_write"
    } else if mode == OpAccess::CondRead {
        "conditional_read"
    } else if reads(mode) && writes(mode) {
        "read_write"
    } else if writes(mode) {
        "write"
    } else {
        "read"
    };
    Some(AccessFact {
        index,
        argument,
        offset,
        width: if address { 0 } else { instruction.memory_size().size() },
        instruction: *instruction,
        kind,
        write: writes(mode) && !address,
    })
}

fn call(image: &Image, instruction: &Instruction, index: usize, state: &State, range: &Range<u64>) -> Option<CallFact> {
    if !listing::is_call(instruction, range) {
        return None;
    }
    let arguments = std::array::from_fn(|index| state.get(ABI_ARGS[index]));
    let argument_spills = std::array::from_fn(|index| match arguments[index] {
        Some(Value::Stack(position)) => state.stack.get(&position).map(|spill| spill.value),
        _ => None,
    });
    let raw_target = super::static_target(image, instruction);
    let destination =
        raw_target.and_then(|target| image.function_at(target).filter(|f| f.start == target).map(|f| f.start));
    Some(CallFact {
        index,
        instruction: *instruction,
        destination,
        arguments,
        argument_spills,
        escaped_stack: state.escaped_stack,
        witness: CallWitness {
            function: format!("{:#x}", range.start),
            instruction: format!("{:#x}", instruction.ip()),
            assembly: scan::format(instruction),
            target: raw_target.map(|target| format!("{target:#x}")),
            role: "key_value_call",
        },
    })
}

impl Facts {
    #[cfg(test)]
    pub fn analyze(image: &Image, range: &Range<u64>) -> Option<Self> {
        Self::analyze_with_instruction_limit(image, range, MAX_INSTRUCTIONS).ok()
    }

    pub fn analyze_with_instruction_limit(
        image: &Image,
        range: &Range<u64>,
        max_instructions: usize,
    ) -> Result<Self, AnalysisFailure> {
        let code = image.code(range).ok_or(AnalysisFailure::NoCode)?;
        if code.len() > function_byte_limit(max_instructions) {
            return Err(AnalysisFailure::FunctionByteLimit);
        }
        let mut instructions = Vec::new();
        scan::decode(code, range.start, |instruction| instructions.push(*instruction));
        if instructions.len() > max_instructions {
            return Err(AnalysisFailure::InstructionBudgetExceeded);
        }
        let flow = FunctionFlow::new(&instructions, image, range);
        if flow.incomplete {
            return Err(AnalysisFailure::UnsupportedFlow);
        }
        let states = solve(image, &instructions, &flow).ok_or(AnalysisFailure::DataflowUnavailable)?;
        let mut result = Self {
            range: range.clone(),
            calls: vec![],
            accesses: vec![],
            local_used: 0,
            limited: false,
            stack_assumption: false,
            flow,
            colons: vec![],
            dereferenced: vec![],
        };
        let load_origins = unique_load_origins(&instructions, &states);
        let mut factory = InstructionInfoFactory::new();
        for (index, (instruction, input)) in instructions.iter().zip(states.iter()).enumerate() {
            let Some(state) = input else { continue };
            result.limited |= state.limited;
            result.stack_assumption |= state.escaped_stack;
            if !zero_idiom(instruction) {
                for used in factory.info(instruction).used_registers() {
                    if reads(used.access())
                        && let Some(argument) = state.get(used.register().full_register()).and_then(Value::argument)
                        && argument < ARG_ROOT_COUNT
                    {
                        result.local_used |= 1_u8 << argument;
                    }
                }
            }
            if instruction.mnemonic() != Mnemonic::Lea
                && let Some(Value::Input { argument, .. }) = state.address(instruction)
                && let Some(origin) = argument.checked_sub(LOAD_ROOT_START).and_then(|slot| load_origins.get(slot))
                && let Some(origin) = *origin
                && !result.dereferenced.contains(&origin)
                && result.dereferenced.len() < MAX_DEREFERENCED
            {
                result.dereferenced.push(origin);
            }
            if let Some(witness) = access(index, instruction, state, &mut factory) {
                if result.accesses.len() < MAX_ACCESSES {
                    result.accesses.push(witness);
                } else {
                    result.limited = true;
                }
            }
            if instruction.mnemonic() == Mnemonic::Mov
                && instruction.op0_kind() == OpKind::Memory
                && instruction.memory_size().size() == 1
                && state.operand(instruction, 1) == Some(Value::Constant(0x3a))
            {
                if result.colons.len() < 32 {
                    result.colons.push((index, *instruction));
                } else {
                    result.limited = true;
                }
            }
            if let Some(witness) = call(image, instruction, index, state, range) {
                if result.calls.len() < MAX_CALLS {
                    result.calls.push(witness);
                } else {
                    result.limited = true;
                }
            }
        }
        Ok(result)
    }
    pub fn argument_register(index: usize) -> String {
        if index < ARG_ROOT_COUNT {
            ABI_ARGS
                .get(index)
                .map_or_else(|| "unknown".to_owned(), |register| format!("{register:?}").to_ascii_lowercase())
        } else if index < LOAD_ROOT_START {
            "rax".to_owned()
        } else if index < MAX_ROOTS {
            "loaded_ptr".to_owned()
        } else {
            "unknown".to_owned()
        }
    }
}
