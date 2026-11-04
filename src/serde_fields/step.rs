/*
 * XRef — Conservative transfer of register and stack field provenance
 * Copyright (c) 2026 Alexander Panasenko
 * Contact: alex@prod.codes
 * Author: https://prod.codes/about/
 * Project: https://github.com/alex09x/xref
 * SPDX-License-Identifier: MIT OR Apache-2.0
 */
use super::values::{MAX_SPILLS, Spill, State, Value, low_mask};
use crate::{
    expr::ABI_ARGS,
    image::{Image, Slot},
};
use iced_x86::{FlowControl, Instruction, InstructionInfoFactory, Mnemonic, OpAccess, OpKind, Register};

pub(super) const fn writes(access: OpAccess) -> bool {
    matches!(access, OpAccess::Write | OpAccess::CondWrite | OpAccess::ReadWrite | OpAccess::ReadCondWrite)
}
pub(super) const fn reads(access: OpAccess) -> bool {
    matches!(access, OpAccess::Read | OpAccess::CondRead | OpAccess::ReadWrite | OpAccess::ReadCondWrite)
}

fn load(image: &Image, input: &State, instruction: &Instruction) -> Option<Value> {
    let width = instruction.memory_size().size();
    if width == 0 {
        return None;
    }
    match input.address(instruction)? {
        Value::Input { argument, offset } => Some(Value::Loaded { argument, offset, width }),
        Value::Stack(position) => input
            .stack
            .get(&position)
            .filter(|spill| spill.width == width)
            .map(|spill| spill.value)
            .or_else(|| (width == 8).then_some(Value::StackCell(position))),
        Value::Constant(address) if width <= 8 => {
            address.checked_add(u64::try_from(width).ok()?)?;
            if width == 8
                && let Some(Slot::Pointer(pointer)) = image.slot(address)
            {
                return Some(Value::Constant(pointer));
            }
            let bytes = image.read(address, width)?;
            let mut bits = 0_u64;
            for (index, byte) in bytes.iter().enumerate() {
                bits |= u64::from(*byte) << (index * 8);
            }
            if matches!(instruction.mnemonic(), Mnemonic::Movsx | Mnemonic::Movsxd) && width < 8 {
                let shift = (8 - width) * 8;
                bits = ((bits << shift).cast_signed() >> shift).cast_unsigned();
            }
            Some(Value::Constant(bits))
        }
        _ => None,
    }
}

fn store(input: &State, output: &mut State, instruction: &Instruction) {
    let width = instruction.memory_size().size();
    match input.address(instruction) {
        Some(Value::Stack(position)) if width > 0 => {
            output.invalidate_stack(position, width);
            if instruction.mnemonic() != Mnemonic::Mov || width > 8 {
                return;
            }
            let Some(value) = input.operand(instruction, 1) else { return };
            if width < 8 && matches!(value, Value::Input { .. } | Value::Stack(_) | Value::StackCell(_)) {
                return;
            }
            if output.stack.len() < MAX_SPILLS {
                output.stack.insert(position, Spill { value, width });
            } else {
                output.limited = true;
            }
        }
        None if matches!(instruction.memory_base().full_register(), Register::RSP | Register::RBP) => {
            output.stack.clear();
        }
        _ => {}
    }
}

fn call(input: &State, output: &mut State, instruction: &Instruction, image: &Image) {
    for register in [
        Register::RAX,
        Register::RCX,
        Register::RDX,
        Register::RSI,
        Register::RDI,
        Register::R8,
        Register::R9,
        Register::R10,
        Register::R11,
    ] {
        output.set(register, None);
    }
    // CALL followed by a return preserves the caller's RSP; the red zone is volatile.
    output.set(Register::RSP, input.get(Register::RSP));
    if let Some(Value::Stack(position)) = input.get(Register::RSP) {
        output.stack.retain(|slot, _| *slot >= position);
    }
    let known = super::static_target(image, instruction).is_some_and(|target| image.function_at(target).is_some());
    for register in ABI_ARGS {
        if let Some(Value::Stack(position)) = input.get(register) {
            output.escaped_stack = true;
            if known {
                output.invalidate_stack(position, 8);
            } else {
                output.stack.clear();
            }
        }
    }
}

fn stack_instruction(input: &State, output: &mut State, instruction: &Instruction) -> bool {
    match instruction.mnemonic() {
        Mnemonic::Push => {
            let width = usize::try_from(instruction.stack_pointer_increment().unsigned_abs()).unwrap_or(0);
            if let Some(Value::Stack(position)) =
                input.get(Register::RSP).and_then(|value| value.add(i64::from(instruction.stack_pointer_increment())))
            {
                output.set(Register::RSP, Some(Value::Stack(position)));
                output.invalidate_stack(position, width);
                if let Some(value) = input.operand(instruction, 0)
                    && output.stack.len() < MAX_SPILLS
                {
                    output.stack.insert(position, Spill { value, width });
                } else if output.stack.len() >= MAX_SPILLS {
                    output.limited = true;
                }
            }
            true
        }
        Mnemonic::Pop => {
            let width = usize::try_from(instruction.stack_pointer_increment().unsigned_abs()).unwrap_or(0);
            if let Some(Value::Stack(position)) = input.get(Register::RSP) {
                let value = input
                    .stack
                    .get(&position)
                    .filter(|spill| spill.width == width && instruction.op0_register().size() == 8)
                    .map(|spill| spill.value);
                output.set(instruction.op0_register(), value);
                if instruction.op0_register() != Register::RSP {
                    output.set(
                        Register::RSP,
                        Value::Stack(position).add(i64::from(instruction.stack_pointer_increment())),
                    );
                }
            }
            true
        }
        Mnemonic::Leave => {
            if let Some(Value::Stack(position)) = input.get(Register::RBP) {
                output.set(Register::RSP, Value::Stack(position).add(8));
                output.set(Register::RBP, input.stack.get(&position).map(|spill| spill.value));
            }
            true
        }
        _ => false,
    }
}

pub(super) fn transfer(
    image: &Image,
    instruction: &Instruction,
    input: &State,
    factory: &mut InstructionInfoFactory,
) -> State {
    let mut output = input.clone();
    let info = factory.info(instruction);
    if instruction.op0_kind() == OpKind::Memory && writes(info.op_access(0)) {
        store(input, &mut output, instruction);
    }
    for used in info.used_registers() {
        if writes(used.access()) {
            output.set(used.register(), None);
        }
    }
    if matches!(instruction.flow_control(), FlowControl::Call | FlowControl::IndirectCall) {
        call(input, &mut output, instruction, image);
        return output;
    }
    if stack_instruction(input, &mut output, instruction) {
        return output;
    }
    if instruction.op0_kind() != OpKind::Register {
        return output;
    }
    let destination = instruction.op0_register();
    let value = match instruction.mnemonic() {
        Mnemonic::Mov | Mnemonic::Movzx | Mnemonic::Movsx | Mnemonic::Movsxd => {
            if instruction.op1_kind() == OpKind::Memory {
                load(image, input, instruction)
            } else {
                input.operand(instruction, 1)
            }
        }
        Mnemonic::Lea => input.address(instruction),
        Mnemonic::Add | Mnemonic::Sub => input.operand(instruction, 1).and_then(|operand| {
            let Value::Constant(bits) = operand else { return None };
            let displacement = if instruction.mnemonic() == Mnemonic::Sub {
                bits.cast_signed().checked_neg()?
            } else {
                bits.cast_signed()
            };
            input.get(destination).and_then(|prior| prior.add(displacement))
        }),
        Mnemonic::Xor if instruction.op1_kind() == OpKind::Register && destination == instruction.op1_register() => {
            Some(Value::Constant(0))
        }
        _ => None,
    };
    let value = value.and_then(|value| match value {
        _ if destination.size() < 4 => None,
        Value::Input { .. } | Value::Stack(_) | Value::StackCell(_) if destination.size() != 8 => None,
        Value::Constant(bits) => Some(Value::Constant(bits & low_mask(destination.size()))),
        _ => Some(value),
    });
    output.set(destination, value);
    output
}
