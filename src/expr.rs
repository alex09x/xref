/*
 * xref — Ultra blazing fast cross-references of an x86-64 ELF binary
 * Copyright (c) 2026 Alexander Panasenko
 *
 * Contact: alex@prod.codes
 * Author: https://prod.codes/about/
 * SPDX-License-Identifier: MIT OR Apache-2.0
 */

//! Symbolic expressions, operands, condition codes and ABI parameter recovery for pseudo-C lifting.

use std::collections::HashMap;
use std::ops::Range;

use iced_x86::{
    ConditionCode, FlowControl, Instruction, InstructionInfoFactory, MemorySize, Mnemonic, OpAccess, OpKind, Register,
};

use crate::image::{Image, Slot};
use crate::locations::Location;
use crate::scan::decode;
use crate::source::location_at;

pub const ABI_ARGS: [Register; 6] =
    [Register::RDI, Register::RSI, Register::RDX, Register::RCX, Register::R8, Register::R9];
pub const CALLEE_SAVED: [Register; 6] =
    [Register::RBX, Register::RBP, Register::R12, Register::R13, Register::R14, Register::R15];
pub const IGNORED: [Mnemonic; 8] = [
    Mnemonic::Push,
    Mnemonic::Pop,
    Mnemonic::Nop,
    Mnemonic::Endbr64,
    Mnemonic::Leave,
    Mnemonic::Cqo,
    Mnemonic::Cdqe,
    Mnemonic::Cdq,
];
pub const MOVES: [Mnemonic; 10] = [
    Mnemonic::Mov,
    Mnemonic::Movzx,
    Mnemonic::Movsxd,
    Mnemonic::Movaps,
    Mnemonic::Movups,
    Mnemonic::Movsd,
    Mnemonic::Movss,
    Mnemonic::Movdqa,
    Mnemonic::Movdqu,
    Mnemonic::Lea,
];
pub const BIN_OPS: &[(Mnemonic, &str)] = &[
    (Mnemonic::Add, "+"),
    (Mnemonic::Sub, "-"),
    (Mnemonic::And, "&"),
    (Mnemonic::Or, "|"),
    (Mnemonic::Xor, "^"),
    (Mnemonic::Shl, "<<"),
    (Mnemonic::Shr, ">>"),
    (Mnemonic::Sar, ">>"),
    (Mnemonic::Imul, "*"),
];
pub const UNARY_OPS: &[(Mnemonic, &str, &str)] = &[
    (Mnemonic::Inc, "(", " + 1)"),
    (Mnemonic::Dec, "(", " - 1)"),
    (Mnemonic::Neg, "(-", ")"),
    (Mnemonic::Not, "(~", ")"),
    (Mnemonic::Bswap, "__builtin_bswap64(", ")"),
    (Mnemonic::Tzcnt, "__builtin_ctzll(", ")"),
    (Mnemonic::Lzcnt, "__builtin_clzll(", ")"),
    (Mnemonic::Popcnt, "__builtin_popcountll(", ")"),
];

const SCRATCH: [Register; 9] = [
    Register::RAX,
    Register::RCX,
    Register::RDX,
    Register::RSI,
    Register::RDI,
    Register::R8,
    Register::R9,
    Register::R10,
    Register::R11,
];

const MEM_TYPES: &[(MemorySize, &str)] = &[
    (MemorySize::UInt8, "u8"),
    (MemorySize::Int8, "u8"),
    (MemorySize::UInt16, "u16"),
    (MemorySize::Int16, "u16"),
    (MemorySize::UInt32, "u32"),
    (MemorySize::Int32, "u32"),
    (MemorySize::DwordOffset, "u32"),
];

const CC_OPS: &[(ConditionCode, &str, bool)] = &[
    (ConditionCode::e, "==", false),
    (ConditionCode::ne, "!=", false),
    (ConditionCode::b, "<", false),
    (ConditionCode::ae, ">=", false),
    (ConditionCode::be, "<=", false),
    (ConditionCode::a, ">", false),
    (ConditionCode::l, "<", true),
    (ConditionCode::ge, ">=", true),
    (ConditionCode::le, "<=", true),
    (ConditionCode::g, ">", true),
    (ConditionCode::s, "<", true),
    (ConditionCode::ns, ">=", true),
];

#[derive(Default)]
pub struct State {
    pub regs: HashMap<Register, String>,
    pub stack: HashMap<i64, String>,
    pub dirty: Vec<Register>,
    pub flags: Option<(String, String)>,
    pub switch_idx: Option<String>,
    pub last_str: Option<(Register, u64)>,
}

impl State {
    pub fn reg(&mut self, reg: Register) -> String {
        let full = reg.full_register();
        self.dirty.retain(|r| *r != full);
        self.regs.get(&full).cloned().unwrap_or_else(|| reg_name(full))
    }

    pub fn set_reg(&mut self, reg: Register, value: String) {
        let full = reg.full_register();
        self.dirty.retain(|r| *r != full);
        self.dirty.push(full);
        self.regs.insert(full, value);
    }

    pub fn clear_scratch(&mut self) {
        for reg in SCRATCH {
            self.regs.remove(&reg);
        }
        self.dirty.clear();
        self.last_str = None;
    }
}

pub fn reg_name(reg: Register) -> String {
    format!("{:?}", reg.full_register()).to_ascii_lowercase()
}

pub fn stack_name(disp: i64) -> String {
    if disp >= 0 { format!("sp_{disp:x}") } else { format!("sp_m{:x}", disp.unsigned_abs()) }
}

pub fn num(val: u64) -> String {
    let signed = val.cast_signed();
    if (-64..=1024).contains(&signed) { format!("{signed}") } else { format!("{val:#x}") }
}

pub fn mem_type(size: MemorySize) -> &'static str {
    MEM_TYPES.iter().find(|(s, _)| *s == size).map_or("u64", |(_, name)| *name)
}

pub fn describe_rip(image: &Image, locations: &[Location], place: u64, is_lea: bool, size: MemorySize) -> String {
    if let Some(loc) = location_at(locations, place) {
        return format!("\"{}:{}:{}\"", loc.file, loc.line, loc.col);
    }
    if image.function_at(place).is_some() {
        return format!("fn_{place:x}");
    }
    match image.slot(place) {
        Some(Slot::Import(name)) => return name.to_owned(),
        Some(Slot::Pointer(target)) if is_lea || size == MemorySize::UInt64 => {
            if image.function_at(target).is_some() {
                return format!("fn_{target:x}");
            }
            return image.preview(target).map_or_else(|| format!("{target:#x}"), |text| format!("{text:?}"));
        }
        _ => {}
    }
    if is_lea && let Some(text) = image.preview(place) {
        return format!("{text:?}");
    }
    if is_lea { format!("{place:#x}") } else { format!("*({} *){place:#x}", mem_type(size)) }
}

pub fn mem_expr(image: &Image, locations: &[Location], state: &mut State, instruction: &Instruction) -> String {
    let is_lea = instruction.mnemonic() == Mnemonic::Lea;
    if instruction.is_ip_rel_memory_operand() {
        return describe_rip(image, locations, instruction.ip_rel_memory_address(), is_lea, instruction.memory_size());
    }
    let base = instruction.memory_base();
    let index = instruction.memory_index();
    let disp = instruction.memory_displacement64().cast_signed();
    if base.full_register() == Register::RSP && index == Register::None {
        let slot = stack_name(disp);
        return if is_lea { format!("&{slot}") } else { state.stack.get(&disp).cloned().unwrap_or(slot) };
    }
    let ty = mem_type(instruction.memory_size());
    if base != Register::None && index != Register::None && disp == 0 && !is_lea {
        let b = state.reg(base);
        let i = state.reg(index);
        return format!("(({ty} *){b})[{i}]");
    }
    let mut parts = Vec::new();
    if base != Register::None {
        parts.push(state.reg(base));
    }
    if index != Register::None {
        let i = state.reg(index);
        let scale = instruction.memory_index_scale();
        parts.push(if scale > 1 { format!("{i} * {scale}") } else { i });
    }
    let mut addr = parts.join(" + ");
    if disp > 0 || addr.is_empty() {
        let d = num(disp.cast_unsigned());
        addr = if addr.is_empty() { d } else { format!("{addr} + {d}") };
    } else if disp < 0 {
        addr = format!("{addr} - {}", num(disp.unsigned_abs()));
    }
    if is_lea { addr } else { format!("*({ty} *)({addr})") }
}

pub fn op_expr(
    image: &Image,
    locations: &[Location],
    state: &mut State,
    instruction: &Instruction,
    operand: u32,
) -> String {
    match instruction.op_kind(operand) {
        OpKind::Register => state.reg(instruction.op_register(operand)),
        OpKind::Memory => mem_expr(image, locations, state, instruction),
        _ => num(instruction.immediate(operand)),
    }
}

pub fn cond_expr(cc: ConditionCode, flags: Option<&(String, String)>) -> String {
    let Some((lhs, rhs)) = flags else {
        return format!("cc_{cc:?}").to_ascii_lowercase();
    };
    let Some((_, op, signed)) = CC_OPS.iter().find(|(c, _, _)| *c == cc) else {
        return format!("{lhs} ? {rhs}");
    };
    if *signed {
        let r = if rhs == "0" { "0".to_owned() } else { format!("(i64){rhs}") };
        format!("(i64){lhs} {op} {r}")
    } else {
        format!("{lhs} {op} {rhs}")
    }
}

pub fn neg_cond_expr(cc: ConditionCode, flags: Option<&(String, String)>) -> String {
    let inv = CC_OPS.iter().position(|(c, _, _)| *c == cc).map_or(cc, |i| CC_OPS[i ^ 1].0);
    cond_expr(inv, flags)
}

/// ABI argument registers read before being written in the entry block of `function`.
pub fn params(image: &Image, function: &Range<u64>) -> Vec<Register> {
    let Some(bytes) = image.code(function) else { return Vec::new() };
    let mut factory = InstructionInfoFactory::new();
    let mut written = Vec::new();
    let mut read = Vec::new();
    let mut stopped = false;
    decode(bytes, function.start, |instruction| {
        if stopped {
            return;
        }
        if matches!(instruction.mnemonic(), Mnemonic::Xor | Mnemonic::Sub)
            && instruction.op0_kind() == OpKind::Register
            && instruction.op1_kind() == OpKind::Register
            && instruction.op0_register() == instruction.op1_register()
        {
            written.push(instruction.op0_register().full_register());
            return;
        }
        for used in factory.info(instruction).used_registers() {
            let full = used.register().full_register();
            if ABI_ARGS.contains(&full) {
                if matches!(
                    used.access(),
                    OpAccess::Read | OpAccess::CondRead | OpAccess::ReadWrite | OpAccess::ReadCondWrite
                ) && !written.contains(&full)
                    && !read.contains(&full)
                {
                    read.push(full);
                }
                if matches!(
                    used.access(),
                    OpAccess::Write | OpAccess::CondWrite | OpAccess::ReadWrite | OpAccess::ReadCondWrite
                ) && !written.contains(&full)
                {
                    written.push(full);
                }
            }
        }
        if instruction.flow_control() != FlowControl::Next {
            stopped = true;
        }
    });
    ABI_ARGS.into_iter().filter(|reg| read.contains(reg)).collect()
}

#[cfg(test)]
mod tests {
    use super::{State, cond_expr, describe_rip, mem_type, neg_cond_expr, num, op_expr, params, reg_name, stack_name};
    use crate::image::{Image, Segment};
    use crate::locations::Location;
    use crate::scan::decode;
    use iced_x86::{ConditionCode, MemorySize, Register};

    fn one(bytes: &[u8]) -> iced_x86::Instruction {
        let mut ins = iced_x86::Instruction::default();
        decode(bytes, 0x1000, |decoded| ins = *decoded);
        ins
    }

    fn sample_image() -> Image {
        let mut data = vec![0u8; 0x300];
        data[0x100..0x109].copy_from_slice(b"hello txt");
        // At 0x200: xor edi, edi; add rax, rsi; ret; nop
        data[0x200..0x207].copy_from_slice(&[0x31, 0xff, 0x48, 0x01, 0xf0, 0xc3, 0x90]);
        Image {
            data,
            segments: vec![Segment { va: 0x1000, offset: 0, size: 0x300 }],
            functions: std::iter::once(0x1200..0x1207).collect(),
            pointers: vec![(0x1050, 0x1100), (0x1060, 0x1200), (0x1070, 0x1010)],
            imports: vec![(0x1040, "puts".to_owned())],
            symbols: Vec::new(),
        }
    }

    #[test]
    fn registers_numbers_stack_and_rip_descriptions_format_cleanly() {
        let image = sample_image();
        let locs = [Location { place: 0x1080, file: "src/lib.rs".to_owned(), line: 10, col: 2 }];
        assert_eq!(reg_name(Register::EAX), "rax");
        assert_eq!(stack_name(0x18), "sp_18");
        assert_eq!(stack_name(-8), "sp_m8");
        assert_eq!(num(9), "9");
        assert_eq!(num(0x4000), "0x4000");
        assert_eq!(mem_type(MemorySize::UInt8), "u8");
        assert_eq!(mem_type(MemorySize::UInt64), "u64");
        assert_eq!(describe_rip(&image, &locs, 0x1080, true, MemorySize::UInt64), "\"src/lib.rs:10:2\"");
        assert_eq!(describe_rip(&image, &locs, 0x1200, true, MemorySize::UInt64), "fn_1200");
        assert_eq!(describe_rip(&image, &locs, 0x1040, false, MemorySize::UInt64), "puts");
        assert_eq!(describe_rip(&image, &locs, 0x1050, false, MemorySize::UInt64), "\"hello txt\"");
        assert_eq!(describe_rip(&image, &locs, 0x1060, false, MemorySize::UInt64), "fn_1200");
        assert_eq!(describe_rip(&image, &locs, 0x1070, false, MemorySize::UInt64), "0x1010");
        assert_eq!(describe_rip(&image, &locs, 0x1070, false, MemorySize::UInt8), "*(u8 *)0x1070");
        assert_eq!(describe_rip(&image, &locs, 0x1100, true, MemorySize::UInt64), "\"hello txt\"");
        assert_eq!(describe_rip(&image, &locs, 0x1010, true, MemorySize::UInt64), "0x1010");
        assert_eq!(describe_rip(&image, &locs, 0x1010, false, MemorySize::UInt32), "*(u32 *)0x1010");
    }

    #[test]
    fn memory_operands_conditions_and_params_cover_all_forms() {
        let image = sample_image();
        let mut state = State::default();
        state.set_reg(Register::RDI, "arg0".to_owned());
        state.stack.insert(8, "saved".to_owned());
        // mov rax, [rsp + 8]; lea rax, [rsp + 8]; mov rax, [rdi + rsi*8]; mov eax, [rdi + rsi*4 + 16]; mov eax, [rdi - 8]; mov eax, [0x2000]
        assert_eq!(op_expr(&image, &[], &mut state, &one(&[0x48, 0x8b, 0x44, 0x24, 0x08]), 1), "saved");
        assert_eq!(op_expr(&image, &[], &mut state, &one(&[0x48, 0x8d, 0x44, 0x24, 0x08]), 1), "&sp_8");
        assert_eq!(op_expr(&image, &[], &mut state, &one(&[0x48, 0x8b, 0x04, 0xf7]), 1), "((u64 *)arg0)[rsi]");
        assert_eq!(
            op_expr(&image, &[], &mut state, &one(&[0x8b, 0x44, 0xb7, 0x10]), 1),
            "*(u32 *)(arg0 + rsi * 4 + 16)"
        );
        assert_eq!(op_expr(&image, &[], &mut state, &one(&[0x48, 0x8d, 0x44, 0x37, 0x10]), 1), "arg0 + rsi + 16");
        assert_eq!(op_expr(&image, &[], &mut state, &one(&[0x8b, 0x47, 0xf8]), 1), "*(u32 *)(arg0 - 8)");
        assert_eq!(
            op_expr(&image, &[], &mut state, &one(&[0x8b, 0x04, 0x25, 0x00, 0x20, 0x00, 0x00]), 1),
            "*(u32 *)(0x2000)"
        );
        assert_eq!(
            op_expr(&image, &[], &mut state, &one(&[0x48, 0x8d, 0x05, 0xf9, 0x00, 0x00, 0x00]), 1),
            "\"hello txt\""
        );
        assert_eq!(op_expr(&image, &[], &mut state, &one(&[0xb8, 0x05, 0x00, 0x00, 0x00]), 1), "5");
        state.clear_scratch();
        let flags = ("a".to_owned(), "0".to_owned());
        let two = ("a".to_owned(), "b".to_owned());
        assert_eq!(cond_expr(ConditionCode::e, Some(&flags)), "a == 0");
        assert_eq!(neg_cond_expr(ConditionCode::e, Some(&flags)), "a != 0");
        assert_eq!(cond_expr(ConditionCode::l, Some(&flags)), "(i64)a < 0");
        assert_eq!(cond_expr(ConditionCode::g, Some(&two)), "(i64)a > (i64)b");
        assert_eq!(cond_expr(ConditionCode::p, Some(&flags)), "a ? 0");
        assert_eq!(cond_expr(ConditionCode::e, None), "cc_e");
        assert_eq!(params(&image, &(0x1200..0x1207)), vec![Register::RSI]);
        assert!(params(&image, &(0x9000..0x9010)).is_empty());
    }
}
