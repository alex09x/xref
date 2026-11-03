/*
 * xref — Ultra blazing fast cross-references of an x86-64 ELF binary
 * Copyright (c) 2026 Alexander Panasenko
 *
 * Contact: alex@prod.codes
 * Author: https://prod.codes/about/
 * Project: https://github.com/alex09x/xref
 * SPDX-License-Identifier: MIT OR Apache-2.0
 */

//! Symbolic expressions, operands, and stack/TLS addressing for pseudo-C lifting.

use std::collections::HashMap;

use iced_x86::{Instruction, MemorySize, Mnemonic, OpKind, Register};

pub use crate::cond::{FlagOp, Flags, cond_expr, neg_cond_expr};
use crate::image::{Image, Slot};
use crate::locations::Location;
use crate::reduce::trim_parens;
use crate::simplify::simplify_linear;
use crate::source::location_at;

pub const ABI_ARGS: [Register; 6] =
    [Register::RDI, Register::RSI, Register::RDX, Register::RCX, Register::R8, Register::R9];
pub const CALLEE_SAVED: [Register; 6] =
    [Register::RBX, Register::RBP, Register::R12, Register::R13, Register::R14, Register::R15];
pub const IGNORED: [Mnemonic; 3] = [Mnemonic::Nop, Mnemonic::Endbr64, Mnemonic::Leave];
pub const MOVES: [Mnemonic; 11] = [
    Mnemonic::Mov,
    Mnemonic::Movzx,
    Mnemonic::Movsx,
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

#[derive(Default)]
pub struct State {
    pub regs: HashMap<Register, String>,
    pub inline_regs: HashMap<Register, String>,
    pub stack: HashMap<i64, String>,
    pub dirty: Vec<Register>,
    pub pushed: Vec<String>,
    pub noted_callees: Vec<u64>,
    pub flags: Option<Flags>,
    pub switch_idx: Option<String>,
    pub rodata_ptrs: HashMap<Register, u64>,
    pub const_saved: HashMap<Register, String>,
    pub fn_saved: HashMap<Register, String>,
    pub arg_base_rsp: Option<i64>,
    pub cur_norm_sp: Option<i64>,
    pub uses_fp: bool,
    pub in_prologue: bool,
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
            self.rodata_ptrs.remove(&reg);
        }
        self.inline_regs.clear();
        self.dirty.clear();
        self.pushed.clear();
    }
}

pub fn reg_name(reg: Register) -> String {
    format!("{:?}", reg.full_register()).to_ascii_lowercase()
}

pub fn stack_name(disp: i64) -> String {
    if disp >= 0 { format!("slot_{disp:x}") } else { format!("slot_m{:x}", disp.unsigned_abs()) }
}

pub fn wrap_unary(pre: &str, val: &str, post: &str) -> String {
    if matches!(pre, "(-" | "(~") && val.contains(' ') && trim_parens(val) == val {
        format!("{pre}({val}){post}")
    } else {
        format!("{pre}{val}{post}")
    }
}

pub fn num(val: u64) -> String {
    let signed = val.cast_signed();
    if (-64..=1024).contains(&signed) { format!("{signed}") } else { format!("{val:#x}") }
}

pub fn mem_type(size: MemorySize) -> &'static str {
    if size.size() == 16 {
        return "u128";
    }
    MEM_TYPES.iter().find(|(s, _)| *s == size).map_or("u64", |(_, name)| *name)
}

pub fn describe_rip(image: &Image, locations: &[Location], place: u64, is_lea: bool, size: MemorySize) -> String {
    if let Some(loc) = location_at(locations, place) {
        return format!("\"{}:{}:{}\"", crate::callee_meta::sanitize_panic_path(&loc.file), loc.line, loc.col);
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
            if let Some((text, true)) = image.rodata_preview(target) {
                return format!("{text:?}");
            }
            return format!("{target:#x}");
        }
        _ => {}
    }
    if is_lea && let Some((text, true)) = image.rodata_preview(place) {
        return format!("{text:?}");
    }
    if is_lea { format!("{place:#x}") } else { format!("*({} *){place:#x}", mem_type(size)) }
}

fn caller_arg_name(state: &State, base: Register, disp: i64) -> Option<String> {
    let idx = if state.uses_fp && base == Register::RBP && disp >= 0x10 && (disp - 0x10) % 8 == 0 {
        (disp - 0x10) / 8
    } else if let Some(ab) = state.arg_base_rsp
        && base == Register::RSP
        && disp >= ab
        && (disp - ab) % 8 == 0
        && !state.stack.contains_key(&disp)
    {
        (disp - ab) / 8
    } else {
        return None;
    };
    (idx < 8).then(|| format!("arg_{}", 6 + idx))
}

pub fn mem_expr(image: &Image, locations: &[Location], state: &mut State, instruction: &Instruction) -> String {
    let is_lea = instruction.mnemonic() == Mnemonic::Lea;
    if instruction.is_ip_rel_memory_operand() {
        return describe_rip(image, locations, instruction.ip_rel_memory_address(), is_lea, instruction.memory_size());
    }
    let seg = match instruction.segment_prefix() {
        Register::FS => Some("fs:"),
        Register::GS => Some("gs:"),
        _ => None,
    };
    let base = instruction.memory_base();
    let index = instruction.memory_index();
    let disp = instruction.memory_displacement64().cast_signed();
    if seg.is_none()
        && !is_lea
        && index == Register::None
        && let Some(arg) = caller_arg_name(state, base.full_register(), disp)
    {
        return arg;
    }
    if seg.is_none()
        && index == Register::None
        && (base.full_register() == Register::RSP
            || (state.uses_fp && base.full_register() == Register::RBP && state.cur_norm_sp.is_some()))
    {
        let norm = state.cur_norm_sp.unwrap_or(disp);
        let slot = stack_name(norm);
        return if is_lea { format!("&{slot}") } else { state.stack.get(&norm).cloned().unwrap_or(slot) };
    }
    let ty = mem_type(instruction.memory_size());
    let (msz, scale) = (instruction.memory_size().size(), i64::from(instruction.memory_index_scale()));
    if seg.is_none()
        && base != Register::None
        && index != Register::None
        && !is_lea
        && ((msz == 1 && scale == 1 && disp == 0) || (msz == 8 && scale == 8 && disp % 8 == 0))
    {
        let (b, i) = (state.reg(base), state.reg(index));
        let elem_off = if scale > 0 { disp / scale } else { 0 };
        let idx = match elem_off.cmp(&0) {
            std::cmp::Ordering::Greater => simplify_linear(&format!("{i} + {}", num(elem_off.cast_unsigned()))),
            std::cmp::Ordering::Less => simplify_linear(&format!("{i} - {}", num(elem_off.unsigned_abs()))),
            std::cmp::Ordering::Equal => i,
        };
        return format!("(({ty} *){b})[{idx}]");
    }
    let mut parts = Vec::new();
    if base != Register::None {
        parts.push(state.reg(base));
    }
    if index != Register::None {
        let i = state.reg(index);
        let scale = instruction.memory_index_scale();
        let wrapped = if scale > 1 && i.contains(' ') && trim_parens(&i) == i { format!("({i})") } else { i };
        parts.push(if scale > 1 { format!("{wrapped} * {scale}") } else { wrapped });
    }
    let mut addr = parts.join(" + ");
    if disp > 0 || addr.is_empty() {
        let d = num(disp.cast_unsigned());
        addr = if addr.is_empty() { d } else { format!("{addr} + {d}") };
    } else if disp < 0 {
        addr = format!("{addr} - {}", num(disp.unsigned_abs()));
    }
    let addr = simplify_linear(&addr);
    let prefixed = seg.map_or_else(|| addr.clone(), |p| format!("{p}{addr}"));
    if is_lea { prefixed } else { format!("*({ty} *)({prefixed})") }
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

#[cfg(test)]
mod tests {
    use super::{Flags, State, cond_expr, describe_rip, mem_type, neg_cond_expr, num, op_expr, reg_name, stack_name};
    use crate::image::{Image, Segment};
    use crate::locations::Location;
    use crate::scan::decode;
    use iced_x86::{ConditionCode, MemorySize, Register};

    fn one(bytes: &[u8]) -> iced_x86::Instruction {
        let mut ins = iced_x86::Instruction::default();
        decode(bytes, 0x1000, |decoded| ins = *decoded);
        ins
    }

    #[test]
    fn registers_memory_operands_tls_caller_args_and_conditions() {
        let mut data = vec![0u8; 0x300];
        data[0x100..0x109].copy_from_slice(b"hello txt");
        data[0x200..0x207].copy_from_slice(&[0x31, 0xff, 0x48, 0x01, 0xf0, 0xc3, 0x90]);
        let image = Image {
            data,
            segments: vec![Segment { va: 0x1000, offset: 0, size: 0x300 }],
            functions: std::iter::once(0x1200..0x1207).collect(),
            pointers: vec![(0x1050, 0x1100), (0x1060, 0x1200), (0x1070, 0x1010)],
            imports: vec![(0x1040, "puts".to_owned())],
            symbols: Vec::new(),
            metadata: crate::image_format::Metadata::default(),
        };
        let locs = [Location { place: 0x1080, file: "src/lib.rs".to_owned(), line: 10, col: 2 }];
        assert_eq!(reg_name(Register::EAX), "rax");
        assert_eq!((stack_name(0x18), stack_name(-8)), ("slot_18".to_owned(), "slot_m8".to_owned()));
        assert_eq!(super::wrap_unary("(-", "rsi == 43", ")"), "(-(rsi == 43))");
        assert_eq!((num(9), num(0x4000)), ("9".to_owned(), "0x4000".to_owned()));
        assert_eq!((mem_type(MemorySize::UInt8), mem_type(MemorySize::UInt64)), ("u8", "u64"));
        assert_eq!(mem_type(MemorySize::UInt128), "u128");
        for (place, lea, sz, exp) in [
            (0x1080, true, MemorySize::UInt64, "\"src/lib.rs:10:2\""),
            (0x1200, true, MemorySize::UInt64, "fn_1200"),
            (0x1040, false, MemorySize::UInt64, "puts"),
            (0x1050, false, MemorySize::UInt64, "\"hello txt\""),
            (0x1060, false, MemorySize::UInt64, "fn_1200"),
            (0x1070, false, MemorySize::UInt64, "0x1010"),
            (0x1070, false, MemorySize::UInt8, "*(u8 *)0x1070"),
            (0x1100, true, MemorySize::UInt64, "\"hello txt\""),
            (0x1010, true, MemorySize::UInt64, "0x1010"),
            (0x1010, false, MemorySize::UInt32, "*(u32 *)0x1010"),
        ] {
            assert_eq!(describe_rip(&image, &locs, place, lea, sz), exp);
        }
        let mut state = State { arg_base_rsp: Some(0x20), ..State::default() };
        state.set_reg(Register::RDI, "arg0".to_owned());
        state.set_reg(Register::RCX, "r9 * 3".to_owned());
        state.rodata_ptrs.insert(Register::RAX, 0x1100);
        state.stack.insert(8, "saved".to_owned());
        for (bytes, exp) in [
            (&[0x48, 0x8b, 0x44, 0x24, 0x08][..], "saved"),
            (&[0x48, 0x8b, 0x44, 0x24, 0x20], "arg_6"),
            (&[0x48, 0x8d, 0x44, 0x24, 0x08], "&slot_8"),
            (&[0x48, 0x8b, 0x04, 0xf7], "((u64 *)arg0)[rsi]"),
            (&[0x48, 0x8d, 0x04, 0xc8], "rax + r9 * 24"),
            (&[0x8b, 0x44, 0xb7, 0x10], "*(u32 *)(arg0 + rsi * 4 + 16)"),
            (&[0x48, 0x8d, 0x44, 0x37, 0x10], "arg0 + rsi + 16"),
            (&[0x8b, 0x47, 0xf8], "*(u32 *)(arg0 - 8)"),
            (&[0x64, 0x48, 0x8b, 0x04, 0x25, 0x00, 0x00, 0x00, 0x00], "*(u64 *)(fs:0)"),
            (&[0x65, 0x48, 0x8b, 0x04, 0x25, 0x08, 0x00, 0x00, 0x00], "*(u64 *)(gs:8)"),
            (&[0x8b, 0x04, 0x25, 0x00, 0x20, 0x00, 0x00], "*(u32 *)(0x2000)"),
            (&[0x48, 0x8d, 0x05, 0xf9, 0x00, 0x00, 0x00], "\"hello txt\""),
            (&[0xb8, 0x05, 0x00, 0x00, 0x00], "5"),
        ] {
            assert_eq!(op_expr(&image, &[], &mut state, &one(bytes), 1), exp);
        }
        state.uses_fp = true;
        assert_eq!(op_expr(&image, &[], &mut state, &one(&[0x48, 0x8b, 0x45, 0x10]), 1), "arg_6");
        state.clear_scratch();
        assert!(state.rodata_ptrs.is_empty());
        let (flags, two, cmp3) = (
            Flags::test("a".to_owned()),
            Flags::cmp("a".to_owned(), "b".to_owned()),
            Flags::cmp("((i64)rax > 0 - rcx)".to_owned(), "1".to_owned()),
        );
        for (got, exp) in [
            (cond_expr(ConditionCode::e, Some(&flags)), "a == 0"),
            (cond_expr(ConditionCode::e, Some(&cmp3)), "(i64)rax > 0"),
            (cond_expr(ConditionCode::ne, Some(&cmp3)), "!((i64)rax > 0)"),
            (neg_cond_expr(ConditionCode::e, Some(&flags)), "a != 0"),
            (cond_expr(ConditionCode::l, Some(&flags)), "(i64)a < 0"),
            (cond_expr(ConditionCode::g, Some(&two)), "(i64)a > (i64)b"),
            (cond_expr(ConditionCode::p, Some(&flags)), "isnan(a)"),
            (neg_cond_expr(ConditionCode::o, Some(&two)), "!sub_overflow((i64)a, (i64)b)"),
            (cond_expr(ConditionCode::e, None), "cc_e"),
        ] {
            assert_eq!(got, exp);
        }
    }
}
