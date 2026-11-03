/*
 * XRef — Stage L3 x86-64 post-execution data watchpoint trap IP attribution and store decoder
 * Copyright (c) 2026 Alexander Panasenko
 * Contact: alex@prod.codes
 * Author: https://prod.codes/about/
 * Project: https://github.com/alex09x/xref
 * SPDX-License-Identifier: MIT OR Apache-2.0
 */

//! Resolves post-execution x86-64 `DR0`–`DR3` data breakpoint `trap_ip` back to the preceding
//! store/access instruction via `iced-x86`, checks branch-target ambiguity inside the enclosing
//! function, and recovers proven `mov [mem], reg` / `mov [mem], imm` store values.

use std::ops::Range;

use iced_x86::{Decoder, DecoderOptions, FlowControl, Instruction, MemorySize, Mnemonic, OpKind, Register};

use crate::image::Image;
use crate::live::classify::{find_region, lookup_symbol, static_va_to_file_offset};
use crate::live::types::{HexAddr, RegionEntry, remove_slide};
use crate::live::watch::types::{WatchRegsSnapshot, WriterConfidence, WrittenValueRecovery};
use crate::scan::format as format_instruction;

#[derive(Clone, Debug)]
pub struct AttributedWriter {
    pub trap_static_ip: Option<u64>,
    pub candidate_writer_static_ip: Option<u64>,
    pub candidate_writer_mnemonic: Option<String>,
    pub candidate_writer_text: Option<String>,
    pub writer_function: Option<u64>,
    pub writer_function_offset: Option<u64>,
    pub writer_symbol: Option<String>,
    pub confidence: WriterConfidence,
    pub written_value: WrittenValueRecovery,
    pub caveat: &'static str,
}

#[must_use]
pub fn attribute_watch_trap(
    image: &Image,
    pie_slide: i64,
    regions: &[RegionEntry],
    trap_runtime_ip: u64,
    regs: Option<&WatchRegsSnapshot>,
) -> AttributedWriter {
    let in_target_exec =
        find_region(regions, trap_runtime_ip).is_some_and(|r| r.is_target_image && r.perms.contains('x'));
    let Some(trap_static) = remove_slide(trap_runtime_ip, pie_slide) else {
        return outside_exec(None, "trap_ip_slide_overflow");
    };
    let in_exec_seg = static_va_to_file_offset(&image.metadata.load_segments, trap_static)
        .is_some_and(|(off, in_bss, exec)| off.is_some() && !in_bss && exec);
    if !in_target_exec || !in_exec_seg {
        return outside_exec(Some(trap_static), "trap_ip_outside_target_executable");
    }

    let lookup_pc = trap_static.saturating_sub(1);
    let Some(func_range) = image.function_at(lookup_pc) else {
        return AttributedWriter {
            trap_static_ip: Some(trap_static),
            candidate_writer_static_ip: None,
            candidate_writer_mnemonic: None,
            candidate_writer_text: None,
            writer_function: None,
            writer_function_offset: None,
            writer_symbol: None,
            confidence: WriterConfidence::OutsideKnownFunction,
            written_value: WrittenValueRecovery::Unknown { reason: "trap_ip_outside_indexed_function" },
            caveat: "trap_ip_outside_indexed_function",
        };
    };

    let fn_start = func_range.start;
    let fn_sym = lookup_symbol(image, fn_start);
    let Some((pred_instr, is_branch_target)) = find_preceding_instruction(image, &func_range, trap_static) else {
        return AttributedWriter {
            trap_static_ip: Some(trap_static),
            candidate_writer_static_ip: None,
            candidate_writer_mnemonic: None,
            candidate_writer_text: None,
            writer_function: Some(fn_start),
            writer_function_offset: None,
            writer_symbol: fn_sym,
            confidence: WriterConfidence::OutsideKnownFunction,
            written_value: WrittenValueRecovery::Unknown { reason: "no_linear_predecessor_at_trap_ip" },
            caveat: "no_linear_predecessor_at_trap_ip",
        };
    };

    let writer_ip = pred_instr.ip();
    let writer_off = writer_ip.saturating_sub(fn_start);
    let mnemonic_str = format!("{:?}", pred_instr.mnemonic()).to_ascii_lowercase();
    let text = format_instruction(&pred_instr);
    let has_mem_op = (0..pred_instr.op_count()).any(|i| pred_instr.op_kind(i) == OpKind::Memory);
    let is_mem_store = pred_instr.op_count() >= 1 && pred_instr.op_kind(0) == OpKind::Memory;

    let (confidence, caveat) = if is_branch_target {
        (WriterConfidence::AmbiguousBranchTarget, "trap_ip_is_intra_function_branch_target_predecessor_not_unique")
    } else if is_mem_store {
        (WriterConfidence::VerifiedLinearPredecessorStore, "post_exec_trap_preceding_store_verified")
    } else if has_mem_op {
        (WriterConfidence::VerifiedLinearPredecessorRead, "post_exec_trap_preceding_memory_access_verified")
    } else {
        (WriterConfidence::PredecessorNotMemoryAccess, "preceding_instruction_has_no_explicit_memory_operand")
    };

    let written_value = if confidence == WriterConfidence::VerifiedLinearPredecessorStore {
        recover_store_value(&pred_instr, regs)
    } else if is_branch_target {
        WrittenValueRecovery::Unknown { reason: "ambiguous_branch_target_at_trap_ip" }
    } else {
        WrittenValueRecovery::Unknown { reason: "not_a_verified_store_instruction" }
    };

    AttributedWriter {
        trap_static_ip: Some(trap_static),
        candidate_writer_static_ip: Some(writer_ip),
        candidate_writer_mnemonic: Some(mnemonic_str),
        candidate_writer_text: Some(text),
        writer_function: Some(fn_start),
        writer_function_offset: Some(writer_off),
        writer_symbol: fn_sym,
        confidence,
        written_value,
        caveat,
    }
}

const fn outside_exec(trap_static_ip: Option<u64>, caveat: &'static str) -> AttributedWriter {
    AttributedWriter {
        trap_static_ip,
        candidate_writer_static_ip: None,
        candidate_writer_mnemonic: None,
        candidate_writer_text: None,
        writer_function: None,
        writer_function_offset: None,
        writer_symbol: None,
        confidence: WriterConfidence::OutsideTargetExecutable,
        written_value: WrittenValueRecovery::Unknown { reason: "trap_ip_outside_target_executable" },
        caveat,
    }
}

fn find_preceding_instruction(
    image: &Image,
    func_range: &Range<u64>,
    trap_static_ip: u64,
) -> Option<(Instruction, bool)> {
    if trap_static_ip <= func_range.start || trap_static_ip > func_range.end {
        return None;
    }
    let fn_len = usize::try_from(func_range.end - func_range.start).ok()?;
    let bytes = image.read(func_range.start, fn_len)?;

    let mut decoder = Decoder::with_ip(64, bytes, func_range.start, DecoderOptions::NONE);
    let mut instr = Instruction::default();
    let mut predecessor: Option<Instruction> = None;
    let mut is_branch_target = false;

    while decoder.can_decode() {
        decoder.decode_out(&mut instr);
        if instr.is_invalid() {
            break;
        }
        if matches!(instr.flow_control(), FlowControl::UnconditionalBranch | FlowControl::ConditionalBranch)
            && instr.near_branch_target() == trap_static_ip
        {
            is_branch_target = true;
        }
        if instr.next_ip() == trap_static_ip
            && !matches!(
                instr.flow_control(),
                FlowControl::UnconditionalBranch | FlowControl::Return | FlowControl::Exception
            )
        {
            predecessor = Some(instr);
        }
    }

    predecessor.map(|pred| (pred, is_branch_target))
}

#[must_use]
pub fn recover_store_value(instr: &Instruction, regs: Option<&WatchRegsSnapshot>) -> WrittenValueRecovery {
    if instr.mnemonic() != Mnemonic::Mov || instr.op_count() != 2 || instr.op_kind(0) != OpKind::Memory {
        return WrittenValueRecovery::Unknown { reason: "store_mnemonic_is_not_simple_mov" };
    }
    let Some(width_bytes) = memory_size_bytes(instr.memory_size()) else {
        return WrittenValueRecovery::Unknown { reason: "unsupported_memory_operand_width" };
    };
    let mask = width_mask(width_bytes);

    match instr.op_kind(1) {
        OpKind::Register => {
            let Some(r) = regs else {
                return WrittenValueRecovery::Unknown { reason: "intr_registers_unavailable" };
            };
            let reg = instr.op_register(1);
            let Some((reg_name, val)) = read_register_value(r, reg) else {
                return WrittenValueRecovery::Unknown { reason: "source_register_not_in_gpr_snapshot" };
            };
            WrittenValueRecovery::ProvenRegisterStore { register: reg_name, width_bytes, value: HexAddr(val & mask) }
        }
        OpKind::Immediate8
        | OpKind::Immediate16
        | OpKind::Immediate32
        | OpKind::Immediate64
        | OpKind::Immediate8to16
        | OpKind::Immediate8to32
        | OpKind::Immediate8to64
        | OpKind::Immediate32to64 => {
            WrittenValueRecovery::ProvenImmediateStore { width_bytes, value: HexAddr(instr.immediate(1) & mask) }
        }
        _ => WrittenValueRecovery::Unknown { reason: "unsupported_mov_source_operand" },
    }
}

const fn memory_size_bytes(size: MemorySize) -> Option<u8> {
    match size {
        MemorySize::UInt8 | MemorySize::Int8 => Some(1),
        MemorySize::UInt16 | MemorySize::Int16 => Some(2),
        MemorySize::UInt32 | MemorySize::Int32 | MemorySize::Float32 => Some(4),
        MemorySize::UInt64 | MemorySize::Int64 | MemorySize::Float64 | MemorySize::QwordOffset => Some(8),
        _ => None,
    }
}

const fn width_mask(width_bytes: u8) -> u64 {
    match width_bytes {
        1 => 0xff,
        2 => 0xffff,
        4 => 0xffff_ffff,
        _ => u64::MAX,
    }
}

const fn read_register_value(regs: &WatchRegsSnapshot, reg: Register) -> Option<(&'static str, u64)> {
    match reg {
        Register::RAX | Register::EAX | Register::AX | Register::AL => Some(("rax", regs.rax.0)),
        Register::AH => Some(("ah", (regs.rax.0 >> 8) & 0xff)),
        Register::RBX | Register::EBX | Register::BX | Register::BL => Some(("rbx", regs.rbx.0)),
        Register::BH => Some(("bh", (regs.rbx.0 >> 8) & 0xff)),
        Register::RCX | Register::ECX | Register::CX | Register::CL => Some(("rcx", regs.rcx.0)),
        Register::CH => Some(("ch", (regs.rcx.0 >> 8) & 0xff)),
        Register::RDX | Register::EDX | Register::DX | Register::DL => Some(("rdx", regs.rdx.0)),
        Register::DH => Some(("dh", (regs.rdx.0 >> 8) & 0xff)),
        Register::RSI | Register::ESI | Register::SI | Register::SIL => Some(("rsi", regs.rsi.0)),
        Register::RDI | Register::EDI | Register::DI | Register::DIL => Some(("rdi", regs.rdi.0)),
        Register::RBP | Register::EBP | Register::BP | Register::BPL => Some(("rbp", regs.rbp.0)),
        Register::RSP | Register::ESP | Register::SP | Register::SPL => Some(("rsp", regs.rsp.0)),
        Register::R8 | Register::R8D | Register::R8W | Register::R8L => Some(("r8", regs.r8.0)),
        Register::R9 | Register::R9D | Register::R9W | Register::R9L => Some(("r9", regs.r9.0)),
        Register::R10 | Register::R10D | Register::R10W | Register::R10L => Some(("r10", regs.r10.0)),
        Register::R11 | Register::R11D | Register::R11W | Register::R11L => Some(("r11", regs.r11.0)),
        Register::R12 | Register::R12D | Register::R12W | Register::R12L => Some(("r12", regs.r12.0)),
        Register::R13 | Register::R13D | Register::R13W | Register::R13L => Some(("r13", regs.r13.0)),
        Register::R14 | Register::R14D | Register::R14W | Register::R14L => Some(("r14", regs.r14.0)),
        Register::R15 | Register::R15D | Register::R15W | Register::R15L => Some(("r15", regs.r15.0)),
        _ => None,
    }
}
