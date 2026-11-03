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

use iced_x86::{
    Decoder, DecoderOptions, FlowControl, Instruction, InstructionInfoFactory, MemorySize, Mnemonic, OpAccess, OpKind,
    Register,
};

use crate::image::Image;
use crate::live::classify::{find_region, lookup_symbol, static_va_to_file_offset};
use crate::live::types::{HexAddr, RegionEntry, remove_slide};
use crate::live::watch::types::{WatchRegsSnapshot, WatchTargetSpec, WriterConfidence, WrittenValueRecovery};
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
    spec: &WatchTargetSpec,
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
        return outside_known_function(trap_static, None, None, "trap_ip_outside_indexed_function");
    };
    let fn_start = func_range.start;
    let fn_sym = lookup_symbol(image, fn_start);
    if trap_static <= func_range.start
        || trap_static >= func_range.end
        || image.function_at(trap_static).as_ref() != Some(&func_range)
        || image.symbols.binary_search_by_key(&trap_static, |&(addr, _)| addr).is_ok()
        || image.pointers.iter().any(|&(_, target)| target == trap_static)
    {
        return AttributedWriter {
            trap_static_ip: Some(trap_static),
            candidate_writer_static_ip: None,
            candidate_writer_mnemonic: None,
            candidate_writer_text: None,
            writer_function: Some(fn_start),
            writer_function_offset: None,
            writer_symbol: fn_sym,
            confidence: WriterConfidence::AmbiguousBranchTarget,
            written_value: WrittenValueRecovery::Unknown { reason: "trap_ip_at_function_or_symbol_boundary" },
            caveat: "trap_ip_at_function_or_symbol_entry_boundary",
        };
    }

    let Some((pred_instr, is_branch_target)) = find_preceding_instruction(image, &func_range, trap_static) else {
        return outside_known_function(trap_static, Some(fn_start), fn_sym, "no_linear_predecessor_at_trap_ip");
    };
    let (confidence, caveat, written_value) = classify_predecessor_outcome(&pred_instr, is_branch_target, spec, regs);

    AttributedWriter {
        trap_static_ip: Some(trap_static),
        candidate_writer_static_ip: Some(pred_instr.ip()),
        candidate_writer_mnemonic: Some(format!("{:?}", pred_instr.mnemonic()).to_ascii_lowercase()),
        candidate_writer_text: Some(format_instruction(&pred_instr)),
        writer_function: Some(fn_start),
        writer_function_offset: Some(pred_instr.ip().saturating_sub(fn_start)),
        writer_symbol: fn_sym,
        confidence,
        written_value,
        caveat,
    }
}

fn classify_predecessor_outcome(
    pred_instr: &Instruction,
    is_branch_target: bool,
    spec: &WatchTargetSpec,
    regs: Option<&WatchRegsSnapshot>,
) -> (WriterConfidence, &'static str, WrittenValueRecovery) {
    if is_branch_target {
        return (
            WriterConfidence::AmbiguousBranchTarget,
            "trap_ip_is_intra_function_branch_target_predecessor_not_unique",
            WrittenValueRecovery::Unknown { reason: "ambiguous_branch_target_at_trap_ip" },
        );
    }
    match classify_memory_access(pred_instr, spec, regs) {
        (MemOpClass::None, _) => (
            WriterConfidence::PredecessorNotMemoryAccess,
            "preceding_instruction_has_no_explicit_memory_operand",
            WrittenValueRecovery::Unknown { reason: "not_a_verified_store_instruction" },
        ),
        (_, EffectiveAddrMatch::Disjoint) => (
            WriterConfidence::UnverifiedMemoryTarget,
            "preceding_instruction_effective_address_disjoint_from_watch_range",
            WrittenValueRecovery::Unknown { reason: "effective_address_disjoint_from_watched_range" },
        ),
        (_, EffectiveAddrMatch::Unresolved) => (
            WriterConfidence::UnverifiedMemoryTarget,
            "preceding_instruction_effective_address_unverified",
            WrittenValueRecovery::Unknown { reason: "effective_address_unverified_against_watched_range" },
        ),
        (MemOpClass::ConditionalStore, EffectiveAddrMatch::Overlaps) => (
            WriterConfidence::UnverifiedMemoryTarget,
            "preceding_instruction_is_conditional_or_rep_memory_operation",
            WrittenValueRecovery::Unknown { reason: "conditional_or_rep_store_not_proven" },
        ),
        (MemOpClass::ReadOnly, EffectiveAddrMatch::Overlaps) => (
            WriterConfidence::VerifiedLinearPredecessorRead,
            "post_exec_trap_preceding_memory_read_verified",
            WrittenValueRecovery::Unknown { reason: "read_only_memory_access_not_a_store" },
        ),
        (MemOpClass::UnconditionalStore, EffectiveAddrMatch::Overlaps) => (
            WriterConfidence::VerifiedLinearPredecessorStore,
            "post_exec_trap_preceding_store_verified",
            recover_store_value(pred_instr, regs),
        ),
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

const fn outside_known_function(
    trap_static_ip: u64,
    writer_function: Option<u64>,
    writer_symbol: Option<String>,
    reason: &'static str,
) -> AttributedWriter {
    AttributedWriter {
        trap_static_ip: Some(trap_static_ip),
        candidate_writer_static_ip: None,
        candidate_writer_mnemonic: None,
        candidate_writer_text: None,
        writer_function,
        writer_function_offset: None,
        writer_symbol,
        confidence: WriterConfidence::OutsideKnownFunction,
        written_value: WrittenValueRecovery::Unknown { reason },
        caveat: reason,
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum MemOpClass {
    None,
    ReadOnly,
    ConditionalStore,
    UnconditionalStore,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum EffectiveAddrMatch {
    Overlaps,
    Disjoint,
    Unresolved,
}

fn classify_memory_access(
    instr: &Instruction,
    spec: &WatchTargetSpec,
    regs: Option<&WatchRegsSnapshot>,
) -> (MemOpClass, EffectiveAddrMatch) {
    let Some(mem_op_idx) = (0..instr.op_count()).find(|&i| instr.op_kind(i) == OpKind::Memory) else {
        return (MemOpClass::None, EffectiveAddrMatch::Unresolved);
    };
    if instr.has_rep_prefix() || instr.has_repe_prefix() || instr.has_repne_prefix() {
        return (MemOpClass::ConditionalStore, EffectiveAddrMatch::Unresolved);
    }
    let access = InstructionInfoFactory::new().info(instr).op_access(mem_op_idx);
    let class = match access {
        OpAccess::Write | OpAccess::ReadWrite => MemOpClass::UnconditionalStore,
        OpAccess::CondWrite | OpAccess::ReadCondWrite => MemOpClass::ConditionalStore,
        OpAccess::Read | OpAccess::CondRead => MemOpClass::ReadOnly,
        OpAccess::None | OpAccess::NoMemAccess => return (MemOpClass::None, EffectiveAddrMatch::Unresolved),
    };
    (class, check_effective_address_overlap(instr, spec, regs))
}

fn check_effective_address_overlap(
    instr: &Instruction,
    spec: &WatchTargetSpec,
    regs: Option<&WatchRegsSnapshot>,
) -> EffectiveAddrMatch {
    if !matches!(instr.memory_segment(), Register::None | Register::DS | Register::SS | Register::ES) {
        return EffectiveAddrMatch::Unresolved;
    }
    let Some(access_len) = memory_size_bytes(instr.memory_size()).map(u64::from) else {
        return EffectiveAddrMatch::Unresolved;
    };
    let base_reg = instr.memory_base();
    let index_reg = instr.memory_index();
    if (base_reg != Register::None && base_reg != Register::RIP && reg_modified_by_instr(instr, base_reg))
        || (index_reg != Register::None && reg_modified_by_instr(instr, index_reg))
    {
        return EffectiveAddrMatch::Unresolved;
    }

    let base_val = match base_reg {
        Register::None => 0,
        Register::RIP => instr.next_ip(),
        Register::EIP => u64::from(instr.next_ip32()),
        reg => {
            let Some(v) = regs.and_then(|r| read_register_value(r, reg)).map(|(_, v)| v) else {
                return EffectiveAddrMatch::Unresolved;
            };
            v
        }
    };
    let index_val = match index_reg {
        Register::None => 0,
        reg => {
            let Some(v) = regs.and_then(|r| read_register_value(r, reg)).map(|(_, v)| v) else {
                return EffectiveAddrMatch::Unresolved;
            };
            v.wrapping_mul(u64::from(instr.memory_index_scale()))
        }
    };
    let ea = base_val.wrapping_add(index_val).wrapping_add(instr.memory_displacement64());
    let Some(ea_end) = ea.checked_add(access_len) else { return EffectiveAddrMatch::Unresolved };
    let watch_start = spec.runtime_va;
    let Some(watch_end) = watch_start.checked_add(u64::from(spec.len_bytes.as_u8())) else {
        return EffectiveAddrMatch::Unresolved;
    };
    if ea < watch_end && watch_start < ea_end { EffectiveAddrMatch::Overlaps } else { EffectiveAddrMatch::Disjoint }
}

fn reg_modified_by_instr(instr: &Instruction, reg: Register) -> bool {
    let full = reg.full_register();
    InstructionInfoFactory::new().info(instr).used_registers().iter().any(|u| {
        u.register().full_register() == full
            && matches!(
                u.access(),
                OpAccess::Write | OpAccess::CondWrite | OpAccess::ReadWrite | OpAccess::ReadCondWrite
            )
    })
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
            let Some((reg_name, val)) = read_register_value(r, instr.op_register(1)) else {
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
    if width_bytes >= 8 { u64::MAX } else { (1_u64 << (width_bytes * 8)) - 1 }
}

const fn read_register_value(regs: &WatchRegsSnapshot, reg: Register) -> Option<(&'static str, u64)> {
    match reg {
        Register::RAX | Register::EAX | Register::AX | Register::AL => Some(("rax", regs.rax.0)),
        Register::RBX | Register::EBX | Register::BX | Register::BL => Some(("rbx", regs.rbx.0)),
        Register::RCX | Register::ECX | Register::CX | Register::CL => Some(("rcx", regs.rcx.0)),
        Register::RDX | Register::EDX | Register::DX | Register::DL => Some(("rdx", regs.rdx.0)),
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
        Register::AH => Some(("ah", (regs.rax.0 >> 8) & 0xff)),
        Register::BH => Some(("bh", (regs.rbx.0 >> 8) & 0xff)),
        Register::CH => Some(("ch", (regs.rcx.0 >> 8) & 0xff)),
        Register::DH => Some(("dh", (regs.rdx.0 >> 8) & 0xff)),
        _ => None,
    }
}
