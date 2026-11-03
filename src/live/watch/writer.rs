/*
 * XRef — Stage L3 x86-64 post-execution data watchpoint trap IP attribution and store decoder
 * Copyright (c) 2026 Alexander Panasenko
 * Contact: alex@prod.codes
 * Author: https://prod.codes/about/
 * Project: https://github.com/alex09x/xref
 * SPDX-License-Identifier: MIT OR Apache-2.0
 */

//! Resolves post-execution x86-64 `DR0`–`DR3` data breakpoint `trap_ip` back to a candidate
//! preceding store/access instruction via `iced-x86`, caches per-FDE static disassembly, and
//! decodes candidate `mov [mem], reg` / `mov [mem], imm` store operands with explicit caveats.

use std::collections::{BTreeMap, BTreeSet};

use iced_x86::{
    Decoder, DecoderOptions, FlowControl, Instruction, InstructionInfoFactory, MemorySize, Mnemonic, OpAccess, OpKind,
    Register,
};

use crate::image::Image;
use crate::live::classify::{find_region, lookup_symbol, static_va_to_file_offset};
use crate::live::types::{HexAddr, RegionEntry, apply_slide, remove_slide};
use crate::live::watch::types::{WatchRegsSnapshot, WatchTargetSpec, WriterConfidence, WrittenValueRecovery};
use crate::scan::format as format_instruction;

pub const CANDIDATE_STORE_CAVEAT: &str =
    "candidate_linear_predecessor_store_operand_assumes_no_indirect_or_cross_fde_entry";
pub const CANDIDATE_READ_CAVEAT: &str =
    "candidate_linear_predecessor_read_operand_assumes_no_indirect_or_cross_fde_entry";

#[derive(Clone, Debug)]
struct CachedFdeLayout {
    fn_start: u64,
    fn_symbol: Option<String>,
    linear_predecessors: BTreeMap<u64, Instruction>,
    direct_branch_targets: BTreeSet<u64>,
}

#[derive(Clone, Debug, Default)]
pub struct WriterStaticCache {
    fdes: BTreeMap<u64, CachedFdeLayout>,
}

impl WriterStaticCache {
    fn get_or_build<'a>(&'a mut self, image: &Image, fn_range: &std::ops::Range<u64>) -> Option<&'a CachedFdeLayout> {
        let start = fn_range.start;
        if let std::collections::btree_map::Entry::Vacant(e) = self.fdes.entry(start) {
            let layout = build_fde_layout(image, fn_range)?;
            e.insert(layout);
        }
        self.fdes.get(&start)
    }
}

fn build_fde_layout(image: &Image, func_range: &std::ops::Range<u64>) -> Option<CachedFdeLayout> {
    let len = usize::try_from(func_range.end.checked_sub(func_range.start)?).ok()?;
    let bytes = image.read(func_range.start, len)?;
    let mut decoder = Decoder::with_ip(64, bytes, func_range.start, DecoderOptions::NONE);
    let mut instr = Instruction::default();
    let mut linear_predecessors = BTreeMap::new();
    let mut direct_branch_targets = BTreeSet::new();

    while decoder.can_decode() {
        decoder.decode_out(&mut instr);
        if instr.is_invalid() {
            break;
        }
        if matches!(
            instr.flow_control(),
            FlowControl::Call | FlowControl::UnconditionalBranch | FlowControl::ConditionalBranch
        ) {
            direct_branch_targets.insert(instr.near_branch_target());
        }
        if !matches!(
            instr.flow_control(),
            FlowControl::Call
                | FlowControl::IndirectCall
                | FlowControl::UnconditionalBranch
                | FlowControl::IndirectBranch
                | FlowControl::Return
                | FlowControl::Exception
        ) {
            linear_predecessors.insert(instr.next_ip(), instr);
        }
    }

    Some(CachedFdeLayout {
        fn_start: func_range.start,
        fn_symbol: lookup_symbol(image, func_range.start),
        linear_predecessors,
        direct_branch_targets,
    })
}

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

pub fn attribute_watch_trap_cached(
    cache: &mut WriterStaticCache,
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
        return unattributed(None, None, None, WriterConfidence::OutsideTargetExecutable, "trap_ip_slide_overflow");
    };
    let in_exec_seg = static_va_to_file_offset(&image.metadata.load_segments, trap_static)
        .is_some_and(|(off, in_bss, exec)| off.is_some() && !in_bss && exec);
    if !in_target_exec || !in_exec_seg {
        let c = WriterConfidence::OutsideTargetExecutable;
        return unattributed(Some(trap_static), None, None, c, "trap_ip_outside_target_executable");
    }

    let lookup_pc = trap_static.saturating_sub(1);
    let Some(func_range) = image.function_at(lookup_pc) else {
        let c = WriterConfidence::OutsideKnownFunction;
        return unattributed(Some(trap_static), None, None, c, "trap_ip_outside_indexed_function");
    };
    let fn_start = func_range.start;
    if trap_static <= func_range.start
        || trap_static >= func_range.end
        || image.function_at(trap_static).as_ref() != Some(&func_range)
        || image.symbols.binary_search_by_key(&trap_static, |&(addr, _)| addr).is_ok()
        || image.pointers.iter().any(|&(_, target)| target == trap_static)
    {
        let sym = lookup_symbol(image, fn_start);
        let c = WriterConfidence::AmbiguousBranchTarget;
        return unattributed(Some(trap_static), Some(fn_start), sym, c, "trap_ip_at_function_or_symbol_entry_boundary");
    }

    let Some(layout) = cache.get_or_build(image, &func_range) else {
        let sym = lookup_symbol(image, fn_start);
        return unattributed(
            Some(trap_static),
            Some(fn_start),
            sym,
            WriterConfidence::OutsideKnownFunction,
            "no_linear_predecessor_at_trap_ip",
        );
    };
    let fn_sym = layout.fn_symbol.clone();
    let Some(&pred_instr) = layout.linear_predecessors.get(&trap_static) else {
        let c = WriterConfidence::OutsideKnownFunction;
        return unattributed(Some(trap_static), Some(layout.fn_start), fn_sym, c, "no_linear_predecessor_at_trap_ip");
    };
    let is_branch_target = layout.direct_branch_targets.contains(&trap_static);
    let (confidence, caveat, written_value) =
        classify_predecessor_outcome(&pred_instr, is_branch_target, pie_slide, spec, regs);

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
    pie_slide: i64,
    spec: &WatchTargetSpec,
    regs: Option<&WatchRegsSnapshot>,
) -> (WriterConfidence, &'static str, WrittenValueRecovery) {
    let unrec = |conf, caveat, reason| (conf, caveat, WrittenValueRecovery::Unknown { reason });
    if is_branch_target {
        return unrec(
            WriterConfidence::AmbiguousBranchTarget,
            "trap_ip_is_intra_function_branch_target_predecessor_not_unique",
            "ambiguous_branch_target_at_trap_ip",
        );
    }
    match classify_memory_access(pred_instr, pie_slide, spec, regs) {
        (MemOpClass::None, _) => unrec(
            WriterConfidence::PredecessorNotMemoryAccess,
            "preceding_instruction_has_no_explicit_memory_operand",
            "not_a_candidate_store_instruction",
        ),
        (_, EffectiveAddrMatch::Disjoint) => unrec(
            WriterConfidence::UnverifiedMemoryTarget,
            "preceding_instruction_effective_address_disjoint_from_watch_range",
            "effective_address_disjoint_from_watched_range",
        ),
        (_, EffectiveAddrMatch::Unresolved) => unrec(
            WriterConfidence::UnverifiedMemoryTarget,
            "preceding_instruction_effective_address_unverified",
            "effective_address_unverified_against_watched_range",
        ),
        (MemOpClass::ConditionalStore, EffectiveAddrMatch::Overlaps) => unrec(
            WriterConfidence::UnverifiedMemoryTarget,
            "preceding_instruction_is_conditional_or_rep_memory_operation",
            "conditional_or_rep_store_not_decoded",
        ),
        (MemOpClass::ReadOnly, EffectiveAddrMatch::Overlaps) => unrec(
            WriterConfidence::CandidateLinearPredecessorRead,
            CANDIDATE_READ_CAVEAT,
            "read_only_memory_access_not_a_store",
        ),
        (MemOpClass::UnconditionalStore, EffectiveAddrMatch::Overlaps) => (
            WriterConfidence::CandidateLinearPredecessorStore,
            CANDIDATE_STORE_CAVEAT,
            recover_store_value(pred_instr, regs),
        ),
    }
}

const fn unattributed(
    trap_static_ip: Option<u64>,
    writer_function: Option<u64>,
    writer_symbol: Option<String>,
    confidence: WriterConfidence,
    caveat: &'static str,
) -> AttributedWriter {
    AttributedWriter {
        trap_static_ip,
        candidate_writer_static_ip: None,
        candidate_writer_mnemonic: None,
        candidate_writer_text: None,
        writer_function,
        writer_function_offset: None,
        writer_symbol,
        confidence,
        written_value: WrittenValueRecovery::Unknown { reason: caveat },
        caveat,
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
    pie_slide: i64,
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
    (class, check_effective_address_overlap(instr, pie_slide, spec, regs))
}

fn check_effective_address_overlap(
    instr: &Instruction,
    pie_slide: i64,
    spec: &WatchTargetSpec,
    regs: Option<&WatchRegsSnapshot>,
) -> EffectiveAddrMatch {
    if !matches!(instr.memory_segment(), Register::None | Register::DS | Register::SS | Register::ES) {
        return EffectiveAddrMatch::Unresolved;
    }
    let Some(access_len) = memory_size_bytes(instr.memory_size()).map(u64::from) else {
        return EffectiveAddrMatch::Unresolved;
    };
    let ea = if instr.is_ip_rel_memory_operand() {
        let Some(rt) = apply_slide(instr.ip_rel_memory_address(), pie_slide) else {
            return EffectiveAddrMatch::Unresolved;
        };
        rt
    } else {
        let Some(base_val) = read_addr_component(instr, regs, instr.memory_base(), 1) else {
            return EffectiveAddrMatch::Unresolved;
        };
        let Some(index_val) =
            read_addr_component(instr, regs, instr.memory_index(), u64::from(instr.memory_index_scale()))
        else {
            return EffectiveAddrMatch::Unresolved;
        };
        base_val.wrapping_add(index_val).wrapping_add(instr.memory_displacement64())
    };
    let Some(ea_end) = ea.checked_add(access_len) else { return EffectiveAddrMatch::Unresolved };
    let watch_start = spec.runtime_va;
    let Some(watch_end) = watch_start.checked_add(u64::from(spec.len_bytes.as_u8())) else {
        return EffectiveAddrMatch::Unresolved;
    };
    if ea < watch_end && watch_start < ea_end { EffectiveAddrMatch::Overlaps } else { EffectiveAddrMatch::Disjoint }
}

fn read_addr_component(
    instr: &Instruction,
    regs: Option<&WatchRegsSnapshot>,
    reg: Register,
    scale: u64,
) -> Option<u64> {
    if reg == Register::None {
        return Some(0);
    }
    let full = reg.full_register();
    if InstructionInfoFactory::new().info(instr).used_registers().iter().any(|u| {
        u.register().full_register() == full
            && matches!(
                u.access(),
                OpAccess::Write | OpAccess::CondWrite | OpAccess::ReadWrite | OpAccess::ReadCondWrite
            )
    }) {
        return None;
    }
    regs.and_then(|r| r.read_register(reg)).map(|(_, v)| v.wrapping_mul(scale))
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
            let Some((reg_name, val)) = r.read_register(instr.op_register(1)) else {
                return WrittenValueRecovery::Unknown { reason: "source_register_not_in_gpr_snapshot" };
            };
            WrittenValueRecovery::CandidateRegisterStore {
                register: reg_name,
                width_bytes,
                value: HexAddr(val & mask),
                caveat: CANDIDATE_STORE_CAVEAT,
            }
        }
        OpKind::Immediate8
        | OpKind::Immediate16
        | OpKind::Immediate32
        | OpKind::Immediate64
        | OpKind::Immediate8to16
        | OpKind::Immediate8to32
        | OpKind::Immediate8to64
        | OpKind::Immediate32to64 => WrittenValueRecovery::CandidateImmediateStore {
            width_bytes,
            value: HexAddr(instr.immediate(1) & mask),
            caveat: CANDIDATE_STORE_CAVEAT,
        },
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
