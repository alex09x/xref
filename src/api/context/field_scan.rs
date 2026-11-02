/*
 * XRef Code — evidence-producing binary analysis
 * Copyright (c) 2026 Alexander Panasenko
 * Contact: alex@prod.codes
 * Author: https://prod.codes/about/
 * Project: https://github.com/alex09x/xref
 * SPDX-License-Identifier: MIT OR Apache-2.0
 */
use super::super::field_types::AccessKind;
use super::super::{
    Analysis, ApiError, Cancellation,
    field_types::{ArgumentOrigin, FieldAccess, FieldCall, Hop, signed_hex},
    investigate::types::Selection,
};
use super::{
    facts::{self, State},
    flow::Flow,
    origin::{self, Origin},
};
use crate::{layout, listing, scan};
use iced_x86::{FlowControl, Instruction, InstructionInfoFactory, Mnemonic, OpAccess, OpKind};
use std::{collections::BTreeSet, ops::Range};

pub(super) struct Scope<'a> {
    pub range: Range<u64>,
    pub code: &'a [u8],
    pub insns: Vec<Instruction>,
    pub flow: Flow,
    pub states: Option<Vec<Option<State>>>,
    pub entry: usize,
    pub delta: i64,
    pub via: Option<Hop>,
}
impl<'a> Scope<'a> {
    pub fn open(
        a: &'a Analysis,
        address: &str,
        entry: usize,
        delta: i64,
        via: Option<Hop>,
        cancel: &Cancellation,
    ) -> Result<Self, ApiError> {
        let range = a.function(address)?;
        if range.end - range.start > 32768 {
            return Err(ApiError::new("field_budget", "field scope supports 32 KiB of machine code"));
        }
        let code = a.image.code(&range).ok_or_else(|| ApiError::new("no_code", "function bytes unavailable"))?;
        let mut insns = vec![];
        scan::decode(code, range.start, |ins| insns.push(*ins));
        if insns.len() > 2048 {
            return Err(ApiError::new("field_budget", "field scope supports 2048 instructions"));
        }
        let flow = Flow::new(&insns, &a.image, &range);
        let states = facts::solve(&insns, &flow, cancel)?;
        Ok(Self { range, code, insns, flow, states, entry, delta, via })
    }
    pub const fn complete(&self) -> bool {
        !self.flow.incomplete && self.states.is_some()
    }
    pub fn is_call(&self, i: usize, a: &Analysis) -> bool {
        let ins = &self.insns[i];
        listing::is_call(ins, &self.range)
            && !(ins.flow_control() == FlowControl::IndirectBranch
                && crate::graph::call_target(&a.image, ins).is_some_and(|ip| self.range.contains(&ip)))
    }
    pub fn memory(&self, a: &Analysis, i: usize) -> Option<(i64, FieldAccess)> {
        if !self.complete() {
            return None;
        }
        let state = self.states.as_ref()?.get(i)?.as_ref()?;
        let ins = &self.insns[i];
        if !((0..ins.op_count()).any(|k| ins.op_kind(k) == OpKind::Memory)) {
            return None;
        }
        let (Origin::Address { register, displacement }, base) = origin::memory_origin(ins, state)? else {
            return None;
        };
        if register != self.entry {
            return None;
        }
        let displacement = self.delta.checked_add(displacement)?;
        let address_taken = ins.mnemonic() == Mnemonic::Lea;
        let mut factory = InstructionInfoFactory::new();
        let access = factory
            .info(ins)
            .used_memory()
            .iter()
            .find(|m| m.base().full_register() == ins.memory_base().full_register() && m.index() == ins.memory_index())
            .map(iced_x86::UsedMemory::access);
        let reads = access.is_some_and(|v| {
            matches!(v, OpAccess::Read | OpAccess::CondRead | OpAccess::ReadWrite | OpAccess::ReadCondWrite)
        });
        let writes = access.is_some_and(|v| {
            matches!(v, OpAccess::Write | OpAccess::CondWrite | OpAccess::ReadWrite | OpAccess::ReadCondWrite)
        });
        let conditional_access =
            access.is_some_and(|v| matches!(v, OpAccess::CondRead | OpAccess::CondWrite | OpAccess::ReadCondWrite));
        if !address_taken && !reads && !writes {
            return None;
        }
        Some((
            displacement,
            FieldAccess {
                function: format!("{:#x}", self.range.start),
                displacement: signed_hex(displacement),
                width_bytes: if address_taken { 0 } else { ins.memory_size().size() },
                access: if address_taken {
                    AccessKind::Address
                } else if reads && writes {
                    AccessKind::ReadWrite
                } else if writes {
                    AccessKind::Write
                } else {
                    AccessKind::Read
                },
                conditional_access,
                instruction: a.evidence_instruction(ins, self.code, self.range.start),
                definitions: state[base]
                    .defs
                    .iter()
                    .map(|&n| a.evidence_instruction(&self.insns[n], self.code, self.range.start))
                    .collect(),
                definitions_truncated: state[base].truncated,
                via: self.via.clone(),
            },
        ))
    }
    pub fn call(
        &self,
        a: &Analysis,
        i: usize,
        offsets: &[i64],
        cancel: &Cancellation,
    ) -> Result<Option<FieldCall>, ApiError> {
        let ins = &self.insns[i];
        if !self.complete() || !self.is_call(i, a) {
            return Ok(None);
        }
        let Some(state) = self.states.as_ref().and_then(|s| s[i].as_ref()) else { return Ok(None) };
        let mut arguments = vec![];
        for k in [7, 6, 2, 1, 8, 9] {
            let Some(origin) = &state[k].origin else { continue };
            let (register, displacement, load_address, load_width_bytes) = match origin {
                Origin::Address { register, displacement } => (*register, *displacement, None, None),
                Origin::Loaded { register, displacement, width, load_ip } => {
                    (*register, *displacement, Some(format!("{load_ip:#x}")), Some(*width))
                }
            };
            if register != self.entry {
                continue;
            }
            let Some(displacement) = self.delta.checked_add(displacement) else { continue };
            if !offsets.is_empty() && !offsets.contains(&displacement) && load_address.is_some() {
                continue;
            }
            arguments.push(ArgumentOrigin {
                register: facts::NAMES[k],
                relation: if load_address.is_some() {
                    "loaded_value"
                } else if displacement == 0 {
                    "base_address"
                } else {
                    "field_address"
                },
                displacement: signed_hex(displacement),
                load_address,
                load_width_bytes,
                requested_offset_match: (!offsets.is_empty()).then(|| offsets.contains(&displacement)),
                definitions: state[k]
                    .defs
                    .iter()
                    .map(|&n| a.evidence_instruction(&self.insns[n], self.code, self.range.start))
                    .collect(),
                definitions_truncated: state[k].truncated,
            });
        }
        if arguments.is_empty() {
            return Ok(None);
        }
        let (guards, evidence, mut guards_complete) = super::guards::guards(&self.insns, &self.flow, i, cancel)?;
        if evidence.len() > 96 {
            guards_complete = false;
        }
        Ok(Some(FieldCall {
            selection: Selection {
                image_sha256: a.identity.sha256.clone(),
                function: format!("{:#x}", self.range.start),
                call_site: format!("{:#x}", ins.ip()),
            },
            target: crate::graph::call_target(&a.image, ins).map(|v| format!("{v:#x}")),
            instruction: a.evidence_instruction(ins, self.code, self.range.start),
            arguments,
            guards,
            guard_instructions: evidence
                .into_iter()
                .take(96)
                .map(|n| a.evidence_instruction(&self.insns[n], self.code, self.range.start))
                .collect(),
            guards_complete,
            via: self.via.clone(),
        }))
    }
    pub fn hops(&self, a: &Analysis, call: &FieldCall) -> Vec<(String, usize, i64, Hop)> {
        if self.via.is_some() {
            return vec![];
        }
        let Some(target) = call.target.as_ref() else { return vec![] };
        let Ok(range) = a.function(target) else { return vec![] };
        if format!("{:#x}", range.start) != *target {
            return vec![];
        }
        let mut seen = BTreeSet::new();
        call.arguments
            .iter()
            .filter_map(|arg| {
                if arg.load_address.is_some() {
                    return None;
                }
                let reg = layout::parse_reg(arg.register).ok()?;
                let entry = facts::reg_index(reg)?;
                let raw = arg.displacement.strip_prefix("-").unwrap_or(&arg.displacement);
                let abs = u64::from_str_radix(raw.strip_prefix("0x")?, 16).ok()?;
                let signed =
                    if arg.displacement.starts_with('-') { i128::from(abs).checked_neg()? } else { i128::from(abs) };
                let delta = i64::try_from(signed).ok()?;
                if !seen.insert((entry, delta)) {
                    return None;
                }
                let hop = Hop {
                    caller: call.selection.function.clone(),
                    call_site: call.selection.call_site.clone(),
                    target: target.clone(),
                    argument_register: arg.register.into(),
                    base_displacement: signed_hex(delta),
                };
                Some((target.clone(), entry, delta, hop))
            })
            .collect()
    }
}
