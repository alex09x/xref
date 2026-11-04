/*
 * XRef — Field store identification and grouping by base
 * Copyright (c) 2026 Alexander Panasenko
 * Contact: alex@prod.codes
 * Author: https://prod.codes/about/
 * Project: https://github.com/alex09x/xref
 * SPDX-License-Identifier: MIT OR Apache-2.0
 */

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::ops::Range;

use iced_x86::{FlowControl, Instruction, Mnemonic, OpKind, Register};

use super::model::FieldStore;
use crate::expr::ABI_ARGS;
use crate::image::Image;
use crate::scan::{decode, immediates};
use crate::sig::FnSig;

const VOLATILE: [Register; 9] = [
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

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum BaseId {
    Arg(usize),
    Stack,
    Global(u64),
}

#[derive(Default)]
struct StoreTracker {
    reg_alias: HashMap<Register, (BaseId, i64)>,
    stack_alias: HashMap<i64, (BaseId, i64)>,
}

impl StoreTracker {
    fn new(sig: &FnSig) -> Self {
        let mut tracker = Self::default();
        for (idx, &reg) in ABI_ARGS.iter().enumerate() {
            tracker.reg_alias.insert(reg, (BaseId::Arg(idx), 0));
        }
        tracker.reg_alias.insert(Register::RSP, (BaseId::Stack, 0));
        if sig.uses_fp {
            tracker.reg_alias.insert(Register::RBP, (BaseId::Stack, 0));
        }
        tracker
    }

    fn step(&mut self, ins: &Instruction) {
        let m = ins.mnemonic();
        if matches!(ins.flow_control(), FlowControl::Call | FlowControl::IndirectCall) {
            for reg in VOLATILE {
                self.reg_alias.remove(&reg);
            }
            return;
        }

        if m == Mnemonic::Mov {
            if ins.op0_kind() == OpKind::Register {
                let dst = ins.op0_register().full_register();
                if ins.op1_kind() == OpKind::Register {
                    let src = ins.op1_register().full_register();
                    if let Some(&val) = self.reg_alias.get(&src) {
                        self.reg_alias.insert(dst, val);
                    } else {
                        self.reg_alias.remove(&dst);
                    }
                } else if !ins.is_ip_rel_memory_operand() && ins.memory_base().full_register() == Register::RSP {
                    let sp = ins.memory_displacement64().cast_signed();
                    if let Some(&val) = self.stack_alias.get(&sp) {
                        self.reg_alias.insert(dst, val);
                    } else {
                        self.reg_alias.remove(&dst);
                    }
                } else {
                    self.reg_alias.remove(&dst);
                }
                return;
            }
            if !ins.is_ip_rel_memory_operand()
                && ins.memory_base().full_register() == Register::RSP
                && ins.op1_kind() == OpKind::Register
            {
                let sp = ins.memory_displacement64().cast_signed();
                let src = ins.op1_register().full_register();
                if let Some(&val) = self.reg_alias.get(&src) {
                    self.stack_alias.insert(sp, val);
                } else {
                    self.stack_alias.remove(&sp);
                }
                return;
            }
        }

        if m == Mnemonic::Lea && ins.op0_kind() == OpKind::Register {
            let dst = ins.op0_register().full_register();
            if ins.is_ip_rel_memory_operand() {
                self.reg_alias.insert(dst, (BaseId::Global(ins.ip_rel_memory_address()), 0));
            } else if ins.memory_index() == Register::None {
                let base = ins.memory_base().full_register();
                let disp = ins.memory_displacement64().cast_signed();
                if let Some(&(base_id, delta)) = self.reg_alias.get(&base) {
                    self.reg_alias.insert(dst, (base_id, delta.wrapping_add(disp)));
                } else {
                    self.reg_alias.remove(&dst);
                }
            } else {
                self.reg_alias.remove(&dst);
            }
            return;
        }

        if matches!(m, Mnemonic::Add | Mnemonic::Sub) && ins.op0_kind() == OpKind::Register {
            let dst = ins.op0_register().full_register();
            if let Some((_, delta)) = self.reg_alias.get_mut(&dst) {
                let imm = immediates(ins).next().map_or(0, u64::cast_signed);
                if m == Mnemonic::Add {
                    *delta = delta.wrapping_add(imm);
                } else {
                    *delta = delta.wrapping_sub(imm);
                }
            }
            return;
        }

        if ins.op0_kind() == OpKind::Register {
            let dst = ins.op0_register().full_register();
            self.reg_alias.remove(&dst);
        }
    }
}

/// Analyze stores in `function`, returning stores grouped by base (argN, stack, global).
#[must_use]
pub fn analyze_stores(image: &Image, function: &Range<u64>, sig: &FnSig) -> BTreeMap<String, Vec<FieldStore>> {
    let Some(bytes) = image.code(function) else { return BTreeMap::new() };
    let mut tracker = StoreTracker::new(sig);
    let mut raw_stores: BTreeMap<String, BTreeMap<i64, BTreeSet<usize>>> = BTreeMap::new();

    decode(bytes, function.start, |ins| {
        for op_idx in 0..ins.op_count() {
            if ins.op_kind(op_idx) == OpKind::Memory && crate::disp::is_mem_write(ins, op_idx) {
                let sz = ins.memory_size().size();
                let width = if sz == 0 { 8 } else { sz };

                if ins.is_ip_rel_memory_operand() {
                    let addr = ins.ip_rel_memory_address();
                    let offset = i64::try_from(addr).unwrap_or(0);
                    raw_stores.entry("global".to_owned()).or_default().entry(offset).or_default().insert(width);
                } else if ins.memory_base() == Register::None && ins.memory_index() == Register::None {
                    let offset = ins.memory_displacement64().cast_signed();
                    raw_stores.entry("global".to_owned()).or_default().entry(offset).or_default().insert(width);
                } else {
                    let base_reg = ins.memory_base().full_register();
                    let disp = ins.memory_displacement64().cast_signed();
                    // An indexed store (`[rdi+rdx*8+0x10]`) hits an element chosen at run time, so it
                    // is grouped under an indexed base instead of posing as the exact field `+0x10`.
                    let index = ins.memory_index();
                    let suffix = if index == Register::None {
                        String::new()
                    } else {
                        format!("[{}*{}]", crate::expr::reg_name(index.full_register()), ins.memory_index_scale())
                    };

                    if base_reg == Register::RSP || (sig.uses_fp && base_reg == Register::RBP) {
                        raw_stores.entry(format!("stack{suffix}")).or_default().entry(disp).or_default().insert(width);
                    } else if let Some(&(base_id, delta)) = tracker.reg_alias.get(&base_reg) {
                        let offset = delta.wrapping_add(disp);
                        let base_name = match base_id {
                            BaseId::Arg(n) => format!("arg{n}{suffix}"),
                            BaseId::Stack => format!("stack{suffix}"),
                            BaseId::Global(addr) => {
                                let g_off = i64::try_from(addr).unwrap_or(0).wrapping_add(offset);
                                raw_stores
                                    .entry(format!("global{suffix}"))
                                    .or_default()
                                    .entry(g_off)
                                    .or_default()
                                    .insert(width);
                                continue;
                            }
                        };
                        raw_stores.entry(base_name).or_default().entry(offset).or_default().insert(width);
                    }
                }
            }
        }
        tracker.step(ins);
    });

    let mut result: BTreeMap<String, Vec<FieldStore>> = BTreeMap::new();
    for (base, fields) in raw_stores {
        let mut field_stores: Vec<FieldStore> = fields
            .into_iter()
            .map(|(offset, widths)| FieldStore { offset, widths: widths.into_iter().collect() })
            .collect();
        field_stores.sort_by_key(|f| f.offset);
        result.insert(base, field_stores);
    }
    result
}
