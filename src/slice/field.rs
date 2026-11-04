/*
 * XRef — Memory field target tracking for program slicing
 * Copyright (c) 2026 Alexander Panasenko
 * Contact: alex@prod.codes
 * Author: https://prod.codes/about/
 * Project: https://github.com/alex09x/xref
 * SPDX-License-Identifier: MIT OR Apache-2.0
 */

//! Tracks base pointer values and constant offsets across register copies, `lea`, and stack slots
//! to identify field-access instructions and may-alias memory operations.

use std::collections::{HashMap, VecDeque};
use std::ops::Range;

use iced_x86::{FlowControl, Instruction, Mnemonic, OpKind, Register};

use crate::expr::ABI_ARGS;
use crate::image::Image;
use crate::scan::{branch_target, decode, immediates};
use crate::slice_parse::{FieldSliceTarget, MarkKind};

#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub enum BaseId {
    Arg(usize),
    Stack,
    Def(u64),
}

#[derive(Clone, PartialEq, Eq, Default, Debug)]
pub struct State {
    pub regs: HashMap<Register, (BaseId, i64)>,
    pub stack: HashMap<i64, (BaseId, i64)>,
}

impl State {
    pub fn merge(&mut self, incoming: &Self) -> bool {
        let mut changed = false;
        self.regs.retain(|reg, val| {
            if incoming.regs.get(reg) == Some(val) {
                true
            } else {
                changed = true;
                false
            }
        });
        self.stack.retain(|slot, val| {
            if incoming.stack.get(slot) == Some(val) {
                true
            } else {
                changed = true;
                false
            }
        });
        changed
    }
}

fn sync_opt<K: Eq + std::hash::Hash, V: Copy>(map: &mut HashMap<K, V>, dst: K, val: Option<V>) {
    match val {
        Some(v) => {
            map.insert(dst, v);
        }
        None => {
            map.remove(&dst);
        }
    }
}

fn copy_key<K: Eq + std::hash::Hash + Copy, V: Copy>(map: &mut HashMap<K, V>, src: &K, dst: K) {
    let val = map.get(src).copied();
    sync_opt(map, dst, val);
}

fn step_mov_lea(ins: &Instruction, dst: Option<Register>, st: &mut State) -> bool {
    let m = ins.mnemonic();
    let ip = ins.ip();
    if m == Mnemonic::Mov {
        if let Some(d) = dst {
            if ins.op1_kind() == OpKind::Register {
                let src = ins.op1_register().full_register();
                copy_key(&mut st.regs, &src, d);
                return true;
            }
            if !ins.is_ip_rel_memory_operand()
                && ins.memory_base().full_register() == Register::RSP
                && ins.memory_index() == Register::None
            {
                let sp = ins.memory_displacement64().cast_signed();
                sync_opt(&mut st.regs, d, st.stack.get(&sp).copied());
                return true;
            }
            st.regs.insert(d, (BaseId::Def(ip), 0));
            return true;
        }
        if !ins.is_ip_rel_memory_operand()
            && ins.memory_base().full_register() == Register::RSP
            && ins.memory_index() == Register::None
            && ins.op1_kind() == OpKind::Register
        {
            let sp = ins.memory_displacement64().cast_signed();
            let src = ins.op1_register().full_register();
            sync_opt(&mut st.stack, sp, st.regs.get(&src).copied());
            return true;
        }
    }

    if matches!(m, Mnemonic::Movzx | Mnemonic::Movsx | Mnemonic::Movsxd) && let Some(d) = dst {
        if ins.op1_kind() == OpKind::Register {
            let src = ins.op1_register().full_register();
            copy_key(&mut st.regs, &src, d);
        } else {
            st.regs.insert(d, (BaseId::Def(ip), 0));
        }
        return true;
    }

    if m == Mnemonic::Lea && let Some(d) = dst {
        let b = ins.memory_base().full_register();
        let ix = ins.memory_index().full_register();
        let disp = ins.memory_displacement64().cast_signed();
        if ix == Register::None {
            if let Some(&(base_id, delta)) = st.regs.get(&b) {
                st.regs.insert(d, (base_id, delta.wrapping_add(disp)));
            } else if b == Register::RSP {
                st.regs.insert(d, (BaseId::Stack, disp));
            } else if b != Register::None {
                st.regs.insert(d, (BaseId::Def(ip), 0));
            } else {
                st.regs.remove(&d);
            }
        } else {
            st.regs.insert(d, (BaseId::Def(ip), 0));
        }
        return true;
    }

    false
}

pub fn step_state(ins: &Instruction, st: &mut State) {
    let m = ins.mnemonic();
    let dst = (ins.op0_kind() == OpKind::Register).then(|| ins.op0_register().full_register());
    let ip = ins.ip();

    if step_mov_lea(ins, dst, st) {
        return;
    }

    if m == Mnemonic::Add && let Some(d) = dst {
        if let Some(imm) = immediates(ins).next() {
            if let Some((_, delta)) = st.regs.get_mut(&d) {
                *delta = delta.wrapping_add(imm.cast_signed());
            } else {
                st.regs.insert(d, (BaseId::Def(ip), 0));
            }
        } else {
            st.regs.insert(d, (BaseId::Def(ip), 0));
        }
        return;
    }

    if m == Mnemonic::Sub && let Some(d) = dst {
        if let Some(imm) = immediates(ins).next() {
            if let Some((_, delta)) = st.regs.get_mut(&d) {
                *delta = delta.wrapping_sub(imm.cast_signed());
            } else {
                st.regs.insert(d, (BaseId::Def(ip), 0));
            }
        } else {
            st.regs.insert(d, (BaseId::Def(ip), 0));
        }
        return;
    }

    if m == Mnemonic::Call {
        for r in [
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
            st.regs.remove(&r);
        }
        st.regs.insert(Register::RAX, (BaseId::Def(ip), 0));
        return;
    }

    if let Some(d) = dst
        && !matches!(m, Mnemonic::Cmp | Mnemonic::Test | Mnemonic::Push)
    {
        st.regs.insert(d, (BaseId::Def(ip), 0));
    }
}

pub fn find_field_targets(
    image: &Image,
    f: &Range<u64>,
    target: &FieldSliceTarget,
) -> Result<HashMap<u64, MarkKind>, String> {
    let Some(bytes) = image.code(f) else {
        return Err(format!("no code found for function {:#x}..{:#x}", f.start, f.end));
    };
    if !f.contains(&target.va) {
        return Err(format!("target instruction {:#x} outside function {:#x}..{:#x}", target.va, f.start, f.end));
    }

    let mut insns = Vec::new();
    let mut ip_to_idx = HashMap::new();
    decode(bytes, f.start, |ins| {
        ip_to_idx.insert(ins.ip(), insns.len());
        insns.push(*ins);
    });

    let mut entry_state = State::default();
    for (i, &reg) in ABI_ARGS.iter().enumerate() {
        entry_state.regs.insert(reg, (BaseId::Arg(i), 0));
    }
    entry_state.regs.insert(Register::RSP, (BaseId::Stack, 0));

    let mut pre_states: HashMap<u64, State> = HashMap::new();
    let mut post_states: HashMap<u64, State> = HashMap::new();
    let mut worklist: VecDeque<u64> = VecDeque::from([f.start]);
    pre_states.insert(f.start, entry_state);

    while let Some(ip) = worklist.pop_front() {
        let Some(&idx) = ip_to_idx.get(&ip) else { continue };
        let ins = &insns[idx];
        let mut st = pre_states.get(&ip).cloned().unwrap_or_default();
        step_state(ins, &mut st);
        post_states.insert(ip, st.clone());

        let fc = ins.flow_control();
        let mut succs = Vec::new();
        if !matches!(fc, FlowControl::Return | FlowControl::Interrupt | FlowControl::Exception) {
            if let Some(target_branch) = branch_target(ins) {
                succs.push(target_branch);
                if fc != FlowControl::UnconditionalBranch {
                    succs.push(ins.next_ip());
                }
            } else {
                succs.push(ins.next_ip());
            }
        }

        for succ in succs {
            if f.contains(&succ) {
                if let Some(existing) = pre_states.get_mut(&succ) {
                    if existing.merge(&st) {
                        worklist.push_back(succ);
                    }
                } else {
                    pre_states.insert(succ, st.clone());
                    worklist.push_back(succ);
                }
            }
        }
    }

    let target_reg = target.reg.full_register();
    let defines_reg = insns
        .iter()
        .find(|i| i.ip() == target.va)
        .is_some_and(|ins| ins.op0_kind() == OpKind::Register && ins.op0_register().full_register() == target_reg);

    let state_at_va = if defines_reg { post_states.get(&target.va) } else { pre_states.get(&target.va) };

    let (target_base, base_delta) =
        state_at_va.and_then(|s| s.regs.get(&target_reg).copied()).unwrap_or((BaseId::Def(target.va), 0));
    let target_field_offset = base_delta.wrapping_add(target.offset);

    let mut mark_targets = HashMap::new();
    for ins in &insns {
        let ip = ins.ip();
        let Some(st) = pre_states.get(&ip) else { continue };
        if ins.mnemonic() == Mnemonic::Lea {
            continue;
        }
        let has_mem = (0..ins.op_count()).any(|i| ins.op_kind(i) == OpKind::Memory);
        if !has_mem || ins.is_ip_rel_memory_operand() {
            continue;
        }

        let base = ins.memory_base().full_register();
        let index = ins.memory_index().full_register();
        let disp = ins.memory_displacement64().cast_signed();

        if target_base != BaseId::Stack && (base == Register::RSP || base == Register::RBP) {
            continue;
        }

        if let Some(&(b_id, b_delta)) = st.regs.get(&base) {
            if b_id == target_base {
                if index == Register::None {
                    let eff = b_delta.wrapping_add(disp);
                    if eff == target_field_offset {
                        mark_targets.insert(ip, MarkKind::Exact);
                    }
                } else {
                    mark_targets.insert(ip, MarkKind::MayAlias);
                }
            } else if b_id == BaseId::Stack && target_base != BaseId::Stack {
                // Stack access does not alias external struct
            } else if index != Register::None || b_delta.wrapping_add(disp) == target_field_offset {
                // A different pointer can only alias the field at the same field offset.
                mark_targets.insert(ip, MarkKind::MayAlias);
            }
        } else if base != Register::None && (index != Register::None || disp == target.offset) {
            mark_targets.insert(ip, MarkKind::MayAlias);
        }
    }

    if mark_targets.is_empty() {
        return Err(format!("field target {target} not found in {:#x}..{:#x}", f.start, f.end));
    }
    Ok(mark_targets)
}
