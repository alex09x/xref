/*
 * xref — Ultra blazing fast cross-references of an x86-64 ELF binary
 * Copyright (c) 2026 Alexander Panasenko
 *
 * Contact: alex@prod.codes
 * Author: https://prod.codes/about/
 * Project: https://github.com/alex09x/xref
 * SPDX-License-Identifier: MIT OR Apache-2.0
 */

//! Carrying `xmm0`..`xmm15` values across basic blocks in the pseudo-C of a function with a
//! floating-point ABI (float parameters or a float return).
//!
//! The renderer starts every block with an empty register state, so a read of `xmmN` there
//! resolves to the register's home variable (`arg_fN` for a float parameter, `zmmN` otherwise).
//! For that read to be right, every block end assigns each xmm value some successor may still read
//! (backward liveness over the instruction-level CFG) to its home: `arg_f0 = (arg_f0 * arg_f0);`.

use std::collections::HashMap;
use std::ops::Range;

use iced_x86::{FlowControl, Instruction, InstructionInfoFactory, Register};

use crate::expr::State;
use crate::image::{Image, Slot};
use crate::listing::is_call;
use crate::scan::{branch_target, decode};
use crate::sig::xmm::{F64, FloatParam, xmm_index, xmm_rw, zmm};
use crate::ssa_cfg::gpr_idx;
use crate::tables::Table;

pub struct XmmLive {
    /// Per instruction: xmm registers some successor reads before writing.
    after: HashMap<u64, u16>,
    /// Per instruction: xmm registers it writes (scalar semantics; calls excluded).
    writes: HashMap<u64, u16>,
    /// Per call: xmm registers the callee may change ([`callee_clobbers`]).
    clobbers: HashMap<u64, u16>,
    params: Vec<FloatParam>,
}

/// Direct target of a call or tail jump, through a GOT slot as `call_expr_abi` resolves it.
fn direct_target(image: &Image, ins: &Instruction) -> Option<u64> {
    let slot = ins.is_ip_rel_memory_operand().then(|| image.slot(ins.ip_rel_memory_address())).flatten();
    branch_target(ins).or(if let Some(Slot::Pointer(t)) = slot { Some(t) } else { None })
}

/// The float parameters a call passes, exactly those `call_expr_abi` renders as arguments.
fn call_reads(image: &Image, ins: &Instruction) -> u16 {
    direct_target(image, ins)
        .map_or(0, |t| crate::sig::callee_float_abi(image, t).0.iter().fold(0u16, |m, p| m | (1 << (p.index & 15))))
}

/// xmm registers a call to `target` may change: what the callee's own code and its direct callees
/// (two levels down) write, or all of them for an import, an indirect call or a deeper chain.
/// Compilers rely on this (GCC's IPA-RA keeps a value in `xmm2` across a callee that never writes
/// it), so a later read of an untouched register still sees the value from before the call.
pub fn callee_clobbers(image: &Image, target: Option<u64>, depth: usize, seen: &mut Vec<u64>) -> u16 {
    let Some(f) = target.and_then(|t| image.function_at(t).filter(|f| f.start == t)) else { return u16::MAX };
    if seen.contains(&f.start) {
        return 0;
    }
    let Some(code) = image.code(&f).filter(|_| depth <= 2) else { return u16::MAX };
    seen.push(f.start);
    let tables = crate::tables::tables(image, &f);
    let (mut mask, mut factory) = (0u16, InstructionInfoFactory::new());
    decode(code, f.start, |ins| {
        mask |= xmm_rw(&mut factory, ins).1;
        let table = || tables.iter().any(|t| t.dispatch <= ins.ip() && ins.ip() - t.dispatch <= 32);
        let leaves = match ins.flow_control() {
            FlowControl::Call | FlowControl::IndirectCall => true,
            FlowControl::UnconditionalBranch => is_call(ins, &f),
            FlowControl::IndirectBranch => !table(),
            _ => false,
        };
        if leaves {
            mask |= callee_clobbers(image, direct_target(image, ins), depth + 1, seen);
        }
    });
    mask
}

impl XmmLive {
    /// `ret_reads`: registers a `ret` renders (`xmm0` for a float result or an `xmm0` note).
    pub fn build(
        image: &Image,
        function: &Range<u64>,
        code: &[u8],
        tables: &[Table],
        ret_reads: u16,
        params: &[FloatParam],
    ) -> Self {
        let mut insns: Vec<Instruction> = Vec::new();
        decode(code, function.start, |ins| insns.push(*ins));
        let idx: HashMap<u64, usize> = insns.iter().enumerate().map(|(i, ins)| (ins.ip(), i)).collect();
        let n = insns.len();
        let (mut gen_read, mut kill) = (vec![0u16; n], vec![0u16; n]);
        let mut succs: Vec<Vec<usize>> = vec![Vec::new(); n];
        let (mut writes, mut clobbers) = (HashMap::new(), HashMap::new());
        let mut factory = InstructionInfoFactory::new();
        for (i, ins) in insns.iter().enumerate() {
            let (r, w) = xmm_rw(&mut factory, ins);
            (gen_read[i], kill[i]) = (r, w);
            writes.insert(ins.ip(), w);
            let next = idx.get(&ins.next_ip()).copied();
            let target = branch_target(ins).and_then(|t| idx.get(&t).copied());
            match ins.flow_control() {
                FlowControl::Return => gen_read[i] |= ret_reads,
                FlowControl::Call | FlowControl::IndirectCall => {
                    // Arguments are read before the callee changes the registers it writes.
                    gen_read[i] |= call_reads(image, ins);
                    kill[i] = callee_clobbers(image, direct_target(image, ins), 0, &mut Vec::new());
                    clobbers.insert(ins.ip(), kill[i]);
                    succs[i].extend(next);
                }
                FlowControl::ConditionalBranch => succs[i].extend(target.into_iter().chain(next)),
                FlowControl::UnconditionalBranch | FlowControl::IndirectBranch => {
                    if let Some(t) = tables.iter().find(|t| t.dispatch <= ins.ip() && ins.ip() - t.dispatch <= 32) {
                        succs[i].extend(t.arms.iter().filter_map(|arm| idx.get(arm).copied()));
                    } else if is_call(ins, function) || ins.flow_control() == FlowControl::IndirectBranch {
                        gen_read[i] |= call_reads(image, ins);
                    } else {
                        succs[i].extend(target);
                    }
                }
                FlowControl::Interrupt | FlowControl::Exception => {}
                _ => succs[i].extend(next),
            }
        }
        let mut live_in = vec![0u16; n];
        let out_of = |live_in: &[u16], i: usize| succs[i].iter().fold(0u16, |m, &s| m | live_in[s]);
        let mut changed = true;
        while changed {
            changed = false;
            for i in (0..n).rev() {
                let v = gen_read[i] | (out_of(&live_in, i) & !kill[i]);
                if v != live_in[i] {
                    (live_in[i], changed) = (v, true);
                }
            }
        }
        let after = (0..n).map(|i| (insns[i].ip(), out_of(&live_in, i))).collect();
        Self { after, writes, clobbers, params: params.to_vec() }
    }

    /// xmm registers live after the instruction at `ip` (all of them for an unknown address).
    pub fn after(&self, ip: u64) -> u16 {
        self.after.get(&ip).copied().unwrap_or(u16::MAX)
    }

    /// xmm registers the call at `ip` may change (all of them for an unknown address).
    pub fn clobbers(&self, ip: u64) -> u16 {
        self.clobbers.get(&ip).copied().unwrap_or(u16::MAX)
    }

    /// An xmm register the instruction at `ip` writes without the lifter binding a value to it in
    /// this block reads as the register itself afterwards, never as a stale home such as `arg_f0`.
    pub fn bind_unlifted_writes(&self, state: &mut State, ip: u64) {
        let w = self.writes.get(&ip).copied().unwrap_or(0);
        for z in (0..16u8).filter(|i| w & (1 << i) != 0).map(zmm) {
            state.regs.entry(z).or_insert_with(|| crate::expr::reg_name(z));
        }
    }

    fn ty(&self, reg: Register) -> &'static str {
        self.params.iter().find(|p| p.reg() == reg).map_or(F64, |p| p.ty)
    }

    /// Block end: other non-GPR registers flush as in [`crate::c_step::flush_non_gpr_dirty`]; every
    /// xmm register in `live` whose value differs from its home is assigned to it as one parallel
    /// assignment (a target still read by another pending value or by the pending condition flags
    /// is first copied to `fp_{tag}_{home}`).
    pub fn flush(&self, state: &mut State, live: u16, tag: u64, lines: &mut Vec<String>) {
        for reg in std::mem::take(&mut state.dirty) {
            if gpr_idx(reg).is_none() && xmm_index(reg).is_none() {
                let (name, val) = (state.home(reg), state.reg(reg));
                if val != name {
                    lines.push(format!("{name} = {val};"));
                }
                state.regs.insert(reg, name);
            }
        }
        let mut pending: Vec<(Register, String, String)> = (0..16u8)
            .filter(|i| live & (1 << i) != 0)
            .map(zmm)
            .filter_map(|z| {
                let (home, val) = (state.home(z), state.regs.get(&z)?.clone());
                (val != home).then_some((z, home, val))
            })
            .collect();
        let mut snaps: HashMap<String, String> = HashMap::new();
        let mut snapshot = |reg: Register, home: &str, lines: &mut Vec<String>| {
            snaps
                .entry(home.to_owned())
                .or_insert_with(|| {
                    let name = format!("fp_{tag:x}_{home}");
                    lines.push(format!("{} {name} = {home};", self.ty(reg)));
                    name
                })
                .clone()
        };
        if let Some(flags) = state.flags.as_mut() {
            for (z, home, _) in &pending {
                let mut texts: Vec<&mut String> = vec![&mut flags.lhs, &mut flags.rhs];
                if let Some((a, b)) = flags.ovf.as_mut() {
                    texts.extend([a, b]);
                }
                texts.extend(flags.carry.as_mut());
                if texts.iter().any(|t| mentions(t, home)) {
                    let snap = snapshot(*z, home, lines);
                    for t in texts {
                        *t = replace_ident(t, home, &snap);
                    }
                }
            }
        }
        while !pending.is_empty() {
            let free = (0..pending.len())
                .find(|&k| pending.iter().enumerate().all(|(m, p)| m == k || !mentions(&p.2, &pending[k].1)));
            let k = free.unwrap_or_else(|| {
                let (z, home) = (pending[0].0, pending[0].1.clone());
                let snap = snapshot(z, &home, lines);
                for p in pending.iter_mut().skip(1) {
                    p.2 = replace_ident(&p.2, &home, &snap);
                }
                0
            });
            let (z, home, val) = pending.remove(k);
            lines.push(format!("{home} = {val};"));
            state.regs.insert(z, home);
        }
    }
}

const fn is_ident(c: u8) -> bool {
    c.is_ascii_alphanumeric() || c == b'_'
}

fn ident_hits<'a>(code: &'a str, name: &'a str) -> impl Iterator<Item = usize> + 'a {
    let bytes = code.as_bytes();
    code.match_indices(name).map(|(pos, _)| pos).filter(move |&pos| {
        let end = pos + name.len();
        (pos == 0 || !is_ident(bytes[pos - 1])) && (end >= bytes.len() || !is_ident(bytes[end]))
    })
}

fn mentions(code: &str, name: &str) -> bool {
    ident_hits(code, name).next().is_some()
}

fn replace_ident(code: &str, name: &str, with: &str) -> String {
    let mut out = String::with_capacity(code.len());
    let mut last = 0;
    for pos in ident_hits(code, name) {
        out.push_str(&code[last..pos]);
        out.push_str(with);
        last = pos + name.len();
    }
    out.push_str(&code[last..]);
    out
}

#[cfg(test)]
mod tests;
