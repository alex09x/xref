/*
 * xref — Ultra blazing fast cross-references of an x86-64 ELF binary
 * Copyright (c) 2026 Alexander Panasenko
 *
 * Contact: alex@prod.codes
 * Author: https://prod.codes/about/
 * Project: https://github.com/alex09x/xref
 * SPDX-License-Identifier: MIT OR Apache-2.0
 */

//! Whole-binary caller return-value consumption index (`CallerIndex`): proves whether all direct
//! callers of a non-escaped function overwrite `rax` before reading it, or consume `(rax, rdx)`.

use std::collections::{HashMap, HashSet};
use std::ops::Range;

use iced_x86::{FlowControl, Instruction, InstructionInfoFactory, Mnemonic, OpAccess, Register};
use object::{Object, ObjectSymbol};
use rayon::prelude::*;

use crate::graph::call_target;
use crate::image::Image;
use crate::listing::is_call;
use crate::scan::decode;
use crate::sig::{call_reads_rdx, zero_idiom_reg};

mod trace;
mod xmm0;
use trace::trace_reg_after;
use xmm0::trace_xmm0_after;

#[derive(Clone, Copy, Debug, Default)]
pub struct CallerRetStats {
    pub direct_callers: usize,
    pub rax_readers: usize,
    pub rdx_readers: usize,
    pub max_rax_bytes: u8,
    pub rax_may_escape: bool,
    pub addr_taken: bool,
    pub unknown_callers: bool,
    /// Direct call sites with an instruction that reads `xmm0` after the call before overwriting it.
    pub xmm0_readers: usize,
    /// Direct call sites whose use of `xmm0` is undecided: the value may be returned on to their
    /// own caller (`call f; add rsp, 8; ret`) or the walk could not follow every path.
    pub xmm0_undecided: usize,
}

impl CallerRetStats {
    /// Every caller is a known direct call site, so their use of `xmm0` decides whether a float
    /// left there at `ret` is a result.
    pub const fn callers_all_known(self) -> bool {
        self.direct_callers > 0 && !self.unknown_callers && !self.addr_taken
    }

    const fn count_xmm0(&mut self, fate: RegFate) {
        match fate {
            RegFate::Read(_) => self.xmm0_readers += 1,
            RegFate::Unknown => self.xmm0_undecided += 1,
            RegFate::Killed => {}
        }
    }

    pub const fn rax_proven_unused(self) -> bool {
        self.direct_callers > 0
            && !self.unknown_callers
            && !self.addr_taken
            && !self.rax_may_escape
            && self.rax_readers == 0
            && self.rdx_readers == 0
    }

    pub const fn ret_rax_bytes(self) -> u8 {
        if self.direct_callers > 0
            && !self.unknown_callers
            && !self.addr_taken
            && !self.rax_may_escape
            && self.max_rax_bytes > 0
        {
            self.max_rax_bytes
        } else {
            8
        }
    }
}

#[derive(Default)]
pub struct CallerIndex {
    by_target: HashMap<u64, CallerRetStats>,
    /// Per callee: direct targets of calls its callers make before reading or overwriting `xmm0`.
    xmm0_next_calls: HashMap<u64, Vec<u64>>,
}

/// Whether a scalar float left in `xmm0` by the function at `target` may be used: some caller
/// reads `xmm0`, passes it on to a callee whose first float parameter is `xmm0`, or its use is
/// undecided. Without a complete set of direct callers there is no evidence against it, and the
/// callee-side result stands. A following call to a callee without that parameter is not a use.
pub fn xmm0_result_used(image: &Image, stats: CallerRetStats, next_calls: &[u64]) -> bool {
    !stats.callers_all_known()
        || stats.xmm0_readers > 0
        || stats.xmm0_undecided > 0
        || next_calls.iter().any(|&t| crate::sig::callee_float_abi(image, t).0.iter().any(|p| p.index == 0))
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum RegFate {
    Killed,
    Read(u8),
    Unknown,
}

fn insn_rax_step(factory: &mut InstructionInfoFactory, ins: &Instruction) -> Option<RegFate> {
    if zero_idiom_reg(ins) == Some(Register::RAX) {
        return Some(RegFate::Killed);
    }
    let (mut read_sz, mut wrote) = (0u8, false);
    for u in factory.info(ins).used_registers() {
        if u.register().full_register() == Register::RAX {
            let acc = u.access();
            let sz = u8::try_from(u.register().size()).unwrap_or(8);
            if matches!(acc, OpAccess::Read | OpAccess::CondRead | OpAccess::ReadWrite | OpAccess::ReadCondWrite) {
                read_sz = read_sz.max(sz);
            }
            if matches!(acc, OpAccess::Write) && sz >= 4 {
                wrote = true;
            }
        }
    }
    if read_sz > 0 { Some(RegFate::Read(read_sz)) } else { wrote.then_some(RegFate::Killed) }
}

fn trace_rax_after(
    factory: &mut InstructionInfoFactory,
    func_bytes: &[u8],
    func: &Range<u64>,
    entry_ip: u64,
) -> RegFate {
    trace_reg_after(factory, func_bytes, func, entry_ip, insn_rax_step, &mut |_| false)
}

/// One direct call site: target, `rax` fate, `rdx` read, and `xmm0` fate with the calls that follow.
type CallSite = (u64, RegFate, bool, (RegFate, Vec<u64>));

struct LocalEdges {
    calls: Vec<CallSite>,
    escaped: Vec<u64>,
}

fn scan_caller_fn(image: &Image, func: &Range<u64>) -> LocalEdges {
    let mut out = LocalEdges { calls: Vec::new(), escaped: Vec::new() };
    let Some(bytes) = image.code(func) else { return out };
    let mut factory = InstructionInfoFactory::new();
    decode(bytes, func.start, |ins| {
        if ins.mnemonic() == Mnemonic::Lea && ins.is_ip_rel_memory_operand() {
            let place = ins.ip_rel_memory_address();
            if image.function_at(place).is_some_and(|tf| tf.start == place) {
                out.escaped.push(place);
            }
        }
        match ins.flow_control() {
            FlowControl::Call | FlowControl::IndirectCall => {
                if let Some(ct) = call_target(image, ins) {
                    out.calls.push((
                        ct,
                        trace_rax_after(&mut factory, bytes, func, ins.next_ip()),
                        call_reads_rdx(image, func, ins.next_ip()),
                        trace_xmm0_after(image, &mut factory, bytes, func, ins.next_ip()),
                    ));
                }
            }
            FlowControl::UnconditionalBranch if is_call(ins, func) => {
                if let Some(ct) = call_target(image, ins) {
                    out.escaped.push(ct);
                }
            }
            _ => {}
        }
    });
    out
}

fn exported_dynsyms(image: &Image) -> HashSet<u64> {
    let mut set = HashSet::new();
    if image.metadata.kind == crate::image_format::Kind::MachO {
        for &address in &image.metadata.exports {
            set.insert(image.function_at(address).map_or(address, |r| r.start));
        }
        return set;
    }
    if let Ok(file) = object::File::parse(&*image.data) {
        if file.entry() != 0 {
            set.insert(file.entry());
        }
        for sym in file.dynamic_symbols() {
            if sym.is_definition() && sym.address() != 0 {
                set.insert(sym.address());
            }
        }
    }
    set
}

impl CallerIndex {
    pub fn build(image: &Image) -> Self {
        let batches: Vec<LocalEdges> = image.functions.par_iter().map(|f| scan_caller_fn(image, f)).collect();
        let mut by_target: HashMap<u64, CallerRetStats> = HashMap::new();
        let mut xmm0_next_calls: HashMap<u64, Vec<u64>> = HashMap::new();
        for va in exported_dynsyms(image) {
            by_target.entry(va).or_default().addr_taken = true;
        }
        for &(_, target) in &image.pointers {
            if image.function_at(target).is_some_and(|tf| tf.start == target) {
                by_target.entry(target).or_default().addr_taken = true;
            }
        }
        for batch in batches {
            for esc in batch.escaped {
                let st = by_target.entry(esc).or_default();
                (st.addr_taken, st.rax_may_escape) = (true, true);
            }
            for (ct, rax_fate, rdx_read, (xmm0_fate, next_calls)) in batch.calls {
                if !next_calls.is_empty() {
                    xmm0_next_calls.entry(ct).or_default().extend(next_calls);
                }
                let st = by_target.entry(ct).or_default();
                st.direct_callers += 1;
                match rax_fate {
                    RegFate::Read(sz) => {
                        st.rax_readers += 1;
                        st.max_rax_bytes = st.max_rax_bytes.max(sz);
                    }
                    RegFate::Unknown => st.rax_may_escape = true,
                    RegFate::Killed => {}
                }
                st.rdx_readers += usize::from(rdx_read);
                st.count_xmm0(xmm0_fate);
            }
        }
        if image.metadata.kind == crate::image_format::Kind::MachO {
            for stats in by_target.values_mut() {
                stats.unknown_callers = true;
            }
        }
        for calls in xmm0_next_calls.values_mut() {
            calls.sort_unstable();
            calls.dedup();
        }
        Self { by_target, xmm0_next_calls }
    }

    pub fn for_target(image: &Image, target: u64) -> CallerRetStats {
        Self::scan_target(image, target).0
    }

    /// Caller statistics of one function and the targets of calls its callers make before
    /// reading or overwriting `xmm0`, by a whole-image scan (no index built).
    pub fn scan_target(image: &Image, target: u64) -> (CallerRetStats, Vec<u64>) {
        let mut stats = CallerRetStats {
            unknown_callers: image.metadata.kind == crate::image_format::Kind::MachO,
            addr_taken: image.pointers.iter().any(|&(_, t)| t == target) || exported_dynsyms(image).contains(&target),
            ..CallerRetStats::default()
        };
        let parts: Vec<(CallerRetStats, Vec<u64>)> = image
            .functions
            .par_iter()
            .filter_map(|f| {
                let bytes = image.code(f)?;
                let mut local = CallerRetStats::default();
                let mut next = Vec::new();
                let mut factory: Option<InstructionInfoFactory> = None;
                let mut touched = false;
                decode(bytes, f.start, |ins| {
                    if ins.mnemonic() == Mnemonic::Lea
                        && ins.is_ip_rel_memory_operand()
                        && ins.ip_rel_memory_address() == target
                    {
                        (local.addr_taken, local.rax_may_escape, touched) = (true, true, true);
                    }
                    match ins.flow_control() {
                        FlowControl::Call | FlowControl::IndirectCall if call_target(image, ins) == Some(target) => {
                            touched = true;
                            local.direct_callers += 1;
                            let fac = factory.get_or_insert_with(InstructionInfoFactory::new);
                            match trace_rax_after(fac, bytes, f, ins.next_ip()) {
                                RegFate::Read(sz) => {
                                    local.rax_readers += 1;
                                    local.max_rax_bytes = local.max_rax_bytes.max(sz);
                                }
                                RegFate::Unknown => local.rax_may_escape = true,
                                RegFate::Killed => {}
                            }
                            local.rdx_readers += usize::from(call_reads_rdx(image, f, ins.next_ip()));
                            let (fate, calls) = trace_xmm0_after(image, fac, bytes, f, ins.next_ip());
                            local.count_xmm0(fate);
                            next.extend(calls);
                        }
                        FlowControl::UnconditionalBranch
                            if is_call(ins, f) && call_target(image, ins) == Some(target) =>
                        {
                            (local.addr_taken, local.rax_may_escape, touched) = (true, true, true);
                        }
                        _ => {}
                    }
                });
                touched.then_some((local, next))
            })
            .collect();
        let mut next_calls = Vec::new();
        for (p, next) in parts {
            next_calls.extend(next);
            stats.direct_callers += p.direct_callers;
            stats.rax_readers += p.rax_readers;
            stats.rdx_readers += p.rdx_readers;
            stats.max_rax_bytes = stats.max_rax_bytes.max(p.max_rax_bytes);
            stats.rax_may_escape |= p.rax_may_escape;
            stats.addr_taken |= p.addr_taken;
            stats.xmm0_readers += p.xmm0_readers;
            stats.xmm0_undecided += p.xmm0_undecided;
        }
        next_calls.sort_unstable();
        next_calls.dedup();
        (stats, next_calls)
    }

    pub fn get(&self, addr: u64) -> CallerRetStats {
        self.by_target.get(&addr).copied().unwrap_or_default()
    }

    pub fn xmm0_next_calls(&self, addr: u64) -> &[u64] {
        self.xmm0_next_calls.get(&addr).map_or(&[], Vec::as_slice)
    }
}

#[cfg(test)]
mod tests {
    use super::CallerIndex;
    use crate::image::{Image, Segment};

    #[test]
    fn proves_unused_rax_only_when_every_caller_kills_rax() {
        let mut data = vec![0u8; 0x100];
        data[0..6].copy_from_slice(&[0xb8, 0x07, 0x00, 0x00, 0x00, 0xc3]);
        data[0x20..0x26].copy_from_slice(&[0xb8, 0x09, 0x00, 0x00, 0x00, 0xc3]);
        let caller: &[u8] =
            &[0xe8, 0xbb, 0xff, 0xff, 0xff, 0x31, 0xc0, 0xe8, 0xd4, 0xff, 0xff, 0xff, 0x83, 0xc0, 0x01, 0xc3];
        data[0x40..0x40 + caller.len()].copy_from_slice(caller);
        let img = Image {
            data,
            segments: vec![Segment { va: 0x1000, offset: 0, size: 0x100 }],
            functions: vec![0x1000..0x1006, 0x1020..0x1026, 0x1040..0x1040 + caller.len() as u64],
            pointers: Vec::new(),
            imports: Vec::new(),
            symbols: Vec::new(),
            metadata: crate::image_format::Metadata::default(),
        };
        let idx = CallerIndex::build(&img);
        assert!(idx.get(0x1000).rax_proven_unused());
        assert!(CallerIndex::for_target(&img, 0x1000).rax_proven_unused());
        assert!(!idx.get(0x1020).rax_proven_unused() && idx.get(0x1020).rax_readers == 1);
        assert!(!CallerIndex::for_target(&img, 0x1020).rax_proven_unused());
    }
}
