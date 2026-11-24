/*
 * xref — Ultra blazing fast cross-references of an x86-64 ELF binary
 * Copyright (c) 2026 Alexander Panasenko
 *
 * Contact: alex@prod.codes
 * Author: https://prod.codes/about/
 * Project: https://github.com/alex09x/xref
 * SPDX-License-Identifier: MIT OR Apache-2.0
 */

//! `path --via-vtables`: candidate edges through `dyn Trait` calls. A Rust vtable is
//! `[drop_in_place, size, align, method...]` in relocated data; a call through it is
//! `call qword ptr [rax+OFF]` with the vtable in `rax`. Without knowing the concrete type, every
//! method stored at `OFF` of some vtable is a candidate callee of that call. The edges are a guess
//! (any implementor), so `path` marks them and uses them only when asked.

use std::collections::HashMap;

use iced_x86::{Decoder, DecoderOptions, OpKind, Register};

use super::CallGraph;
use crate::image::Image;

/// Methods a vtable may hold; longer runs of function pointers are tables of another kind.
const MAX_METHODS: u64 = 256;

/// Largest alignment a type can have.
const MAX_ALIGN: u64 = 1 << 29;

/// Candidate callers of vtable methods.
pub struct Candidates {
    /// Indirect call sites `call [reg+off]` by `off`: `(calling function, call address)`.
    sites: HashMap<u64, Vec<(u64, u64)>>,
    /// The vtable offsets each method is stored at.
    methods: HashMap<u64, Vec<u64>>,
}

fn word(image: &Image, at: u64) -> Option<u64> {
    image.read(at, 8).and_then(|bytes| bytes.try_into().ok()).map(u64::from_le_bytes)
}

/// The method slots of a vtable starting at `start`: a drop pointer or zero, a plain size, a
/// power-of-two alignment, then pointers to function starts.
fn vtable_methods(image: &Image, start: u64) -> Vec<(u64, u64)> {
    let pointer =
        |at: u64| image.pointers.binary_search_by_key(&at, |(place, _)| *place).ok().map(|i| image.pointers[i].1);
    let drop_ok = pointer(start).is_some() || word(image, start) == Some(0);
    let size_ok = pointer(start + 8).is_none() && word(image, start + 8).is_some_and(|size| size < 1 << 32);
    let align_ok = pointer(start + 16).is_none()
        && word(image, start + 16).is_some_and(|align| align.is_power_of_two() && align <= MAX_ALIGN);
    if !(drop_ok && size_ok && align_ok) {
        return Vec::new();
    }
    (0..MAX_METHODS)
        .map(|k| start + 24 + k * 8)
        .map_while(|at| {
            let target = pointer(at)?;
            image.function_at(target).filter(|f| f.start == target).map(|_| (at - start, target))
        })
        .collect()
}

/// `call qword ptr [reg+off]` (no index, not RIP-relative): the offset.
fn slot_offset(image: &Image, ip: u64) -> Option<u64> {
    let bytes = image.read(ip, 15).or_else(|| image.read(ip, 7))?;
    let instruction = Decoder::with_ip(64, bytes, ip, DecoderOptions::NONE).decode();
    (instruction.op0_kind() == OpKind::Memory
        && !instruction.is_ip_rel_memory_operand()
        && instruction.memory_base() != Register::None
        && instruction.memory_index() == Register::None)
        .then(|| instruction.memory_displacement64())
        .filter(|&off| (24..24 + MAX_METHODS * 8).contains(&off) && off.is_multiple_of(8))
}

impl Candidates {
    pub fn build(image: &Image, graph: &CallGraph) -> Self {
        let mut sites: HashMap<u64, Vec<(u64, u64)>> = HashMap::new();
        for (&function, ips) in &graph.unresolved {
            for &ip in ips {
                if let Some(off) = slot_offset(image, ip) {
                    sites.entry(off).or_default().push((function, ip));
                }
            }
        }
        // A vtable starts at a drop pointer, or at a zero word followed by size and align.
        let mut starts: Vec<u64> = image.pointers.iter().map(|(place, _)| *place).collect();
        starts.extend(image.pointers.iter().filter_map(|(place, _)| place.checked_sub(24)));
        starts.sort_unstable();
        starts.dedup();
        let mut methods: HashMap<u64, Vec<u64>> = HashMap::new();
        for start in starts {
            for (off, function) in vtable_methods(image, start) {
                let offsets = methods.entry(function).or_default();
                if sites.contains_key(&off) && !offsets.contains(&off) {
                    offsets.push(off);
                }
            }
        }
        Self { sites, methods }
    }

    /// `methods M at N offsets, K dyn call sites` for the output.
    pub fn summary(&self) -> String {
        let offsets: std::collections::HashSet<u64> = self.methods.values().flatten().copied().collect();
        let methods = self.methods.values().filter(|offsets| !offsets.is_empty()).count();
        let sites: usize = self.sites.values().map(Vec::len).sum();
        format!(
            "via vtables: {methods} vtable methods at {} slot offsets, {sites} dyn call sites `call [reg+off]` as candidate edges",
            offsets.len()
        )
    }

    /// The calls that may reach `function` through a vtable: `(call address, calling function)`.
    pub fn callers(&self, function: u64) -> Vec<(u64, u64)> {
        self.methods
            .get(&function)
            .into_iter()
            .flatten()
            .flat_map(|off| self.sites.get(off).into_iter().flatten())
            .map(|&(caller, ip)| (ip, caller))
            .collect()
    }
}

#[cfg(test)]
#[path = "vtable_paths_tests.rs"]
mod tests;
