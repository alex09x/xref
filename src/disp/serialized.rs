/*
 * xref — Ultra blazing fast cross-references of an x86-64 ELF binary
 * Copyright (c) 2026 Alexander Panasenko
 *
 * Contact: alex@prod.codes
 * Author: https://prod.codes/about/
 * Project: https://github.com/alex09x/xref
 * SPDX-License-Identifier: MIT OR Apache-2.0
 */

//! `xref disp OFF --who-serializes`: the key a struct field is serialized under. A derived
//! serializer passes each field with its key to one call, `serialize_field(state, "key", len,
//! &self.field)`, so the call takes a `(ptr, len)` key literal and `lea rcx, [rbx+OFF]` (or the
//! loaded value) in ABI argument registers. When the key and the value go to separate calls
//! (`serialize_key("key")` then the value written inline), a read of the field shortly after the
//! key call is reported as following it.

use std::collections::{BTreeMap, BTreeSet};
use std::io::Write;
use std::ops::Range;

use iced_x86::{Code, FlowControl, Instruction, Mnemonic, OpKind, Register};
use rayon::prelude::*;

use crate::commands::Res;
use crate::expr::ABI_ARGS;
use crate::image::Image;
use crate::listing::describe_branch;
use crate::literal_len::literal_at;
use crate::scan::{decode, format};

/// Instructions after a key call within which a read of the field still follows that key.
const FOLLOW_WINDOW: usize = 12;

/// One field passed or read next to a key.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct Serialized {
    pub offset: u64,
    pub key: String,
    pub function: u64,
    /// The call taking key and field, or the field read following the key call.
    pub at: u64,
    /// The key and the field go to the same call.
    pub same_call: bool,
    pub access: String,
    pub callee: String,
}

/// An ABI argument register loaded from `[reg+offset]` (address or value) outside the stack.
fn field_argument(instruction: &Instruction, offsets: &[u64]) -> Option<(Register, u64)> {
    let field = field_access(instruction, offsets)?;
    if instruction.op0_kind() != OpKind::Register {
        return None;
    }
    let register = instruction.op0_register().full_register();
    let loads = matches!(instruction.mnemonic(), Mnemonic::Lea | Mnemonic::Mov | Mnemonic::Movzx | Mnemonic::Movsx);
    (loads && ABI_ARGS.contains(&register)).then_some((register, field))
}

/// The offset of `instruction`'s non-stack, non-RIP-relative memory operand, if it is one of `offsets`.
fn field_access(instruction: &Instruction, offsets: &[u64]) -> Option<u64> {
    let memory = (0..instruction.op_count()).any(|index| instruction.op_kind(index) == OpKind::Memory);
    let base = instruction.memory_base().full_register();
    let off = instruction.memory_displacement64();
    (memory
        && !instruction.is_ip_rel_memory_operand()
        && !matches!(base, Register::None | Register::RSP | Register::RBP)
        && offsets.contains(&off))
    .then_some(off)
}

/// The register written by `instruction`, if its first operand is one.
fn written(instruction: &Instruction) -> Option<Register> {
    (instruction.op_count() > 0
        && instruction.op0_kind() == OpKind::Register
        && !matches!(instruction.mnemonic(), Mnemonic::Cmp | Mnemonic::Test))
    .then(|| instruction.op0_register().full_register())
}

/// Whether `instruction` hands control to another function: a call or a jump out of `function`.
fn is_call(instruction: &Instruction, function: &Range<u64>) -> bool {
    match instruction.flow_control() {
        FlowControl::Call | FlowControl::IndirectCall => true,
        FlowControl::UnconditionalBranch => !function.contains(&instruction.near_branch_target()),
        _ => false,
    }
}

/// Keys and fields of one function, in code order.
fn in_function(image: &Image, function: &Range<u64>, offsets: &[u64]) -> Vec<Serialized> {
    let Some(code) = image.code(function) else { return Vec::new() };
    let mut listing = Vec::new();
    decode(code, function.start, |instruction| listing.push(*instruction));
    let row = |offset, key, at, same_call, access, callee| Serialized {
        offset,
        key,
        function: function.start,
        at,
        same_call,
        access,
        callee,
    };
    let mut found = Vec::new();
    // Since the last call: the key literal and the registers holding a field.
    let mut key: Option<String> = None;
    let mut fields: Vec<(Register, u64, String)> = Vec::new();
    // After a call that took only a key: the key, the index right after the call, and the field
    // reads since then. The reads are dropped when another key is loaded before the next call:
    // they prepare that key's value.
    let mut previous: Option<(String, usize)> = None;
    let mut guesses: Vec<Serialized> = Vec::new();
    for (index, instruction) in listing.iter().enumerate() {
        if is_call(instruction, function) {
            found.append(&mut guesses);
            previous = None;
            let passed = std::mem::take(&mut fields).into_iter().filter(|(held, _, _)| ABI_ARGS.contains(held));
            match key.take() {
                Some(name) => {
                    let passed: Vec<_> = passed.collect();
                    for (_, offset, access) in &passed {
                        let callee = describe_branch(image, instruction);
                        found.push(row(*offset, name.clone(), instruction.ip(), true, access.clone(), callee));
                    }
                    if passed.is_empty() {
                        previous = Some((name, index + 1));
                    }
                }
                // `lea rcx, [rbx+OFF]; call helper` where the helper passes the key with its argument.
                None => {
                    for (register, offset, access) in passed {
                        let Some((name, call)) = helper_key(image, instruction, register) else { continue };
                        let callee = format!("{} -> {call}", describe_branch(image, instruction));
                        found.push(row(offset, name, instruction.ip(), true, access, callee));
                    }
                }
            }
            continue;
        }
        match instruction.flow_control() {
            // The next instruction starts a block reached some other way.
            FlowControl::Return | FlowControl::IndirectBranch | FlowControl::Interrupt | FlowControl::Exception => {
                found.append(&mut guesses);
                (key, previous) = (None, None);
                fields.clear();
                continue;
            }
            FlowControl::UnconditionalBranch => {
                found.append(&mut guesses);
                previous = None;
            }
            _ => {}
        }
        if let Some(text) = key_literal(image, &listing, instruction) {
            key = Some(text);
            fields.retain(|(held, _, _)| Some(*held) != written(instruction));
            guesses.clear();
            previous = None;
            continue;
        }
        if let Some((name, after)) = &previous
            && index - after < FOLLOW_WINDOW
            && let Some(offset) = field_access(instruction, offsets)
        {
            guesses.push(row(offset, name.clone(), instruction.ip(), false, format(instruction), String::new()));
        }
        let copied = copied_from(instruction).and_then(|source| fields.iter().find(|(held, _, _)| *held == source));
        let copied = copied.map(|(_, offset, access)| (*offset, access.clone()));
        if let Some(register) = written(instruction) {
            fields.retain(|(held, _, _)| *held != register);
            if let Some((offset, access)) = copied {
                fields.push((register, offset, access));
            }
        }
        if let Some((register, offset)) = field_argument(instruction, offsets) {
            fields.push((register, offset, format(instruction)));
        }
        // `add rbx, 0x20; mov rcx, rbx`: the base moved to the field, then passed.
        if instruction.mnemonic() == Mnemonic::Add
            && instruction.op0_kind() == OpKind::Register
            && !matches!(instruction.op0_register().full_register(), Register::RSP | Register::RBP)
            && let Some(offset) = immediate(instruction).filter(|value| offsets.contains(value))
        {
            fields.push((instruction.op0_register().full_register(), offset, format(instruction)));
        }
    }
    found.append(&mut guesses);
    found
}

/// The second operand of `instruction` as an immediate, if it is one.
fn immediate(instruction: &Instruction) -> Option<u64> {
    matches!(
        instruction.op1_kind(),
        OpKind::Immediate8to64 | OpKind::Immediate32to64 | OpKind::Immediate8to32 | OpKind::Immediate32
    )
    .then(|| instruction.immediate(1))
}

/// A `(ptr, len)` key literal loaded by `instruction`: an identifier of at most 64 bytes.
fn key_literal(image: &Image, listing: &[Instruction], instruction: &Instruction) -> Option<String> {
    if instruction.code() != Code::Lea_r64_m || !instruction.is_ip_rel_memory_operand() {
        return None;
    }
    let text = literal_at(image, listing, instruction.ip())?;
    let identifier = text.chars().all(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '.' | '-'));
    (text.len() <= 64 && identifier).then_some(text)
}

/// The source register of `mov reg, reg`.
fn copied_from(instruction: &Instruction) -> Option<Register> {
    (instruction.mnemonic() == Mnemonic::Mov
        && instruction.op0_kind() == OpKind::Register
        && instruction.op1_kind() == OpKind::Register)
        .then(|| instruction.op1_register().full_register())
}

/// Largest helper looked into: a field helper only forwards its argument with a key.
const MAX_HELPER_BYTES: u64 = 0x200;

/// Calls followed inside a helper before giving up.
const MAX_HELPER_CALLS: usize = 4;

/// The key a small helper called by `call` passes together with its argument `register`
/// (unchanged or copied to another register), and the call it passes them to.
fn helper_key(image: &Image, call: &Instruction, register: Register) -> Option<(String, String)> {
    let target = match call.op0_kind() {
        OpKind::NearBranch64 | OpKind::NearBranch32 => call.near_branch_target(),
        _ => return None,
    };
    let helper = image.function_at(target).filter(|f| f.start == target && f.end - f.start <= MAX_HELPER_BYTES)?;
    let code = image.code(&helper)?;
    let mut listing = Vec::new();
    decode(code, helper.start, |instruction| listing.push(*instruction));
    let mut holders = vec![register];
    let mut key: Option<String> = None;
    // A key written by a call of its own; the value goes to the very next call (`serialize_key`,
    // then the value). A later call (a drop, a panic path) says nothing about the key.
    let mut written_key: Option<String> = None;
    let mut calls = 0;
    for instruction in &listing {
        if matches!(instruction.flow_control(), FlowControl::Return | FlowControl::IndirectBranch) {
            return None;
        }
        if is_call(instruction, &helper) {
            let passes_field = holders.iter().any(|held| ABI_ARGS.contains(held));
            match key.take() {
                Some(name) if passes_field => return Some((name, describe_branch(image, instruction))),
                Some(name) => written_key = Some(name),
                None if passes_field => return written_key.map(|name| (name, describe_branch(image, instruction))),
                None => written_key = None,
            }
            calls += 1;
            if calls >= MAX_HELPER_CALLS {
                return None;
            }
            holders.retain(|held| !ABI_ARGS.contains(held) && *held != Register::RAX);
            continue;
        }
        if let Some(text) = key_literal(image, &listing, instruction) {
            key = Some(text);
            holders.retain(|held| Some(*held) != written(instruction));
            continue;
        }
        let copied = copied_from(instruction).is_some_and(|source| holders.contains(&source));
        if let Some(written) = written(instruction) {
            holders.retain(|held| *held != written);
            if copied {
                holders.push(written);
            }
        }
    }
    None
}

/// Every key the fields at `offsets` are serialized under, and the functions accessing each offset.
#[must_use]
pub fn find(
    image: &Image,
    functions: &[Range<u64>],
    offsets: &[u64],
) -> (Vec<Serialized>, BTreeMap<u64, BTreeSet<u64>>) {
    let mut accessing: BTreeMap<u64, BTreeSet<u64>> = BTreeMap::new();
    for hit in crate::scan::search_disp(image, functions, offsets, false, false, None) {
        accessing.entry(hit.offset).or_default().insert(hit.hit.function.start);
    }
    let all: BTreeSet<u64> = accessing.values().flatten().copied().collect();
    // One function (`--in`) is read whole: it may take a field address with `add` alone.
    let candidates: Vec<&Range<u64>> =
        functions.iter().filter(|f| functions.len() == 1 || all.contains(&f.start)).collect();
    let mut found: Vec<Serialized> =
        candidates.par_iter().flat_map_iter(|function| in_function(image, function, offsets)).collect();
    found.sort();
    found.dedup();
    (found, accessing)
}

/// `xref disp OFF.. --who-serializes`.
pub fn run(image: &Image, functions: &[Range<u64>], offsets: &[u64], out: &mut dyn Write) -> Res {
    let (found, accessing) = find(image, functions, offsets);
    for &offset in offsets {
        let accessing = accessing.get(&offset).map_or(0, BTreeSet::len);
        let rows: Vec<&Serialized> = found.iter().filter(|row| row.offset == offset).collect();
        let mut keys: Vec<&str> = rows.iter().filter(|row| row.same_call).map(|row| row.key.as_str()).collect();
        if keys.is_empty() {
            keys = rows.iter().map(|row| row.key.as_str()).collect();
        }
        keys.sort_unstable();
        keys.dedup();
        if keys.is_empty() {
            if accessing == 0 {
                writeln!(out, "+{offset:#x}  not serialized: no struct access at this displacement")?;
            } else {
                writeln!(
                    out,
                    "+{offset:#x}  not serialized: {accessing} functions access it, none passes it with a key literal"
                )?;
            }
            continue;
        }
        let quoted: Vec<String> = keys.iter().map(|key| format!("{key:?}")).collect();
        writeln!(out, "+{offset:#x}  {}", quoted.join(", "))?;
        // A read after a key call is only a guess; it is shown when no call takes the field with its key.
        let direct = rows.iter().any(|row| row.same_call);
        for row in rows.into_iter().filter(|row| row.same_call || !direct) {
            if row.same_call {
                writeln!(
                    out,
                    "  {:?}  in {:#x}  call {:#x} -> {}  ({})",
                    row.key, row.function, row.at, row.callee, row.access
                )?;
            } else {
                writeln!(
                    out,
                    "  {:?}  in {:#x}  {:#x}  {}  (after the key call)",
                    row.key, row.function, row.at, row.access
                )?;
            }
        }
    }
    Ok(())
}

#[cfg(test)]
#[path = "serialized_tests.rs"]
mod tests;
