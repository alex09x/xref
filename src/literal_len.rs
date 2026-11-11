/*
 * xref — Ultra blazing fast cross-references of an x86-64 ELF binary
 * Copyright (c) 2026 Alexander Panasenko
 *
 * Contact: alex@prod.codes
 * Author: https://prod.codes/about/
 * SPDX-License-Identifier: MIT OR Apache-2.0
 */

//! The length of a Rust string literal passed as `(ptr, len)`: `lea rsi, [text]` followed, before
//! the next call, by `mov edx, N` in the next ABI argument register. Rust literals are packed
//! without terminators, so the preview of `text` runs into the next literal; the length cuts it.

use iced_x86::{Code, FlowControl, Instruction, Mnemonic, OpKind, Register};

/// Instructions followed after the `lea` (one unconditional jump is taken).
const MAX_STEPS: usize = 24;

/// The ABI argument register after `reg`, which holds the length of a `(ptr, len)` pair.
fn len_register(reg: Register) -> Option<Register> {
    Some(match reg.full_register() {
        Register::RDI => Register::RSI,
        Register::RSI => Register::RDX,
        Register::RDX => Register::RCX,
        Register::RCX => Register::R8,
        Register::R8 => Register::R9,
        _ => return None,
    })
}

/// The literal length set for the `lea` at `ip` in `listing` (one function, in address order),
/// when the next ABI register gets an immediate before any call or other write to either register.
#[must_use]
pub fn literal_len(listing: &[Instruction], ip: u64) -> Option<usize> {
    let at = listing.binary_search_by_key(&ip, Instruction::ip).ok()?;
    let lea = listing[at];
    if lea.code() != Code::Lea_r64_m || !lea.is_ip_rel_memory_operand() {
        return None;
    }
    let (ptr, len) = (lea.op0_register(), len_register(lea.op0_register())?);
    let mut i = at + 1;
    let mut jumped = false;
    // The length seen so far; it counts only when a call then takes both registers unchanged.
    let mut found: Option<usize> = None;
    for _ in 0..MAX_STEPS {
        let insn = listing.get(i)?;
        let writes = |reg: Register| {
            insn.op_count() > 0 && insn.op0_kind() == OpKind::Register && insn.op0_register().full_register() == reg
        };
        match insn.flow_control() {
            FlowControl::Call | FlowControl::IndirectCall => return found.or_else(|| len_before(listing, at, len)),
            FlowControl::UnconditionalBranch if !jumped => {
                jumped = true;
                match listing.binary_search_by_key(&insn.near_branch_target(), Instruction::ip) {
                    Ok(next) => {
                        i = next;
                        continue;
                    }
                    // A jump out of the function is a tail call taking (ptr, len).
                    Err(_) => return found,
                }
            }
            FlowControl::Next => {}
            _ => return None,
        }
        if writes(len) {
            if found.is_some() || insn.mnemonic() != Mnemonic::Mov || insn.op0_register().size() < 4 {
                return None;
            }
            let imm = matches!(insn.op1_kind(), OpKind::Immediate32 | OpKind::Immediate32to64 | OpKind::Immediate8to32)
                .then(|| insn.immediate(1))?;
            found = Some(usize::try_from(imm).ok().filter(|n| (1..=4096).contains(n))?);
        } else if writes(ptr) {
            return None;
        }
        i += 1;
    }
    None
}

/// The length set just before the `lea` at `at` (`mov edx, 1; lea rsi, [text]; call`), looking
/// back through straight-line code only.
fn len_before(listing: &[Instruction], at: usize, len: Register) -> Option<usize> {
    for insn in listing[..at].iter().rev().take(MAX_STEPS) {
        if insn.flow_control() != FlowControl::Next {
            return None;
        }
        if insn.op_count() > 0 && insn.op0_kind() == OpKind::Register && insn.op0_register().full_register() == len {
            if insn.mnemonic() != Mnemonic::Mov || insn.op0_register().size() < 4 {
                return None;
            }
            let imm = matches!(insn.op1_kind(), OpKind::Immediate32 | OpKind::Immediate32to64 | OpKind::Immediate8to32)
                .then(|| insn.immediate(1))?;
            return usize::try_from(imm).ok().filter(|n| (1..=4096).contains(n));
        }
    }
    None
}

/// The text of the `(ptr, len)` literal loaded by the `lea` at `ip`: exactly `len` bytes of
/// printable UTF-8, however short (a `"e"` followed by other data still reads as `"e"`).
#[must_use]
pub fn literal_at(image: &crate::image::Image, listing: &[Instruction], ip: u64) -> Option<String> {
    let lea = listing[listing.binary_search_by_key(&ip, Instruction::ip).ok()?];
    let len = literal_len(listing, ip)?;
    let text = std::str::from_utf8(image.read(lea.ip_rel_memory_address(), len)?).ok()?;
    text.chars().all(|c| !c.is_control()).then(|| text.to_owned())
}

/// The identifier-like literals (`[A-Za-z0-9_.-]`, 1..=64 bytes) the function passes as
/// `(ptr, len)`, in code order without repeats: the keys a serializer writes.
#[must_use]
pub fn passed_keys(image: &crate::image::Image, function: &std::ops::Range<u64>) -> Vec<String> {
    let Some(code) = image.code(function) else { return Vec::new() };
    let mut listing = Vec::new();
    crate::scan::decode(code, function.start, |instruction| listing.push(*instruction));
    let mut keys: Vec<String> = Vec::new();
    for insn in &listing {
        if insn.code() != Code::Lea_r64_m || !insn.is_ip_rel_memory_operand() {
            continue;
        }
        let Some(key) = literal_at(image, &listing, insn.ip()) else { continue };
        let identifier = key.chars().all(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '.' | '-'));
        if key.len() <= 64 && identifier && !keys.contains(&key) {
            keys.push(key);
        }
    }
    keys
}

#[cfg(test)]
mod tests {
    use iced_x86::{Decoder, DecoderOptions, Instruction};

    use super::literal_len;

    fn decode(bytes: &[u8], ip: u64) -> Vec<Instruction> {
        Decoder::with_ip(64, bytes, ip, DecoderOptions::NONE).into_iter().collect()
    }

    #[test]
    fn a_length_after_a_jump_cuts_the_literal() {
        // 0x1000 lea rsi,[rip+0x100]; 0x1007 jmp 0x1010; 0x1009 nop*7; 0x1010 mov edx,1; 0x1015 call
        let mut bytes = vec![0x48, 0x8d, 0x35, 0x00, 0x01, 0x00, 0x00, 0xeb, 0x07];
        bytes.extend([0x90; 7]);
        bytes.extend([0xba, 0x01, 0x00, 0x00, 0x00, 0xe8, 0x00, 0x00, 0x00, 0x00]);
        let listing = decode(&bytes, 0x1000);
        assert_eq!(literal_len(&listing, 0x1000), Some(1));
    }

    #[test]
    fn no_length_when_a_call_or_a_pointer_write_comes_first() {
        // lea rsi,[rip]; call; mov edx,3
        let listing = decode(&[0x48, 0x8d, 0x35, 0, 0, 0, 0, 0xe8, 0, 0, 0, 0, 0xba, 3, 0, 0, 0], 0x2000);
        assert_eq!(literal_len(&listing, 0x2000), None);
        // lea rsi,[rip]; mov edx,1; ret: no call takes the pair
        let listing = decode(&[0x48, 0x8d, 0x35, 0, 0, 0, 0, 0xba, 1, 0, 0, 0, 0xc3], 0x6000);
        assert_eq!(literal_len(&listing, 0x6000), None);
        // lea rsi,[rip]; mov edx,1; lea rsi,[rip+8]; call: the length belongs to the second literal
        let listing = decode(
            &[0x48, 0x8d, 0x35, 0, 0, 0, 0, 0xba, 1, 0, 0, 0, 0x48, 0x8d, 0x35, 8, 0, 0, 0, 0xe8, 0, 0, 0, 0],
            0x7000,
        );
        assert_eq!(literal_len(&listing, 0x7000), None);
        assert_eq!(literal_len(&listing, 0x700c), Some(1));
        // lea rsi,[rip]; mov dl,1: a partial write is not the length
        let listing = decode(&[0x48, 0x8d, 0x35, 0, 0, 0, 0, 0xb2, 0x01], 0x5000);
        assert_eq!(literal_len(&listing, 0x5000), None);
        // lea rsi,[rip]; cmp edx,5: a comparison is not the length
        let listing = decode(&[0x48, 0x8d, 0x35, 0, 0, 0, 0, 0x83, 0xfa, 0x05], 0x4000);
        assert_eq!(literal_len(&listing, 0x4000), None);
        // lea rsi,[rip]; mov rsi,rdi; mov edx,3
        let listing = decode(&[0x48, 0x8d, 0x35, 0, 0, 0, 0, 0x48, 0x89, 0xfe, 0xba, 3, 0, 0, 0], 0x3000);
        assert_eq!(literal_len(&listing, 0x3000), None);
    }
}
