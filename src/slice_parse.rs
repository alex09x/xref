/*
 * xref — Ultra blazing fast cross-references of an x86-64 ELF binary
 * Copyright (c) 2026 Alexander Panasenko
 *
 * Contact: alex@prod.codes
 * Author: https://prod.codes/about/
 * Project: https://github.com/alex09x/xref
 * SPDX-License-Identifier: MIT OR Apache-2.0
 */

//! Pseudo-C line, declaration, def-use, block-span, and target-hint parsers for `xref slice`.

use std::collections::HashSet;

use crate::c::find_comment_outside_str;
use crate::callee_meta::sanitize_panic_path;
use crate::graph::call_target;
use crate::image::Image;
use crate::locations::Location;
use crate::scan::{branch_target, decode};
use crate::source::location_at;

pub struct BlockSpan {
    pub open: usize,
    pub elses: Vec<usize>,
    pub close: usize,
}

pub fn strip_comment(line: &str) -> &str {
    find_comment_outside_str(line).map_or(line, |idx| &line[..idx]).trim()
}

pub fn extract_idents(text: &str) -> Vec<String> {
    let (mut out, mut cur) = (Vec::new(), String::new());
    for ch in text.chars() {
        if ch.is_ascii_alphanumeric() || ch == '_' {
            cur.push(ch);
        } else if !cur.is_empty() {
            if cur.chars().next().is_some_and(|c| c.is_ascii_alphabetic() || c == '_') {
                out.push(std::mem::take(&mut cur));
            } else {
                cur.clear();
            }
        }
    }
    if !cur.is_empty() && cur.chars().next().is_some_and(|c| c.is_ascii_alphabetic() || c == '_') {
        out.push(cur);
    }
    out
}

pub fn pure_decl_ident(code: &str) -> Option<String> {
    if code.contains('=') || code.contains('(') || !code.ends_with(';') {
        return None;
    }
    let body = code.strip_suffix(';')?.trim();
    if body.starts_with("return") || body == "break" || body == "continue" || body.starts_with("goto ") {
        return None;
    }
    extract_idents(body).pop()
}

pub fn decl_ident(code: &str) -> Option<String> {
    if let Some(id) = pure_decl_ident(code) {
        return Some(id);
    }
    let (lhs, _) = code.strip_suffix(';')?.split_once(" = ")?;
    let lt = lhs.trim();
    if lt.starts_with('*') || lt.starts_with('(') || lt.contains("->") || lt.contains('[') {
        return None;
    }
    let mut ids = extract_idents(lt);
    (ids.len() >= 2).then(|| ids.pop()).flatten()
}

fn split_single_line_if(trimmed: &str) -> Option<(&str, &str)> {
    if !trimmed.starts_with("if (") || trimmed.ends_with('{') {
        return None;
    }
    let mut depth = 0i32;
    for (i, &b) in trimmed.as_bytes().iter().enumerate().skip(3) {
        depth += i32::from(b == b'(') - i32::from(b == b')');
        if depth == 0 {
            return Some((&trimmed[4..i], trimmed[i + 1..].trim()));
        }
    }
    None
}

pub fn collect_stack_ptr_vars(lines: &[&str]) -> HashSet<String> {
    let mut out = HashSet::new();
    for &line in lines {
        if let Some((lhs, rhs)) = strip_comment(line).strip_suffix(';').and_then(|s| s.split_once(" = "))
            && rhs.trim().starts_with("&slot_")
            && let Some(id) = extract_idents(lhs.trim()).pop()
        {
            out.insert(id);
        }
    }
    out
}

pub fn stmt_def_use(raw_trimmed: &str, stack_ptr_vars: &HashSet<String>) -> (Vec<String>, Vec<String>) {
    let trimmed = strip_comment(raw_trimmed);
    if trimmed.is_empty() {
        return (Vec::new(), Vec::new());
    }
    if let Some((cond, body)) = split_single_line_if(trimmed) {
        let (defs, mut uses) = stmt_def_use(body, stack_ptr_vars);
        uses.extend(extract_idents(cond));
        return (defs, uses);
    }
    let mut call_defs = Vec::new();
    if trimmed.contains('(') {
        for rest in trimmed.split("&slot_").skip(1) {
            let hex_len = rest.bytes().take_while(u8::is_ascii_hexdigit).count();
            if hex_len > 0
                && let Ok(off) = u64::from_str_radix(&rest[..hex_len], 16)
            {
                call_defs.extend([
                    format!("slot_{off:x}"),
                    format!("slot_{:x}", off + 8),
                    format!("slot_{:x}", off + 16),
                ]);
            }
        }
        for id in extract_idents(trimmed) {
            if stack_ptr_vars.contains(&id) {
                call_defs.push(id);
            }
        }
    }
    if let Some((lhs, rhs)) = trimmed.strip_suffix(';').and_then(|s| s.split_once(" = ")) {
        let lhs_t = lhs.trim();
        if lhs_t.starts_with('*') || lhs_t.contains("->") || lhs_t.contains('[') {
            let mut uses = extract_idents(lhs_t);
            uses.extend(extract_idents(rhs));
            return (call_defs, uses);
        }
        let mut lhs_ids = extract_idents(lhs_t);
        let mut defs: Vec<String> = if lhs_t.starts_with('(') { lhs_ids } else { lhs_ids.pop().into_iter().collect() };
        defs.extend(call_defs);
        return (defs, extract_idents(rhs));
    }
    (call_defs, extract_idents(trimmed))
}

pub fn build_block_spans(lines: &[&str], sig_idx: usize) -> Vec<BlockSpan> {
    let (mut stack, mut spans): (Vec<(usize, Vec<usize>)>, Vec<BlockSpan>) = (Vec::new(), Vec::new());
    for (idx, &line) in lines.iter().enumerate().skip(sig_idx + 1).take(lines.len().saturating_sub(sig_idx + 2)) {
        let t = strip_comment(line);
        if t.starts_with("} else") && t.ends_with('{') {
            if let Some((_, elses)) = stack.last_mut() {
                elses.push(idx);
            }
        } else if t.ends_with('{') {
            stack.push((idx, Vec::new()));
        } else if (t == "}" || t.starts_with("} while"))
            && let Some((open, elses)) = stack.pop()
        {
            spans.push(BlockSpan { open, elses, close: idx });
        }
    }
    spans
}

pub fn target_hints_for_ip(image: &Image, locs: &[Location], f: &std::ops::Range<u64>, target_ip: u64) -> Vec<String> {
    let mut hints = vec![format!("{target_ip:#x}"), format!("L_{target_ip:x}")];
    let Some(bytes) = image.code(f) else { return hints };
    decode(bytes, f.start, |ins| {
        if ins.ip() <= target_ip + 32 && target_ip < ins.next_ip() {
            if let Some(ct) = call_target(image, ins) {
                hints.push(format!("fn_{ct:x}"));
            }
            if let Some(bt) = branch_target(ins) {
                hints.push(format!("L_{bt:x}"));
            }
            if ins.is_ip_rel_memory_operand() {
                let place = ins.ip_rel_memory_address();
                if let Some(loc) = location_at(locs, place) {
                    hints.push(format!("{}:{}", sanitize_panic_path(&loc.file), loc.line));
                } else if let Some(prev) = image.preview(place) {
                    hints.push(prev);
                }
            }
        }
    });
    hints
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MarkKind {
    Exact,
    MayAlias,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FieldSliceTarget {
    pub offset: i64,
    pub reg: iced_x86::Register,
    pub va: u64,
}

impl std::fmt::Display for FieldSliceTarget {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let reg = format!("{:?}", self.reg).to_ascii_lowercase();
        if self.offset < 0 {
            write!(f, "-{:#x} of {reg}@{:#x}", self.offset.unsigned_abs(), self.va)
        } else {
            write!(f, "+{:#x} of {reg}@{:#x}", self.offset, self.va)
        }
    }
}

pub fn parse_register(name: &str) -> Option<iced_x86::Register> {
    let reg = match name.trim().to_ascii_lowercase().as_str() {
        "rax" | "eax" | "ax" | "al" => iced_x86::Register::RAX,
        "rcx" | "ecx" | "cx" | "cl" => iced_x86::Register::RCX,
        "rdx" | "edx" | "dx" | "dl" => iced_x86::Register::RDX,
        "rbx" | "ebx" | "bx" | "bl" => iced_x86::Register::RBX,
        "rsp" | "esp" | "sp" | "spl" => iced_x86::Register::RSP,
        "rbp" | "ebp" | "bp" | "bpl" => iced_x86::Register::RBP,
        "rsi" | "esi" | "si" | "sil" => iced_x86::Register::RSI,
        "rdi" | "edi" | "di" | "dil" => iced_x86::Register::RDI,
        "r8" | "r8d" | "r8w" | "r8b" => iced_x86::Register::R8,
        "r9" | "r9d" | "r9w" | "r9b" => iced_x86::Register::R9,
        "r10" | "r10d" | "r10w" | "r10b" => iced_x86::Register::R10,
        "r11" | "r11d" | "r11w" | "r11b" => iced_x86::Register::R11,
        "r12" | "r12d" | "r12w" | "r12b" => iced_x86::Register::R12,
        "r13" | "r13d" | "r13w" | "r13b" => iced_x86::Register::R13,
        "r14" | "r14d" | "r14w" | "r14b" => iced_x86::Register::R14,
        "r15" | "r15d" | "r15w" | "r15b" => iced_x86::Register::R15,
        _ => return None,
    };
    Some(reg)
}

pub fn parse_signed_offset(s: &str) -> Option<i64> {
    let s = s.trim();
    let (neg, s) = s.strip_prefix('-').map_or_else(
        || s.strip_prefix('+').map_or_else(|| (false, s), |sp| (false, sp.trim_start())),
        |sp| (true, sp.trim_start()),
    );
    let val = if let Some(hex) = s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")) {
        i64::from_str_radix(hex, 16).ok()?
    } else {
        s.parse::<i64>().ok()?
    };
    Some(if neg { -val } else { val })
}

impl FieldSliceTarget {
    pub fn parse(target: &str) -> Option<Self> {
        let (off_s, rest) = target.trim().split_once(" of ")?;
        let offset = parse_signed_offset(off_s)?;
        let (reg_s, va_s) = rest.trim().split_once('@')?;
        let reg = parse_register(reg_s)?;
        let va = va_s.trim().strip_prefix("0x").or_else(|| va_s.trim().strip_prefix("0X")).map_or_else(
            || u64::from_str_radix(va_s.trim(), 16).ok().or_else(|| va_s.trim().parse::<u64>().ok()),
            |h| u64::from_str_radix(h, 16).ok(),
        )?;
        Some(Self { offset, reg, va })
    }
}
