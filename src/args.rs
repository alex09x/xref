/*
 * xref — Ultra blazing fast cross-references of an x86-64 ELF binary
 * Copyright (c) 2026 Alexander Panasenko
 *
 * Contact: alex@prod.codes
 * Author: https://prod.codes/about/
 * SPDX-License-Identifier: MIT OR Apache-2.0
 */

//! Call-site constant and symbolic argument recovery (`args`) for System V AMD64 register and stack slots.

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::io::Write;
use std::ops::Range;

use iced_x86::{ConditionCode, FlowControl, Instruction, Mnemonic, OpKind, Register};
use rayon::prelude::*;

use crate::commands::Res;
use crate::expr::{ABI_ARGS, reg_name};
use crate::graph::{call_target, resolve_addr};
use crate::image::{Image, Slot};
use crate::listing::is_call;
use crate::locations::{Location, locations};
use crate::scan::{branch_target, decode, immediates};
use crate::source::location_at;

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

fn fmt_imm(v: u64) -> String {
    if v < 10 { format!("{v}") } else { format!("{v:#x}") }
}

fn fmt_rip(image: &Image, locs: &[Location], addr: u64) -> String {
    if let Some(loc) = location_at(locs, addr) {
        return format!("{addr:#x} ({}:{}:{})", loc.file, loc.line, loc.col);
    }
    let target = match image.slot(addr) {
        Some(Slot::Pointer(t)) => t,
        _ => addr,
    };
    image.preview(target).map_or_else(|| format!("{target:#x}"), |text| format!("{target:#x} ({text:?})"))
}

fn op_val(
    image: &Image,
    locs: &[Location],
    regs: &HashMap<Register, String>,
    instruction: &Instruction,
    idx: u32,
) -> String {
    match instruction.op_kind(idx) {
        OpKind::Register => {
            let r = instruction.op_register(idx).full_register();
            regs.get(&r).cloned().unwrap_or_else(|| format!("{} (dynamic)", reg_name(r)))
        }
        OpKind::Memory if instruction.is_ip_rel_memory_operand() => {
            fmt_rip(image, locs, instruction.ip_rel_memory_address())
        }
        OpKind::Memory => "mem (dynamic)".to_owned(),
        _ => fmt_imm(immediates(instruction).next().unwrap_or(0)),
    }
}

const fn cc_op(cc: ConditionCode) -> &'static str {
    match cc {
        ConditionCode::e => "==",
        ConditionCode::ne => "!=",
        _ => "?",
    }
}

struct Tracker {
    regs: HashMap<Register, String>,
    stack: BTreeMap<u64, String>,
    pushed: Vec<String>,
    last_cmp: Option<(String, String)>,
}

impl Tracker {
    fn step(&mut self, image: &Image, locs: &[Location], instruction: &Instruction, max_stack: usize) {
        let m = instruction.mnemonic();
        if m == Mnemonic::Push {
            let val = op_val(image, locs, &self.regs, instruction, 0);
            self.pushed.push(val);
            return;
        }
        if matches!(m, Mnemonic::Sub | Mnemonic::Add | Mnemonic::Pop)
            && instruction.op0_register().full_register() == Register::RSP
        {
            self.pushed.clear();
            return;
        }
        if m == Mnemonic::Cmp {
            let lhs = op_val(image, locs, &self.regs, instruction, 0).replace(" (dynamic)", "");
            let rhs = op_val(image, locs, &self.regs, instruction, 1).replace(" (dynamic)", "");
            self.last_cmp = Some((lhs, rhs));
            return;
        }
        if m == Mnemonic::Test && instruction.op0_register() == instruction.op1_register() {
            let lhs = op_val(image, locs, &self.regs, instruction, 0).replace(" (dynamic)", "");
            self.last_cmp = Some((lhs, "0".to_owned()));
            return;
        }
        if matches!(m, Mnemonic::Mov | Mnemonic::Movzx | Mnemonic::Movsx | Mnemonic::Movsxd)
            && instruction.op0_kind() == OpKind::Memory
        {
            if instruction.memory_base().full_register() == Register::RSP
                && instruction.memory_index() == Register::None
            {
                let disp = instruction.memory_displacement64();
                if disp.is_multiple_of(8) && disp < (max_stack as u64) * 8 {
                    let val = op_val(image, locs, &self.regs, instruction, 1);
                    self.stack.insert(disp / 8, val);
                }
            }
            return;
        }
        if instruction.op0_kind() != OpKind::Register {
            return;
        }
        let dst = instruction.op0_register().full_register();
        if m == Mnemonic::Xor && instruction.op0_register() == instruction.op1_register() {
            self.regs.insert(dst, "0".to_owned());
        } else if matches!(m, Mnemonic::Mov | Mnemonic::Movzx | Mnemonic::Movsx | Mnemonic::Movsxd) {
            let val = op_val(image, locs, &self.regs, instruction, 1);
            self.regs.insert(dst, val);
        } else if m == Mnemonic::Lea {
            let val = if instruction.is_ip_rel_memory_operand() {
                fmt_rip(image, locs, instruction.ip_rel_memory_address())
            } else if instruction.memory_base().full_register() == Register::RSP {
                format!("&rsp[{:#x}] (dynamic)", instruction.memory_displacement64())
            } else {
                format!("{} (dynamic)", reg_name(dst))
            };
            self.regs.insert(dst, val);
        } else if instruction.condition_code() != ConditionCode::None
            && instruction.flow_control() == FlowControl::Next
            && let Some((lhs, rhs)) = &self.last_cmp
        {
            let op = cc_op(instruction.condition_code());
            self.regs.insert(dst, format!("{lhs}{op}{rhs}"));
        } else {
            self.regs.remove(&dst);
        }
    }

    fn snapshot(&self, max_stack: usize) -> Vec<String> {
        let mut items = Vec::new();
        for &reg in &ABI_ARGS {
            if let Some(val) = self.regs.get(&reg) {
                items.push(format!("{}={val}", reg_name(reg)));
            }
        }
        if self.pushed.is_empty() {
            for idx in 0..max_stack {
                if let Some(val) = self.stack.get(&(idx as u64)) {
                    items.push(format!("stack{idx}={val}"));
                }
            }
        } else {
            for (idx, val) in self.pushed.iter().rev().take(max_stack).enumerate() {
                items.push(format!("stack{idx}={val}"));
            }
        }
        items
    }
}

fn analyze_caller(
    image: &Image,
    locs: &[Location],
    f: &Range<u64>,
    bytes: &[u8],
    target: u64,
    max_stack: usize,
) -> Vec<(u64, Range<u64>, Vec<String>)> {
    let mut has_call = false;
    let mut leaders = BTreeSet::new();
    decode(bytes, f.start, |instruction| {
        if is_call(instruction, f) && call_target(image, instruction) == Some(target) {
            has_call = true;
        }
        if let Some(dest) = branch_target(instruction)
            && f.contains(&dest)
        {
            leaders.insert(dest);
        }
    });
    if !has_call {
        return Vec::new();
    }
    let mut tracker = Tracker { regs: HashMap::new(), stack: BTreeMap::new(), pushed: Vec::new(), last_cmp: None };
    let mut sites = Vec::new();
    decode(bytes, f.start, |instruction| {
        if leaders.contains(&instruction.ip()) {
            tracker.pushed.clear();
        }
        if is_call(instruction, f) && call_target(image, instruction) == Some(target) {
            sites.push((instruction.ip(), f.clone(), tracker.snapshot(max_stack)));
        }
        if matches!(instruction.flow_control(), FlowControl::Call | FlowControl::IndirectCall) {
            for r in VOLATILE {
                tracker.regs.remove(&r);
            }
            tracker.pushed.clear();
            return;
        }
        tracker.step(image, locs, instruction, max_stack);
    });
    sites
}

pub fn args(image: &Image, spec: &str, max_stack: usize, out: &mut dyn Write) -> Res {
    let raw = resolve_addr(image, spec)?;
    let target = image.function_at(raw).map_or(raw, |f| f.start);
    let all_locs = locations(image);
    let mut sites: Vec<(u64, Range<u64>, Vec<String>)> = image
        .functions
        .par_iter()
        .filter_map(|f| Some((f, image.code(f)?)))
        .flat_map_iter(|(f, bytes)| analyze_caller(image, &all_locs, f, bytes, target, max_stack))
        .collect();
    sites.sort_by_key(|(ip, ..)| *ip);
    for (ip, f, items) in &sites {
        let joined = items.join("  ");
        let (start, end) = (f.start, f.end);
        writeln!(out, "{ip:#x}  in {start:#x}..{end:#x}  {joined}")?;
    }
    writeln!(out, "{} call sites", sites.len())?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::args;
    use crate::image::{Image, Segment};

    #[test]
    fn recovers_register_and_stack_arguments_at_call_sites() {
        let mut data = vec![0xc3u8; 0x400];
        // Caller 1 at 0x1000: xor r8d, r8d; push 0; push r12; mov ecx, 1; call 0x1200; ret
        let c1: &[u8] = &[
            0x74, 0x00, // je +0 (local branch target leader)
            0x45, 0x31, 0xc0, // xor r8d, r8d
            0x6a, 0x00, // push 0
            0x41, 0x54, // push r12
            0xb9, 0x01, 0x00, 0x00, 0x00, // mov ecx, 1
            0xe8, 0xed, 0x01, 0x00, 0x00, // call 0x1200
            0xc3,
        ];
        data[..c1.len()].copy_from_slice(c1);

        // Caller 2 at 0x1040: prologue sub rsp, cmp/sete/setne/setg, mov [rsp+N], lea rip/rsp/reg, call helper, call 0x1200
        let c2: &[u8] = &[
            0x55, // push rbp
            0x48, 0x83, 0xec, 0x20, // sub rsp, 0x20 (clears prologue push)
            0x80, 0xfb, 0x03, // cmp bl, 3
            0x0f, 0x94, 0xc0, // sete al
            0x89, 0x04, 0x24, // mov [rsp], eax
            0x48, 0xc7, 0x44, 0x24, 0x08, 0x20, 0x00, 0x00, 0x00, // mov qword ptr [rsp+8], 0x20
            0xe8, 0xa4, 0x01, 0x00, 0x00, // call 0x1200 (first call)
            0x48, 0x85, 0xff, // test rdi, rdi
            0x0f, 0x95, 0xc2, // setne dl
            0x0f, 0x9f, 0xc1, // setg cl
            0x48, 0x8d, 0x3d, 0x94, 0x02, 0x00, 0x00, // lea rdi, [rip+0x294] -> 0x1300
            0x48, 0x8d, 0x35, 0xa8, 0x02, 0x00, 0x00, // lea rsi, [rip+0x2a8] -> 0x131b -> 0x1340 "hello"
            0x4c, 0x8d, 0x44, 0x24, 0x10, // lea r8, [rsp+0x10]
            0x4c, 0x8d, 0x4b, 0x08, // lea r9, [rbx+8]
            0x48, 0x83, 0xc1, 0x05, // add rcx, 5 (invalidates rcx)
            0x48, 0x8b, 0x05, 0xa9, 0x02, 0x00, 0x00, // mov rax, [rip+0x2a9] -> 0x1330 (unmapped)
            0x48, 0x8b, 0x13, // mov rdx, [rbx] (mem dynamic)
            0x89, 0x1c, 0x24, // mov [rsp], ebx
            0xe8, 0x6e, 0x01, 0x00, 0x00, // call 0x1200 (second call)
            0xc3,
        ];
        data[0x40..0x40 + c2.len()].copy_from_slice(c2);

        // Panic location at 0x1300 -> "src/arg.rs":12:3
        data[0x308..0x310].copy_from_slice(&10u64.to_le_bytes());
        data[0x310..0x314].copy_from_slice(&12u32.to_le_bytes());
        data[0x314..0x318].copy_from_slice(&3u32.to_le_bytes());
        data[0x320..0x32a].copy_from_slice(b"src/arg.rs");
        data[0x340..0x345].copy_from_slice(b"hello");

        let image = Image {
            data,
            segments: vec![Segment { va: 0x1000, offset: 0, size: 0x400 }],
            functions: vec![0x1000..0x1000 + c1.len() as u64, 0x1040..0x1040 + c2.len() as u64, 0x1200..0x1201],
            pointers: vec![(0x1300, 0x1320), (0x131b, 0x1340)],
            imports: Vec::new(),
            symbols: vec![(0x1200, "target_fn".to_owned())],
            metadata: crate::image_format::Metadata::default(),
        };

        let mut out = Vec::new();
        assert!(args(&image, "target_fn", 4, &mut out).is_ok());
        let text = String::from_utf8_lossy(&out);
        assert!(text.contains("rcx=1  r8=0  stack0=r12 (dynamic)  stack1=0"), "{text}");
        assert!(text.contains("stack0=rbx==3  stack1=0x20"), "{text}");
        assert!(text.contains("rdi=0x1300 (src/arg.rs:12:3)  rsi=0x1340 (\"hello\")"), "{text}");
        assert!(text.contains("r8=&rsp[0x10] (dynamic)  r9=r9 (dynamic)"), "{text}");
    }
}
