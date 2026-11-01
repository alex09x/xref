/*
 * xref — Ultra blazing fast cross-references of an x86-64 ELF binary
 * Copyright (c) 2026 Alexander Panasenko
 *
 * Contact: alex@prod.codes
 * Author: https://prod.codes/about/
 * SPDX-License-Identifier: MIT OR Apache-2.0
 */

//! Struct field layout reconstruction (`layout`): tracks pointer aliases, stack spills, `lea`
//! sub-borrows, array element strides and forwarded callees from a base argument register.

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::io::Write;
use std::ops::Range;

use iced_x86::{Instruction, MemorySize, Mnemonic, OpKind, Register};

use crate::commands::Res;
use crate::expr::{ABI_ARGS, CALLEE_SAVED};
use crate::graph::{call_target, resolve};
use crate::image::Image;
use crate::listing::{describe_code, is_call};
use crate::runtime::RuntimeMap;
use crate::scan::{decode, immediates};

const NAMED_REGS: &[(&str, Register)] = &[
    ("rdi", Register::RDI),
    ("rsi", Register::RSI),
    ("rdx", Register::RDX),
    ("rcx", Register::RCX),
    ("r8", Register::R8),
    ("r9", Register::R9),
    ("rax", Register::RAX),
    ("rbx", Register::RBX),
    ("rbp", Register::RBP),
    ("r12", Register::R12),
    ("r13", Register::R13),
    ("r14", Register::R14),
    ("r15", Register::R15),
];

#[derive(Default)]
struct FieldInfo {
    width: usize,
    ty: &'static str,
    reads: usize,
    writes: usize,
    leas: usize,
    stride: Option<u64>,
    callees: BTreeSet<u64>,
}

const fn size_and_type(ms: MemorySize) -> (usize, &'static str) {
    match ms {
        MemorySize::UInt8 | MemorySize::Int8 => (1, "u8"),
        MemorySize::UInt16 | MemorySize::Int16 => (2, "u16"),
        MemorySize::UInt32 | MemorySize::Int32 | MemorySize::Float32 | MemorySize::DwordOffset => (4, "u32"),
        MemorySize::UInt128 | MemorySize::Int128 | MemorySize::Packed128_Float32 | MemorySize::Packed128_Float64 => {
            (16, "u128")
        }
        _ => (8, "u64"),
    }
}

pub fn parse_reg(name: &str) -> Result<Register, String> {
    let lower = name.to_ascii_lowercase();
    NAMED_REGS
        .iter()
        .find(|(n, _)| *n == lower)
        .map(|(_, r)| *r)
        .ok_or_else(|| format!("unknown register {name:?} (expected rdi, rsi, rdx, rcx, r8, r9, rbx, rbp, r12..r15)"))
}

#[derive(Default)]
struct AliasState {
    reg_alias: HashMap<Register, i64>,
    stack_alias: HashMap<i64, i64>,
    arr_ptrs: HashMap<Register, u64>,
    strides: HashMap<Register, u64>,
}

fn scan_mem_op(
    ins: &Instruction,
    dst: Option<Register>,
    st: &mut AliasState,
    fields: &mut BTreeMap<u64, FieldInfo>,
) -> bool {
    let m = ins.mnemonic();
    let (b, ix, disp) = (
        ins.memory_base().full_register(),
        ins.memory_index().full_register(),
        ins.memory_displacement64().cast_signed(),
    );
    if let Some(&delta) = st.reg_alias.get(&b)
        && let Ok(off) = u64::try_from(delta + disp)
    {
        if m == Mnemonic::Lea {
            if ix == Register::None {
                if disp != 0 {
                    fields.entry(off).or_default().leas += 1;
                }
                if let Some(d) = dst {
                    st.reg_alias.insert(d, delta + disp);
                }
                return true;
            }
        } else {
            let (w, ty) = size_and_type(ins.memory_size());
            let info = fields.entry(off).or_default();
            if w > info.width {
                (info.width, info.ty) = (w, ty);
            }
            if ins.op0_kind() == OpKind::Memory && !matches!(m, Mnemonic::Cmp | Mnemonic::Test) {
                info.writes += 1;
            } else {
                info.reads += 1;
            }
            if m == Mnemonic::Mov
                && let Some(d) = dst
                && w == 8
            {
                st.arr_ptrs.insert(d, off);
                st.reg_alias.remove(&d);
                return true;
            }
        }
    } else if let Some(&field_off) = st.arr_ptrs.get(&b).or_else(|| st.arr_ptrs.get(&ix))
        && let Some(s) = st
            .strides
            .get(&ix)
            .or_else(|| st.strides.get(&b))
            .copied()
            .or_else(|| (ins.memory_index_scale() > 1).then(|| u64::from(ins.memory_index_scale())))
    {
        fields.entry(field_off).or_default().stride = Some(s);
    }
    false
}

fn scan_fn(
    image: &Image,
    function: &Range<u64>,
    entry_reg: Register,
    base_delta: i64,
    fields: &mut BTreeMap<u64, FieldInfo>,
    forwarded: &mut Vec<(u64, Register, i64)>,
) {
    let Some(bytes) = image.code(function) else { return };
    let mut st = AliasState { reg_alias: HashMap::from([(entry_reg, base_delta)]), ..AliasState::default() };

    decode(bytes, function.start, |ins: &Instruction| {
        let m = ins.mnemonic();
        let dst = (ins.op0_kind() == OpKind::Register).then(|| ins.op0_register().full_register());
        if (0..ins.op_count()).any(|i| ins.op_kind(i) == OpKind::Memory)
            && !ins.is_ip_rel_memory_operand()
            && scan_mem_op(ins, dst, &mut st, fields)
        {
            return;
        }
        if m == Mnemonic::Mov {
            if let Some(d) = dst {
                if ins.op1_kind() == OpKind::Register {
                    let src = ins.op1_register().full_register();
                    match st.reg_alias.get(&src).copied() {
                        Some(delta) => _ = st.reg_alias.insert(d, delta),
                        None => _ = st.reg_alias.remove(&d),
                    }
                    match st.arr_ptrs.get(&src).copied() {
                        Some(f_off) => _ = st.arr_ptrs.insert(d, f_off),
                        None => _ = st.arr_ptrs.remove(&d),
                    }
                    return;
                }
                if !ins.is_ip_rel_memory_operand()
                    && ins.memory_base().full_register() == Register::RSP
                    && ins.memory_index() == Register::None
                {
                    let sp = ins.memory_displacement64().cast_signed();
                    match st.stack_alias.get(&sp).copied() {
                        Some(delta) => _ = st.reg_alias.insert(d, delta),
                        None => _ = st.reg_alias.remove(&d),
                    }
                    return;
                }
            } else if !ins.is_ip_rel_memory_operand()
                && ins.memory_base().full_register() == Register::RSP
                && ins.memory_index() == Register::None
                && ins.op1_kind() == OpKind::Register
            {
                let (sp, src) = (ins.memory_displacement64().cast_signed(), ins.op1_register().full_register());
                match st.reg_alias.get(&src).copied() {
                    Some(delta) => _ = st.stack_alias.insert(sp, delta),
                    None => _ = st.stack_alias.remove(&sp),
                }
                return;
            }
        }
        if m == Mnemonic::Add
            && let Some(d) = dst
            && let Some(imm) = immediates(ins).next()
            && let Some(delta) = st.reg_alias.get_mut(&d)
        {
            *delta = delta.wrapping_add(imm.cast_signed());
            if let Ok(off) = u64::try_from(*delta) {
                fields.entry(off).or_default().leas += 1;
            }
            return;
        }
        if m == Mnemonic::Imul
            && let Some(d) = dst
            && let Some(s) = immediates(ins).find(|&v| v > 1)
        {
            st.strides.insert(d, s);
            st.reg_alias.remove(&d);
            return;
        }
        if m == Mnemonic::Shl
            && let Some(d) = dst
            && let Some(sh) = immediates(ins).find(|&v| (1..=16).contains(&v))
        {
            st.strides.insert(d, 1u64 << sh);
            st.reg_alias.remove(&d);
            return;
        }
        if is_call(ins, function) {
            if let Some(ct) = call_target(image, ins) {
                for &abi_r in &ABI_ARGS {
                    if let Some(&delta) = st.reg_alias.get(&abi_r).filter(|&&d| d >= 0) {
                        if delta > 0
                            && let Ok(off) = u64::try_from(delta)
                        {
                            fields.entry(off).or_default().callees.insert(ct);
                        }
                        forwarded.push((ct, abi_r, delta));
                    }
                }
            }
            st.reg_alias.retain(|r, _| CALLEE_SAVED.contains(r));
            st.arr_ptrs.retain(|r, _| CALLEE_SAVED.contains(r));
            st.strides.retain(|r, _| CALLEE_SAVED.contains(r));
            return;
        }
        if let Some(d) = dst {
            st.reg_alias.remove(&d);
            st.arr_ptrs.remove(&d);
            st.strides.remove(&d);
        }
    });
}

pub fn layout(image: &Image, spec: &str, reg_name: &str, follow_callees: bool, out: &mut dyn Write) -> Res {
    let root = resolve(image, spec)?;
    let reg = parse_reg(reg_name)?;
    let rt = RuntimeMap::detect(image);
    let mut fields: BTreeMap<u64, FieldInfo> = BTreeMap::new();
    let mut forwarded = Vec::new();
    scan_fn(image, &root, reg, 0, &mut fields, &mut forwarded);

    let mut visited_callees = BTreeSet::new();
    if follow_callees {
        let mut seen_hop = BTreeSet::new();
        for (ct, abi_r, delta) in forwarded {
            if ct != root.start
                && seen_hop.insert((ct, abi_r, delta))
                && let Some(cf) = image.function_at(ct).filter(|cf| cf.start == ct)
            {
                visited_callees.insert(ct);
                let mut dummy = Vec::new();
                scan_fn(image, &cf, abi_r, delta, &mut fields, &mut dummy);
            }
        }
    }

    if visited_callees.is_empty() {
        writeln!(out, "layout of {} in {:#x}..{:#x}:", reg_name.to_ascii_lowercase(), root.start, root.end)?;
    } else {
        writeln!(
            out,
            "layout of {} in {:#x}..{:#x} (+{} callees):",
            reg_name.to_ascii_lowercase(),
            root.start,
            root.end,
            visited_callees.len()
        )?;
    }
    for (&off, info) in &fields {
        let ty = if info.ty.is_empty() { "&sub" } else { info.ty };
        let mut notes = Vec::new();
        if info.leas > 0 {
            notes.push(format!("lea:{}", info.leas));
        }
        if let Some(st) = info.stride {
            notes.push(format!("stride={st:#x}"));
        }
        if !info.callees.is_empty() {
            let names: Vec<String> = info
                .callees
                .iter()
                .take(3)
                .map(|&c| rt.label(image, c).map_or_else(|| describe_code(image, c), str::to_owned))
                .collect();
            notes.push(format!("-> {}", names.join(", ")));
        }
        let extra = if notes.is_empty() { String::new() } else { format!("  {}", notes.join("  ")) };
        writeln!(
            out,
            "  +{off:<6x}  size {:>2}  {ty:<4}  r:{:<2} w:{:<2}{extra}",
            info.width, info.reads, info.writes
        )?;
    }
    let span = fields.last_key_value().map_or(0, |(&off, info)| off + info.width.max(1) as u64);
    writeln!(out, "{} fields (min span {span:#x})", fields.len())?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{layout, parse_reg};
    use crate::image::{Image, Segment};
    use iced_x86::Register;

    #[test]
    fn reconstructs_fields_spills_strides_leas_and_callees() {
        assert_eq!(parse_reg("RDI"), Ok(Register::RDI));
        assert!(parse_reg("xmm0").is_err());

        let mut data = vec![0u8; 0x300];
        // 0x1000: mov r12, rdi; mov [rsp+8], r12; mov r13, [rsp+8];
        // mov al, [r13+0x10]; mov dword ptr [r13+0x14], 5;
        // mov rbx, [r13+0x20]; imul rcx, rsi, 0x30; mov rdx, [rbx+rcx+8];
        // lea rdi, [r13+0x40]; call 0x1100; ret
        let root: &[u8] = &[
            0x49, 0x89, 0xfc, // mov r12, rdi
            0x4c, 0x89, 0x64, 0x24, 0x08, // mov [rsp+8], r12
            0x4c, 0x8b, 0x6c, 0x24, 0x08, // mov r13, [rsp+8]
            0x41, 0x8a, 0x45, 0x10, // mov al, [r13+0x10]
            0x41, 0xc7, 0x45, 0x14, 0x05, 0x00, 0x00, 0x00, // mov dword ptr [r13+0x14], 5
            0x49, 0x8b, 0x5d, 0x20, // mov rbx, [r13+0x20]
            0x48, 0x6b, 0xce, 0x30, // imul rcx, rsi, 0x30
            0x48, 0x8b, 0x54, 0x0b, 0x08, // mov rdx, [rbx+rcx+8]
            0x49, 0x8d, 0x7d, 0x40, // lea rdi, [r13+0x40]
            0xe8, 0xd1, 0x00, 0x00, 0x00, // call 0x1100
            0xc3,
        ];
        data[..root.len()].copy_from_slice(root);
        // 0x1100: mov qword ptr [rdi+0x8], 1; movups xmm0, [rdi+0x10]; add rdi, 0x20; shl rsi, 4; ret
        let sub: &[u8] = &[
            0x66, 0x8b, 0x47, 0x02, // mov ax, [rdi+2] -> +0x42 (u16)
            0x48, 0xc7, 0x47, 0x08, 0x01, 0x00, 0x00, 0x00, // mov qword ptr [rdi+8], 1 -> +0x48
            0x0f, 0x10, 0x47, 0x10, // movups xmm0, [rdi+0x10] -> +0x50 (u128)
            0x48, 0x8d, 0x44, 0x37, 0x04, // lea rax, [rdi+rsi+4] -> indexed lea
            0x48, 0x83, 0xc7, 0x20, // add rdi, 0x20 -> +0x60 lea
            0x48, 0xc1, 0xe6, 0x04, // shl rsi, 4
            0xc3,
        ];
        data[0x100..0x100 + sub.len()].copy_from_slice(sub);
        data[0x200] = 0xc3;

        let image = Image {
            data,
            segments: vec![Segment { va: 0x1000, offset: 0, size: 0x300 }],
            functions: vec![0x1000..0x1000 + root.len() as u64, 0x1100..0x1100 + sub.len() as u64, 0x1200..0x1201],
            pointers: Vec::new(),
            imports: Vec::new(),
            symbols: Vec::new(),
        };
        let mut out = Vec::new();
        assert!(layout(&image, "0x1000", "bad", false, &mut out).is_err());
        assert!(layout(&image, "0x9999", "rdi", false, &mut out).is_err());
        assert!(layout(&image, "0x1200", "rdi", false, &mut out).is_ok());
        out.clear();
        assert!(layout(&image, "0x1000", "rdi", false, &mut out).is_ok());
        let plain = String::from_utf8_lossy(&out);
        assert!(plain.contains("+10") && plain.contains("stride=0x30") && plain.contains("-> 0x1100"), "{plain}");

        let mut deep = Vec::new();
        assert!(layout(&image, "0x1000", "rdi", true, &mut deep).is_ok());
        let deep_s = String::from_utf8_lossy(&deep);
        assert!(deep_s.contains("u16") && deep_s.contains("+48") && deep_s.contains("u128"), "{deep_s}");
    }
}
