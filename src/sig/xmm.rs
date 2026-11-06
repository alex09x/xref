/*
 * xref — Ultra blazing fast cross-references of an x86-64 ELF binary
 * Copyright (c) 2026 Alexander Panasenko
 *
 * Contact: alex@prod.codes
 * Author: https://prod.codes/about/
 * Project: https://github.com/alex09x/xref
 * SPDX-License-Identifier: MIT OR Apache-2.0
 */

//! The SSE half of the System V signature: scalar-semantics reads and writes of `xmm0`..`xmm15`,
//! and which of `xmm0`..`xmm7` are read before written (floating-point parameters, typed from the
//! scalar width of their first use).

use iced_x86::{Instruction, InstructionInfoFactory, Mnemonic, OpAccess, OpKind, Register};

pub const F64: &str = "f64";
pub const F32: &str = "f32";

const ZMM: [Register; 16] = [
    Register::ZMM0,
    Register::ZMM1,
    Register::ZMM2,
    Register::ZMM3,
    Register::ZMM4,
    Register::ZMM5,
    Register::ZMM6,
    Register::ZMM7,
    Register::ZMM8,
    Register::ZMM9,
    Register::ZMM10,
    Register::ZMM11,
    Register::ZMM12,
    Register::ZMM13,
    Register::ZMM14,
    Register::ZMM15,
];

/// A floating-point parameter: `xmm{index}` read before written, named `arg_f{index}`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FloatParam {
    pub index: u8,
    pub ty: &'static str,
}

impl FloatParam {
    pub fn reg(self) -> Register {
        zmm(self.index)
    }

    pub fn name(self) -> String {
        format!("arg_f{}", self.index)
    }
}

/// The scalar type in `xmm0` at every `ret`; `rax_written` when some return path also leaves an
/// `rax` written by a non-call instruction (an integer result candidate).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FloatRet {
    pub ty: &'static str,
    pub rax_written: bool,
}

/// Full register of `xmm{index}` (`index` taken modulo 16).
pub fn zmm(index: u8) -> Register {
    ZMM[usize::from(index) & 15]
}

pub fn xmm_index(reg: Register) -> Option<u8> {
    let full = reg.full_register();
    ZMM.iter().position(|&z| z == full).and_then(|i| u8::try_from(i).ok())
}

fn lower_name(m: Mnemonic) -> String {
    format!("{m:?}").to_ascii_lowercase()
}

/// Packed-integer mnemonics (`pminsd`, `pabsd`, ...) end in `sd`/`ss` without being floating point.
fn packed_integer(name: &str) -> bool {
    name.starts_with('p') || name.starts_with("vp")
}

/// Scalar width an instruction reads its xmm sources with (`*sd`/`*pd` = f64, `*ss` = f32).
pub fn read_width(m: Mnemonic) -> Option<&'static str> {
    let name = lower_name(m);
    if packed_integer(&name) {
        return None;
    }
    if name.contains("sd2") {
        Some(F64)
    } else if name.contains("ss2") {
        Some(F32)
    } else if name.ends_with("sd") || name.ends_with("pd") {
        Some(F64)
    } else if name.ends_with("ss") {
        Some(F32)
    } else {
        None
    }
}

/// Scalar floating-point type an instruction writes to its xmm destination, if it is one.
pub fn result_width(m: Mnemonic) -> Option<&'static str> {
    let name = lower_name(m);
    if packed_integer(&name) || name.contains("cmp") || name.contains("2si") || name.contains("2usi") {
        return None;
    }
    if name.ends_with("sd") {
        Some(F64)
    } else if name.ends_with("ss") {
        Some(F32)
    } else {
        None
    }
}

/// Scalar results that ignore the old destination value (moves, conversions, square roots, rounding);
/// SSE only merges the destination's upper lanes, which is not a scalar read.
fn writes_without_reading_dest(m: Mnemonic) -> bool {
    let name = lower_name(m);
    let base = name.strip_prefix('v').unwrap_or(&name);
    result_width(m).is_some()
        && ["mov", "cvt", "sqrt", "rcp", "rsqrt", "round"].iter().any(|prefix| base.starts_with(prefix))
}

/// Full-width xmm moves (`movaps`, `movdqu`, ...), which carry no scalar type.
fn is_full_width_move(ins: &Instruction) -> bool {
    matches!(
        ins.mnemonic(),
        Mnemonic::Movaps
            | Mnemonic::Movapd
            | Mnemonic::Movups
            | Mnemonic::Movupd
            | Mnemonic::Movdqa
            | Mnemonic::Movdqu
            | Mnemonic::Vmovaps
            | Mnemonic::Vmovapd
            | Mnemonic::Vmovups
            | Mnemonic::Vmovupd
            | Mnemonic::Vmovdqa
            | Mnemonic::Vmovdqu
    ) && ins.op_count() == 2
}

pub fn is_reg_copy(ins: &Instruction) -> bool {
    is_full_width_move(ins) && ins.op0_kind() == OpKind::Register && ins.op1_kind() == OpKind::Register
}

/// `xorps x, x` / `pxor x, x` (and VEX forms): writes zero without reading.
pub fn xmm_zero_idiom(ins: &Instruction) -> Option<u8> {
    let zeroing = matches!(
        ins.mnemonic(),
        Mnemonic::Xorps | Mnemonic::Xorpd | Mnemonic::Pxor | Mnemonic::Vxorps | Mnemonic::Vxorpd | Mnemonic::Vpxor
    );
    let n = ins.op_count();
    let (a, b) = if n == 3 { (1, 2) } else { (0, 1) };
    (zeroing
        && n >= 2
        && (0..n).all(|i| ins.op_kind(i) == OpKind::Register)
        && ins.op_register(a) == ins.op_register(b))
    .then(|| xmm_index(ins.op0_register()))
    .flatten()
}

pub fn reg_operand(ins: &Instruction, i: u32) -> Option<u8> {
    (i < ins.op_count() && ins.op_kind(i) == OpKind::Register).then(|| xmm_index(ins.op_register(i))).flatten()
}

/// `(reads, writes)` of `xmm0`..`xmm15` with scalar semantics.
pub fn xmm_rw(factory: &mut InstructionInfoFactory, ins: &Instruction) -> (u16, u16) {
    if let Some(d) = xmm_zero_idiom(ins) {
        return (0, 1 << d);
    }
    let (mut r, mut w) = (0u16, 0u16);
    for u in factory.info(ins).used_registers() {
        let Some(i) = xmm_index(u.register()) else { continue };
        let acc = u.access();
        if matches!(acc, OpAccess::Read | OpAccess::CondRead | OpAccess::ReadWrite | OpAccess::ReadCondWrite) {
            r |= 1 << i;
        }
        if matches!(acc, OpAccess::Write | OpAccess::CondWrite | OpAccess::ReadWrite | OpAccess::ReadCondWrite) {
            w |= 1 << i;
        }
    }
    if writes_without_reading_dest(ins.mnemonic())
        && let Some(dest) = reg_operand(ins, 0)
    {
        // Legacy `op dst, src`: only src is a scalar source. VEX `op dst, merge, src`: merge only
        // supplies upper lanes.
        let vex = ins.op_count() >= 3 && lower_name(ins.mnemonic()).starts_with('v');
        let (merge, src) =
            if vex { (reg_operand(ins, 1), reg_operand(ins, 2)) } else { (Some(dest), reg_operand(ins, 1)) };
        if let Some(m) = merge
            && src != Some(m)
        {
            r &= !(1 << m);
        }
        w |= 1 << dest;
    }
    (r, w)
}

/// Upward-exposed `xmm0`..`xmm7` reads of one basic block, with the scalar width of each first read.
#[derive(Clone, Default)]
pub struct XmmBlock {
    pub read: u8,
    pub written: u8,
    pub first: [Option<(u64, &'static str)>; 8],
    /// The block has a scalar or packed-double floating-point instruction (`*sd`, `*ss`, `*pd`,
    /// conversions to or from float).
    pub scalar_fp: bool,
}

/// A full-width (packed) store of an xmm register to memory: `movaps [rsp+0x50], xmm0`. This is how a
/// variadic prologue spills `xmm0`..`xmm7` into the register-save area behind `test al, al; je`
/// whether or not the caller passed any floating-point value, so it is not evidence of a parameter.
pub fn is_packed_spill(ins: &Instruction) -> bool {
    is_full_width_move(ins) && ins.op0_kind() == OpKind::Memory && ins.op1_kind() == OpKind::Register
}

/// Whether reading an xmm register in `ins` may be a floating-point use: a scalar or packed float
/// operation, a register copy, or a bit move out to a GPR or memory (`movq rax, xmm0`,
/// `f64::to_bits`). Packed-integer work (`paddq`, `pshufd`, `punpcklqdq`) is not: vectorised
/// integer loops read accumulators on paths the compiler knows are infeasible. Copies, bit moves
/// and `*ps` operations also extract lanes of integer SIMD values, so they count only in a function
/// that has scalar floating-point evidence of its own ([`XmmBlock::scalar_fp`]).
fn float_read_evidence(ins: &Instruction) -> bool {
    let name = lower_name(ins.mnemonic());
    if packed_integer(&name) {
        return false;
    }
    if matches!(ins.mnemonic(), Mnemonic::Movq | Mnemonic::Movd | Mnemonic::Vmovq | Mnemonic::Vmovd) {
        return ins.op0_kind() != OpKind::Register || xmm_index(ins.op0_register()).is_none();
    }
    read_width(ins.mnemonic()).is_some() || is_reg_copy(ins) || name.ends_with("ps")
}

impl XmmBlock {
    pub fn step(&mut self, factory: &mut InstructionInfoFactory, ins: &Instruction) {
        let (r, w) = xmm_rw(factory, ins);
        let r = if is_packed_spill(ins) || !float_read_evidence(ins) { 0 } else { r };
        self.scalar_fp |= read_width(ins.mnemonic()).is_some() || result_width(ins.mnemonic()).is_some();
        let width = read_width(ins.mnemonic()).unwrap_or(F64);
        let written = self.written;
        self.use_regs(r.to_le_bytes()[0], written, ins.ip(), |_| width);
        self.written |= w.to_le_bytes()[0];
    }

    /// Records reads of `mask` at `ip` not preceded in this block by a write (`written` at `ip`).
    pub fn use_regs(&mut self, mask: u8, written: u8, ip: u64, width: impl Fn(u8) -> &'static str) {
        let exposed = mask & !written;
        for i in (0..8u8).filter(|i| exposed & (1 << i) != 0) {
            let slot = &mut self.first[usize::from(i)];
            if slot.is_none_or(|(first_ip, _)| ip < first_ip) {
                *slot = Some((ip, width(i)));
            }
        }
        self.read |= exposed;
    }
}

/// Float parameters from the live mask: the width of the earliest upward-exposed read in a block
/// where the register is not yet written on every path from the entry.
pub fn float_params(blocks: &[XmmBlock], exposed: &[u8], live: u8) -> Vec<FloatParam> {
    (0..8u8)
        .filter(|i| live & (1 << i) != 0)
        .map(|i| {
            let ty = blocks
                .iter()
                .zip(exposed)
                .filter(|(_, e)| *e & (1 << i) != 0)
                .filter_map(|(blk, _)| blk.first[usize::from(i)])
                .min_by_key(|(ip, _)| *ip)
                .map_or(F64, |(_, ty)| ty);
            FloatParam { index: i, ty }
        })
        .collect()
}

/// `(float argument count, type)` of common libm imports (`sin`, `pow`, `sqrtf`, ...).
pub fn import_float_sig(raw_name: &str) -> Option<(u8, &'static str)> {
    let name = raw_name.split('@').next().unwrap_or(raw_name);
    let arity = |base: &str| match base {
        "sin" | "cos" | "tan" | "asin" | "acos" | "atan" | "sinh" | "cosh" | "tanh" | "exp" | "exp2" | "expm1"
        | "log" | "log2" | "log10" | "log1p" | "sqrt" | "cbrt" | "fabs" | "floor" | "ceil" | "round" | "trunc"
        | "rint" | "nearbyint" => Some(1),
        "pow" | "atan2" | "fmod" | "hypot" | "fmin" | "fmax" | "copysign" | "remainder" | "fdim" => Some(2),
        "fma" => Some(3),
        _ => None,
    };
    arity(name).map(|n| (n, F64)).or_else(|| name.strip_suffix('f').and_then(arity).map(|n| (n, F32)))
}
