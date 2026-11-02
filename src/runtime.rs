/*
 * xref — Ultra blazing fast cross-references of an x86-64 ELF binary
 * Copyright (c) 2026 Alexander Panasenko
 *
 * Contact: alex@prod.codes
 * Author: https://prod.codes/about/
 * SPDX-License-Identifier: MIT OR Apache-2.0
 */

//! Automatic recognition of standard Rust runtime helpers and PLT import stubs in stripped binaries.

use std::collections::HashMap;
use std::ops::Range;

use iced_x86::{FlowControl, Instruction, MemorySize, Mnemonic, OpKind, Register};
use rayon::prelude::*;

use crate::caller_ret::{CallerIndex, CallerRetStats};
use crate::graph::call_target;
use crate::image::{Image, Slot};
use crate::listing::is_call;
use crate::scan::{decode, immediates};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RuntimeFn {
    PanicBoundsCheck,
    PanicFmt,
    UnwrapFailed,
    SliceIndexFail,
    PanicInCleanup,
    PanicNounwind,
    CapacityOverflow,
    OnceCall,
    FmtWrite,
    Dealloc,
    Alloc,
}

impl RuntimeFn {
    pub const fn name(self) -> &'static str {
        match self {
            Self::PanicBoundsCheck => "rust_panic_bounds_check",
            Self::PanicFmt => "rust_panic_fmt",
            Self::UnwrapFailed => "rust_unwrap_failed",
            Self::SliceIndexFail => "rust_slice_index_fail",
            Self::PanicInCleanup => "rust_panic_in_cleanup",
            Self::PanicNounwind => "rust_panic_nounwind",
            Self::CapacityOverflow => "rust_capacity_overflow",
            Self::OnceCall => "rust_once_call",
            Self::FmtWrite => "rust_fmt_write",
            Self::Dealloc => "rust_dealloc",
            Self::Alloc => "rust_alloc",
        }
    }

    /// Argument index pair `(ptr_idx, tagged_len_idx)` when this helper takes `core::fmt::Arguments`.
    pub const fn fmt_args_pair(self) -> Option<(usize, usize)> {
        match self {
            Self::PanicFmt => Some((0, 1)),
            Self::FmtWrite => Some((2, 3)),
            _ => None,
        }
    }

    /// Known exact x86-64 System V register parameter count for standard Rust runtime helpers.
    pub const fn arity(self) -> Option<usize> {
        match self {
            Self::Alloc => Some(2),
            Self::PanicBoundsCheck | Self::PanicFmt | Self::Dealloc => Some(3),
            Self::FmtWrite => Some(4),
            Self::UnwrapFailed => Some(5),
            _ => None,
        }
    }
}

pub fn plt_import(image: &Image, target: u64) -> Option<&str> {
    let bytes = image.read(target, 16)?;
    let mut found = None;
    decode(bytes, target, |ins| {
        if ins.flow_control() == FlowControl::IndirectBranch
            && ins.is_ip_rel_memory_operand()
            && let Some(Slot::Import(name)) = image.slot(ins.ip_rel_memory_address())
        {
            found = Some(name);
        }
    });
    found
}

fn has_prefix(buf: &[u8], pat: &[u8]) -> bool {
    buf.starts_with(pat) || buf.get(1..).is_some_and(|rest| rest.starts_with(pat))
}

struct ScanOut {
    direct: Option<(u64, RuntimeFn)>,
    chained: Option<(u64, RuntimeFn)>,
    small_callee: Option<(u64, u64, bool)>,
}

fn classify_one(image: &Image, f: &Range<u64>, code: &[u8]) -> ScanOut {
    let len = f.end - f.start;
    let mut direct = None;
    let mut last_call = None;
    let (mut has_fs, mut cmp_page, mut any_call, mut tail_jmp) = (false, false, false, false);
    let (mut stores_rdi, mut loads_rax) = (false, false);
    let (mut test_one, mut movzx_byte, mut vtable_18, mut reads_r8) = (false, false, false, false);

    decode(code, f.start, |ins: &Instruction| {
        if matches!(ins.flow_control(), FlowControl::Call | FlowControl::IndirectCall) {
            any_call = true;
            last_call = call_target(image, ins);
        } else if is_call(ins, f) {
            tail_jmp = true;
            last_call = call_target(image, ins);
        }
        if ins.segment_prefix() == Register::FS {
            has_fs = true;
        }
        if ins.mnemonic() == Mnemonic::Cmp && immediates(ins).any(|v| matches!(v, 0x1000 | 0x2000)) {
            cmp_page = true;
        }
        if ins.mnemonic() == Mnemonic::Mov
            && ins.op0_kind() == OpKind::Memory
            && ins.op1_kind() == OpKind::Register
            && ins.op1_register().full_register() == Register::RDI
        {
            stores_rdi = true;
        }
        if ins.mnemonic() == Mnemonic::Mov
            && ins.op0_kind() == OpKind::Register
            && ins.op0_register().full_register() == Register::RAX
            && ins.op1_kind() == OpKind::Memory
            && ins.segment_prefix() != Register::FS
        {
            loads_rax = true;
        }
        if ins.mnemonic() == Mnemonic::Test && immediates(ins).any(|v| v == 1) {
            test_one = true;
        }
        if ins.mnemonic() == Mnemonic::Movzx && ins.memory_size() == MemorySize::UInt8 {
            movzx_byte = true;
        }
        if ins.op1_kind() == OpKind::Memory && ins.memory_base() == Register::RSI && ins.memory_displacement64() == 0x18
        {
            vtable_18 = true;
        }
        for op in 0..ins.op_count() {
            if ins.op_kind(op) == OpKind::Register && ins.op_register(op).full_register() == Register::R8 {
                reads_r8 = true;
            }
        }
        if ins.mnemonic() == Mnemonic::Lea
            && ins.is_ip_rel_memory_operand()
            && let Some(buf) = image.read(ins.ip_rel_memory_address(), 44)
        {
            if len <= 200 && has_prefix(buf, b"index out of bounds: the len is") {
                direct = Some((f.start, RuntimeFn::PanicBoundsCheck));
            } else if len <= 128 && has_prefix(buf, b"panic in a destructor during cleanup") {
                direct = Some((f.start, RuntimeFn::PanicInCleanup));
            } else if has_prefix(buf, b"Once instance has previously been poisoned") {
                direct = Some((f.start, RuntimeFn::OnceCall));
            } else if len <= 140 && has_prefix(buf, b"capacity overflow") {
                direct = Some((f.start, RuntimeFn::CapacityOverflow));
            } else if len <= 260
                && (has_prefix(buf, b"slice index starts at")
                    || has_prefix(buf, b"range end index")
                    || has_prefix(buf, b"byte index "))
            {
                direct = Some((f.start, RuntimeFn::SliceIndexFail));
            }
        }
    });

    if direct.is_none() && (64..=320).contains(&len) && has_fs && cmp_page && !any_call && tail_jmp {
        if stores_rdi {
            direct = Some((f.start, RuntimeFn::Dealloc));
        } else if loads_rax {
            direct = Some((f.start, RuntimeFn::Alloc));
        }
    }
    if direct.is_none() && (240..=640).contains(&len) && !any_call && test_one && movzx_byte && vtable_18 {
        direct = Some((f.start, RuntimeFn::FmtWrite));
    }
    let chained = match (direct, last_call) {
        (Some((_, RuntimeFn::PanicBoundsCheck)), Some(c)) => Some((c, RuntimeFn::PanicFmt)),
        (Some((_, RuntimeFn::PanicInCleanup)), Some(c)) => Some((c, RuntimeFn::PanicNounwind)),
        _ => None,
    };
    let small_callee = (len <= 160).then_some(last_call).flatten().map(|c| (f.start, c, reads_r8));
    ScanOut { direct, chained, small_callee }
}

#[derive(Default)]
pub struct RuntimeMap {
    by_addr: HashMap<u64, RuntimeFn>,
    callers: Option<CallerIndex>,
}

impl RuntimeMap {
    fn scan_helpers(image: &Image) -> HashMap<u64, RuntimeFn> {
        let outs: Vec<ScanOut> = image
            .functions
            .par_iter()
            .filter(|f| f.end - f.start <= 640)
            .filter_map(|f| Some(classify_one(image, f, image.code(f)?)))
            .collect();
        let mut by_addr = HashMap::new();
        let mut panic_fmt_addrs = Vec::new();
        for out in &outs {
            if let Some((addr, kind)) = out.direct {
                by_addr.insert(addr, kind);
            }
            if let Some((addr, kind)) = out.chained {
                by_addr.entry(addr).or_insert(kind);
                if kind == RuntimeFn::PanicFmt {
                    panic_fmt_addrs.push(addr);
                }
            }
        }
        for out in &outs {
            if let Some((caller, callee, true)) = out.small_callee
                && panic_fmt_addrs.contains(&callee)
            {
                by_addr.entry(caller).or_insert(RuntimeFn::UnwrapFailed);
            }
        }
        by_addr
    }

    pub fn detect(image: &Image) -> Self {
        Self { by_addr: Self::scan_helpers(image), callers: None }
    }

    pub fn detect_with_callers(image: &Image) -> Self {
        let (by_addr, callers) = rayon::join(|| Self::scan_helpers(image), || CallerIndex::build(image));
        Self { by_addr, callers: Some(callers) }
    }

    pub fn get(&self, addr: u64) -> Option<RuntimeFn> {
        self.by_addr.get(&addr).copied()
    }

    pub fn caller_stats(&self, image: &Image, addr: u64) -> CallerRetStats {
        self.callers.as_ref().map_or_else(|| CallerIndex::for_target(image, addr), |c| c.get(addr))
    }

    pub fn label<'a>(&self, image: &'a Image, addr: u64) -> Option<&'a str> {
        self.get(addr).map(RuntimeFn::name).or_else(|| plt_import(image, addr))
    }
}

#[cfg(test)]
mod tests {
    use super::{RuntimeFn, RuntimeMap, plt_import};
    use crate::image::{Image, Segment};

    #[test]
    fn detects_rust_runtime_helpers_and_plt_stubs() {
        let mut data = vec![0u8; 0x1000];
        // Strings at 0x800+
        data[0x800..0x821].copy_from_slice(b"\x20index out of bounds: the len is ");
        data[0x840..0x864].copy_from_slice(b"panic in a destructor during cleanup");
        data[0x880..0x8aa].copy_from_slice(b"Once instance has previously been poisoned");
        data[0x8c0..0x8d1].copy_from_slice(b"capacity overflow");
        data[0x8e0..0x8f5].copy_from_slice(b"slice index starts at");

        // 0x1000 (bounds -> calls 0x1040): lea rdi, [0x1800]; call 0x1040; ud2
        data[0x000..0x00e]
            .copy_from_slice(&[0x48, 0x8d, 0x3d, 0xf9, 0x07, 0x00, 0x00, 0xe8, 0x34, 0x00, 0x00, 0x00, 0x0f, 0x0b]);
        // 0x1040 (panic_fmt): ret
        data[0x040] = 0xc3;
        // 0x1050 (unwrap_failed -> reads r8, calls 0x1040): mov rdx, r8; call 0x1040; ud2
        data[0x050..0x05a].copy_from_slice(&[0x4c, 0x89, 0xc2, 0xe8, 0xe8, 0xff, 0xff, 0xff, 0x0f, 0x0b]);
        // 0x1060 (cleanup -> calls 0x1080): lea rdi, [0x1840]; call 0x1080; ud2
        data[0x060..0x06e]
            .copy_from_slice(&[0x48, 0x8d, 0x3d, 0xd9, 0x07, 0x00, 0x00, 0xe8, 0x14, 0x00, 0x00, 0x00, 0x0f, 0x0b]);
        data[0x080] = 0xc3;
        // 0x1090 (once_call): lea rdi, [0x1880]; ret
        data[0x090..0x098].copy_from_slice(&[0x48, 0x8d, 0x3d, 0xe9, 0x07, 0x00, 0x00, 0xc3]);
        // 0x10a0 (cap_overflow): lea rdi, [0x18c0]; ret
        data[0x0a0..0x0a8].copy_from_slice(&[0x48, 0x8d, 0x3d, 0x19, 0x08, 0x00, 0x00, 0xc3]);
        // 0x10b0 (slice_index): lea rdi, [0x18e0]; ret
        data[0x0b0..0x0b8].copy_from_slice(&[0x48, 0x8d, 0x3d, 0x29, 0x08, 0x00, 0x00, 0xc3]);
        // 0x1100..0x1150 (dealloc: 80B): cmp rsi, 0x1000; mov rax, fs:[0]; mov [rax], rdi; jmp 0x1500
        let dealloc = [
            0x48, 0x81, 0xfe, 0x00, 0x10, 0x00, 0x00, // cmp rsi, 0x1000
            0x64, 0x48, 0x8b, 0x04, 0x25, 0x00, 0x00, 0x00, 0x00, // mov rax, fs:[0]
            0x48, 0x89, 0x38, // mov [rax], rdi
            0xe9, 0xeb, 0x03, 0x00, 0x00, // jmp 0x1500
        ];
        data[0x100..0x100 + dealloc.len()].copy_from_slice(&dealloc);
        // 0x1160..0x11b0 (alloc: 80B): cmp rdi, 0x1000; mov rcx, fs:[0]; mov rax, [rcx]; jmp 0x1500
        let alloc = [
            0x48, 0x81, 0xff, 0x00, 0x10, 0x00, 0x00, 0x64, 0x48, 0x8b, 0x0c, 0x25, 0x00, 0x00, 0x00, 0x00, 0x48, 0x8b,
            0x01, 0xe9, 0x8b, 0x03, 0x00, 0x00,
        ];
        data[0x160..0x160 + alloc.len()].copy_from_slice(&alloc);
        // 0x1200..0x1300 (fmt_write: 256B): test cl, 1; movzx eax, byte ptr [rdx]; mov rcx, [rsi+0x18]; ret
        let fmt_w = [0xf6, 0xc1, 0x01, 0x0f, 0xb6, 0x02, 0x48, 0x8b, 0x4e, 0x18, 0xc3];
        data[0x200..0x200 + fmt_w.len()].copy_from_slice(&fmt_w);
        // 0x1400 (plt stub -> 0x1900): jmp [rip + 0x4fa] -> 0x1406 + 0x4fa = 0x1900
        data[0x400..0x406].copy_from_slice(&[0xff, 0x25, 0xfa, 0x04, 0x00, 0x00]);

        let image = Image {
            data,
            segments: vec![Segment { va: 0x1000, offset: 0, size: 0x1000 }],
            functions: vec![
                0x1000..0x100e,
                0x1040..0x1041,
                0x1050..0x105a,
                0x1060..0x106e,
                0x1080..0x1081,
                0x1090..0x1098,
                0x10a0..0x10a8,
                0x10b0..0x10b8,
                0x1100..0x1150,
                0x1160..0x11b0,
                0x1200..0x1300,
            ],
            pointers: Vec::new(),
            imports: vec![(0x1900, "memcpy".to_owned())],
            symbols: Vec::new(),
        };
        let rt = RuntimeMap::detect(&image);
        assert_eq!(rt.get(0x1000), Some(RuntimeFn::PanicBoundsCheck));
        assert_eq!(rt.get(0x1040), Some(RuntimeFn::PanicFmt));
        assert_eq!(rt.get(0x1050), Some(RuntimeFn::UnwrapFailed));
        assert_eq!(rt.get(0x1060), Some(RuntimeFn::PanicInCleanup));
        assert_eq!(rt.get(0x1080), Some(RuntimeFn::PanicNounwind));
        assert_eq!(rt.get(0x1090), Some(RuntimeFn::OnceCall));
        assert_eq!(rt.get(0x10a0), Some(RuntimeFn::CapacityOverflow));
        assert_eq!(rt.get(0x10b0), Some(RuntimeFn::SliceIndexFail));
        assert_eq!(rt.get(0x1100), Some(RuntimeFn::Dealloc));
        assert_eq!(rt.get(0x1160), Some(RuntimeFn::Alloc));
        assert_eq!(rt.get(0x1200), Some(RuntimeFn::FmtWrite));
        assert_eq!(rt.get(0x1040).and_then(RuntimeFn::fmt_args_pair), Some((0, 1)));
        assert_eq!(rt.get(0x1200).and_then(RuntimeFn::fmt_args_pair), Some((2, 3)));
        assert_eq!(rt.get(0x1000).and_then(RuntimeFn::fmt_args_pair), None);
        assert_eq!(
            [RuntimeFn::Alloc, RuntimeFn::Dealloc, RuntimeFn::FmtWrite, RuntimeFn::UnwrapFailed, RuntimeFn::OnceCall]
                .map(RuntimeFn::arity),
            [Some(2), Some(3), Some(4), Some(5), None]
        );
        for (addr, expected) in [
            (0x1000, "rust_panic_bounds_check"),
            (0x1040, "rust_panic_fmt"),
            (0x1050, "rust_unwrap_failed"),
            (0x1060, "rust_panic_in_cleanup"),
            (0x1080, "rust_panic_nounwind"),
            (0x1090, "rust_once_call"),
            (0x10a0, "rust_capacity_overflow"),
            (0x10b0, "rust_slice_index_fail"),
            (0x1100, "rust_dealloc"),
            (0x1160, "rust_alloc"),
            (0x1200, "rust_fmt_write"),
            (0x1400, "memcpy"),
        ] {
            assert_eq!(rt.label(&image, addr), Some(expected));
        }
        assert_eq!(plt_import(&image, 0x9999), None);
    }
}
