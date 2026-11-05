/*
 * XRef — x86-64 binary analysis and cross-reference tooling
 * Copyright (c) 2026 Alexander Panasenko
 *
 * Contact: alex@prod.codes
 * Author: https://prod.codes/about/
 * Project: https://github.com/alex09x/xref
 * SPDX-License-Identifier: MIT OR Apache-2.0
 */

use iced_x86::{Instruction, MemorySize, Mnemonic, OpKind, Register};

use super::{is_xmm_register, read_only_bytes, rip_memory_address};
use crate::{
    c_step::FnCtx,
    expr::{State, op_expr},
    image::Image,
};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct U64ConversionIdiom {
    pub dest_reg: Register,
    pub final_reg: Register,
}

pub fn match_conversion_sequence(image: &Image, insns: &[Instruction], start: usize) -> Option<U64ConversionIdiom> {
    let seq = insns.get(start..start.saturating_add(6))?;

    if seq.windows(2).any(|pair| pair[0].next_ip() != pair[1].ip()) {
        return None;
    }

    if seq[0].op0_kind() != OpKind::Register || !is_xmm_register(seq[0].op0_register()) {
        return None;
    }
    let dest = seq[0].op0_register();

    let valid_source = match seq[0].mnemonic() {
        Mnemonic::Movq => {
            if seq[0].op1_kind() == OpKind::Register {
                !is_xmm_register(seq[0].op1_register()) && seq[0].op1_register().size() == 8
            } else if seq[0].op1_kind() == OpKind::Memory {
                seq[0].memory_size().size() == 8 || seq[0].memory_size() == MemorySize::Unknown
            } else {
                false
            }
        }
        Mnemonic::Movsd => {
            seq[0].op1_kind() == OpKind::Memory
                && (seq[0].memory_size().size() == 8 || seq[0].memory_size() == MemorySize::Unknown)
        }
        _ => false,
    };
    if !valid_source {
        return None;
    }

    if seq[1].op0_kind() != OpKind::Register
        || seq[1].op0_register() != dest
        || !matches!(seq[1].mnemonic(), Mnemonic::Punpckldq | Mnemonic::Unpcklps)
    {
        return None;
    }
    let magic_address = rip_memory_address(&seq[1])?;
    let magic = read_only_bytes(image, magic_address, 8)?;
    if magic != 0x4530_0000_4330_0000u64.to_le_bytes() {
        return None;
    }

    if seq[2].op0_kind() != OpKind::Register || seq[2].op0_register() != dest || seq[2].mnemonic() != Mnemonic::Subpd {
        return None;
    }
    let bias_address = rip_memory_address(&seq[2])?;
    let bias = read_only_bytes(image, bias_address, 16)?;
    let expected_bias = [0x4330_0000_0000_0000u64.to_le_bytes(), 0x4530_0000_0000_0000u64.to_le_bytes()].concat();
    if bias != expected_bias {
        return None;
    }

    if seq[3].op0_kind() != OpKind::Register
        || seq[3].op1_kind() != OpKind::Register
        || !matches!(seq[3].mnemonic(), Mnemonic::Movapd | Mnemonic::Movaps | Mnemonic::Movupd | Mnemonic::Movdqa)
        || seq[3].op1_register() != dest
        || seq[3].op0_register() == dest
        || !is_xmm_register(seq[3].op0_register())
    {
        return None;
    }
    let copy = seq[3].op0_register();

    if seq[4].op0_kind() != OpKind::Register
        || seq[4].op1_kind() != OpKind::Register
        || seq[4].mnemonic() != Mnemonic::Unpckhpd
    {
        return None;
    }
    let unpck_dst = seq[4].op0_register();
    let unpck_src = seq[4].op1_register();

    if seq[5].op0_kind() != OpKind::Register
        || seq[5].op1_kind() != OpKind::Register
        || seq[5].mnemonic() != Mnemonic::Addsd
    {
        return None;
    }
    let final_reg = seq[5].op0_register();
    let add_src = seq[5].op1_register();

    if final_reg != dest && final_reg != copy {
        return None;
    }
    let other_reg = if final_reg == dest { copy } else { dest };
    if add_src != other_reg {
        return None;
    }

    if unpck_dst != final_reg || (unpck_src != dest && unpck_src != copy) {
        return None;
    }

    Some(U64ConversionIdiom { dest_reg: dest, final_reg })
}

pub fn step_u64_conversion_idiom(
    ctx: &FnCtx<'_>,
    state: &mut State,
    ins: &Instruction,
    ins_idx: usize,
    block: &mut crate::cfg::Block,
) -> bool {
    let matched = (ins_idx.saturating_sub(5)..=ins_idx).find_map(|candidate| {
        match_conversion_sequence(ctx.image, &ctx.ssa.insns, candidate).map(|idiom| (candidate, idiom))
    });
    let Some((start, idiom)) = matched else { return false };

    if ins_idx == start {
        let first = &ctx.ssa.insns[start];
        let raw = op_expr(ctx.image, ctx.locations, state, first, 1);
        let rhs = if first.op1_kind() == OpKind::Memory { raw.replace("(f64 *)", "(u64 *)") } else { raw };
        let converted = format!("(f64)(u64)({rhs})");
        let name = format!("fp_{:x}", first.ip());
        block.stmts.push(format!("f64 {name} = {converted};"));
        // The sum is in `final_reg`. When that is the copy, `dest_reg` still holds the low partial
        // lane; compilers do not read it after the idiom, so both names map to the converted value.
        for reg in [idiom.dest_reg, idiom.final_reg] {
            let full = reg.full_register();
            state.inline_regs.remove(&full);
            state.rodata_ptrs.remove(&full);
            state.set_reg(full, name.clone());
            let _ = state.reg(full);
        }
    } else if ctx.is_marked(ins) {
        let source = state.reg(idiom.final_reg);
        block.stmts.push(format!("f64 fp_{:x} = {source};", ins.ip()));
    }
    true
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        image::Segment,
        image_format::{LoadSegment, Metadata},
    };

    const BIAS: [u8; 16] = [0, 0, 0, 0, 0, 0, 0x30, 0x43, 0, 0, 0, 0, 0, 0, 0x30, 0x45];

    fn test_image(magic: [u8; 8], bias: [u8; 16]) -> Image {
        let mut data = vec![0u8; 0x20];
        data[..8].copy_from_slice(&magic);
        data[0x10..0x20].copy_from_slice(&bias);
        Image {
            data,
            segments: vec![Segment { va: 0x3000, offset: 0, size: 0x20 }],
            metadata: Metadata {
                load_segments: vec![LoadSegment {
                    va: 0x3000,
                    file_offset: 0,
                    file_size: 0x20,
                    mem_size: 0x20,
                    executable: false,
                    writable: false,
                }],
                ..Metadata::default()
            },
            ..Image::default()
        }
    }

    #[test]
    fn u64_to_f64_idiom_matches_unpcklps_and_memory_source() {
        let magic = 0x4530_0000_4330_0000u64.to_le_bytes();
        let image = test_image(magic, BIAS);

        // movsd xmm2, [rdi] (4B: f2 0f 10 17, next: 0x1004)
        // unpcklps xmm2, [rip + 0x1ff5] (7B, next: 0x100b; target 0x3000)
        // subpd xmm2, [rip + 0x1ffd] (8B, next: 0x1013; target 0x3010)
        // movapd xmm1, xmm2 (4B: 66 0f 28 ca, next: 0x1017)
        // unpckhpd xmm1, xmm2 (4B: 66 0f 15 ca, next: 0x101b)
        // addsd xmm1, xmm2 (4B: f2 0f 58 ca, next: 0x101f)
        #[rustfmt::skip]
        let code = [
            0xf2, 0x0f, 0x10, 0x17,
            0x0f, 0x14, 0x15, 0xf5, 0x1f, 0x00, 0x00,
            0x66, 0x0f, 0x5c, 0x15, 0xfd, 0x1f, 0x00, 0x00,
            0x66, 0x0f, 0x28, 0xca,
            0x66, 0x0f, 0x15, 0xca,
            0xf2, 0x0f, 0x58, 0xca,
        ];
        let mut decoder = iced_x86::Decoder::new(64, &code, iced_x86::DecoderOptions::NONE);
        decoder.set_ip(0x1000);
        let mut insns = Vec::new();
        while decoder.can_decode() {
            insns.push(decoder.decode());
        }
        assert_eq!(insns.len(), 6);

        let idiom = match_conversion_sequence(&image, &insns, 0);
        assert_eq!(idiom, Some(U64ConversionIdiom { dest_reg: Register::XMM2, final_reg: Register::XMM1 }));
    }

    #[test]
    fn u64_to_f64_idiom_matches_dest_accumulator_variant() {
        let magic = 0x4530_0000_4330_0000u64.to_le_bytes();
        let image = test_image(magic, BIAS);

        // movq xmm0, rdi (0x1000..0x1005)
        // punpckldq xmm0, [rip + 0x1ff3] (0x1005..0x100d, target 0x3000)
        // subpd xmm0, [rip + 0x1ffb] (0x100d..0x1015, target 0x3010)
        // movapd xmm1, xmm0 (0x1015..0x1019)
        // unpckhpd xmm0, xmm0 (0x1019..0x101d)
        // addsd xmm0, xmm1 (0x101d..0x1021)
        #[rustfmt::skip]
        let code = [
            0x66, 0x48, 0x0f, 0x6e, 0xc7,
            0x66, 0x0f, 0x62, 0x05, 0xf3, 0x1f, 0x00, 0x00,
            0x66, 0x0f, 0x5c, 0x05, 0xfb, 0x1f, 0x00, 0x00,
            0x66, 0x0f, 0x28, 0xc8,
            0x66, 0x0f, 0x15, 0xc0,
            0xf2, 0x0f, 0x58, 0xc1,
        ];
        let mut decoder = iced_x86::Decoder::new(64, &code, iced_x86::DecoderOptions::NONE);
        decoder.set_ip(0x1000);
        let mut insns = Vec::new();
        while decoder.can_decode() {
            insns.push(decoder.decode());
        }
        assert_eq!(insns.len(), 6);

        let idiom = match_conversion_sequence(&image, &insns, 0);
        assert_eq!(idiom, Some(U64ConversionIdiom { dest_reg: Register::XMM0, final_reg: Register::XMM0 }));
    }

    #[test]
    fn u64_to_f64_idiom_rejects_altered_constants() {
        let magic = 0x4530_0000_4330_0001u64.to_le_bytes(); // changed
        let image = test_image(magic, BIAS);

        #[rustfmt::skip]
        let code = [
            0x66, 0x48, 0x0f, 0x6e, 0xc7,
            0x66, 0x0f, 0x62, 0x05, 0xf3, 0x1f, 0x00, 0x00,
            0x66, 0x0f, 0x5c, 0x05, 0xfb, 0x1f, 0x00, 0x00,
            0x66, 0x0f, 0x28, 0xc8,
            0x66, 0x0f, 0x15, 0xc0,
            0xf2, 0x0f, 0x58, 0xc1,
        ];
        let mut decoder = iced_x86::Decoder::new(64, &code, iced_x86::DecoderOptions::NONE);
        decoder.set_ip(0x1000);
        let mut insns = Vec::new();
        while decoder.can_decode() {
            insns.push(decoder.decode());
        }
        assert_eq!(match_conversion_sequence(&image, &insns, 0), None);
    }
}
