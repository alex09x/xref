/*
 * XRef — x86-64 binary analysis and cross-reference tooling
 * Copyright (c) 2026 Alexander Panasenko
 *
 * Contact: alex@prod.codes
 * Author: https://prod.codes/about/
 * Project: https://github.com/alex09x/xref
 * SPDX-License-Identifier: MIT OR Apache-2.0
 */

//! What both registers of the u64-to-f64 idiom hold afterwards, and refusal to fuse when a branch
//! enters the middle of the sequence.

use iced_x86::Register;

use super::step_u64_conversion_idiom;
use crate::c_step::FnCtx;
use crate::expr::State;
use crate::image::{Image, Segment};
use crate::image_format::{LoadSegment, Metadata};
use crate::ssa_webs::SsaCfg;

/// Magic lanes at 0x3000, bias pair at 0x3010 (read-only data).
fn constants() -> Image {
    let mut data = vec![0u8; 0x20];
    data[..8].copy_from_slice(&0x4530_0000_4330_0000u64.to_le_bytes());
    data[0x10..0x18].copy_from_slice(&0x4330_0000_0000_0000u64.to_le_bytes());
    data[0x18..0x20].copy_from_slice(&0x4530_0000_0000_0000u64.to_le_bytes());
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

/// Step every instruction of `code` (at 0x1000) through the idiom lifter; returns the final state
/// and which instructions it claimed.
fn run(code: &[u8]) -> (State, Vec<bool>) {
    let image = constants();
    let mut decoder = iced_x86::Decoder::new(64, code, iced_x86::DecoderOptions::NONE);
    decoder.set_ip(0x1000);
    let mut insns = Vec::new();
    while decoder.can_decode() {
        insns.push(decoder.decode());
    }
    let end = insns.last().map_or(0x1000, iced_x86::Instruction::next_ip);
    let ssa = SsaCfg { insns, ..Default::default() };
    let runtime = crate::runtime::RuntimeMap::default();
    let ctx = FnCtx {
        image: &image,
        locations: &[],
        runtime: &runtime,
        tables: &[],
        function: &(0x1000..end),
        ssa: &ssa,
        ret_kind: crate::type_facts::ReturnKind::VoidUnused,
        partial_slice: false,
        mark_ip: None,
        mark_targets: None,
    };
    let mut state = State::default();
    let mut block = crate::cfg::Block { start: 0x1000, stmts: Vec::new(), term: crate::cfg::Term::Fall };
    let claimed = (0..ssa.insns.len())
        .map(|i| step_u64_conversion_idiom(&ctx, &mut state, &ssa.insns[i], i, &mut block))
        .collect();
    (state, claimed)
}

// movq xmm2, rdi; punpckldq xmm2, [0x3000]; subpd xmm2, [0x3010];
// movapd xmm1, xmm2; unpckhpd xmm1, xmm2; addsd xmm1, xmm2   (sum in the copy, xmm1)
const SUM_IN_COPY: [u8; 33] = [
    0x66, 0x48, 0x0f, 0x6e, 0xd7, 0x66, 0x0f, 0x62, 0x15, 0xf3, 0x1f, 0x00, 0x00, 0x66, 0x0f, 0x5c, 0x15, 0xfb, 0x1f,
    0x00, 0x00, 0x66, 0x0f, 0x28, 0xca, 0x66, 0x0f, 0x15, 0xca, 0xf2, 0x0f, 0x58, 0xca,
];

// movq xmm0, rdi; punpckldq xmm0, [0x3000]; subpd xmm0, [0x3010];
// movapd xmm1, xmm0; unpckhpd xmm0, xmm0; addsd xmm0, xmm1   (sum in the original, xmm0)
const SUM_IN_ORIGINAL: [u8; 33] = [
    0x66, 0x48, 0x0f, 0x6e, 0xc7, 0x66, 0x0f, 0x62, 0x05, 0xf3, 0x1f, 0x00, 0x00, 0x66, 0x0f, 0x5c, 0x05, 0xfb, 0x1f,
    0x00, 0x00, 0x66, 0x0f, 0x28, 0xc8, 0x66, 0x0f, 0x15, 0xc0, 0xf2, 0x0f, 0x58, 0xc1,
];

#[test]
fn u64_to_f64_sum_in_copy_leaves_the_low_half_in_the_original() {
    let (mut state, claimed) = run(&SUM_IN_COPY);
    assert_eq!(claimed, vec![true; 6]);
    assert_eq!(state.reg(Register::XMM1), "fp_1000");
    assert!(state.reg(Register::XMM2).starts_with("(f64)(u32)("), "{}", state.reg(Register::XMM2));
}

#[test]
fn u64_to_f64_sum_in_original_leaves_the_low_half_in_the_copy() {
    let (mut state, claimed) = run(&SUM_IN_ORIGINAL);
    assert_eq!(claimed, vec![true; 6]);
    assert_eq!(state.reg(Register::XMM0), "fp_1000");
    assert!(state.reg(Register::XMM1).starts_with("(f64)(u32)("), "{}", state.reg(Register::XMM1));
}

#[test]
fn u64_to_f64_is_not_fused_when_a_branch_enters_the_sequence() {
    // The same six instructions followed by `jmp 0x1005`, a jump to the second one.
    let mut code = SUM_IN_ORIGINAL.to_vec();
    code.extend_from_slice(&[0xeb, 0xe2]);
    let (_, claimed) = run(&code);
    assert!(claimed.iter().all(|&c| !c), "{claimed:?}");
}
