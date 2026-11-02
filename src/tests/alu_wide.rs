/*
 * xref — Ultra blazing fast cross-references of an x86-64 ELF binary
 * Copyright (c) 2026 Alexander Panasenko
 *
 * Contact: alex@prod.codes
 * Author: https://prod.codes/about/
 * Project: https://github.com/alex09x/xref
 * SPDX-License-Identifier: MIT OR Apache-2.0
 */

//! Unit tests for `wide_alu` across 8/16/32/64-bit widening multiply, divide, and sign-extension.

use iced_x86::Instruction;

use crate::c::c_one;
use crate::image::{Image, Segment};
use crate::runtime::RuntimeMap;
use crate::scan::decode;
use crate::wide_alu::op_byte_width;

fn run_fn(bytes: &[u8]) -> String {
    let mut data = vec![0xccu8; 0x100];
    data[..bytes.len()].copy_from_slice(bytes);
    let img = Image {
        data,
        segments: vec![Segment { va: 0x1000, offset: 0, size: 0x100 }],
        functions: std::iter::once(0x1000..0x1000 + bytes.len() as u64).collect(),
        pointers: Vec::new(),
        imports: Vec::new(),
        symbols: Vec::new(),
    };
    let rt = RuntimeMap::detect(&img);
    c_one(&img, &[], &rt, 0x1000, None, None).unwrap_or_default().1
}

#[test]
fn covers_all_widening_mul_div_and_sign_extension_widths() {
    // 8-bit signed imul dil: mov rax, rsi; imul dil; ret -> 48 89 f0 40 f6 ef c3
    let imul8 = run_fn(&[0x48, 0x89, 0xf0, 0x40, 0xf6, 0xef, 0xc3]);
    assert!(imul8.contains("(i16)(i8)"));

    // 16-bit signed imul di reading both ax and dx: mov rax, rsi; imul di; add ax, dx; ret
    let imul16 = run_fn(&[0x48, 0x89, 0xf0, 0x66, 0xf7, 0xef, 0x66, 0x01, 0xd0, 0xc3]);
    assert!(imul16.contains("prod_") && imul16.contains("(i32)(i16)"));

    // 32-bit unsigned mul edi reading both eax and edx: mov eax, esi; mul edi; add eax, edx; ret
    let mul32_both = run_fn(&[0x89, 0xf0, 0xf7, 0xe7, 0x01, 0xd0, 0xc3]);
    assert!(mul32_both.contains("prod_") && mul32_both.contains("(u64)(u32)"));

    // 32-bit signed imul edi reading only eax (lo_web Some, hi_web None, sz == 4): mov eax, esi; imul edi; xor edx, edx; ret
    let imul32_lo = run_fn(&[0x89, 0xf0, 0xf7, 0xef, 0x31, 0xd2, 0xc3]);
    assert!(imul32_lo.contains("(u32)"));

    // 64-bit unsigned mul rdi reading only rax (sz == 8, lo_web Some, hi_web None): mov rax, rsi; mul rdi; add rax, 1; xor edx, edx; ret
    let mul64_lo = run_fn(&[0x48, 0x89, 0xf0, 0x48, 0xf7, 0xe7, 0x48, 0x83, 0xc0, 0x01, 0x31, 0xd2, 0xc3]);
    assert!(mul64_lo.contains('*'));

    // 64-bit signed imul rdi reading both rax and rdx: mov rax, rsi; imul rdi; add rax, rdx; ret
    let imul64_both = run_fn(&[0x48, 0x89, 0xf0, 0x48, 0xf7, 0xef, 0x48, 0x01, 0xd0, 0xc3]);
    assert!(imul64_both.contains("i128 prod_"));

    // High-only widening mul (lo_web None, hi_web Some): mov rax, rsi; mul rdi; mov rax, rdx; ret
    let mul_hi_only = run_fn(&[0x48, 0x89, 0xf0, 0x48, 0xf7, 0xe7, 0x48, 0x89, 0xd0, 0xc3]);
    assert!(mul_hi_only.contains(">> 64"));

    // Dead widening mul reading only overflow flag (lo_web None, hi_web None): mov rax, rsi; mul rdi; setb al; movzx eax, al; xor edx, edx; ret
    let mul_dead = run_fn(&[0x48, 0x89, 0xf0, 0x48, 0xf7, 0xe7, 0x0f, 0x92, 0xc0, 0x0f, 0xb6, 0xc0, 0x31, 0xd2, 0xc3]);
    assert!(mul_dead.contains("umul_overflow"));

    // 8-bit signed idiv dil: mov eax, esi; idiv dil; ret -> 89 f0 40 f6 ff c3
    let idiv8 = run_fn(&[0x89, 0xf0, 0x40, 0xf6, 0xff, 0xc3]);
    assert!(idiv8.contains("(i16)(i8)"));

    // 8-bit unsigned div cl preserving upper bits: mov eax, 0x12340007; mov cl, 3; div cl; ret
    let div8 = run_fn(&[0xb8, 0x07, 0x00, 0x34, 0x12, 0xb1, 0x03, 0xf6, 0xf1, 0xc3]);
    assert!(div8.contains("& ~0xffff") && div8.contains("<< 8"));

    // 16/32/64-bit zero-hi unsigned div (`xor edx, edx; mov rax, rsi; div di/edi/rdi; add rax, rdx; ret`)
    let div16_z = run_fn(&[0x31, 0xd2, 0x89, 0xf0, 0x66, 0xf7, 0xf7, 0x66, 0x01, 0xd0, 0xc3]);
    assert!(div16_z.contains("(u16)"));
    let div32_z = run_fn(&[0x31, 0xd2, 0x89, 0xf0, 0xf7, 0xf7, 0x01, 0xd0, 0xc3]);
    assert!(div32_z.contains("((u32)arg_1 / (u32)arg_0)"), "{div32_z}");
    let div64_z = run_fn(&[0x31, 0xd2, 0x48, 0x89, 0xf0, 0x48, 0xf7, 0xf7, 0x48, 0x01, 0xd0, 0xc3]);
    assert!(div64_z.contains("((u64)arg_1 / (u64)arg_0)"), "{div64_z}");

    // 16-bit zero rdx + cwd + nop + idiv di (`xor edx, edx; mov eax, esi; cwd; nop; idiv di; xor edx, edx; ret`)
    let idiv16_sext = run_fn(&[0x31, 0xd2, 0x89, 0xf0, 0x66, 0x99, 0x90, 0x66, 0xf7, 0xff, 0x31, 0xd2, 0xc3]);
    assert!(idiv16_sext.contains("(u16)((i16)"), "{idiv16_sext}");

    // 32-bit cdq + idiv edi (`mov eax, esi; cdq; idiv edi; ret`)
    let idiv32_sext = run_fn(&[0x89, 0xf0, 0x99, 0xf7, 0xff, 0xc3]);
    assert!(idiv32_sext.contains("(i32)"));

    // 64-bit cqo + nop + in-place rax loop so lo_reg == web.name & intervening insn (`L: cqo; nop; idiv rdi; test rdx, rdx; jnz L; ret`)
    let idiv64_loop =
        run_fn(&[0x48, 0x89, 0xf0, 0x48, 0x99, 0x90, 0x48, 0xf7, 0xff, 0x48, 0x85, 0xd2, 0x75, 0xf5, 0xc3]);
    assert!(idiv64_loop.contains("div_") && idiv64_loop.contains("% (i64)"));

    // Full wide div (non-zero rdx) for 16-bit unsigned/signed, 32-bit unsigned/signed, 64-bit unsigned & signed (lo only & both):
    // 16-bit unsigned div di (lo only, rdx killed): mov rax, rsi; div di; xor edx, edx; ret
    let div16_w = run_fn(&[0x48, 0x89, 0xf0, 0x66, 0xf7, 0xf7, 0x31, 0xd2, 0xc3]);
    assert!(div16_w.contains("(u32)"));
    // 16-bit signed idiv di (non-sext rdx): mov rax, rsi; idiv di; ret
    let idiv16_w = run_fn(&[0x48, 0x89, 0xf0, 0x66, 0xf7, 0xff, 0xc3]);
    assert!(idiv16_w.contains("(i32)"));
    // 32-bit unsigned div edi (non-zero edx): mov eax, esi; div edi; ret
    let div32_w = run_fn(&[0x89, 0xf0, 0xf7, 0xf7, 0xc3]);
    assert!(div32_w.contains("(u64)"));
    // 32-bit signed idiv edi (non-sext edx): mov eax, esi; idiv edi; ret
    let idiv32_w = run_fn(&[0x89, 0xf0, 0xf7, 0xff, 0xc3]);
    assert!(idiv32_w.contains("(i64)"));
    // 64-bit unsigned div rdi reading both rax and rdx: mov rax, rsi; div rdi; add rax, rdx; ret
    let div64_w = run_fn(&[0x48, 0x89, 0xf0, 0x48, 0xf7, 0xf7, 0x48, 0x01, 0xd0, 0xc3]);
    assert!(div64_w.contains("u128 div_"));
    // 64-bit signed idiv rdi (non-sext rdx, rdx killed so hi_live is None & rem rhs > 56 chars): mov rax, rsi; idiv rdi; xor edx, edx; ret
    let idiv64_lo_only = run_fn(&[0x48, 0x89, 0xf0, 0x48, 0xf7, 0xff, 0x31, 0xd2, 0xc3]);
    assert!(idiv64_lo_only.contains("(i128)("), "{idiv64_lo_only}");

    // Sign extensions cbw (66 98), cwde (98), cdqe (48 98):
    let sexts = run_fn(&[0x48, 0x89, 0xf8, 0x66, 0x98, 0x98, 0x48, 0x98, 0xc3]);
    assert!(sexts.contains("(i64)(i32)"));

    // op_byte_width on non-register instruction with 0 memory_size (`jmp +0` -> 0xeb, 0x00 -> 8)
    let mut jmp = Instruction::default();
    decode(&[0xeb, 0x00], 0x1000, |d| jmp = *d);
    assert_eq!(op_byte_width(&jmp), 8);
}
