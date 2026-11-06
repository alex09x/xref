/*
 * xref — Ultra blazing fast cross-references of an x86-64 ELF binary
 * Copyright (c) 2026 Alexander Panasenko
 *
 * Contact: alex@prod.codes
 * Author: https://prod.codes/about/
 * Project: https://github.com/alex09x/xref
 * SPDX-License-Identifier: MIT OR Apache-2.0
 */

use std::ops::Range;

use super::fn_sig;
use super::xmm::{FloatParam, FloatRet, import_float_sig};
use crate::image::{Image, Segment};
use crate::runtime::RuntimeMap;

/// 0x1000 add:      addsd xmm0, xmm1; ret
/// 0x1010 conv:     cvtsi2sd xmm0, rdi; ret                  (xmm0 written first)
/// 0x1020 fwd:      sub rsp, 8; call add; add rsp, 8; ret    (xmm0/xmm1 only forwarded)
/// 0x1040 mul32:    mulss xmm0, xmm1; ret
/// 0x1050 partial:  test edi, edi; je ret; addsd xmm0, xmm1; ret
/// 0x1060 bits:     movq xmm0, rdi; ret
/// 0x1070 tail:     addsd xmm0, xmm1; jmp add
/// 0x1080 both:     cvttsd2si rax, xmm0; addsd xmm0, xmm0; ret
/// 0x1090 fwd32:    sub rsp, 8; call mul32; add rsp, 8; ret
const FUNCS: &[(u64, &[u8])] = &[
    (0x1000, &[0xf2, 0x0f, 0x58, 0xc1, 0xc3]),
    (0x1010, &[0xf2, 0x48, 0x0f, 0x2a, 0xc7, 0xc3]),
    (0x1020, &[0x48, 0x83, 0xec, 0x08, 0xe8, 0xd7, 0xff, 0xff, 0xff, 0x48, 0x83, 0xc4, 0x08, 0xc3]),
    (0x1040, &[0xf3, 0x0f, 0x59, 0xc1, 0xc3]),
    (0x1050, &[0x85, 0xff, 0x74, 0x04, 0xf2, 0x0f, 0x58, 0xc1, 0xc3]),
    (0x1060, &[0x66, 0x48, 0x0f, 0x6e, 0xc7, 0xc3]),
    (0x1070, &[0xf2, 0x0f, 0x58, 0xc1, 0xe9, 0x87, 0xff, 0xff, 0xff]),
    (0x1080, &[0xf2, 0x48, 0x0f, 0x2c, 0xc0, 0xf2, 0x0f, 0x58, 0xc0, 0xc3]),
    (0x1090, &[0x48, 0x83, 0xec, 0x08, 0xe8, 0xa7, 0xff, 0xff, 0xff, 0x48, 0x83, 0xc4, 0x08, 0xc3]),
];

fn image() -> Image {
    let mut data = vec![0u8; 0x100];
    let mut functions = Vec::new();
    for &(va, code) in FUNCS {
        let off = usize::try_from(va - 0x1000).unwrap_or(0);
        data[off..off + code.len()].copy_from_slice(code);
        functions.push(va..va + code.len() as u64);
    }
    Image {
        data,
        segments: vec![Segment { va: 0x1000, offset: 0, size: 0x100 }],
        functions,
        pointers: Vec::new(),
        imports: Vec::new(),
        symbols: Vec::new(),
        metadata: crate::image_format::Metadata::default(),
    }
}

fn range(img: &Image, start: u64) -> Range<u64> {
    img.function_at(start).unwrap_or(start..start)
}

const fn p(index: u8, ty: &'static str) -> FloatParam {
    FloatParam { index, ty }
}

#[test]
fn f64_abi_float_params_are_read_before_written_xmm_registers_typed_by_first_use() {
    let img = image();
    let add = fn_sig(&img, &range(&img, 0x1000));
    assert_eq!(add.float_params, vec![p(0, "f64"), p(1, "f64")]);
    assert!(add.regs.is_empty(), "no integer parameters: {:?}", add.regs);
    let conv = fn_sig(&img, &range(&img, 0x1010));
    assert!(conv.float_params.is_empty(), "cvtsi2sd writes xmm0 without reading it: {:?}", conv.float_params);
    assert_eq!(conv.regs, vec![iced_x86::Register::RDI]);
    let mul32 = fn_sig(&img, &range(&img, 0x1040));
    assert_eq!(mul32.float_params, vec![p(0, "f32"), p(1, "f32")]);
    let bits = fn_sig(&img, &range(&img, 0x1060));
    assert!(bits.float_params.is_empty(), "movq writes xmm0 from a GPR: {:?}", bits.float_params);
}

#[test]
fn f64_abi_registers_only_forwarded_to_a_direct_call_are_params_with_the_callee_width() {
    let img = image();
    let fwd = fn_sig(&img, &range(&img, 0x1020));
    assert_eq!(fwd.float_params, vec![p(0, "f64"), p(1, "f64")]);
    let fwd32 = fn_sig(&img, &range(&img, 0x1090));
    assert_eq!(fwd32.float_params, vec![p(0, "f32"), p(1, "f32")]);
}

#[test]
fn f64_abi_float_return_requires_a_scalar_result_in_xmm0_on_every_path() {
    let img = image();
    let ret = |start| fn_sig(&img, &range(&img, start)).float_ret;
    assert_eq!(ret(0x1000), Some(FloatRet { ty: "f64", rax_written: false }));
    assert_eq!(ret(0x1010), Some(FloatRet { ty: "f64", rax_written: false }));
    assert_eq!(ret(0x1040), Some(FloatRet { ty: "f32", rax_written: false }));
    assert_eq!(ret(0x1020), Some(FloatRet { ty: "f64", rax_written: false }), "call result of an f64 function");
    assert_eq!(ret(0x1090), Some(FloatRet { ty: "f32", rax_written: false }));
    assert_eq!(ret(0x1050), None, "the je path leaves xmm0 unwritten");
    assert_eq!(ret(0x1060), None, "movq from a GPR is not a floating-point result");
    assert_eq!(ret(0x1070), None, "ends by a tail call");
    assert_eq!(ret(0x1080), Some(FloatRet { ty: "f64", rax_written: true }));
}

#[test]
fn f64_abi_libm_imports_have_float_signatures() {
    assert_eq!(import_float_sig("sin@GLIBC_2.2.5"), Some((1, "f64")));
    assert_eq!(import_float_sig("powf"), Some((2, "f32")));
    assert_eq!(import_float_sig("memcpy"), None);
}

#[test]
fn f64_abi_pseudo_c_names_float_params_returns_and_call_results() {
    let img = image();
    let rt = RuntimeMap::default();
    let c = |start| crate::c::c_one(&img, &[], &rt, start, None, None).map(|(_, text)| text).unwrap_or_default();
    let add = c(0x1000);
    assert!(add.contains("f64 fn_1000(f64 arg_f0, f64 arg_f1) {"), "{add}");
    assert!(add.contains("return (arg_f0 + arg_f1);"), "{add}");
    assert!(!add.contains("zmm0") && !add.contains("zmm1"), "{add}");
    assert!(add.contains("arg_f0 (xmm0): f64"), "{add}");
    let fwd = c(0x1020);
    assert!(fwd.contains("f64 fn_1020(f64 arg_f0, f64 arg_f1) {"), "{fwd}");
    assert!(fwd.contains("return fn_1000(arg_f0, arg_f1);"), "{fwd}");
    let fwd32 = c(0x1090);
    assert!(fwd32.contains("f32 fn_1090(f32 arg_f0, f32 arg_f1) {"), "{fwd32}");
    assert!(fwd32.contains("return fn_1040(arg_f0, arg_f1);"), "{fwd32}");
    let both = c(0x1080);
    let sig_line = both.lines().find(|l| l.contains("fn_1080(")).unwrap_or_default();
    assert!(!sig_line.starts_with("f64") && sig_line.contains("f64 arg_f0"), "{both}");
    assert!(both.contains("f64 fp_1085 = (arg_f0 + arg_f0);"), "{both}");
    assert!(both.contains("/* xmm0 = fp_1085 (f64) */"), "{both}");
    let partial = c(0x1050);
    assert!(partial.lines().any(|l| l.starts_with("void fn_1050(") || l.starts_with("unk64 fn_1050(")), "{partial}");
}
