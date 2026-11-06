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
/// 0x10b0 varargs:  test al, al; je ret; movaps [rsp-0x40], xmm0; movaps [rsp-0x30], xmm1; ret
/// 0x10c0 vcaller:  sub rsp, 8; call varargs; add rsp, 8; ret
/// 0x10d0 after:    sub rsp, 8; call tail; add rsp, 8; addsd xmm0, xmm1; ret   (tail's xmm0 is unknown)
/// 0x10e8 callbr:   sub rsp, 8; call add; test eax, eax; je L; addsd xmm0, xmm1; L: add rsp, 8; ret
/// 0x1100 branchy:  mulsd xmm0, xmm0; test edi, edi; je L; addsd xmm0, xmm1; L: ret
/// 0x1110 cmpmov:   ucomisd xmm0, xmm1; movsd xmm0, xmm1; ja L; addsd xmm0, xmm0; L: ret
/// 0x1120 dbl:      movapd xmm1, xmm0; addsd xmm0, xmm1; ret                  (writes xmm1)
/// 0x1130 clob:     sub rsp, 8; call dbl; test eax, eax; je L; addsd xmm0, xmm1; L: add rsp, 8; ret
/// 0x1150 simd:     paddq xmm0, xmm1; ret                                     (packed integer)
/// 0x1160 lane:     movq rax, xmm0; ret              (`_mm_cvtsi128_si64` or `f64::to_bits`)
/// 0x1170 copy:     movapd xmm2, xmm0; addsd xmm2, xmm1; movapd xmm0, xmm2; ret
/// 0x1180 mixed:    movq rax, xmm0; addsd xmm1, xmm1; ret       (integer vector, then a double)
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
    (0x10b0, &[0x84, 0xc0, 0x74, 0x0a, 0x0f, 0x29, 0x44, 0x24, 0xc0, 0x0f, 0x29, 0x4c, 0x24, 0xd0, 0xc3]),
    (0x10c0, &[0x48, 0x83, 0xec, 0x08, 0xe8, 0xe7, 0xff, 0xff, 0xff, 0x48, 0x83, 0xc4, 0x08, 0xc3]),
    (
        0x10d0,
        &[0x48, 0x83, 0xec, 0x08, 0xe8, 0x97, 0xff, 0xff, 0xff, 0x48, 0x83, 0xc4, 0x08, 0xf2, 0x0f, 0x58, 0xc1, 0xc3],
    ),
    (
        0x10e8,
        &[
            0x48, 0x83, 0xec, 0x08, 0xe8, 0x0f, 0xff, 0xff, 0xff, 0x85, 0xc0, 0x74, 0x04, 0xf2, 0x0f, 0x58, 0xc1, 0x48,
            0x83, 0xc4, 0x08, 0xc3,
        ],
    ),
    (0x1100, &[0xf2, 0x0f, 0x59, 0xc0, 0x85, 0xff, 0x74, 0x04, 0xf2, 0x0f, 0x58, 0xc1, 0xc3]),
    (0x1110, &[0x66, 0x0f, 0x2e, 0xc1, 0xf2, 0x0f, 0x10, 0xc1, 0x77, 0x04, 0xf2, 0x0f, 0x58, 0xc0, 0xc3]),
    (0x1120, &[0x66, 0x0f, 0x28, 0xc8, 0xf2, 0x0f, 0x58, 0xc1, 0xc3]),
    (
        0x1130,
        &[
            0x48, 0x83, 0xec, 0x08, 0xe8, 0xe7, 0xff, 0xff, 0xff, 0x85, 0xc0, 0x74, 0x04, 0xf2, 0x0f, 0x58, 0xc1, 0x48,
            0x83, 0xc4, 0x08, 0xc3,
        ],
    ),
    (0x1150, &[0x66, 0x0f, 0xd4, 0xc1, 0xc3]),
    (0x1160, &[0x66, 0x48, 0x0f, 0x7e, 0xc0, 0xc3]),
    (0x1170, &[0x66, 0x0f, 0x28, 0xd0, 0xf2, 0x0f, 0x58, 0xd1, 0x66, 0x0f, 0x28, 0xc2, 0xc3]),
    (0x1180, &[0x66, 0x48, 0x0f, 0x7e, 0xc0, 0xf2, 0x0f, 0x58, 0xc9, 0xc3]),
];

fn image() -> Image {
    let mut data = vec![0u8; 0x200];
    let mut functions = Vec::new();
    for &(va, code) in FUNCS {
        let off = usize::try_from(va - 0x1000).unwrap_or(0);
        data[off..off + code.len()].copy_from_slice(code);
        functions.push(va..va + code.len() as u64);
    }
    Image {
        data,
        segments: vec![Segment { va: 0x1000, offset: 0, size: 0x200 }],
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
fn f64_abi_integer_simd_reads_are_not_float_params_without_float_evidence() {
    let img = image();
    let simd = fn_sig(&img, &range(&img, 0x1150));
    assert!(simd.float_params.is_empty(), "paddq is integer SIMD: {:?}", simd.float_params);
    // A bit move out of xmm0 alone is an integer lane extraction as much as a float bitcast.
    let lane = fn_sig(&img, &range(&img, 0x1160));
    assert!(lane.float_params.is_empty(), "movq rax, xmm0 alone: {:?}", lane.float_params);
    // A copy of xmm0 in a function with scalar float arithmetic is a float parameter.
    let copy = fn_sig(&img, &range(&img, 0x1170));
    assert_eq!(copy.float_params, vec![p(0, "f64"), p(1, "f64")]);
    // Float math on xmm1 is no evidence for the lane moved out of xmm0.
    let mixed = fn_sig(&img, &range(&img, 0x1180));
    assert_eq!(mixed.float_params, vec![p(1, "f64")]);
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

fn pseudo_c(img: &Image, start: u64) -> String {
    let rt = RuntimeMap::default();
    crate::c::c_one(img, &[], &rt, start, None, None).map(|(_, text)| text).unwrap_or_default()
}

#[test]
fn f64_abi_varargs_register_save_spills_are_not_float_params() {
    let img = image();
    let varargs = fn_sig(&img, &range(&img, 0x10b0));
    assert!(varargs.float_params.is_empty(), "movaps spills behind test al: {:?}", varargs.float_params);
    let caller = fn_sig(&img, &range(&img, 0x10c0));
    assert!(caller.float_params.is_empty(), "nothing to propagate to the caller: {:?}", caller.float_params);
    for start in [0x10b0, 0x10c0] {
        let text = pseudo_c(&img, start);
        assert!(!text.is_empty() && !text.contains("arg_f"), "{text}");
    }
    let text = pseudo_c(&img, 0x10c0);
    assert!(text.contains("fn_10b0()"), "the call passes no float arguments:\n{text}");
}

#[test]
fn f64_abi_xmm_read_after_a_call_shows_only_what_the_callee_may_have_changed() {
    let img = image();
    let sig = fn_sig(&img, &range(&img, 0x10d0));
    assert_eq!(sig.float_params, vec![p(0, "f64"), p(1, "f64")], "forwarded to the tail-calling callee");
    let text = pseudo_c(&img, 0x10d0);
    let call = "fn_1070(arg_f0, arg_f1)";
    let (_, after) = text.split_once(call).unwrap_or_else(|| panic!("no call {call}:\n{text}"));
    // fn_1070 (and fn_1000 it tail-calls) writes xmm0 with a value of unknown type and never xmm1.
    assert!(after.contains("(zmm0 + arg_f1)") && !after.contains("arg_f0"), "{text}");
}

#[test]
fn f64_abi_xmm_written_by_the_callee_is_not_the_parameter_after_the_call() {
    let img = image();
    let text = pseudo_c(&img, 0x1130);
    assert!(text.contains("f64 fn_1130(f64 arg_f0) {"), "xmm1 read after the call is no parameter:\n{text}");
    let lines = body(&text);
    let branch = lines.iter().position(|l| l.starts_with("if ("));
    let call = lines.iter().position(|l| *l == "arg_f0 = fn_1120(arg_f0);");
    assert!(call.is_some() && call < branch, "{text}");
    // fn_1120 writes xmm1 (movapd xmm1, xmm0): the add reads the register, not a stale value.
    let add = lines.iter().position(|l| *l == "arg_f0 = (arg_f0 + zmm1);");
    assert!(add > branch, "{text}");
    assert_eq!(lines.iter().filter(|l| l.starts_with("return")).collect::<Vec<_>>(), vec![&"return arg_f0;"], "{text}");
}

/// Statement lines of the body (no comments, declarations or the signature).
fn body(text: &str) -> Vec<&str> {
    text.lines().map(str::trim).filter(|l| !l.is_empty() && !l.starts_with("/*") && !l.starts_with('*')).collect()
}

#[test]
fn f64_abi_float_values_written_before_a_branch_reach_the_join_and_the_return() {
    let img = image();
    let text = pseudo_c(&img, 0x1100);
    let sig_line = text.lines().find(|l| l.contains("fn_1100(")).unwrap_or_default();
    assert!(sig_line.starts_with("f64 fn_1100(") && sig_line.ends_with(" arg_0, f64 arg_f0, f64 arg_f1) {"), "{text}");
    let lines = body(&text);
    let square = lines.iter().position(|l| *l == "arg_f0 = (arg_f0 * arg_f0);");
    let branch = lines.iter().position(|l| l.starts_with("if ("));
    assert!(square.is_some() && square < branch, "x*x is carried into the branch:\n{text}");
    assert!(lines.contains(&"arg_f0 = (arg_f0 + arg_f1);"), "the add reads x*x and is carried to the join:\n{text}");
    assert_eq!(lines.iter().filter(|l| l.starts_with("return")).collect::<Vec<_>>(), vec![&"return arg_f0;"], "{text}");
}

#[test]
fn f64_abi_call_result_reaches_later_blocks() {
    let img = image();
    let text = pseudo_c(&img, 0x10e8);
    assert!(text.contains("f64 fn_10e8(f64 arg_f0, f64 arg_f1) {"), "{text}");
    let lines = body(&text);
    let at = |line: &str| lines.iter().position(|l| *l == line).unwrap_or_else(|| panic!("no `{line}`:\n{text}"));
    let branch = lines.iter().position(|l| l.starts_with("if (")).unwrap_or_default();
    assert!(at("arg_f0 = fn_1000(arg_f0, arg_f1);") < branch, "the call result is kept:\n{text}");
    // fn_1000 (addsd xmm0, xmm1; ret) never writes xmm1, so it still holds the parameter.
    assert!(at("arg_f0 = (arg_f0 + arg_f1);") > branch, "the add reads the call result:\n{text}");
    assert!(!text.contains("zmm"), "{text}");
    assert_eq!(lines.iter().filter(|l| l.starts_with("return")).collect::<Vec<_>>(), vec![&"return arg_f0;"], "{text}");
}

#[test]
fn f64_abi_branch_condition_reads_the_value_compared_before_the_register_is_overwritten() {
    let img = image();
    let text = pseudo_c(&img, 0x1110);
    let lines = body(&text);
    let snap = lines.iter().position(|l| *l == "f64 fp_1118_arg_f0 = arg_f0;");
    let moved = lines.iter().position(|l| *l == "arg_f0 = arg_f1;");
    assert!(snap.is_some() && snap < moved, "the compared value is copied first:\n{text}");
    let cond = lines.iter().find(|l| l.starts_with("if (")).copied().unwrap_or_default();
    assert!(cond.contains("fp_1118_arg_f0") && !cond.contains("(arg_f0"), "{text}");
    assert_eq!(lines.iter().filter(|l| l.starts_with("return")).collect::<Vec<_>>(), vec![&"return arg_f0;"], "{text}");
}
