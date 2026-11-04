/*
 * xref — Ultra blazing fast cross-references of an x86-64 ELF binary
 * Copyright (c) 2026 Alexander Panasenko
 *
 * Contact: alex@prod.codes
 * Author: https://prod.codes/about/
 * Project: https://github.com/alex09x/xref
 * SPDX-License-Identifier: MIT OR Apache-2.0
 */

//! Unit tests for slicing, C diffing, dump, and simplification (`slice`, `slice_parse`, `diffc`,
//! `dump`, `c`, `simplify`).

use std::collections::HashSet;
use std::ops::Range;

use crate::c::{c_one, c_one_marked, find_comment_outside_str};
use crate::diffc::diff_c;
use crate::dump::dump_tree;
use crate::image::{Image, Segment};
use crate::locations::Location;
use crate::runtime::RuntimeMap;
use crate::simplify::simplify_linear;
use crate::slice::slice_fn;
use crate::slice_parse::{collect_stack_ptr_vars, decl_ident, pure_decl_ident, stmt_def_use, target_hints_for_ip};

fn make_img(code: &[u8], f_range: Range<u64>) -> Image {
    let mut data = vec![0x90u8; 0x4000];
    let offset = usize::try_from(f_range.start.saturating_sub(0x1000)).unwrap_or_default();
    let len = code.len();
    if offset + len <= data.len() {
        data[offset..offset + len].copy_from_slice(code);
    }
    Image {
        data,
        segments: vec![Segment { va: 0x1000, offset: 0, size: 0x4000 }],
        functions: vec![f_range],
        pointers: Vec::new(),
        imports: Vec::new(),
        symbols: Vec::new(),
        metadata: crate::image_format::Metadata::default(),
    }
}

#[test]
fn simplify_and_c_escapes_coverage() {
    // simplify.rs line 105: split_additive_terms when previous char is *, +, -, or <
    assert_eq!(simplify_linear("rax * -1 + 4"), "-rax + 4");
    assert_eq!(simplify_linear("rax + -1"), "rax + -1");
    assert_eq!(simplify_linear("rax - -1"), "rax - -1");
    assert_eq!(simplify_linear("(rax << -1) + 2"), "(rax << -1) + 2");

    // simplify.rs line 184: eval_linear when constant factor is 0 or lhs is constant
    assert_eq!(simplify_linear("0 * (rax + rbx)"), "0");
    assert_eq!(simplify_linear("0 * rax + 5"), "5");
    assert_eq!(simplify_linear("2 * (rax + rax)"), "rax * 4");

    // c.rs lines 40, 42: find_comment_outside_str with escaped backslash and quote
    let commented = r#""escaped \\ \" str" // comment"#;
    assert_eq!(find_comment_outside_str(commented), Some(20));
    assert_eq!(find_comment_outside_str(r#""no comment""#), None);
}

#[test]
fn slice_parse_coverage() {
    // slice_parse.rs lines 59-60: pure_decl_ident
    assert_eq!(pure_decl_ident("goto L_1000;"), None);
    assert_eq!(pure_decl_ident("break;"), None);
    assert_eq!(pure_decl_ident("continue;"), None);
    assert_eq!(pure_decl_ident("return 0;"), None);
    assert_eq!(pure_decl_ident("u64 var_x;"), Some("var_x".to_owned()));

    // slice_parse.rs line 65: decl_ident for pure declaration
    assert_eq!(decl_ident("u64 var_y;"), Some("var_y".to_owned()));

    // slice_parse.rs line 87: split_single_line_if unclosed parens returns None
    let empty_set = HashSet::new();
    let (d_none, u_none) = stmt_def_use("if (x > 0", &empty_set);
    assert!(d_none.is_empty() && !u_none.is_empty());

    // slice_parse.rs line 106: empty statement
    let (d_empty, u_empty) = stmt_def_use("   /* only comment */  ", &empty_set);
    assert!(d_empty.is_empty() && u_empty.is_empty());

    // slice_parse.rs lines 95-97: collect_stack_ptr_vars
    let ptr_lines = ["  ptr_v = &slot_10;"];
    let ptr_vars = collect_stack_ptr_vars(&ptr_lines);
    assert!(ptr_vars.contains("ptr_v"));

    // slice_parse.rs lines 116-125 and line 129: stmt_def_use with &slot_ and stack_ptr_vars
    let (call_defs, call_uses) = stmt_def_use("fn_sub(&slot_20, ptr_v);", &ptr_vars);
    assert!(call_defs.contains(&"slot_20".to_owned()));
    assert!(call_defs.contains(&"slot_28".to_owned()));
    assert!(call_defs.contains(&"slot_30".to_owned()));
    assert!(call_defs.contains(&"ptr_v".to_owned()));
    assert!(call_uses.contains(&"ptr_v".to_owned()));

    // slice_parse.rs lines 179-184: target_hints_for_ip with ip-relative operand and Location / preview
    let code: &[u8] = &[
        0x48, 0x8b, 0x05, 0x09, 0x00, 0x00, 0x00, // mov rax, [rip + 9] -> 0x1010
        0x48, 0x8b, 0x0d, 0x42, 0x00, 0x00, 0x00, // mov rcx, [rip + 0x42] -> 0x1050
        0xc3,
    ];
    let mut img = make_img(code, 0x1000..0x100f);
    let p_off = 0x50usize;
    img.data[p_off..p_off + 11].copy_from_slice(b"sample_str\0");
    let locs = vec![Location { place: 0x1010, file: "src/sample.rs".to_owned(), line: 123, col: 1 }];
    let hints = target_hints_for_ip(&img, &locs, &(0x1000..0x100f), 0x1000);
    assert!(hints.iter().any(|h| h.contains("sample.rs:123")), "{hints:?}");
    assert!(hints.iter().any(|h| h.contains("sample_str")), "{hints:?}");
}

#[test]
fn dump_tree_and_sanitize_coverage() {
    // dump.rs lines 86, 99-101, 127, 129, 132, 162, 177
    let code: &[u8] = &[0x48, 0x8b, 0x05, 0x10, 0x00, 0x00, 0x00, 0xc3]; // rip-rel to 0x1017
    let mut data = vec![0x90u8; 0x4000];
    data[..code.len()].copy_from_slice(code);
    data[0x1f..0x27].copy_from_slice(&17u64.to_le_bytes());
    data[0x27..0x2b].copy_from_slice(&10u32.to_le_bytes());
    data[0x2b..0x2f].copy_from_slice(&1u32.to_le_bytes());
    data[0x100..0x111].copy_from_slice(b"nested/sub/mod.rs");

    let image = Image {
        data,
        segments: vec![Segment { va: 0x1000, offset: 0, size: 0x4000 }],
        functions: std::iter::once(0x1000..0x1008).collect(),
        pointers: vec![(0x1017, 0x1100)],
        imports: Vec::new(),
        symbols: vec![(0x1000, "demo_func".to_owned())],
        metadata: crate::image_format::Metadata::default(),
    };

    let tmp = std::env::temp_dir().join(format!("xref_test_dump_{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&tmp);

    // Filter out everything: dump.rs lines 127, 129
    let mut out_filtered = Vec::new();
    assert!(dump_tree(&image, &tmp, Some("nonexistent_pat"), false, &mut out_filtered).is_ok());

    // Dump with matching locations: dump.rs lines 99-101, 132, 162, 177
    let mut out_all = Vec::new();
    assert!(dump_tree(&image, &tmp, None, false, &mut out_all).is_ok());
    let _ = std::fs::remove_dir_all(&tmp);
}

#[test]
fn diffc_coverage() {
    // diffc.rs lines 91, 94, 96-97, 154-159, 188-191, 240, 245-246, 260, 262-263, 276-280
    // 1. Function named "function" (lines 94, 96-97), negative rsp slot slot_m10 (lines 154-159),
    // and immediate 0x12345678 so score_pair matches in best_matches (line 240).
    let code_slot_m: &[u8] = &[
        0xb8, 0x78, 0x56, 0x34, 0x12, // mov eax, 0x12345678
        0x48, 0x89, 0x44, 0x24, 0xf0, // mov [rsp-0x10], rax
        0xc3, // ret
    ];
    let len_slot = u64::try_from(code_slot_m.len()).unwrap_or_default();
    let mut img1 = make_img(code_slot_m, 0x1000..0x1000 + len_slot);
    img1.symbols = vec![(0x1000, "function".to_owned())];

    let mut img2 = make_img(code_slot_m, 0x1000..0x1000 + len_slot);
    img2.symbols = vec![(0x1000, "function".to_owned())];

    let mut out = Vec::new();
    // Line 240 (explicit_target is None), lines 260, 262-263 (identical normalized pseudo-C)
    assert!(diff_c(&img1, &img2, &["0x1000".to_owned()], None, false, &mut out).is_ok());
    let s_ident = String::from_utf8_lossy(&out);
    assert!(s_ident.contains("identical normalized pseudo-C"), "{s_ident}");

    // Lines 245-246: counterpart not found in --other
    let img_empty = Image {
        data: vec![0xccu8; 0x100],
        segments: vec![Segment { va: 0x2000, offset: 0, size: 0x100 }],
        functions: Vec::new(),
        pointers: Vec::new(),
        imports: Vec::new(),
        symbols: Vec::new(),
        metadata: crate::image_format::Metadata::default(),
    };
    out.clear();
    assert!(diff_c(&img1, &img_empty, &["0x1000".to_owned()], None, false, &mut out).is_ok());
    let s_no_match = String::from_utf8_lossy(&out);
    assert!(s_no_match.contains("no counterpart found in --other"), "{s_no_match}");

    // Lines 276-280: skipped context lines (show[idx] == false -> "  ...")
    let mut seq1 = Vec::new();
    for i in 0..10u8 {
        seq1.extend([0xc6, 0x44, 0x24, 0x10 + i, i]); // mov byte [rsp + 0x10 + i], i
    }
    seq1.extend([0xb8, 0x01, 0x00, 0x00, 0x00, 0xc3]); // mov eax, 1; ret

    let mut seq2 = Vec::new();
    for i in 0..10u8 {
        seq2.extend([0xc6, 0x44, 0x24, 0x10 + i, i]); // mov byte [rsp + 0x10 + i], i
    }
    seq2.extend([0xb8, 0x02, 0x00, 0x00, 0x00, 0xc3]); // mov eax, 2; ret

    let img_ctx1 = make_img(&seq1, 0x1000..0x1000 + u64::try_from(seq1.len()).unwrap_or_default());
    let img_ctx2 = make_img(&seq2, 0x1000..0x1000 + u64::try_from(seq2.len()).unwrap_or_default());
    out.clear();
    assert!(diff_c(&img_ctx1, &img_ctx2, &["0x1000".to_owned()], Some("0x1000"), false, &mut out).is_ok());
    let s_ctx = String::from_utf8_lossy(&out);
    assert!(s_ctx.contains("  ..."), "{s_ctx}");
    // The len_a * len_b > 2_500_000 fallback is covered directly on lcs_edits in diffc::tests
    // without decompiling two 1600-statement functions.
}

#[test]
fn c_marked_and_scoped_coverage() {
    // c.rs lines 161 (spill_to_arg), 165 (unused stack slot), 314-318 (c_one_marked target on ret)
    let code_ret: &[u8] = &[0xb8, 0x2a, 0x00, 0x00, 0x00, 0xc3]; // mov eax, 42 (0x1000..0x1005); ret (0x1005)
    let img_ret = make_img(code_ret, 0x1000..0x1006);
    let rt = RuntimeMap::default();
    let res_marked = c_one_marked(&img_ret, &[], &rt, 0x1000, None, None, Some(0x1005));
    let (_, s_marked) = res_marked.unwrap_or_default();
    assert!(s_marked.contains("/* @xref_slice_target */"), "{s_marked}");

    // c.rs line 161 (spill_to_arg: mov [rsp+8], rdi; ret)
    let code_spill: &[u8] = &[0x48, 0x89, 0x7c, 0x24, 0x08, 0xc3];
    let img_spill = make_img(code_spill, 0x1000..0x1006);
    let (_, s_spill) = c_one(&img_spill, &[], &rt, 0x1000, None, None).unwrap_or_default();
    assert!(s_spill.contains("fn_1000"), "{s_spill}");

    // c.rs line 165 (unused stack slot: mov rbx, rsp; ret)
    let code_slot_unused: &[u8] = &[0x48, 0x89, 0xe3, 0xc3];
    let img_slot_unused = make_img(code_slot_unused, 0x1000..0x1004);
    let (_, s_unused) = c_one(&img_slot_unused, &[], &rt, 0x1000, None, None).unwrap_or_default();
    assert!(s_unused.contains("fn_1000"), "{s_unused}");

    // c.rs lines 121, 124 (inline_scoped_decls: first use after label and multiple scopes)
    let code_scope: &[u8] = &[
        0xbb, 0x0a, 0x00, 0x00, 0x00, // mov ebx, 10
        0x85, 0xff, // test edi, edi
        0x74, 0x07, // jz 0x1010
        0x89, 0xd8, // mov eax, ebx
        0xeb, 0x05, // jmp 0x1015
        0x90, 0x90, 0x90, // nop nop nop (align to 0x1010)
        0x89, 0xd8, // 0x1010: mov eax, ebx
        0x83, 0xc0, 0x01, // add eax, 1
        0xc3, // 0x1015: ret
    ];
    let img_scope = make_img(code_scope, 0x1000..0x1016);
    let (_, s_scope) = c_one(&img_scope, &[], &rt, 0x1000, None, None).unwrap_or_default();
    assert!(s_scope.contains("fn_1000"), "{s_scope}");
}

#[test]
fn slice_fn_coverage() {
    // slice.rs lines 41-48, 50, 55, 78, 103, 118, 126, 133-134, 147, 174-177, 180-182
    let code: &[u8] = &[
        0x83, 0xff, 0x00, // 0x1000: cmp edi, 0
        0x74, 0x15, // 0x1003: jz 0x101a (jump to L_101a)
        0x83, 0xff, 0x01, // 0x1005: cmp edi, 1
        0x75, 0x06, // 0x1008: jne 0x1010
        0xb8, 0x01, 0x00, 0x00, 0x00, // 0x100a: mov eax, 1
        0xc3, // 0x100f: ret (single-line if with return: line 126)
        0xb8, 0x05, 0x00, 0x00, 0x00, // 0x1010: mov eax, 5
        0xc3, // 0x1015: ret (top-level return: line 118)
        0x90, 0x90, 0x90, 0x90, // 0x1016..0x101a: nops
        0xb8, 0x00, 0x2a, 0x00, 0x00, // 0x101a: mov eax, 0x2a00 (target 0x2a00)
        0xc3, // 0x101f: ret
    ];
    let len = u64::try_from(code.len()).unwrap_or_default();
    let img = make_img(code, 0x1000..0x1000 + len);

    let mut out = Vec::new();
    // Slice for "0x2a00":
    // - line 78: target_ip is None, prefix "0x" adds "_2a00"
    // - line 103: matched hint in non-pure-decl
    // - line 118: top_ret before target line kept
    // - line 126: single-line if kept
    // - lines 41-48, 50: propagate_labels_and_gotos finds L_101a and goto L_101a
    // - line 55: break on earlier return
    // - line 147: empty line skipped
    // - lines 180-182: label kept via ever_used
    let res = slice_fn(&img, "0x1000", "0x2a00", false, &mut out);
    assert!(res.is_ok(), "{res:?}");
    let s_slice = String::from_utf8_lossy(&out);
    assert!(s_slice.contains("0x2a00"), "{s_slice}");

    // Slicing PLT call for lines 174-177 (comment directly before kept target)
    let code_call: &[u8] = &[
        0x48, 0x83, 0xec, 0x08, // sub rsp, 8
        0xff, 0x15, 0x02, 0x10, 0x00, 0x00, // call [rip+0x1002] -> 0x200c
        0x48, 0x83, 0xc4, 0x08, // add rsp, 8
        0xc3,
    ];
    let mut img_call = make_img(code_call, 0x1000..0x1000 + u64::try_from(code_call.len()).unwrap_or_default());
    img_call.imports = vec![(0x200c, "malloc".to_owned())];
    img_call.pointers = vec![(0x200c, 0x3000)];
    out.clear();
    assert!(slice_fn(&img_call, "0x1000", "malloc", false, &mut out).is_ok());
    let s_call = String::from_utf8_lossy(&out);
    assert!(s_call.contains("malloc"), "{s_call}");
}
