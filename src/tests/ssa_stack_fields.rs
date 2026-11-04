/*
 * xref — Ultra blazing fast cross-references of an x86-64 ELF binary
 * Copyright (c) 2026 Alexander Panasenko
 *
 * Contact: alex@prod.codes
 * Author: https://prod.codes/about/
 * Project: https://github.com/alex09x/xref
 * SPDX-License-Identifier: MIT OR Apache-2.0
 */

//! Unit tests for `stack_frame`, `type_facts`, `type_prop`, `fields_c`, `ssa_inline`, and `ssa_webs`.

use std::ops::Range;

use iced_x86::Register;

use crate::fields_c::apply_field_sugar;
use crate::image::{Image, Segment};
use crate::runtime::RuntimeMap;
use crate::sig::FnSig;
use crate::ssa_webs::SsaCfg;
use crate::stack_frame::StackFrame;
use crate::type_facts::{ReturnKind, TypeFacts};
use crate::type_prop::LocalTypes;

fn default_sig() -> FnSig {
    FnSig { regs: Vec::new(), stack_args: Vec::new(), arg_base_rsp: None, uses_fp: false, exact: false }
}

fn make_img(bytes: &[u8], f: Range<u64>) -> Image {
    let mut data = vec![0xccu8; 0x1000];
    let offset = usize::try_from(f.start.saturating_sub(0x1000)).unwrap_or(0);
    let end = offset.saturating_add(bytes.len());
    if end <= data.len() {
        data[offset..end].copy_from_slice(bytes);
    }
    Image {
        data,
        segments: vec![Segment { va: 0x1000, offset: 0, size: 0x1000 }],
        functions: vec![f],
        pointers: Vec::new(),
        imports: Vec::new(),
        symbols: Vec::new(),
        metadata: crate::image_format::Metadata::default(),
    }
}

#[test]
fn stack_frame_covers_step_sp_width_bits_and_fp_prologue() {
    let code: &[u8] = &[
        0xf3, 0x0f, 0x1e, 0xfa, 0x90, 0x55, 0x48, 0x89, 0xe5, 0x48, 0x83, 0xec, 0x50, 0x88, 0x44, 0x24, 0x01, 0x66,
        0x89, 0x44, 0x24, 0x02, 0x89, 0x44, 0x24, 0x04, 0x0f, 0x29, 0x44, 0x24, 0x10, 0xc5, 0xfe, 0x11, 0x44, 0x24,
        0x20, 0x48, 0x8b, 0x45, 0xf8, 0x48, 0x8b, 0x45, 0x10, 0x48, 0x8b, 0x04, 0xcc, 0x48, 0x89, 0xec, 0xc9, 0xc3,
    ];
    let len = u64::try_from(code.len()).unwrap_or(0);
    let func = 0x1000..0x1000 + len;
    let img = make_img(code, func.clone());
    let mut sig = default_sig();
    sig.uses_fp = true;

    let empty_f = 0x1000..0x1000;
    let sf_empty = StackFrame::analyze(&img, &empty_f, &sig, &[]);
    assert!(sf_empty.slots.is_empty());

    let sf = StackFrame::analyze(&img, &func, &sig, &[]);
    assert!(!sf.slots.is_empty());
}

#[test]
fn stack_frame_covers_split_zero_128_and_overlapping_slots() {
    let code: &[u8] = &[0x0f, 0x29, 0x04, 0x24, 0x48, 0x8b, 0x44, 0x24, 0x08, 0x89, 0x44, 0x24, 0x04, 0xc3];
    let len = u64::try_from(code.len()).unwrap_or(0);
    let func = 0x1000..0x1000 + len;
    let img = make_img(code, func.clone());
    let sf = StackFrame::analyze(&img, &func, &default_sig(), &[]);
    assert!(sf.split_zero_128.contains(&0));
    assert!(sf.slots.get(&0).is_some_and(|sl| sl.overlapping));
}

#[test]
fn type_facts_covers_plt_import_and_noreturn_and_stack_args() {
    let plt_code: &[u8] = &[0xff, 0x25, 0x10, 0x00, 0x00, 0x00];
    let len1 = u64::try_from(plt_code.len()).unwrap_or(0);
    let f1 = 0x1000..0x1000 + len1;
    let mut img = make_img(plt_code, f1.clone());
    img.imports.push((0x1016, "strlen".to_owned()));

    let rt = RuntimeMap::default();
    let ssa1 = SsaCfg::analyze(&img, &rt, &f1, &default_sig(), &[]);
    let tf1 = TypeFacts::build(&img, &[], &rt, &f1, &default_sig(), &ssa1);
    assert_eq!(tf1.ret_kind, ReturnKind::Single("usize"));

    let nr_code: &[u8] = &[0x0f, 0x0b];
    let len2 = u64::try_from(nr_code.len()).unwrap_or(0);
    let f2 = 0x1040..0x1040 + len2;
    let mut data = vec![0xccu8; 0x1000];
    let off2 = usize::try_from(f2.start.saturating_sub(0x1000)).unwrap_or(0);
    data[off2..off2 + nr_code.len()].copy_from_slice(nr_code);
    let img2 = Image {
        data,
        segments: vec![Segment { va: 0x1000, offset: 0, size: 0x1000 }],
        functions: vec![f2.clone()],
        pointers: Vec::new(),
        imports: Vec::new(),
        symbols: Vec::new(),
        metadata: crate::image_format::Metadata::default(),
    };
    let ssa2 = SsaCfg::analyze(&img2, &rt, &f2, &default_sig(), &[]);
    let mut sig2 = default_sig();
    sig2.regs.push(Register::RDI);
    sig2.stack_args = vec![0, 1];
    let tf2 = TypeFacts::build(&img2, &[], &rt, &f2, &sig2, &ssa2);
    assert_eq!(tf2.ret_kind, ReturnKind::NoReturn);
    assert!(tf2.sig_line.contains("arg_6") && tf2.sig_line.contains("arg_7"));
}

#[test]
fn type_facts_covers_callers_unused_rax() {
    let f_target: &[u8] = &[0xb8, 0x01, 0x00, 0x00, 0x00, 0xc3];
    let f_c1: &[u8] = &[
        0x48, 0x83, 0xec, 0x08, 0xe8, 0xd7, 0xff, 0xff, 0xff, 0xb8, 0x00, 0x00, 0x00, 0x00, 0x48, 0x83, 0xc4, 0x08,
        0xc3,
    ];
    let f_c2: &[u8] = &[0x48, 0x83, 0xec, 0x08, 0xe8, 0xb7, 0xff, 0xff, 0xff, 0x31, 0xc0, 0x48, 0x83, 0xc4, 0x08, 0xc3];
    let mut data = vec![0xccu8; 0x1000];
    data[..f_target.len()].copy_from_slice(f_target);
    data[0x20..0x20 + f_c1.len()].copy_from_slice(f_c1);
    data[0x40..0x40 + f_c2.len()].copy_from_slice(f_c2);
    let r_tgt = 0x1000..0x1000 + u64::try_from(f_target.len()).unwrap_or(0);
    let r_c1 = 0x1020..0x1020 + u64::try_from(f_c1.len()).unwrap_or(0);
    let r_c2 = 0x1040..0x1040 + u64::try_from(f_c2.len()).unwrap_or(0);
    let img = Image {
        data,
        segments: vec![Segment { va: 0x1000, offset: 0, size: 0x1000 }],
        functions: vec![r_tgt.clone(), r_c1, r_c2],
        pointers: Vec::new(),
        imports: Vec::new(),
        symbols: Vec::new(),
        metadata: crate::image_format::Metadata::default(),
    };
    let rt = RuntimeMap::detect(&img);
    let ssa = SsaCfg::analyze(&img, &rt, &r_tgt, &default_sig(), &[]);
    let tf = TypeFacts::build(&img, &[], &rt, &r_tgt, &default_sig(), &ssa);
    assert_eq!(tf.ret_kind, ReturnKind::VoidUnused);
    assert!(tf.header_block.contains("across all 2 direct call sites"));
}

#[test]
fn type_facts_covers_deref_returns_and_indexed_param_store() {
    let bytes_store: &[u8] =
        &[0x85, 0xff, 0x74, 0x05, 0xc6, 0x00, 0x01, 0xc3, 0x90, 0x48, 0xc7, 0x00, 0x01, 0x00, 0x00, 0x00, 0xc3];
    let len_store = u64::try_from(bytes_store.len()).unwrap_or(0);
    let func_store = 0x1000..0x1000 + len_store;
    let img_store = make_img(bytes_store, func_store.clone());
    let rt = RuntimeMap::default();
    let ssa_store = SsaCfg::analyze(&img_store, &rt, &func_store, &default_sig(), &[]);
    let facts_store = TypeFacts::build(&img_store, &[], &rt, &func_store, &default_sig(), &ssa_store);
    assert_eq!(facts_store.ret_kind, ReturnKind::Single("void *"));

    let bytes_base: &[u8] = &[0x85, 0xff, 0x74, 0x05, 0x0f, 0xb6, 0x08, 0xc3, 0x90, 0x48, 0x8b, 0x08, 0xc3];
    let len_base = u64::try_from(bytes_base.len()).unwrap_or(0);
    let func_base = 0x1000..0x1000 + len_base;
    let img_base = make_img(bytes_base, func_base.clone());
    let ssa_base = SsaCfg::analyze(&img_base, &rt, &func_base, &default_sig(), &[]);
    let facts_base = TypeFacts::build(&img_base, &[], &rt, &func_base, &default_sig(), &ssa_base);
    assert_eq!(facts_base.ret_kind, ReturnKind::Single("const void *"));

    let bytes_indexed: &[u8] = &[0x88, 0x04, 0x0f, 0xc3];
    let len_indexed = u64::try_from(bytes_indexed.len()).unwrap_or(0);
    let func_indexed = 0x1000..0x1000 + len_indexed;
    let img_indexed = make_img(bytes_indexed, func_indexed.clone());
    let mut sig_indexed = default_sig();
    sig_indexed.regs.push(Register::RDI);
    let ssa_indexed = SsaCfg::analyze(&img_indexed, &rt, &func_indexed, &sig_indexed, &[]);
    let facts_indexed = TypeFacts::build(&img_indexed, &[], &rt, &func_indexed, &sig_indexed, &ssa_indexed);
    assert!(facts_indexed.header_block.contains("dereferenced by store"));
}

#[test]
fn type_prop_covers_imul_slots_cmp_and_usize_unification() {
    let code: &[u8] = &[
        0x48, 0x6b, 0xc7, 0x28, 0x48, 0x01, 0xf8, 0x48, 0x01, 0xf0, 0x48, 0x83, 0xec, 0x38, 0x88, 0x44, 0x24, 0x01,
        0x66, 0x89, 0x44, 0x24, 0x02, 0x89, 0x44, 0x24, 0x04, 0x0f, 0x29, 0x44, 0x24, 0x10, 0x48, 0x39, 0x44, 0x24,
        0x08, 0xe8, 0x16, 0x00, 0x00, 0x00, 0x48, 0x83, 0xc4, 0x38, 0xc3,
    ];
    let close_stub: &[u8] = &[0xff, 0x25, 0x10, 0x00, 0x00, 0x00];
    let mut data = vec![0xccu8; 0x1000];
    data[..code.len()].copy_from_slice(code);
    data[0x40..0x40 + close_stub.len()].copy_from_slice(close_stub);
    let f1 = 0x1000..0x1000 + u64::try_from(code.len()).unwrap_or(0);
    let f2 = 0x1040..0x1040 + u64::try_from(close_stub.len()).unwrap_or(0);
    let img = Image {
        data,
        segments: vec![Segment { va: 0x1000, offset: 0, size: 0x1000 }],
        functions: vec![f1.clone(), f2],
        pointers: Vec::new(),
        imports: vec![(0x1056, "close".to_owned())],
        symbols: Vec::new(),
        metadata: crate::image_format::Metadata::default(),
    };
    let rt = RuntimeMap::default();
    let mut sig = default_sig();
    sig.regs = vec![Register::RDI, Register::RSI];
    let ssa = SsaCfg::analyze(&img, &rt, &f1, &sig, &[]);
    let lt = LocalTypes::analyze(&img, &[], &rt, &ssa);
    assert!(lt.slot_ty.values().any(|&ty| ty == "u8"));
    assert!(lt.slot_ty.values().any(|&ty| ty == "u16"));
    assert!(lt.slot_ty.values().any(|&ty| ty == "u32"));
    assert!(lt.slot_ty.values().any(|&ty| ty == "u128"));

    let tf = TypeFacts::build(&img, &[], &rt, &f1, &sig, &ssa);
    assert!(tf.header_block.contains("via close param `fd`"));
}

#[test]
fn fields_c_covers_sugar_aliases_comments_and_zero_offset() {
    let code: &[u8] = &[0x48, 0x8b, 0x07, 0x48, 0x8b, 0x57, 0x08, 0xc3];
    let len = u64::try_from(code.len()).unwrap_or(0);
    let func = 0x1000..0x1000 + len;
    let img = make_img(code, func.clone());
    let raw = "\
/* header comment */
* comment line
*/
unk64 fn_1000(void *arg_0) {
  unk64 slot_10; /* [rsp+0x10] addr-taken */
  (v_1, v_2) = call();
  ptr_9 = arg_0;
  v_0 = *(u64 *)(arg_0);
  v_8 = *(u64 *)(ptr_9 + 0x8);
}
";
    let sugared = apply_field_sugar(&img, &func, raw);
    assert!(sugared.contains("arg_0->f_0"));
    assert!(sugared.contains("ptr_9->f_8"));
}

#[test]
fn ssa_inline_and_webs_cover_flag_users_arg_slot_and_oob_graph() {
    let code_flags: &[u8] = &[0x48, 0x8b, 0x47, 0x08, 0x48, 0x83, 0xf8, 0x2a, 0x0f, 0x94, 0xc3, 0x83, 0xc2, 0x01, 0xc3];
    let len_f = u64::try_from(code_flags.len()).unwrap_or(0);
    let f_flags = 0x1000..0x1000 + len_f;
    let img_f = make_img(code_flags, f_flags.clone());
    let rt = RuntimeMap::default();
    let sig = default_sig();
    let ssa_f = SsaCfg::analyze(&img_f, &rt, &f_flags, &sig, &[]);
    assert_ne!(ssa_f.insns.len(), 0);

    let code_slot: &[u8] = &[
        0x48, 0x83, 0xec, 0x18, 0x48, 0x89, 0x7c, 0x24, 0x08, 0x48, 0x8b, 0x5c, 0x24, 0x08, 0x48, 0x8b, 0x43, 0x10,
        0x48, 0x83, 0xc4, 0x18, 0xc3,
    ];
    let len_s = u64::try_from(code_slot.len()).unwrap_or(0);
    let f_slot = 0x1000..0x1000 + len_s;
    let img_s = make_img(code_slot, f_slot.clone());
    let mut sig_s = default_sig();
    sig_s.regs.push(Register::RDI);
    let ssa_s = SsaCfg::analyze(&img_s, &rt, &f_slot, &sig_s, &[]);
    let (fields, _, _) = ssa_s.param_fields(0);
    assert!(fields.contains_key(&0x10));

    let oob_f = 0x9000..0x9010;
    let ssa_oob = SsaCfg::analyze(&img_s, &rt, &oob_f, &sig, &[]);
    assert_eq!(ssa_oob.insns.len(), 0);

    let zero_f = 0x1000..0x1000;
    let ssa_zero = SsaCfg::analyze(&img_s, &rt, &zero_f, &sig, &[]);
    assert_eq!(ssa_zero.insns.len(), 0);
}

#[test]
fn type_null_checked_function_pointer_stays_code_ptr() {
    let mut data = vec![0x90u8; 0x100];
    let code: &[u8] = &[
        0x48, 0x83, 0xff, 0x00, // 0x1000: cmp rdi, 0
        0x76, 0x02, // 0x1004: jbe 0x1008
        0xff, 0xd7, // 0x1006: call rdi
        0xc3, // 0x1008: ret
    ];
    data[..code.len()].copy_from_slice(code);
    let img = Image {
        data,
        segments: vec![Segment { va: 0x1000, offset: 0, size: 0x100 }],
        functions: std::iter::once(0x1000..0x1009).collect(),
        pointers: Vec::new(),
        imports: Vec::new(),
        symbols: vec![(0x1000, "invoke_optional".to_owned())],
        metadata: crate::image_format::Metadata::default(),
    };
    let (_, decompiled) = crate::c::c_one(&img, &[], &RuntimeMap::default(), 0x1000, None, None).unwrap_or_default();
    assert!(decompiled.contains("code_ptr arg_0"), "a compared but called pointer is a code_ptr:\n{decompiled}");
}

#[test]
fn type_jump_table_selector_is_integer_not_code_ptr() {
    let mut data = vec![0x90u8; 0x1000];
    let code: &[u8] = &[
        0x48, 0x8d, 0x41, 0xff, // 0x1000: lea rax, [rcx - 1]
        0x48, 0x83, 0xf8, 0x02, // 0x1004: cmp rax, 2
        0x77, 0x20, // 0x1008: ja +32 (to default at 0x102a)
        0x48, 0x83, 0xe1, 0x01, // 0x100a: and rcx, 1
        0x48, 0x8d, 0x15, 0x2f, 0x00, 0x00,
        0x00, // 0x100e: lea rdx, [rip + 0x2f] -> 0x1015 + 0x2f = 0x1044 (table)
        0x48, 0x63, 0x0c, 0x8a, // 0x1015: movsxd rcx, dword ptr [rdx + rcx*4]
        0x48, 0x01, 0xd1, // 0x1019: add rcx, rdx
        0xff, 0xe1, // 0x101c: jmp rcx
        // arm 0 at 0x101e:
        0xb8, 0x0a, 0x00, 0x00, 0x00, 0xc3, // 0x101e: mov eax, 10; ret
        // arm 1 at 0x1024:
        0xb8, 0x14, 0x00, 0x00, 0x00, 0xc3, // 0x1024: mov eax, 20; ret
        // default at 0x102a:
        0x31, 0xc0, 0xc3, // 0x102a: xor eax, eax; ret
    ];
    let f = 0x1000..0x102d;
    data[..code.len()].copy_from_slice(code);
    // Table at 0x1044:
    let arm0_off = (-38i32).to_le_bytes();
    data[0x44..0x48].copy_from_slice(&arm0_off);
    let arm1_off = (-32i32).to_le_bytes();
    data[0x48..0x4c].copy_from_slice(&arm1_off);
    data[0x4c..0x50].copy_from_slice(&[0, 0, 0, 0]);

    let img = Image {
        data,
        segments: vec![Segment { va: 0x1000, offset: 0, size: 0x1000 }],
        functions: vec![f],
        pointers: Vec::new(),
        imports: Vec::new(),
        symbols: vec![(0x1000, "dispatch_op".to_owned())],
        metadata: crate::image_format::Metadata::default(),
    };
    let rt = RuntimeMap::default();
    let (_, decompiled) = crate::c::c_one(&img, &[], &rt, 0x1000, None, None).unwrap_or_default();
    assert!(decompiled.contains("dispatch_op"), "{decompiled}");
    assert!(!decompiled.contains("code_ptr arg_3"), "{decompiled}");
    assert!(!decompiled.contains("code_ptr — invoked via indirect call/jump"), "{decompiled}");
    assert!(
        decompiled.contains("unk64 arg_3") || decompiled.contains("usize arg_3") || decompiled.contains("u32 arg_3"),
        "{decompiled}"
    );
}
