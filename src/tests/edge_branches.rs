/*
 * xref — Ultra blazing fast cross-references of an x86-64 ELF binary
 * Copyright (c) 2026 Alexander Panasenko
 *
 * Contact: alex@prod.codes
 * Author: https://prod.codes/about/
 * Project: https://github.com/alex09x/xref
 * SPDX-License-Identifier: MIT OR Apache-2.0
 */

//! Targeted branch-closure unit tests across slice, type inference, loop unrotation,
//! goto elimination, ELF dynamic tables, caller tracing, and I/O error propagation.

use std::collections::{BTreeMap, BTreeSet};
use std::io::{self, Write};

use iced_x86::Register;

use crate::c::{c_one, line_idents};
use crate::callee_meta::is_target_noreturn;
use crate::caller_ret::CallerIndex;
use crate::cfg::{Block, Term, structure};
use crate::cli::Command;
use crate::commands::run;
use crate::diffc::diff_c;
use crate::dump::dump_tree;
use crate::fields_c::apply_field_sugar;
use crate::goto_elim::eliminate_forward_gotos;
use crate::image::{Image, Segment};
use crate::layout::{FieldInfo, scan_fn};
use crate::layout_fmt::render_layout;
use crate::runtime::RuntimeMap;
use crate::sig::{FnSig, call_reads_reg, fn_sig};
use crate::slice::slice_rendered_c;
use crate::ssa_webs::SsaCfg;
use crate::type_facts::TypeFacts;
use crate::type_prop::LocalTypes;
use crate::variant::{arms, variants};

struct FailAfterWriter {
    left: usize,
}

impl Write for FailAfterWriter {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        if self.left == 0 {
            return Err(io::Error::other("write fail"));
        }
        self.left -= 1;
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

fn make_img(code: &[u8], func: std::ops::Range<u64>) -> Image {
    let mut data = vec![0xc3u8; code.len().max(0x100)];
    data[..code.len()].copy_from_slice(code);
    let sz = data.len();
    Image {
        data,
        segments: vec![Segment { va: 0x1000, offset: 0, size: sz }],
        functions: vec![func],
        pointers: Vec::new(),
        imports: Vec::new(),
        symbols: Vec::new(),
    }
}

fn build_minimal_dyn_elf() -> Vec<u8> {
    let mut b = vec![0u8; 0x380];
    b[0..8].copy_from_slice(&[0x7f, b'E', b'L', b'F', 2, 1, 1, 0]);
    b[0x10..0x12].copy_from_slice(&3u16.to_le_bytes());
    b[0x12..0x14].copy_from_slice(&62u16.to_le_bytes());
    b[0x14..0x18].copy_from_slice(&1u32.to_le_bytes());
    b[0x18..0x20].copy_from_slice(&0x1000u64.to_le_bytes());
    b[0x20..0x28].copy_from_slice(&0x40u64.to_le_bytes());
    b[0x28..0x30].copy_from_slice(&0x200u64.to_le_bytes());
    b[0x34..0x36].copy_from_slice(&64u16.to_le_bytes());
    b[0x36..0x38].copy_from_slice(&56u16.to_le_bytes());
    b[0x38..0x3a].copy_from_slice(&1u16.to_le_bytes());
    b[0x3a..0x3c].copy_from_slice(&64u16.to_le_bytes());
    b[0x3c..0x3e].copy_from_slice(&6u16.to_le_bytes());
    b[0x3e..0x40].copy_from_slice(&2u16.to_le_bytes());

    b[0x40..0x44].copy_from_slice(&1u32.to_le_bytes());
    b[0x44..0x48].copy_from_slice(&5u32.to_le_bytes());
    b[0x48..0x50].copy_from_slice(&0x80u64.to_le_bytes());
    b[0x50..0x58].copy_from_slice(&0x1000u64.to_le_bytes());
    b[0x58..0x60].copy_from_slice(&0x1000u64.to_le_bytes());
    b[0x60..0x68].copy_from_slice(&0x10u64.to_le_bytes());
    b[0x68..0x70].copy_from_slice(&0x10u64.to_le_bytes());
    b[0x70..0x78].copy_from_slice(&0x1000u64.to_le_bytes());

    b[0x80] = 0xc3;
    let strs = b"\0.text\0.strtab\0.dynsym\0.rela.dyn\0.eh_frame\0exp_fn\0";
    b[0x90..0x90 + strs.len()].copy_from_slice(strs);

    let mut sym = [0u8; 24];
    sym[0..4].copy_from_slice(&43u32.to_le_bytes());
    sym[4] = 0x12;
    sym[6..8].copy_from_slice(&1u16.to_le_bytes());
    sym[8..16].copy_from_slice(&0x1000u64.to_le_bytes());
    sym[16..24].copy_from_slice(&1u64.to_le_bytes());
    b[0xd0 + 24..0xd0 + 48].copy_from_slice(&sym);

    b[0x100..0x108].copy_from_slice(&0x1000u64.to_le_bytes());

    let put_shdr = |buf: &mut [u8],
                    idx: usize,
                    name: u32,
                    ty: u32,
                    flags: u64,
                    addr: u64,
                    off: u64,
                    sz: u64,
                    link: u32,
                    info: u32,
                    ent: u64| {
        let base = 0x200 + idx * 64;
        buf[base..base + 4].copy_from_slice(&name.to_le_bytes());
        buf[base + 4..base + 8].copy_from_slice(&ty.to_le_bytes());
        buf[base + 8..base + 16].copy_from_slice(&flags.to_le_bytes());
        buf[base + 16..base + 24].copy_from_slice(&addr.to_le_bytes());
        buf[base + 24..base + 32].copy_from_slice(&off.to_le_bytes());
        buf[base + 32..base + 40].copy_from_slice(&sz.to_le_bytes());
        buf[base + 40..base + 44].copy_from_slice(&link.to_le_bytes());
        buf[base + 44..base + 48].copy_from_slice(&info.to_le_bytes());
        buf[base + 48..base + 56].copy_from_slice(&8u64.to_le_bytes());
        buf[base + 56..base + 64].copy_from_slice(&ent.to_le_bytes());
    };
    put_shdr(&mut b, 1, 1, 1, 6, 0x1000, 0x80, 1, 0, 0, 0);
    put_shdr(&mut b, 2, 7, 3, 2, 0, 0x90, 50, 0, 0, 0);
    put_shdr(&mut b, 3, 15, 11, 2, 0, 0xd0, 48, 2, 1, 24);
    put_shdr(&mut b, 4, 23, 4, 2, 0, 0x100, 24, 3, 0, 24);
    put_shdr(&mut b, 5, 33, 1, 2, 0x1010, 0x120, 4, 0, 0, 0);
    b
}

#[test]
fn write_errors_propagate_across_commands_diff_dump_layout_and_variants() {
    let mut data = vec![0u8; 0x200];
    let code: &[u8] = &[
        0x48, 0x8d, 0x0d, 0xf9, 0x00, 0x00, 0x00, 0x48, 0x63, 0x04, 0x89, 0xff, 0xe0, 0x48, 0x8d, 0x05, 0x2c, 0x00,
        0x00, 0x00, 0xc3,
    ];
    data[..code.len()].copy_from_slice(code);
    data[0x40..0x4a].copy_from_slice(b"target_err");
    data[0x100..0x104].copy_from_slice(&(-0xf3i32).to_le_bytes());
    data[0x104..0x108].copy_from_slice(&(-0xeci32).to_le_bytes());
    let img = Image {
        data,
        segments: vec![Segment { va: 0x1000, offset: 0, size: 0x200 }],
        functions: std::iter::once(0x1000..0x1015).collect(),
        pointers: vec![(0x1060, 0x1040)],
        imports: vec![(0x1070, "imp".to_owned())],
        symbols: vec![(0x1000, "sym".to_owned())],
    };

    for k in 0..80 {
        let _ = run(&img, Command::Stats, &mut FailAfterWriter { left: k });
        let _ = run(&img, Command::Func { addrs: vec![0x1005, 0x9999] }, &mut FailAfterWriter { left: k });
        let _ = run(&img, Command::Error { text: "target_err".to_owned(), back: 1 }, &mut FailAfterWriter { left: k });
        let _ = variants(&img, 0x1000, &[0, 99], &mut FailAfterWriter { left: k });
        let _ = arms(&img, &[0x100d, 0x1014], &mut FailAfterWriter { left: k });
        let _ = diff_c(&img, &img, &["0x1000".to_owned()], Some("0x1000"), false, &mut FailAfterWriter { left: k });
    }

    let tmp_dir = std::env::temp_dir().join(format!("xref_fail_dump_{}", std::process::id()));
    assert!(dump_tree(&img, &tmp_dir, None, false, &mut FailAfterWriter { left: 0 }).is_err());
    let _ = std::fs::remove_dir_all(&tmp_dir);

    let f_info = FieldInfo { width: 8, ty: "u64", reads: 1, ..FieldInfo::default() };
    let fmap = BTreeMap::from([(8u64, f_info)]);
    let hops = BTreeSet::from([(0i64, 0x1000u64, "rdi")]);
    for k in 0..80 {
        let _ = render_layout(
            &img,
            &(0x1000..0x1015),
            Register::RDI,
            "rdi",
            &fmap,
            &hops,
            &mut FailAfterWriter { left: k },
        );
    }
}

#[test]
fn slice_rendered_c_covers_short_body_labels_gotos_guards_and_comments() {
    let f = 0x1000..0x1080;
    let mut out = Vec::new();
    assert!(slice_rendered_c(&f, "x", &["x".to_owned()], "void fn_1000(void) {\n}\n", &mut out).is_ok());

    let rich = "\
unk64 fn_1000(unk64 arg_0, unk64 arg_1) {
  u64 v_1;

  if (arg_0 == 0) return 0;
  if (arg_1 == 0) {
    early_log();
    return 0;
  }
  L_loop:
  /* fn_2000: compute */
  v_1 = fn_2000(arg_0);
  if (v_1 == 9) goto L_cold;
  if (v_1 == 2) goto L_loop;
  sink_main(v_1);
  return v_1;
  L_cold:
  cold_sink(arg_0);
  return 0;
}
";
    out.clear();
    assert!(slice_rendered_c(&f, "sink_main", &["sink_main".to_owned()], rich, &mut out).is_ok());
    let s_main = String::from_utf8_lossy(&out);
    assert!(s_main.contains("if (arg_1 == 0) {") && s_main.contains("fn_2000: compute"));

    out.clear();
    assert!(slice_rendered_c(&f, "goto l_loop", &["goto l_loop".to_owned()], rich, &mut out).is_ok());
    assert!(String::from_utf8_lossy(&out).contains("L_loop:"));

    out.clear();
    assert!(slice_rendered_c(&f, "cold_sink", &["cold_sink".to_owned()], rich, &mut out).is_ok());
    let s_cold = String::from_utf8_lossy(&out);
    assert!(s_cold.contains("goto L_cold;") && s_cold.contains("return v_1;"));

    let fwd_lbl = "unk64 fn_1000(unk64 arg_0) {\n  v_1 = arg_0;\n  if (v_1 == 1) goto L_fwd;\n  return 0;\n  L_fwd:\n  return 1;\n}\n";
    out.clear();
    assert!(slice_rendered_c(&f, "goto l_fwd", &["goto l_fwd".to_owned()], fwd_lbl, &mut out).is_ok());
    assert!(String::from_utf8_lossy(&out).contains("L_fwd:"));
}

#[test]
fn elf_dynsym_caller_bounds_runtime_noreturn_and_layout_edges() {
    let elf_path = std::env::temp_dir().join(format!("xref_edge_dyn_{}.elf", std::process::id()));
    assert!(std::fs::write(&elf_path, build_minimal_dyn_elf()).is_ok());
    let loaded_res = Image::load(&elf_path);
    let _ = std::fs::remove_file(&elf_path);
    assert!(loaded_res.is_ok());
    if let Ok(loaded) = loaded_res {
        let _idx = CallerIndex::build(&loaded);
    }

    let mut data = vec![0xc3u8; 0x200];
    data[0..5].copy_from_slice(&[0xe8, 0x1b, 0x00, 0x00, 0x00]);
    let img_end_call = Image {
        data: data.clone(),
        segments: vec![Segment { va: 0x1000, offset: 0, size: 0x200 }],
        functions: vec![0x1000..0x1005, 0x1020..0x1021],
        pointers: Vec::new(),
        imports: Vec::new(),
        symbols: Vec::new(),
    };
    let _ = CallerIndex::build(&img_end_call);

    let img_trunc_seg = Image {
        data: vec![0xe8, 0x05, 0x00, 0x00, 0x00, 0x90, 0x90, 0x90, 0x90, 0x90, 0xc3],
        segments: vec![Segment { va: 0x1000, offset: 0, size: 11 }],
        functions: vec![0x1000..0x1030, 0x100a..0x100b],
        pointers: Vec::new(),
        imports: Vec::new(),
        symbols: Vec::new(),
    };
    let _ = CallerIndex::build(&img_trunc_seg);

    let mut rt_data = vec![0xc3u8; 0x200];
    rt_data[0..8].copy_from_slice(&[0x48, 0x8d, 0x3d, 0x79, 0x00, 0x00, 0x00, 0x0f]);
    rt_data[8] = 0x0b;
    rt_data[0x20..0x28].copy_from_slice(&[0x48, 0x8d, 0x3d, 0x99, 0x00, 0x00, 0x00, 0xc3]);
    rt_data[0x80..0x80 + 17].copy_from_slice(b"capacity overflow");
    rt_data[0xc0..0xc0 + 42].copy_from_slice(b"Once instance has previously been poisoned");
    let rt_img = Image {
        data: rt_data,
        segments: vec![Segment { va: 0x1000, offset: 0, size: 0x200 }],
        functions: vec![0x1000..0x1009, 0x1020..0x1028],
        pointers: Vec::new(),
        imports: Vec::new(),
        symbols: Vec::new(),
    };
    let rt = RuntimeMap::detect(&rt_img);
    assert!(is_target_noreturn(&rt_img, &rt, 0x1000));
    assert!(!is_target_noreturn(&rt_img, &rt, 0x1020));

    let lay_code: &[u8] = &[0x48, 0x8d, 0x37, 0x48, 0x83, 0xc7, 0xf8, 0xff, 0xd0, 0xc3];
    let lay_img = make_img(lay_code, 0x1000..0x100a);
    let (mut fields, mut fwd) = (BTreeMap::new(), Vec::new());
    scan_fn(&lay_img, &(0x1000..0x100a), Register::RDI, 0, None, &mut fields, &mut fwd);
}

#[test]
fn c_idents_mem_not_fields_sig_ssa_stack_goto_unrotate_and_types() {
    let not_mem = make_img(&[0xf6, 0x17, 0xc3], 0x1000..0x1003);
    let rt = RuntimeMap::default();
    let (_, c_txt) = c_one(&not_mem, &[], &rt, 0x1000, None, None).unwrap_or_default();
    assert!(c_txt.contains('~'));

    assert!(line_idents("  L\"\\\"x\";").contains("L"));
    assert!(line_idents("  v_0").contains("v_0"));

    let sugar_img = make_img(&[0x48, 0x8b, 0x07, 0x48, 0x8b, 0x57, 0x08, 0xc3], 0x1000..0x1008);
    let no_alias = "unk64 fn_1000(void *arg_0) {\n  v_0 = *(u64 *)(arg_0);\n  v_8 = *(u64 *)(arg_0 + 0x8);\n}\n";
    assert!(apply_field_sugar(&sugar_img, &(0x1000..0x1008), no_alias).contains("arg_0->f_0"));

    let nop_img = make_img(&[0x0f, 0x1f, 0x07, 0xc3], 0x1000..0x1004);
    assert!(!call_reads_reg(&nop_img, &(0x1000..0x1004), 0x1000, Register::RDI));

    let flag_code: &[u8] = &[0x8b, 0x4f, 0x08, 0x83, 0xf9, 0x2a, 0x0f, 0x94, 0xc0, 0x83, 0xc2, 0x01, 0xc3];
    let flag_img = make_img(flag_code, 0x1000..0x100d);
    let _ = SsaCfg::analyze(&flag_img, &rt, &(0x1000..0x100d), &fn_sig(&flag_img, &(0x1000..0x100d)), &[]);

    let sf_code: &[u8] = &[
        0x55, 0x48, 0x89, 0xe5, 0x48, 0x83, 0xec, 0x40, 0xc5, 0xfe, 0x6f, 0x44, 0x24, 0x08, 0x48, 0x8b, 0x45, 0x10,
        0xc9, 0xc3,
    ];
    let sf_img = make_img(sf_code, 0x1000..0x1014);
    let _ = SsaCfg::analyze(&sf_img, &rt, &(0x1000..0x1014), &fn_sig(&sf_img, &(0x1000..0x1014)), &[]);

    for case in [
        vec!["else goto L_90;", "return 0;", "L_90:", "x = 1;", "return x;"],
        vec!["if (a) goto L_90;", "if (b) goto L_90;", "x = 1;", "L_90:"],
        vec!["switch (x) {", "  case 1: goto L_80;", "}", "L_80:", "return;"],
        vec!["while (a) {", "  if (b) goto L_80;", "}", "L_80:", "return;"],
    ] {
        let mut lines: Vec<String> = case.into_iter().map(str::to_owned).collect();
        eliminate_forward_gotos(&mut lines);
    }

    let blocks = vec![
        Block { start: 0x10, stmts: vec!["x = 0;".to_owned()], term: Term::Jump(0x30) },
        Block { start: 0x20, stmts: vec!["x += 1;".to_owned()], term: Term::Fall },
        Block {
            start: 0x30,
            stmts: Vec::new(),
            term: Term::Cond { cond: "c".to_owned(), neg: "!c".to_owned(), target: 0x20 },
        },
        Block { start: 0x40, stmts: vec!["if (d) goto L_30;".to_owned()], term: Term::Return("return 1;".to_owned()) },
        Block { start: 0x50, stmts: Vec::new(), term: Term::Return("return 0;".to_owned()) },
    ];
    assert!(structure(blocks).join("\n").contains("return 1;"));

    let mut_ptr_ret: &[u8] =
        &[0x85, 0xd2, 0x74, 0x07, 0x48, 0x89, 0xf8, 0xc6, 0x00, 0x01, 0xc3, 0x48, 0x89, 0xf0, 0x48, 0x89, 0x08, 0xc3];
    let mp_img = make_img(mut_ptr_ret, 0x1000..0x1012);
    let mp_sig = FnSig {
        regs: vec![Register::RDI, Register::RSI, Register::RDX, Register::RCX, Register::RAX],
        ..fn_sig(&mp_img, &(0x1000..0x1012))
    };
    let mp_ssa = SsaCfg::analyze(&mp_img, &rt, &(0x1000..0x1012), &mp_sig, &[]);
    assert!(TypeFacts::build(&mp_img, &[], &rt, &(0x1000..0x1012), &mp_sig, &mp_ssa).sig_line.starts_with("void *"));

    let cst_ptr_ret: &[u8] =
        &[0x85, 0xd2, 0x74, 0x06, 0x48, 0x89, 0xf8, 0x8a, 0x08, 0xc3, 0x48, 0x89, 0xf0, 0x48, 0x8b, 0x08, 0xc3];
    let cp_img = make_img(cst_ptr_ret, 0x1000..0x1011);
    let cp_sig = fn_sig(&cp_img, &(0x1000..0x1011));
    let cp_ssa = SsaCfg::analyze(&cp_img, &rt, &(0x1000..0x1011), &cp_sig, &[]);
    assert!(
        TypeFacts::build(&cp_img, &[], &rt, &(0x1000..0x1011), &cp_sig, &cp_ssa).sig_line.starts_with("const void *")
    );

    let idx_first: &[u8] =
        &[0x48, 0x0f, 0xaf, 0xca, 0x8b, 0x0c, 0xb7, 0x48, 0x89, 0xd0, 0x48, 0x01, 0xf0, 0x01, 0xc8, 0xc3];
    let first_img = make_img(idx_first, 0x1000..0x1010);
    let first_ssa = SsaCfg::analyze(&first_img, &rt, &(0x1000..0x1010), &fn_sig(&first_img, &(0x1000..0x1010)), &[]);
    assert_eq!(
        LocalTypes::analyze(&first_img, &[], &rt, &first_ssa).web_ty.iter().filter(|&&t| t == "usize").count(),
        4
    );

    let idx_second: &[u8] = &[0x48, 0x01, 0xd6, 0x0f, 0xb6, 0x04, 0xb7, 0xc3];
    let second_img = make_img(idx_second, 0x1000..0x1008);
    let second_ssa = SsaCfg::analyze(&second_img, &rt, &(0x1000..0x1008), &fn_sig(&second_img, &(0x1000..0x1008)), &[]);
    assert_eq!(
        LocalTypes::analyze(&second_img, &[], &rt, &second_ssa).web_ty.iter().filter(|&&t| t == "usize").count(),
        3
    );
}
