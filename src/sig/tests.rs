/*
 * xref — Ultra blazing fast cross-references of an x86-64 ELF binary
 * Copyright (c) 2026 Alexander Panasenko
 *
 * Contact: alex@prod.codes
 * Author: https://prod.codes/about/
 * Project: https://github.com/alex09x/xref
 * SPDX-License-Identifier: MIT OR Apache-2.0
 */

use super::{call_reads_rdx, fn_sig, has_frame_pointer, import_arity};
use crate::image::{Image, Segment};
use iced_x86::Register;

#[test]
fn recovers_branched_params_stack_args_thunks_imports_and_rdx_returns() {
    let mut data = vec![0u8; 0x500];
    let f1: &[u8] = &[
        0xf3, 0x0f, 0x1e, 0xfa, 0x53, 0x48, 0x83, 0xec, 0x10, 0x31, 0xc0, 0x83, 0xff, 0x01, 0x74, 0x09, 0x48, 0x8b,
        0x44, 0x24, 0x20, 0x48, 0x01, 0xf0, 0xc3, 0x48, 0x89, 0xd0, 0xe9, 0xdf, 0x00, 0x00, 0x00,
    ];
    data[..f1.len()].copy_from_slice(f1);
    let f2: &[u8] =
        &[0x55, 0x48, 0x89, 0xe5, 0x48, 0x8b, 0x45, 0x10, 0x48, 0x01, 0xc8, 0x5d, 0xe9, 0xef, 0x01, 0x00, 0x00];
    data[0x100..0x100 + f2.len()].copy_from_slice(f2);
    let f3: &[u8] = &[0xa8, 0x01, 0x75, 0x04, 0x48, 0x89, 0xfa, 0xc3, 0x48, 0x39, 0xf2, 0xc3];
    data[0x200..0x200 + f3.len()].copy_from_slice(f3);
    data[0x240..0x243].copy_from_slice(&[0x31, 0xd2, 0xc3]);
    data[0x300..0x306].copy_from_slice(&[0xff, 0x25, 0xfa, 0x00, 0x00, 0x00]);
    data[0x320..0x322].copy_from_slice(&[0xff, 0xe0]);
    data[0x340..0x342].copy_from_slice(&[0xeb, 0x3e]);
    // 0x1360: push rbp; mov rbp, rsp; call 0x1300 (plt memcpy, 3 args); ud2 -> noreturn wrapper!
    let f_wrap: &[u8] = &[0x55, 0x48, 0x89, 0xe5, 0xe8, 0x97, 0xff, 0xff, 0xff, 0x0f, 0x0b];
    data[0x360..0x360 + f_wrap.len()].copy_from_slice(f_wrap);

    let r1 = 0x1000..0x1000 + f1.len() as u64;
    let r2 = 0x1100..0x1100 + f2.len() as u64;
    let r3 = 0x1200..0x1200 + f3.len() as u64;
    let rw = 0x1360..0x1360 + f_wrap.len() as u64;
    let image = Image {
        data,
        segments: vec![Segment { va: 0x1000, offset: 0, size: 0x500 }],
        functions: vec![r1.clone(), r2.clone(), r3.clone(), 0x1240..0x1243, 0x1320..0x1322, 0x1340..0x1342, rw.clone()],
        pointers: Vec::new(),
        imports: vec![(0x1400, "memcpy".to_owned())],
        symbols: Vec::new(),
        metadata: crate::image_format::Metadata::default(),
    };
    let (s1, s2, sw) = (fn_sig(&image, &r1), fn_sig(&image, &r2), fn_sig(&image, &rw));
    let four = vec![Register::RDI, Register::RSI, Register::RDX, Register::RCX];
    assert_eq!((&s1.regs, &s1.stack_args, s1.arg_base_rsp), (&four, &vec![0], Some(0x20)));
    assert!(s1.exact && !s1.uses_fp && s2.uses_fp && has_frame_pointer(f2, 0x1100));
    assert_eq!((&s2.regs, &s2.stack_args), (&four, &vec![0]));
    assert_eq!((sw.regs, sw.exact), (vec![Register::RDI, Register::RSI, Register::RDX], true));
    assert!(!fn_sig(&image, &(0x1320..0x1322)).exact);
    assert!(!fn_sig(&image, &(0x1340..0x1342)).exact);
    assert!(!fn_sig(&image, &(0x9000..0x9010)).exact);
    assert_eq!(import_arity("memcpy@GLIBC_2.14"), Some(3));
    assert_eq!((import_arity("free"), import_arity("calloc")), (Some(1), Some(2)));
    assert_eq!((import_arity("abort"), import_arity("custom_sym")), (Some(0), None));
    assert!(call_reads_rdx(&image, &r3, 0x1208) && call_reads_rdx(&image, &r3, 0x1200));
    assert!(!call_reads_rdx(&image, &r3, 0x1204) && !call_reads_rdx(&image, &(0x1240..0x1243), 0x1240));
    assert!(!call_reads_rdx(&image, &(0x1240..0x1243), 0x1243));
}
