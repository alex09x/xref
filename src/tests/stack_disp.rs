/*
 * xref — Ultra blazing fast cross-references of an x86-64 ELF binary
 * Copyright (c) 2026 Alexander Panasenko
 *
 * Contact: alex@prod.codes
 * Author: https://prod.codes/about/
 * Project: https://github.com/alex09x/xref
 * SPDX-License-Identifier: MIT OR Apache-2.0
 */

//! Unit tests covering opt-in stack displacement search and filtering.

use iced_x86::Register;

use crate::disp::{self, DispOptions};
use crate::image::{Image, Segment};
use crate::scan;

fn make_image(functions: Vec<std::ops::Range<u64>>, segments: Vec<(u64, Vec<u8>)>) -> Image {
    let mut data = Vec::new();
    let mut segs = Vec::new();
    for (va, bytes) in segments {
        let offset = data.len();
        data.extend_from_slice(&bytes);
        segs.push(Segment { va, offset, size: bytes.len() });
    }
    Image { data, segments: segs, functions, pointers: Vec::new(), imports: Vec::new(), symbols: Vec::new() }
}

#[test]
fn rsp_positive_offset_and_raw_disp() {
    // mov eax, [rsp+0x18]; mov [rsp+0x28], eax; ret
    let code = [
        0x8b, 0x44, 0x24, 0x18, // 0x1000: mov eax, [rsp+0x18]
        0x89, 0x44, 0x24, 0x28, // 0x1004: mov [rsp+0x28], eax
        0xc3, // 0x1008: ret
    ];
    let f = 0x1000..0x1000 + code.len() as u64;
    let image = make_image(vec![f.clone()], vec![(0x1000, code.to_vec())]);

    let no_stack = disp::search(&image, std::slice::from_ref(&f), &[0x18, 0x28], DispOptions::default());
    assert!(no_stack.is_empty(), "RSP must be excluded by default");

    let legacy = scan::search_disp(&image, std::slice::from_ref(&f), &[0x18, 0x28], false, false, None);
    assert!(legacy.is_empty(), "legacy search_disp must delegate with stack=false");

    let opts = DispOptions { stack: true, ..Default::default() };
    let hits = disp::search(&image, &[f], &[0x18, 0x28], opts);
    assert_eq!(hits.len(), 2);
    assert_eq!(hits[0].offset, 0x18);
    assert_eq!(hits[0].base, Register::RSP);
    assert!(hits[0].hit.text.ends_with("; stack"), "{}", hits[0].hit.text);
    assert_eq!(hits[1].offset, 0x28);
    assert_eq!(hits[1].base, Register::RSP);
    assert!(hits[1].hit.text.ends_with("; stack"), "{}", hits[1].hit.text);
}

#[test]
fn negative_rbp_frame_offset_with_frame_pointer() {
    // push rbp; mov rbp, rsp; mov eax, [rbp-0x18]; mov [rbp-0x20], eax; ret
    let code = [
        0x55, // 0x1000: push rbp
        0x48, 0x89, 0xe5, // 0x1001: mov rbp, rsp
        0x8b, 0x45, 0xe8, // 0x1004: mov eax, [rbp-0x18]
        0x89, 0x45, 0xe0, // 0x1007: mov [rbp-0x20], eax
        0xc3, // 0x100a: ret
    ];
    let f = 0x1000..0x1000 + code.len() as u64;
    let image = make_image(vec![f.clone()], vec![(0x1000, code.to_vec())]);

    let off_18 = (-0x18i64).cast_unsigned();
    let off_20 = (-0x20i64).cast_unsigned();

    let no_stack = disp::search(&image, std::slice::from_ref(&f), &[off_18, off_20], DispOptions::default());
    assert!(no_stack.is_empty(), "frame RBP must be excluded when stack=false");

    let legacy = scan::search_disp(&image, std::slice::from_ref(&f), &[off_18, off_20], false, false, None);
    assert!(legacy.is_empty());

    let opts = DispOptions { stack: true, ..Default::default() };
    let hits = disp::search(&image, &[f], &[off_18, off_20], opts);
    assert_eq!(hits.len(), 2);
    assert_eq!(hits[0].offset, off_18);
    assert_eq!(hits[0].base, Register::RBP);
    assert!(hits[0].hit.text.ends_with("; stack"), "{}", hits[0].hit.text);
    assert_eq!(hits[1].offset, off_20);
    assert_eq!(hits[1].base, Register::RBP);
    assert!(hits[1].hit.text.ends_with("; stack"), "{}", hits[1].hit.text);
}

#[test]
fn frameless_rbp_retained_by_default() {
    // push rbx; mov eax, [rbp+0x30]; ret (no mov rbp, rsp in prologue)
    let code = [
        0x53, // 0x1000: push rbx
        0x8b, 0x45, 0x30, // 0x1001: mov eax, [rbp+0x30]
        0xc3, // 0x1004: ret
    ];
    let f = 0x1000..0x1000 + code.len() as u64;
    let image = make_image(vec![f.clone()], vec![(0x1000, code.to_vec())]);

    let default_hits = disp::search(&image, std::slice::from_ref(&f), &[0x30], DispOptions::default());
    assert_eq!(default_hits.len(), 1, "non-frame RBP retained by default");
    assert_eq!(default_hits[0].offset, 0x30);
    assert_eq!(default_hits[0].base, Register::RBP);
    assert!(!default_hits[0].hit.text.contains("; stack"));

    let legacy = scan::search_disp(&image, std::slice::from_ref(&f), &[0x30], false, false, None);
    assert_eq!(legacy.len(), 1);

    let stack_hits = disp::search(&image, &[f], &[0x30], DispOptions { stack: true, ..Default::default() });
    assert_eq!(stack_hits.len(), 1);
    assert!(!stack_hits[0].hit.text.contains("; stack"), "frameless RBP remains ordinary base");
}

#[test]
fn non_stack_hits_unaffected() {
    // mov eax, [rbx+0x38]; mov [rdx+0x38], eax; ret
    let code = [
        0x8b, 0x43, 0x38, // 0x1000: mov eax, [rbx+0x38]
        0x89, 0x42, 0x38, // 0x1003: mov [rdx+0x38], eax
        0xc3, // 0x1006: ret
    ];
    let f = 0x1000..0x1000 + code.len() as u64;
    let image = make_image(vec![f.clone()], vec![(0x1000, code.to_vec())]);

    let off_no_stack = disp::search(&image, std::slice::from_ref(&f), &[0x38], DispOptions::default());
    let off_stack = disp::search(&image, &[f], &[0x38], DispOptions { stack: true, ..Default::default() });
    assert_eq!(off_no_stack.len(), 2);
    assert_eq!(off_stack.len(), 2);
    for h in &off_stack {
        assert!(!h.hit.text.contains("; stack"));
    }
}

#[test]
fn read_write_lea_filters_and_cmp_test() {
    // 0x1000: mov eax, [rsp+0x20]         (load)
    // 0x1004: cmp dword ptr [rsp+0x20], 1 (cmp read)
    // 0x1009: test [rsp+0x20], eax        (test read)
    // 0x100d: mov [rsp+0x20], eax         (store write)
    // 0x1011: lea rax, [rsp+0x20]         (lea)
    // 0x1016: ret
    let code = [
        0x8b, 0x44, 0x24, 0x20, // load
        0x83, 0x7c, 0x24, 0x20, 0x01, // cmp
        0x85, 0x44, 0x24, 0x20, // test
        0x89, 0x44, 0x24, 0x20, // store
        0x48, 0x8d, 0x44, 0x24, 0x20, // lea
        0xc3,
    ];
    let f = 0x1000..0x1000 + code.len() as u64;
    let image = make_image(vec![f.clone()], vec![(0x1000, code.to_vec())]);

    // write=false, lea=false: all 5 accesses
    let all =
        disp::search(&image, std::slice::from_ref(&f), &[0x20], DispOptions { stack: true, ..Default::default() });
    assert_eq!(all.len(), 5);

    // write=true, lea=false: only actual stores (CMP and TEST are reads, not writes)
    let writes = disp::search(
        &image,
        std::slice::from_ref(&f),
        &[0x20],
        DispOptions { write: true, lea: false, stack: true, stride: None },
    );
    assert_eq!(writes.len(), 1, "only store must match write=true");
    assert_eq!(writes[0].hit.ip, 0x100d);

    // write=false, lea=true: only LEA
    let leas = disp::search(
        &image,
        std::slice::from_ref(&f),
        &[0x20],
        DispOptions { write: false, lea: true, stack: true, stride: None },
    );
    assert_eq!(leas.len(), 1, "only LEA must match lea=true");
    assert_eq!(leas[0].hit.ip, 0x1011);

    // write=true, lea=true: union of stores and LEAs
    let union = disp::search(
        &image,
        std::slice::from_ref(&f),
        &[0x20],
        DispOptions { write: true, lea: true, stack: true, stride: None },
    );
    assert_eq!(union.len(), 2, "write+lea is union of stores and address formation");
    assert_eq!(union[0].hit.ip, 0x100d);
    assert_eq!(union[1].hit.ip, 0x1011);

    // Verify Query::Disp on heap base also rejects cmp/test as stores
    let rbx_cmp = [
        0x83, 0x7b, 0x20, 0x01, // 0x2000: cmp dword ptr [rbx+0x20], 1
        0x85, 0x43, 0x20, // 0x2004: test [rbx+0x20], eax
        0x89, 0x43, 0x20, // 0x2007: mov [rbx+0x20], eax
        0xc3,
    ];
    let f2 = 0x2000..0x2000 + rbx_cmp.len() as u64;
    let img2 = make_image(vec![f2.clone()], vec![(0x2000, rbx_cmp.to_vec())]);
    let rbx_writes =
        disp::search(&img2, &[f2], &[0x20], DispOptions { write: true, lea: false, stack: false, stride: None });
    assert_eq!(rbx_writes.len(), 1);
    assert_eq!(rbx_writes[0].hit.ip, 0x2007);
}

#[test]
fn stride_and_multiple_functions_sorted_unique() {
    // fn1 at 0x1000: mov rax, [rdx + rcx*8 + 0x10]; ret
    let code1 = [0x48, 0x8b, 0x44, 0xca, 0x10, 0xc3];
    // fn2 at 0x2000: mov rax, [rdx + rcx*4 + 0x10]; mov rax, [rdx + rcx*8 + 0x10]; ret
    let code2 = [
        0x48, 0x8b, 0x44, 0x8a, 0x10, // scale 4
        0x48, 0x8b, 0x44, 0xca, 0x10, // scale 8
        0xc3,
    ];
    let f1 = 0x1000..0x1000 + code1.len() as u64;
    let f2 = 0x2000..0x2000 + code2.len() as u64;
    let image = make_image(vec![f1.clone(), f2.clone()], vec![(0x1000, code1.to_vec()), (0x2000, code2.to_vec())]);

    // Pass functions in reverse order to ensure sorting
    let all = disp::search(&image, &[f2.clone(), f1.clone()], &[0x10], DispOptions::default());
    assert_eq!(all.len(), 3);
    assert_eq!(all[0].hit.ip, 0x1000);
    assert_eq!(all[1].hit.ip, 0x2000);
    assert_eq!(all[2].hit.ip, 0x2005);

    // Filter by stride 8
    let s8 = disp::search(&image, &[f2, f1.clone()], &[0x10], DispOptions { stride: Some(8), ..Default::default() });
    assert_eq!(s8.len(), 2);
    assert_eq!(s8[0].hit.ip, 0x1000);
    assert_eq!(s8[1].hit.ip, 0x2005);

    // Deduplication check: duplicate input function
    let dedup = disp::search(&image, &[f1.clone(), f1], &[0x10], DispOptions::default());
    assert_eq!(dedup.len(), 1);
}

#[test]
fn rip_and_absolute_memory_excluded() {
    // lea rax, [rip+0x10]; mov eax, [0x10]; ret
    let code = [
        0x48, 0x8d, 0x05, 0x10, 0x00, 0x00, 0x00, // rip-relative
        0x8b, 0x04, 0x25, 0x10, 0x00, 0x00, 0x00, // absolute
        0xc3,
    ];
    let f = 0x1000..0x1000 + code.len() as u64;
    let image = make_image(vec![f.clone()], vec![(0x1000, code.to_vec())]);

    let hits = disp::search(&image, &[f], &[0x10], DispOptions { stack: true, ..Default::default() });
    assert!(hits.is_empty(), "RIP-relative and absolute memory must be excluded");
}

#[test]
fn empty_and_missing_code_functions() {
    let image = make_image(Vec::new(), Vec::new());
    // Missing segment
    let f_missing = 0x8000..0x8020;
    let hits = disp::search(&image, &[f_missing], &[0x10], DispOptions::default());
    assert!(hits.is_empty());

    // Empty range
    let f_empty = 0x1000..0x1000;
    let hits_empty = disp::search(&image, &[f_empty], &[0x10], DispOptions::default());
    assert!(hits_empty.is_empty());
}
