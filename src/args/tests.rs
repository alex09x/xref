/*
 * XRef — Unit tests for call-site argument recovery and filter preflight
 * Copyright (c) 2026 Alexander Panasenko
 * Contact: alex@prod.codes
 * Author: https://prod.codes/about/
 * Project: https://github.com/alex09x/xref
 * SPDX-License-Identifier: MIT OR Apache-2.0
 */

#![allow(clippy::unwrap_used, clippy::expect_used)]

use super::args;
use super::preflight::{SiteVerdict, filter_preflight};
use crate::image::{Image, Segment};

#[test]
fn recovers_register_and_stack_arguments_at_call_sites() {
    let mut data = vec![0xc3u8; 0x400];
    // Caller 1 at 0x1000: xor r8d, r8d; push 0; push r12; mov ecx, 1; call 0x1200; ret
    let c1: &[u8] = &[
        0x74, 0x00, // je +0 (local branch target leader)
        0x45, 0x31, 0xc0, // xor r8d, r8d
        0x6a, 0x00, // push 0
        0x41, 0x54, // push r12
        0xb9, 0x01, 0x00, 0x00, 0x00, // mov ecx, 1
        0xe8, 0xed, 0x01, 0x00, 0x00, // call 0x1200
        0xc3,
    ];
    data[..c1.len()].copy_from_slice(c1);

    // Caller 2 at 0x1040: prologue sub rsp, cmp/sete/setne/setg, mov [rsp+N], lea rip/rsp/reg, call helper, call 0x1200
    let c2: &[u8] = &[
        0x55, // push rbp
        0x48, 0x83, 0xec, 0x20, // sub rsp, 0x20 (clears prologue push)
        0x80, 0xfb, 0x03, // cmp bl, 3
        0x0f, 0x94, 0xc0, // sete al
        0x89, 0x04, 0x24, // mov [rsp], eax
        0x48, 0xc7, 0x44, 0x24, 0x08, 0x20, 0x00, 0x00, 0x00, // mov qword ptr [rsp+8], 0x20
        0xe8, 0xa4, 0x01, 0x00, 0x00, // call 0x1200 (first call)
        0x48, 0x85, 0xff, // test rdi, rdi
        0x0f, 0x95, 0xc2, // setne dl
        0x0f, 0x9f, 0xc1, // setg cl
        0x48, 0x8d, 0x3d, 0x94, 0x02, 0x00, 0x00, // lea rdi, [rip+0x294] -> 0x1300
        0x48, 0x8d, 0x35, 0xa8, 0x02, 0x00, 0x00, // lea rsi, [rip+0x2a8] -> 0x131b -> 0x1340 "hello"
        0x4c, 0x8d, 0x44, 0x24, 0x10, // lea r8, [rsp+0x10]
        0x4c, 0x8d, 0x4b, 0x08, // lea r9, [rbx+8]
        0x48, 0x83, 0xc1, 0x05, // add rcx, 5 (invalidates rcx)
        0x48, 0x8b, 0x05, 0xa9, 0x02, 0x00, 0x00, // mov rax, [rip+0x2a9] -> 0x1330 (unmapped)
        0x48, 0x8b, 0x13, // mov rdx, [rbx] (mem dynamic)
        0x89, 0x1c, 0x24, // mov [rsp], ebx
        0xe8, 0x6e, 0x01, 0x00, 0x00, // call 0x1200 (second call)
        0xc3,
    ];
    data[0x40..0x40 + c2.len()].copy_from_slice(c2);

    // Panic location at 0x1300 -> "src/arg.rs":12:3
    data[0x308..0x310].copy_from_slice(&10u64.to_le_bytes());
    data[0x310..0x314].copy_from_slice(&12u32.to_le_bytes());
    data[0x314..0x318].copy_from_slice(&3u32.to_le_bytes());
    data[0x320..0x32a].copy_from_slice(b"src/arg.rs");
    data[0x340..0x345].copy_from_slice(b"hello");

    let image = Image {
        data,
        segments: vec![Segment { va: 0x1000, offset: 0, size: 0x400 }],
        functions: vec![0x1000..0x1000 + c1.len() as u64, 0x1040..0x1040 + c2.len() as u64, 0x1200..0x1201],
        pointers: vec![(0x1300, 0x1320), (0x131b, 0x1340)],
        imports: Vec::new(),
        symbols: vec![(0x1200, "target_fn".to_owned())],
        metadata: crate::image_format::Metadata::default(),
    };

    let mut out = Vec::new();
    assert!(args(&image, "target_fn", 4, None, &mut out).is_ok());
    let text = String::from_utf8_lossy(&out);
    assert!(text.contains("rcx=1  r8=0  stack0=r12 (dynamic)  stack1=0"), "{text}");
    assert!(text.contains("stack0=rbx==3  stack1=0x20"), "{text}");
    assert!(text.contains("rdi=0x1300 (src/arg.rs:12:3)  rsi=0x1340 (\"hello\")"), "{text}");
    assert!(text.contains("r8=&rsp[0x10] (dynamic)  r9=r9 (dynamic)"), "{text}");
}

#[test]
fn recovers_register_copy_resolution_and_byte_load_from_argument() {
    let mut data = vec![0xc3u8; 0x400];

    // Caller 1 at 0x1000: mov rdx, rbx; call 0x1200; ret
    let c1: &[u8] = &[
        0x48, 0x89, 0xda, // mov rdx, rbx
        0xe8, 0xf8, 0x01, 0x00, 0x00, // call 0x1200
        0xc3,
    ];
    data[..c1.len()].copy_from_slice(c1);

    // Caller 2 at 0x1020: movzx edx, byte ptr [rsi + 0x3d]; call 0x1200; ret
    let c2: &[u8] = &[
        0x0f, 0xb6, 0x56, 0x3d, // movzx edx, byte ptr [rsi+0x3d]
        0xe8, 0xd7, 0x01, 0x00, 0x00, // call 0x1200
        0xc3,
    ];
    data[0x20..0x20 + c2.len()].copy_from_slice(c2);

    // Caller 3 at 0x1040: mov rdx, rbx; and rdx, 1; call 0x1200; ret
    let c3: &[u8] = &[
        0x48, 0x89, 0xda, // mov rdx, rbx
        0x48, 0x83, 0xe2, 0x01, // and rdx, 1
        0xe8, 0xb4, 0x01, 0x00, 0x00, // call 0x1200
        0xc3,
    ];
    data[0x40..0x40 + c3.len()].copy_from_slice(c3);

    let image = Image {
        data,
        segments: vec![Segment { va: 0x1000, offset: 0, size: 0x400 }],
        functions: vec![
            0x1000..0x1000 + c1.len() as u64,
            0x1020..0x1020 + c2.len() as u64,
            0x1040..0x1040 + c3.len() as u64,
            0x1200..0x1201,
        ],
        pointers: Vec::new(),
        imports: Vec::new(),
        symbols: vec![(0x1200, "target_fn".to_owned())],
        metadata: crate::image_format::Metadata::default(),
    };

    let mut out = Vec::new();
    assert!(args(&image, "target_fn", 4, None, &mut out).is_ok());
    let text = String::from_utf8_lossy(&out);
    assert!(text.contains("rdx=rbx"), "expected register copy rdx=rbx in {text}");
    assert!(text.contains("rdx=u8 [arg2+0x3d]"), "expected byte load rdx=u8 [arg2+0x3d] in {text}");
    assert!(text.contains("rdx=rbx & 1"), "expected dynamic mask rdx=rbx & 1 in {text}");
}

#[test]
fn register_clobbered_by_an_earlier_call_is_not_an_incoming_argument() {
    let mut data = vec![0xc3u8; 0x400];
    // Caller at 0x1000: call 0x1100; mov rdx, rsi; call 0x1200; ret
    let caller: &[u8] = &[
        0xe8, 0xfb, 0x00, 0x00, 0x00, // call 0x1100 (clobbers rsi)
        0x48, 0x89, 0xf2, // mov rdx, rsi
        0xe8, 0xf3, 0x01, 0x00, 0x00, // call 0x1200
        0xc3,
    ];
    data[..caller.len()].copy_from_slice(caller);
    let image = Image {
        data,
        segments: vec![Segment { va: 0x1000, offset: 0, size: 0x400 }],
        functions: vec![0x1000..0x1000 + caller.len() as u64, 0x1100..0x1101, 0x1200..0x1201],
        pointers: Vec::new(),
        imports: Vec::new(),
        symbols: vec![(0x1200, "target_fn".to_owned())],
        metadata: crate::image_format::Metadata::default(),
    };
    let mut out = Vec::new();
    assert!(args(&image, "target_fn", 4, None, &mut out).is_ok());
    let text = String::from_utf8_lossy(&out);
    assert!(!text.contains("arg2"), "rsi after a call is not the caller's second argument: {text}");
    assert!(text.contains("rdx=rsi"), "{text}");
}

#[test]
fn filter_preflight_constant_flags_unsatisfiable_at_all_sites() {
    let mut data = vec![0xc3u8; 0x400];

    // Caller 1 at 0x1000: mov edx, 1; call 0x1200; ret
    let c1: &[u8] = &[
        0xba, 0x01, 0x00, 0x00, 0x00, // mov edx, 1
        0xe8, 0xf6, 0x01, 0x00, 0x00, // call 0x1200
        0xc3,
    ];
    data[..c1.len()].copy_from_slice(c1);

    // Caller 2 at 0x1020: mov edx, 0x20; call 0x1200; ret
    let c2: &[u8] = &[
        0xba, 0x20, 0x00, 0x00, 0x00, // mov edx, 0x20
        0xe8, 0xd6, 0x01, 0x00, 0x00, // call 0x1200
        0xc3,
    ];
    data[0x20..0x20 + c2.len()].copy_from_slice(c2);

    let image = Image {
        data,
        segments: vec![Segment { va: 0x1000, offset: 0, size: 0x400 }],
        functions: vec![0x1000..0x1000 + c1.len() as u64, 0x1020..0x1020 + c2.len() as u64, 0x1200..0x1201],
        pointers: Vec::new(),
        imports: Vec::new(),
        symbols: vec![(0x1200, "target_fn".to_owned())],
        metadata: crate::image_format::Metadata::default(),
    };

    let preflight = filter_preflight(&image, 0x1200, "rdx == 0").expect("preflight parses");
    assert_eq!(preflight.sites.len(), 2);
    assert_eq!(preflight.sites[0].verdict, SiteVerdict::Unsatisfiable);
    assert_eq!(preflight.sites[1].verdict, SiteVerdict::Unsatisfiable);
    assert!(preflight.unsatisfiable_at_all_sites);

    let mut out = Vec::new();
    assert!(args(&image, "target_fn", 4, Some("rdx == 0"), &mut out).is_ok());
    let text = String::from_utf8_lossy(&out);
    assert!(text.contains("unsatisfiable at all 2 call sites"), "{text}");
}

#[test]
fn filter_preflight_never_proves_loads_partial_writes_or_signed_conditions() {
    let mut data = vec![0xc3u8; 0x400];
    // Caller 1 at 0x1000: mov rdi, [rip+0x2f9] (load from 0x1300); call 0x1200; ret
    let c1: &[u8] = &[0x48, 0x8b, 0x3d, 0xf9, 0x02, 0x00, 0x00, 0xe8, 0xf4, 0x01, 0x00, 0x00, 0xc3];
    data[..c1.len()].copy_from_slice(c1);
    // Caller 2 at 0x1020: mov edi, 0x100; xor dil, dil (rdi stays 0x100); call 0x1200; ret
    let c2: &[u8] = &[0xbf, 0x00, 0x01, 0x00, 0x00, 0x40, 0x30, 0xff, 0xe8, 0xd3, 0x01, 0x00, 0x00, 0xc3];
    data[0x20..0x20 + c2.len()].copy_from_slice(c2);
    let image = Image {
        data,
        segments: vec![Segment { va: 0x1000, offset: 0, size: 0x400 }],
        functions: vec![0x1000..0x1000 + c1.len() as u64, 0x1020..0x1020 + c2.len() as u64, 0x1200..0x1201],
        pointers: Vec::new(),
        imports: Vec::new(),
        symbols: vec![(0x1200, "target_fn".to_owned())],
        metadata: crate::image_format::Metadata::default(),
    };
    // The global at 0x1300 may hold zero, so the load is not the address 0x1300.
    let load = filter_preflight(&image, 0x1200, "rdi == 0").expect("preflight parses");
    assert_eq!(load.sites[0].verdict, SiteVerdict::Unknown, "{:?}", load.sites[0]);
    // xor dil, dil only clears the low byte: rdi is 0x100 and `rdi != 0` holds.
    let partial = filter_preflight(&image, 0x1200, "rdi != 0").expect("preflight parses");
    assert_eq!(partial.sites[1].verdict, SiteVerdict::Unknown, "{:?}", partial.sites[1]);
    assert!(!partial.unsatisfiable_at_all_sites);
    // Signed predicates need the comparison width; they are never evaluated on raw u64.
    assert_eq!(super::resolve::evaluate_cc(iced_x86::ConditionCode::g, u64::MAX, 0), None);
    assert_eq!(super::resolve::evaluate_cc(iced_x86::ConditionCode::a, u64::MAX, 0), Some(true));
}

#[test]
fn setcc_after_a_non_compare_flag_writer_is_not_the_compare_result() {
    let mut data = vec![0xc3u8; 0x400];
    let caller: &[u8] = &[
        0xbf, 0x01, 0x00, 0x00, 0x00, // mov edi, 1
        0x83, 0xff, 0x01, // cmp edi, 1
        0xb8, 0x01, 0x00, 0x00, 0x00, // mov eax, 1
        0x83, 0xc0, 0x01, // add eax, 1 (flags now from the add)
        0x40, 0x0f, 0x94, 0xc7, // sete dil
        0x40, 0x0f, 0xb6, 0xff, // movzx edi, dil
        0xe8, 0xe3, 0x01, 0x00, 0x00, // call 0x1200
        0xc3,
    ];
    data[..caller.len()].copy_from_slice(caller);
    let image = Image {
        data,
        segments: vec![Segment { va: 0x1000, offset: 0, size: 0x400 }],
        functions: vec![0x1000..0x1000 + caller.len() as u64, 0x1200..0x1201],
        pointers: Vec::new(),
        imports: Vec::new(),
        symbols: vec![(0x1200, "target_fn".to_owned())],
        metadata: crate::image_format::Metadata::default(),
    };
    let mut out = Vec::new();
    assert!(args(&image, "target_fn", 4, None, &mut out).is_ok());
    let text = String::from_utf8_lossy(&out);
    assert!(!text.contains("1==1"), "sete reads the add's flags, not the cmp: {text}");
}

#[test]
fn cmov_is_not_treated_as_a_comparison_result() {
    let mut data = vec![0xc3u8; 0x400];
    let caller: &[u8] = &[
        0x48, 0xc7, 0xc7, 0x2a, 0x00, 0x00, 0x00, // mov rdi, 42
        0x48, 0xc7, 0xc0, 0x63, 0x00, 0x00, 0x00, // mov rax, 99
        0x31, 0xc9, // xor ecx, ecx
        0x83, 0xf9, 0x00, // cmp ecx, 0
        0x48, 0x0f, 0x44, 0xf8, // cmove rdi, rax (rdi = 99)
        0xe8, 0xe4, 0x01, 0x00, 0x00, // call 0x1200
        0xc3,
    ];
    data[..caller.len()].copy_from_slice(caller);
    let image = Image {
        data,
        segments: vec![Segment { va: 0x1000, offset: 0, size: 0x400 }],
        functions: vec![0x1000..0x1000 + caller.len() as u64, 0x1200..0x1201],
        pointers: Vec::new(),
        imports: Vec::new(),
        symbols: vec![(0x1200, "target_fn".to_owned())],
        metadata: crate::image_format::Metadata::default(),
    };
    let preflight = filter_preflight(&image, 0x1200, "rdi == 99").expect("preflight parses");
    assert_ne!(preflight.sites[0].verdict, SiteVerdict::Unsatisfiable, "{:?}", preflight.sites[0]);
    let mut out = Vec::new();
    assert!(args(&image, "target_fn", 4, None, &mut out).is_ok());
    assert!(!String::from_utf8_lossy(&out).contains("0==0"), "cmove is not a boolean of the compare");
}

#[test]
fn long_register_copy_ladders_are_bounded_not_recursed() {
    let mut data = vec![0xc3u8; 0x8000];
    // 1500 x (mov rdi, rax; mov rax, rdi), then call 0x7f00; ret
    let mut caller = Vec::new();
    for _ in 0..1500 {
        caller.extend([0x48, 0x89, 0xc7, 0x48, 0x89, 0xf8]);
    }
    let call_end = 0x1000 + i64::try_from(caller.len()).unwrap_or_default() + 5;
    let rel = i32::try_from(0x7f00_i64 - call_end).unwrap_or_default();
    caller.push(0xe8);
    caller.extend(rel.to_le_bytes());
    caller.push(0xc3);
    data[..caller.len()].copy_from_slice(&caller);
    let image = Image {
        data,
        segments: vec![Segment { va: 0x1000, offset: 0, size: 0x8000 }],
        functions: vec![0x1000..0x1000 + caller.len() as u64, 0x7f00..0x7f01],
        pointers: Vec::new(),
        imports: Vec::new(),
        symbols: vec![(0x7f00, "target_fn".to_owned())],
        metadata: crate::image_format::Metadata::default(),
    };
    let preflight = filter_preflight(&image, 0x7f00, "rdi == 0").expect("no stack overflow");
    assert_eq!(preflight.sites.len(), 1);
    assert_eq!(preflight.sites[0].verdict, SiteVerdict::Unknown);
}

#[test]
fn filter_preflight_with_unknown_site_is_not_unsatisfiable_at_all_sites() {
    let mut data = vec![0xc3u8; 0x400];

    // Caller 1 at 0x1000: mov edx, 1; call 0x1200; ret
    let c1: &[u8] = &[
        0xba, 0x01, 0x00, 0x00, 0x00, // mov edx, 1
        0xe8, 0xf6, 0x01, 0x00, 0x00, // call 0x1200
        0xc3,
    ];
    data[..c1.len()].copy_from_slice(c1);

    // Caller 2 at 0x1020: movzx edx, byte ptr [rsi + 0x3d]; call 0x1200; ret (unknown at compile-time)
    let c2: &[u8] = &[
        0x0f, 0xb6, 0x56, 0x3d, // movzx edx, byte ptr [rsi+0x3d]
        0xe8, 0xd7, 0x01, 0x00, 0x00, // call 0x1200
        0xc3,
    ];
    data[0x20..0x20 + c2.len()].copy_from_slice(c2);

    let image = Image {
        data,
        segments: vec![Segment { va: 0x1000, offset: 0, size: 0x400 }],
        functions: vec![0x1000..0x1000 + c1.len() as u64, 0x1020..0x1020 + c2.len() as u64, 0x1200..0x1201],
        pointers: Vec::new(),
        imports: Vec::new(),
        symbols: vec![(0x1200, "target_fn".to_owned())],
        metadata: crate::image_format::Metadata::default(),
    };

    let preflight = filter_preflight(&image, 0x1200, "rdx == 0").expect("preflight parses");
    assert_eq!(preflight.sites.len(), 2);
    assert_eq!(preflight.sites[0].verdict, SiteVerdict::Unsatisfiable);
    assert_eq!(preflight.sites[1].verdict, SiteVerdict::Unknown);
    assert!(!preflight.unsatisfiable_at_all_sites);

    let mut out = Vec::new();
    assert!(args(&image, "target_fn", 4, Some("rdx == 0"), &mut out).is_ok());
    let text = String::from_utf8_lossy(&out);
    assert!(text.contains("unknown"), "{text}");
    assert!(text.contains("2 call sites (1 unsatisfiable, 0 satisfiable, 1 unknown)"), "{text}");
}

#[test]
fn filter_preflight_rejects_invalid_filter_syntax() {
    let image = Image {
        data: vec![0xc3; 0x10],
        segments: vec![Segment { va: 0x1000, offset: 0, size: 0x10 }],
        functions: vec![std::ops::Range { start: 0x1000, end: 0x1001 }],
        pointers: Vec::new(),
        imports: Vec::new(),
        symbols: Vec::new(),
        metadata: crate::image_format::Metadata::default(),
    };

    assert!(filter_preflight(&image, 0x1000, "rdx == -1").is_err());
    assert!(filter_preflight(&image, 0x1000, "rdx == 0x").is_err());
    assert!(filter_preflight(&image, 0x1000, "not_a_valid_filter").is_err());
}
