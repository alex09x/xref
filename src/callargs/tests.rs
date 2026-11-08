/*
 * XRef — Tests for constant call arguments
 * Copyright (c) 2026 Alexander Panasenko
 * Contact: alex@prod.codes
 * Author: https://prod.codes/about/
 * Project: https://github.com/alex09x/xref
 * SPDX-License-Identifier: MIT OR Apache-2.0
 */

use super::forward::arg_stores;
use super::scan::{Slot, calls};
use super::{CallArgsOptions, callargs};
use crate::image::{Image, Segment};

/// - 0x1000 `caller`: `mov r9d, 0x27; xor edi, edi; mov dword [rsp], 7; call 0x1100;
///   mov esi, 5; call 0x1100; ret` (the first call clobbers r9 and the stack slot);
/// - 0x1100 `callee`: `ret`;
/// - 0x1200 `store`: `mov byte [rdi], sil; ret`;
/// - 0x1300 `forward`: `mov esi, r9d; jmp 0x1200`.
fn image() -> Image {
    let mut data = vec![0xcc; 0x310];
    let caller: &[u8] = &[
        0x41, 0xb9, 0x27, 0x00, 0x00, 0x00, 0x31, 0xff, 0xc7, 0x04, 0x24, 0x07, 0x00, 0x00, 0x00, 0xe8, 0xec, 0x00,
        0x00, 0x00, 0xbe, 0x05, 0x00, 0x00, 0x00, 0xe8, 0xe2, 0x00, 0x00, 0x00, 0xc3,
    ];
    data[..caller.len()].copy_from_slice(caller);
    data[0x100] = 0xc3;
    data[0x200..0x204].copy_from_slice(&[0x40, 0x88, 0x37, 0xc3]);
    data[0x300..0x308].copy_from_slice(&[0x44, 0x89, 0xce, 0xe9, 0xf8, 0xfe, 0xff, 0xff]);
    Image {
        segments: vec![Segment { va: 0x1000, offset: 0, size: data.len() }],
        data,
        functions: vec![0x1000..0x101f, 0x1100..0x1101, 0x1200..0x1204, 0x1300..0x1308],
        pointers: Vec::new(),
        imports: Vec::new(),
        symbols: Vec::new(),
        metadata: crate::image_format::Metadata::default(),
    }
}

#[test]
fn slots_parse_and_print_as_abi_names() {
    assert_eq!(Slot::parse("r9"), Ok(Slot::Reg(5)));
    assert_eq!(Slot::parse("stack3"), Ok(Slot::Stack(3)));
    assert!(Slot::parse("stack8").is_err());
    assert!(Slot::parse("rax").is_err());
    assert_eq!(Slot::Reg(0).to_string(), "rdi");
    assert_eq!(Slot::Stack(1).to_string(), "stack1");
}

#[test]
fn constants_reach_the_call_until_a_call_clobbers_them() {
    let found = calls(&image(), &|callee, _| callee == 0x1100);
    let args: Vec<_> = found.iter().map(|call| (call.ip, call.args.clone())).collect();
    assert_eq!(
        args,
        vec![
            (0x100f, vec![(Slot::Reg(0), 0), (Slot::Reg(5), 0x27), (Slot::Stack(0), 7)]),
            (0x1019, vec![(Slot::Reg(1), 5)]),
        ]
    );
}

#[test]
fn callargs_lists_only_the_call_passing_the_value_and_names_the_callee() -> Result<(), Box<dyn std::error::Error>> {
    let mut out = Vec::new();
    let options = CallArgsOptions { value: 0x27, slot: Some(Slot::Reg(5)), callee: None, limit: 10 };
    callargs(&image(), &options, &mut out)?;
    let text = String::from_utf8(out)?;
    assert!(text.contains("callee 0x1100  r9: 1 of 2 call sites pass 0x27; constants there: 0x27 ×1"), "{text}");
    assert!(text.contains("  0x100f  in 0x1000..0x101f  call  rdi=0x0  r9=0x27  stack0=0x7"), "{text}");
    assert!(!text.contains("0x1019"), "{text}");
    Ok(())
}

#[test]
fn an_argument_is_followed_into_its_store_and_one_call_on() {
    let image = image();
    let direct = arg_stores(&image, 0x1200, Slot::Reg(1), 1, false);
    assert_eq!(direct.len(), 1);
    assert!(direct[0].at_object_offset(0));
    let forwarded = arg_stores(&image, 0x1300, Slot::Reg(5), 1, true);
    assert_eq!(
        forwarded.iter().map(|s| (s.ip, s.via)).collect::<Vec<_>>(),
        vec![(0x1200, Some((0x1200, Slot::Reg(1))))]
    );
    assert!(arg_stores(&image, 0x1300, Slot::Reg(5), 1, false).is_empty(), "the store is only one call deeper");
}
