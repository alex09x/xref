/*
 * XRef Code — evidence-producing binary analysis
 * Copyright (c) 2026 Alexander Panasenko
 * Contact: alex@prod.codes
 * Author: https://prod.codes/about/
 * Project: https://github.com/alex09x/xref
 * SPDX-License-Identifier: MIT OR Apache-2.0
 */

#![allow(clippy::unwrap_used, clippy::expect_used)]

use super::*;
use crate::api::Cancellation;
use crate::api::context::facts::{solve, Fact, State};
use crate::api::context::flow::Flow;
use crate::api::context::types::Value;
use iced_x86::Instruction;
use std::collections::BTreeSet;

fn decode_bytes(code: &[u8]) -> Vec<Instruction> {
    let mut insns = vec![];
    crate::scan::decode(code, 0x1000, |ins| insns.push(*ins));
    insns
}

fn solve_bytes(code: &[u8]) -> (Vec<Instruction>, Vec<Option<State>>) {
    let mut a = crate::api::tests::fixture();
    a.image.data[..code.len()].copy_from_slice(code);
    a.image.functions[0] = 0x1000..0x1000 + code.len() as u64;
    let function = a.image.functions[0].clone();
    let insns = decode_bytes(code);
    let flow = Flow::new(&insns, &a.image, &function);
    let states = solve(&insns, &flow, &Cancellation::default())
        .expect("solve ok")
        .expect("within budget");
    (insns, states)
}

#[test]
fn field_origin_lea_field_address_vs_mov_loaded_value() {
    // 0x1000: lea rax, [rdi + 0x10]  (48 8d 47 10)
    // 0x1004: mov rdx, [rdi + 0x10]  (48 8b 57 10)
    // 0x1008: mov rcx, [rdx + 0x08]  (48 8b 4a 08)
    // 0x100c: mov esi, [rdi + 0x20]  (8b 77 20)
    // 0x100f: ret                    (c3)
    let code = [
        0x48, 0x8d, 0x47, 0x10,
        0x48, 0x8b, 0x57, 0x10,
        0x48, 0x8b, 0x4a, 0x08,
        0x8b, 0x77, 0x20,
        0xc3,
    ];
    let (_insns, states) = solve_bytes(&code);
    let s1 = states[1].as_ref().unwrap();
    assert_eq!(s1[0].origin, Some(Origin::Address { register: 7, displacement: 16 }));
    assert_eq!(s1[0].value, Value::Unknown);

    let s2 = states[2].as_ref().unwrap();
    assert_eq!(s2[2].origin, Some(Origin::Loaded { register: 7, displacement: 16, width: 8, load_ip: 0x1004 }));
    assert_eq!(s2[2].value, Value::Unknown);

    let s3 = states[3].as_ref().unwrap();
    // Do not follow pointers loaded from a field as if they were the original base
    assert_eq!(s3[1].origin, None);

    let s4 = states[4].as_ref().unwrap();
    assert_eq!(s4[6].origin, Some(Origin::Loaded { register: 7, displacement: 32, width: 4, load_ip: 0x100c }));
    assert_eq!(s4[6].value, Value::Unknown);
}

#[test]
fn field_origin_copied_base_offset_to_arguments() {
    // 0x1000: lea rax, [rdi + 0x18]  (48 8d 47 18)
    // 0x1004: mov rsi, rax           (48 89 c6)
    // 0x1007: add rsi, 0x08          (48 83 c6 08)
    // 0x100b: sub rsi, 0x04          (48 83 ee 04)
    // 0x100f: mov rdx, [rsi + 0x04]  (48 8b 56 04)
    // 0x1013: mov r8, rdx            (49 89 d0)
    // 0x1016: ret                    (c3)
    let code = [
        0x48, 0x8d, 0x47, 0x18,
        0x48, 0x89, 0xc6,
        0x48, 0x83, 0xc6, 0x08,
        0x48, 0x83, 0xee, 0x04,
        0x48, 0x8b, 0x56, 0x04,
        0x49, 0x89, 0xd0,
        0xc3,
    ];
    let (_insns, states) = solve_bytes(&code);
    let s2 = states[2].as_ref().unwrap();
    assert_eq!(s2[6].origin, Some(Origin::Address { register: 7, displacement: 24 }));

    let s3 = states[3].as_ref().unwrap();
    assert_eq!(s3[6].origin, Some(Origin::Address { register: 7, displacement: 32 }));

    let s4 = states[4].as_ref().unwrap();
    assert_eq!(s4[6].origin, Some(Origin::Address { register: 7, displacement: 28 }));

    let s5 = states[5].as_ref().unwrap();
    assert_eq!(s5[2].origin, Some(Origin::Loaded { register: 7, displacement: 32, width: 8, load_ip: 0x100f }));

    let s6 = states[6].as_ref().unwrap();
    assert_eq!(s6[8].origin, Some(Origin::Loaded { register: 7, displacement: 32, width: 8, load_ip: 0x100f }));
}

#[test]
fn field_origin_overwritten_base() {
    // 0x1000: mov rsi, rdi                  (48 89 fe)
    // 0x1003: mov rdi, 0x2a                 (48 c7 c7 2a 00 00 00)
    // 0x100a: lea rax, [rsi + 0x10]         (48 8d 46 10)
    // 0x100e: lea rbx, [rdi + 0x10]         (48 8d 5f 10)
    // 0x1012: mov rcx, [rdi + 0x08]         (48 8b 4f 08)
    // 0x1016: ret                           (c3)
    let code = [
        0x48, 0x89, 0xfe,
        0x48, 0xc7, 0xc7, 0x2a, 0x00, 0x00, 0x00,
        0x48, 0x8d, 0x46, 0x10,
        0x48, 0x8d, 0x5f, 0x10,
        0x48, 0x8b, 0x4f, 0x08,
        0xc3,
    ];
    let (_insns, states) = solve_bytes(&code);
    let s2 = states[2].as_ref().unwrap();
    assert_eq!(s2[7].origin, None);
    assert_eq!(s2[6].origin, Some(Origin::Address { register: 7, displacement: 0 }));

    let s3 = states[3].as_ref().unwrap();
    assert_eq!(s3[0].origin, Some(Origin::Address { register: 7, displacement: 16 }));

    let s4 = states[4].as_ref().unwrap();
    assert_eq!(s4[3].origin, None);

    let s5 = states[5].as_ref().unwrap();
    assert_eq!(s5[1].origin, None);
}

#[test]
fn field_origin_joins_with_differing_or_missing_origins() {
    // 0x1000: test edi, edi                 (85 ff)
    // 0x1002: jz 0x100a                     (74 06)
    // 0x1004: lea rax, [rdi + 0x10]         (48 8d 47 10)
    // 0x1008: jmp 0x100e                    (eb 04)
    // 0x100a: lea rax, [rdi + 0x20]         (48 8d 47 20)
    // 0x100e: ret                           (c3)
    let code_diff = [
        0x85, 0xff,
        0x74, 0x06,
        0x48, 0x8d, 0x47, 0x10,
        0xeb, 0x04,
        0x48, 0x8d, 0x47, 0x20,
        0xc3,
    ];
    let (_insns, states) = solve_bytes(&code_diff);
    let join_state = states[5].as_ref().unwrap();
    assert_eq!(join_state[0].origin, None);

    // Agreeing origin preserved at join:
    // 0x1000: lea rax, [rdi + 0x10]         (48 8d 47 10)
    // 0x1004: test edi, edi                 (85 ff)
    // 0x1006: jz 0x1011                     (74 09)
    // 0x1008: mov ebx, 1                    (bb 01 00 00 00)
    // 0x100d: jmp 0x1016                    (eb 07)
    // 0x100f: nop                           (90 90)
    // 0x1011: mov ebx, 2                    (bb 02 00 00 00)
    // 0x1016: ret                           (c3)
    let code_agree = [
        0x48, 0x8d, 0x47, 0x10,
        0x85, 0xff,
        0x74, 0x09,
        0xbb, 0x01, 0x00, 0x00, 0x00,
        0xeb, 0x07,
        0x90, 0x90,
        0xbb, 0x02, 0x00, 0x00, 0x00,
        0xc3,
    ];
    let (insns_agree, states_agree) = solve_bytes(&code_agree);
    let ret_idx = insns_agree.iter().position(|i| i.ip() == 0x1016).unwrap();
    let agree_state = states_agree[ret_idx].as_ref().unwrap();
    assert_eq!(agree_state[0].origin, Some(Origin::Address { register: 7, displacement: 16 }));

    // Loaded at different IPs -> differing load_ip -> None at join:
    // 0x1000: test edi, edi                 (85 ff)
    // 0x1002: jz 0x100a                     (74 06)
    // 0x1004: mov rax, [rdi + 0x10]         (48 8b 47 10)
    // 0x1008: jmp 0x100e                    (eb 04)
    // 0x100a: mov rax, [rdi + 0x10]         (48 8b 47 10)
    // 0x100e: ret                           (c3)
    let code_loaded = [
        0x85, 0xff,
        0x74, 0x06,
        0x48, 0x8b, 0x47, 0x10,
        0xeb, 0x04,
        0x48, 0x8b, 0x47, 0x10,
        0xc3,
    ];
    let (_insns, states_loaded) = solve_bytes(&code_loaded);
    let join_loaded = states_loaded[5].as_ref().unwrap();
    assert_eq!(join_loaded[0].origin, None);
}

#[test]
fn field_origin_volatile_clobber_vs_callee_saved_preservation() {
    // 0x1000: lea rax, [rdi + 0x08]         (48 8d 47 08)
    // 0x1004: lea r12, [rdi + 0x10]         (4c 8d 67 10)
    // 0x1008: lea rbx, [rdi + 0x18]         (48 8d 5f 18)
    // 0x100c: call 0x1100                   (e8 ef 00 00 00)
    // 0x1011: ret                           (c3)
    let code = [
        0x48, 0x8d, 0x47, 0x08,
        0x4c, 0x8d, 0x67, 0x10,
        0x48, 0x8d, 0x5f, 0x18,
        0xe8, 0xef, 0x00, 0x00, 0x00,
        0xc3,
    ];
    let (_insns, states) = solve_bytes(&code);
    let at_call_state = states[3].as_ref().unwrap();
    assert_eq!(at_call_state[0].origin, Some(Origin::Address { register: 7, displacement: 8 }));
    assert_eq!(at_call_state[12].origin, Some(Origin::Address { register: 7, displacement: 16 }));
    assert_eq!(at_call_state[3].origin, Some(Origin::Address { register: 7, displacement: 24 }));

    let after_call = states[4].as_ref().unwrap();
    assert_eq!(after_call[0].origin, None);
    assert_eq!(after_call[6].origin, None);
    assert_eq!(after_call[7].origin, None);
    assert_eq!(after_call[12].origin, Some(Origin::Address { register: 7, displacement: 16 }));
    assert_eq!(after_call[3].origin, Some(Origin::Address { register: 7, displacement: 24 }));
}

#[test]
fn field_origin_rejection_fs_gs_address_size32_and_dynamic_index() {
    let mut initial_state: State = std::array::from_fn(|i| Fact {
        value: Value::EntryRegister { register: crate::api::context::facts::NAMES[i] },
        origin: if i == 4 { None } else { Some(Origin::Address { register: i, displacement: 0 }) },
        defs: BTreeSet::new(),
        truncated: false,
    });
    initial_state[1].origin = Some(Origin::Address { register: 1, displacement: 0 });

    // FS segment override: mov rax, fs:[rdi + 8] (64 48 8b 47 08)
    let ins = decode_bytes(&[0x64, 0x48, 0x8b, 0x47, 0x08]);
    assert_eq!(memory_origin(&ins[0], &initial_state), None);
    assert_eq!(derive(&ins[0], &initial_state), None);

    // GS segment override: mov rax, gs:[rdi + 8] (65 48 8b 47 08)
    let ins = decode_bytes(&[0x65, 0x48, 0x8b, 0x47, 0x08]);
    assert_eq!(memory_origin(&ins[0], &initial_state), None);
    assert_eq!(derive(&ins[0], &initial_state), None);

    // Address-size 32 prefix: mov rax, [edi + 8] (67 48 8b 47 08)
    let ins = decode_bytes(&[0x67, 0x48, 0x8b, 0x47, 0x08]);
    assert_eq!(memory_origin(&ins[0], &initial_state), None);
    assert_eq!(derive(&ins[0], &initial_state), None);

    // Address-size 32 prefix on LEA: lea rax, [edi + 8] (67 48 8d 47 08)
    let ins = decode_bytes(&[0x67, 0x48, 0x8d, 0x47, 0x08]);
    assert_eq!(memory_origin(&ins[0], &initial_state), None);
    assert_eq!(derive(&ins[0], &initial_state), None);

    // Dynamic index: mov rax, [rdi + rcx*8] (48 8b 04 cf)
    let ins = decode_bytes(&[0x48, 0x8b, 0x04, 0xcf]);
    assert_eq!(memory_origin(&ins[0], &initial_state), None);
    assert_eq!(derive(&ins[0], &initial_state), None);

    // Dynamic index: mov rax, [rdi + rcx] (48 8b 04 0f)
    let ins = decode_bytes(&[0x48, 0x8b, 0x04, 0x0f]);
    assert_eq!(memory_origin(&ins[0], &initial_state), None);
    assert_eq!(derive(&ins[0], &initial_state), None);
}

#[test]
fn field_origin_partial_gpr_write_and_loaded_arithmetic() {
    // 0x1000: mov rax, [rdi + 0x08]         (48 8b 47 08)
    // 0x1004: add rax, 0x01                 (48 83 c0 01)
    // 0x1008: lea rsi, [rdi + 0x08]         (48 8d 77 08)
    // 0x100c: mov sil, 0x01                 (40 b6 01)
    // 0x100f: lea rdx, [rdi + 0x08]         (48 8d 57 08)
    // 0x1013: mov edx, 0x01                 (ba 01 00 00 00)
    // 0x1018: ret                           (c3)
    let code = [
        0x48, 0x8b, 0x47, 0x08,
        0x48, 0x83, 0xc0, 0x01,
        0x48, 0x8d, 0x77, 0x08,
        0x40, 0xb6, 0x01,
        0x48, 0x8d, 0x57, 0x08,
        0xba, 0x01, 0x00, 0x00, 0x00,
        0xc3,
    ];
    let (_insns, states) = solve_bytes(&code);
    let s1 = states[1].as_ref().unwrap();
    assert_eq!(s1[0].origin, Some(Origin::Loaded { register: 7, displacement: 8, width: 8, load_ip: 0x1000 }));

    // Loaded + arithmetic -> becomes unknown (None origin)
    let s2 = states[2].as_ref().unwrap();
    assert_eq!(s2[0].origin, None);

    let s3 = states[3].as_ref().unwrap();
    assert_eq!(s3[6].origin, Some(Origin::Address { register: 7, displacement: 8 }));

    // Subword write clobbers origin
    let s4 = states[4].as_ref().unwrap();
    assert_eq!(s4[6].origin, None);

    let s5 = states[5].as_ref().unwrap();
    assert_eq!(s5[2].origin, Some(Origin::Address { register: 7, displacement: 8 }));

    // Partial register write clobbers origin
    let s6 = states[6].as_ref().unwrap();
    assert_eq!(s6[2].origin, None);
}

#[test]
fn field_origin_signed_offset_overflow() {
    let mut state: State = std::array::from_fn(|_| Fact {
        value: Value::Unknown,
        origin: None,
        defs: BTreeSet::new(),
        truncated: false,
    });
    // RDI base with maximum displacement
    state[7] = Fact {
        value: Value::Unknown,
        origin: Some(Origin::Address { register: 7, displacement: i64::MAX }),
        defs: BTreeSet::new(),
        truncated: false,
    };
    // lea rax, [rdi + 1] -> overflow
    let ins = decode_bytes(&[0x48, 0x8d, 0x47, 0x01]);
    assert_eq!(memory_origin(&ins[0], &state), None);
    assert_eq!(derive(&ins[0], &state), None);

    // add rdi, 1 -> overflow
    let ins = decode_bytes(&[0x48, 0x83, 0xc7, 0x01]);
    assert_eq!(derive(&ins[0], &state), None);

    // RDI base with minimum displacement
    state[7].origin = Some(Origin::Address { register: 7, displacement: i64::MIN });
    // sub rdi, 1 -> overflow
    let ins = decode_bytes(&[0x48, 0x83, 0xef, 0x01]);
    assert_eq!(derive(&ins[0], &state), None);

    // Valid negative displacements
    state[7].origin = Some(Origin::Address { register: 7, displacement: 10 });
    // sub rdi, 20 -> 10 - 20 = -10
    let ins = decode_bytes(&[0x48, 0x83, 0xef, 0x14]);
    assert_eq!(derive(&ins[0], &state), Some((Origin::Address { register: 7, displacement: -10 }, 7)));

    // lea rax, [rdi - 20] -> 10 + (-20) = -10
    let ins = decode_bytes(&[0x48, 0x8d, 0x47, 0xec]);
    assert_eq!(memory_origin(&ins[0], &state), Some((Origin::Address { register: 7, displacement: -10 }, 7)));
}

#[test]
fn field_origin_definition_provenance_and_truncation_cap() {
    // Chain:
    // 0: lea rax, [rdi + 8]   (48 8d 47 08)
    // 1: mov rsi, rax         (48 89 c6)
    // 2: add rsi, 8           (48 83 c6 08)
    // 3: add rsi, 8           (48 83 c6 08)
    // 4: add rsi, 8           (48 83 c6 08)
    // 5: add rsi, 8           (48 83 c6 08)
    // 6: add rsi, 8           (48 83 c6 08)
    // 7: add rsi, 8           (48 83 c6 08)
    // 8: add rsi, 8           (48 83 c6 08)
    // 9: add rsi, 8           (48 83 c6 08)
    // 10: ret                 (c3)
    let mut code = vec![0x48, 0x8d, 0x47, 0x08, 0x48, 0x89, 0xc6];
    for _ in 0..8 {
        code.extend_from_slice(&[0x48, 0x83, 0xc6, 0x08]);
    }
    code.push(0xc3);

    let (_insns, states) = solve_bytes(&code);
    let s1 = states[1].as_ref().unwrap();
    assert_eq!(s1[0].defs, BTreeSet::from([0]));
    assert!(!s1[0].truncated);

    let s2 = states[2].as_ref().unwrap();
    assert_eq!(s2[6].defs, BTreeSet::from([0, 1]));
    assert!(!s2[6].truncated);

    let s9 = states[9].as_ref().unwrap();
    // At state 9 (after 9 operations 0..=8): defs capped at 8, truncated true
    assert_eq!(s9[6].defs.len(), 8);
    assert!(s9[6].truncated);
    // Current instruction (8) must be recorded
    assert!(s9[6].defs.contains(&8));
}
