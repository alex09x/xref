/*
 * XRef Code — evidence-producing binary analysis
 * Copyright (c) 2026 Alexander Panasenko
 * Contact: alex@prod.codes
 * Author: https://prod.codes/about/
 * Project: https://github.com/alex09x/xref
 * SPDX-License-Identifier: MIT OR Apache-2.0
 */
use super::*;
use crate::api::{
    Cancellation,
    context::{
        facts::{Fact, NAMES, State, solve},
        flow::Flow,
        types::Value,
    },
};
use std::collections::BTreeSet;
type Error = Box<dyn std::error::Error>;
type Solved = (Vec<Instruction>, Vec<Option<State>>);

fn decode(code: &[u8]) -> Vec<Instruction> {
    let mut insns = vec![];
    crate::scan::decode(code, 0x1000, |ins| insns.push(*ins));
    insns
}
fn solve_bytes(code: &[u8]) -> Result<Solved, Error> {
    let mut a = crate::api::tests::fixture();
    a.image.data[..code.len()].copy_from_slice(code);
    let function = 0x1000..0x1000 + code.len() as u64;
    let insns = decode(code);
    let flow = Flow::new(&insns, &a.image, &function);
    let states = solve(&insns, &flow, &Cancellation::default())?.ok_or("dataflow budget")?;
    Ok((insns, states))
}
fn state_at(states: &[Option<State>], i: usize) -> Result<&State, Error> {
    states.get(i).and_then(Option::as_ref).ok_or_else(|| "unreachable test instruction".into())
}
fn instruction(bytes: &[u8]) -> Result<Instruction, Error> {
    decode(bytes).first().copied().ok_or_else(|| "instruction".into())
}
fn initial() -> State {
    std::array::from_fn(|i| Fact {
        value: Value::EntryRegister { register: NAMES[i] },
        origin: if i == 4 { None } else { Some(Origin::Address { register: i, displacement: 0 }) },
        defs: BTreeSet::new(),
        truncated: false,
    })
}
#[test]
fn field_origin_lea_field_address_vs_mov_loaded_value() -> Result<(), Error> {
    let (_, s) =
        solve_bytes(&[0x48, 0x8d, 0x47, 0x10, 0x48, 0x8b, 0x57, 0x10, 0x48, 0x8b, 0x4a, 8, 0x8b, 0x77, 0x20, 0xc3])?;
    assert_eq!(state_at(&s, 1)?[0].origin, Some(Origin::Address { register: 7, displacement: 16 }));
    assert_eq!(state_at(&s, 1)?[0].value, Value::Unknown);
    assert_eq!(
        state_at(&s, 2)?[2].origin,
        Some(Origin::Loaded { register: 7, displacement: 16, width: 8, load_ip: 0x1004 })
    );
    assert_eq!(state_at(&s, 2)?[2].value, Value::Unknown);
    assert_eq!(state_at(&s, 3)?[1].origin, None); // A loaded pointer is not the original base.
    assert_eq!(
        state_at(&s, 4)?[6].origin,
        Some(Origin::Loaded { register: 7, displacement: 32, width: 4, load_ip: 0x100c })
    );
    Ok(())
}
#[test]
fn field_origin_copied_base_offset_to_arguments() -> Result<(), Error> {
    let (_, s) = solve_bytes(&[
        0x48, 0x8d, 0x47, 0x18, 0x48, 0x89, 0xc6, 0x48, 0x83, 0xc6, 8, 0x48, 0x83, 0xee, 4, 0x48, 0x8b, 0x56, 4, 0x49,
        0x89, 0xd0, 0xc3,
    ])?;
    for (i, displacement) in [(2, 24), (3, 32), (4, 28)] {
        assert_eq!(state_at(&s, i)?[6].origin, Some(Origin::Address { register: 7, displacement }));
    }
    let loaded = Some(Origin::Loaded { register: 7, displacement: 32, width: 8, load_ip: 0x100f });
    assert_eq!(state_at(&s, 5)?[2].origin, loaded);
    assert_eq!(state_at(&s, 6)?[8].origin, loaded);
    Ok(())
}
#[test]
fn field_origin_overwritten_base() -> Result<(), Error> {
    let (_, s) = solve_bytes(&[
        0x48, 0x89, 0xfe, 0x48, 0xc7, 0xc7, 42, 0, 0, 0, 0x48, 0x8d, 0x46, 0x10, 0x48, 0x8d, 0x5f, 0x10, 0x48, 0x8b,
        0x4f, 8, 0xc3,
    ])?;
    assert_eq!(state_at(&s, 2)?[7].origin, None);
    assert_eq!(state_at(&s, 2)?[6].origin, Some(Origin::Address { register: 7, displacement: 0 }));
    assert_eq!(state_at(&s, 3)?[0].origin, Some(Origin::Address { register: 7, displacement: 16 }));
    assert_eq!(state_at(&s, 4)?[3].origin, None);
    assert_eq!(state_at(&s, 5)?[1].origin, None);
    Ok(())
}
#[test]
fn field_origin_joins_with_differing_or_missing_origins() -> Result<(), Error> {
    let (_, s) = solve_bytes(&[0x85, 0xff, 0x74, 6, 0x48, 0x8d, 0x47, 0x10, 0xeb, 4, 0x48, 0x8d, 0x47, 0x20, 0xc3])?;
    assert_eq!(state_at(&s, 5)?[0].origin, None);
    let (_, s) = solve_bytes(&[0x85, 0xc9, 0x74, 6, 0x48, 0x8d, 0x47, 0x10, 0xeb, 2, 0x31, 0xc0, 0xc3])?;
    assert_eq!(state_at(&s, 5)?[0].origin, None);
    let (insns, s) = solve_bytes(&[
        0x48, 0x8d, 0x47, 0x10, 0x85, 0xff, 0x74, 9, 0xbb, 1, 0, 0, 0, 0xeb, 7, 0x90, 0x90, 0xbb, 2, 0, 0, 0, 0xc3,
    ])?;
    let ret = insns.iter().position(|i| i.ip() == 0x1016).ok_or("ret")?;
    assert_eq!(state_at(&s, ret)?[0].origin, Some(Origin::Address { register: 7, displacement: 16 }));
    let (_, s) = solve_bytes(&[0x85, 0xff, 0x74, 6, 0x48, 0x8b, 0x47, 0x10, 0xeb, 4, 0x48, 0x8b, 0x47, 0x10, 0xc3])?;
    assert_eq!(state_at(&s, 5)?[0].origin, None); // Distinct load sites cannot be conflated.
    Ok(())
}
#[test]
fn field_origin_volatile_clobber_vs_callee_saved_preservation() -> Result<(), Error> {
    let (_, s) =
        solve_bytes(&[0x48, 0x8d, 0x47, 8, 0x4c, 0x8d, 0x67, 0x10, 0x48, 0x8d, 0x5f, 0x18, 0xe8, 0xef, 0, 0, 0, 0xc3])?;
    assert_eq!(state_at(&s, 3)?[0].origin, Some(Origin::Address { register: 7, displacement: 8 }));
    let after = state_at(&s, 4)?;
    assert_eq!(after[0].origin, None);
    assert_eq!(after[6].origin, None);
    assert_eq!(after[7].origin, None);
    assert_eq!(after[12].origin, Some(Origin::Address { register: 7, displacement: 16 }));
    assert_eq!(after[3].origin, Some(Origin::Address { register: 7, displacement: 24 }));
    Ok(())
}
#[test]
fn field_origin_rejection_fs_gs_address_size32_and_dynamic_index() -> Result<(), Error> {
    let state = initial();
    for code in [
        &[0x64, 0x48, 0x8b, 0x47, 8][..],
        &[0x65, 0x48, 0x8b, 0x47, 8][..],
        &[0x67, 0x48, 0x8b, 0x47, 8][..],
        &[0x67, 0x48, 0x8d, 0x47, 8][..],
        &[0x48, 0x8b, 0x04, 0xcf][..],
        &[0x48, 0x8b, 0x04, 0x0f][..],
    ] {
        let ins = instruction(code)?;
        assert_eq!(memory_origin(&ins, &state), None);
        assert_eq!(derive(&ins, &state), None);
    }
    Ok(())
}
#[test]
fn field_origin_partial_gpr_write_and_loaded_arithmetic() -> Result<(), Error> {
    let (_, s) = solve_bytes(&[
        0x48, 0x8b, 0x47, 8, 0x48, 0x83, 0xc0, 1, 0x48, 0x8d, 0x77, 8, 0x40, 0xb6, 1, 0x48, 0x8d, 0x57, 8, 0xba, 1, 0,
        0, 0, 0xc3,
    ])?;
    assert_eq!(
        state_at(&s, 1)?[0].origin,
        Some(Origin::Loaded { register: 7, displacement: 8, width: 8, load_ip: 0x1000 })
    );
    assert_eq!(state_at(&s, 2)?[0].origin, None);
    assert_eq!(state_at(&s, 3)?[6].origin, Some(Origin::Address { register: 7, displacement: 8 }));
    assert_eq!(state_at(&s, 4)?[6].origin, None);
    assert_eq!(state_at(&s, 5)?[2].origin, Some(Origin::Address { register: 7, displacement: 8 }));
    assert_eq!(state_at(&s, 6)?[2].origin, None);
    Ok(())
}
#[test]
fn field_origin_signed_offset_overflow() -> Result<(), Error> {
    let mut state = initial();
    state[7].origin = Some(Origin::Address { register: 7, displacement: i64::MAX });
    for code in [&[0x48, 0x8d, 0x47, 1][..], &[0x48, 0x83, 0xc7, 1][..]] {
        assert_eq!(derive(&instruction(code)?, &state), None);
    }
    state[7].origin = Some(Origin::Address { register: 7, displacement: i64::MIN });
    assert_eq!(derive(&instruction(&[0x48, 0x83, 0xef, 1])?, &state), None);
    state[7].origin = Some(Origin::Address { register: 7, displacement: 10 });
    for code in [&[0x48, 0x83, 0xef, 20][..], &[0x48, 0x8d, 0x47, 0xec][..]] {
        assert_eq!(derive(&instruction(code)?, &state), Some((Origin::Address { register: 7, displacement: -10 }, 7)));
    }
    Ok(())
}
#[test]
fn field_origin_definition_provenance_and_truncation_cap() -> Result<(), Error> {
    let mut code = vec![0x48, 0x8d, 0x47, 8, 0x48, 0x89, 0xc6];
    for _ in 0..8 {
        code.extend_from_slice(&[0x48, 0x83, 0xc6, 8]);
    }
    code.push(0xc3);
    let (_, s) = solve_bytes(&code)?;
    assert_eq!(state_at(&s, 1)?[0].defs, BTreeSet::from([0]));
    assert_eq!(state_at(&s, 2)?[6].defs, BTreeSet::from([0, 1]));
    let last = &state_at(&s, 9)?[6];
    assert_eq!(last.defs.len(), 8);
    assert!(last.truncated);
    assert!(last.defs.contains(&8));
    Ok(())
}
