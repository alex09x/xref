/*
 * XRef — Regression contracts for field provenance and bounded memory reads
 * Copyright (c) 2026 Alexander Panasenko
 * Contact: alex@prod.codes
 * Author: https://prod.codes/about/
 * Project: https://github.com/alex09x/xref
 * SPDX-License-Identifier: MIT OR Apache-2.0
 */
#![allow(clippy::unwrap_used, clippy::expect_used)] // Exact test oracles.
use super::{
    catalog::Catalog,
    facts::Facts,
    infer, step,
    values::{MAX_SPILLS, State, Value},
};
use crate::{
    image::{Image, Segment},
    scan,
};
use iced_x86::{InstructionInfoFactory, Register};

fn code_image(bytes: &[u8]) -> Image {
    Image {
        data: bytes.to_vec(),
        segments: vec![Segment { va: 0x1000, offset: 0, size: bytes.len() }],
        functions: std::iter::once(0x1000..0x1000 + u64::try_from(bytes.len()).unwrap()).collect(),
        ..Image::default()
    }
}
fn execute(bytes: &[u8]) -> State {
    let image = code_image(bytes);
    let mut state = State::initial();
    let mut factory = InstructionInfoFactory::new();
    scan::decode(bytes, 0x1000, |instruction| state = step::transfer(&image, instruction, &state, &mut factory));
    state
}

#[test]
fn virtual_memory_read_handles_extreme_addresses_without_overflow() {
    let image = Image { data: vec![0x55], segments: vec![Segment { va: 0, offset: 0, size: 1 }], ..Image::default() };
    assert!(image.read(u64::MAX, 1).is_none());
    assert!(image.read(1, usize::MAX).is_none());
    let high =
        Image { data: vec![0xaa], segments: vec![Segment { va: u64::MAX, offset: 0, size: 1 }], ..Image::default() };
    assert_eq!(high.read(u64::MAX, 1), Some(&[0xaa][..]));
    assert!(high.read(u64::MAX, 2).is_none());
}

#[test]
fn stack_adjustments_and_partial_overwrites_do_not_reuse_pointer_facts() {
    let state = execute(&[
        0x48, 0x89, 0xf8, 0x48, 0x89, 0x44, 0x24, 0x20, // rax=rdi; spill at entry-rsp+0x20
        0x48, 0x83, 0xec, 0x10, 0x48, 0x8b, 0x4c, 0x24, 0x30, // change RSP; load the same slot into RCX
        0xc6, 0x44, 0x24, 0x30, 0x00, 0x48, 0x8b, 0x74, 0x24, 0x30, // overwrite one byte, then load into RSI
    ]);
    assert_eq!(state.get(Register::RCX), Some(Value::Input { argument: 0, offset: 0 }));
    assert!(state.get(Register::RSI).and_then(Value::argument).is_none());
    assert_eq!(execute(&[0x40, 0xb7, 0]).get(Register::RDI), None, "writing DIL must not create a known full RDI");
}

#[test]
fn stack_fact_budget_is_enforced_for_pushes() {
    let state = execute(&[0x57; MAX_SPILLS + 8]);
    assert!(state.stack.len() <= MAX_SPILLS);
    assert!(state.limited);
}

#[test]
fn cfg_merge_does_not_choose_one_of_two_input_roots() {
    let code = [
        0x85, 0xd2, 0x74, 0x05, 0x48, 0x89, 0xf8, 0xeb, 0x03, 0x48, 0x89, 0xf0, 0x48, 0x89, 0xc1, 0xe8, 0xec, 0x0f, 0,
        0, 0xc3,
    ];
    let mut image = code_image(&code);
    image.functions.push(0x2000..0x2001);
    let facts = Facts::analyze(&image, &image.functions[0]).unwrap();
    assert_eq!(facts.calls.len(), 1);
    assert_eq!(facts.calls[0].arguments[3], None);
}

fn key_value_image(uses_value: bool) -> Image {
    let emitter =
        [0x48, 0x8d, 0x4f, 0x18, 0x48, 0x8d, 0x35, 0xf5, 0x1f, 0, 0, 0xba, 7, 0, 0, 0, 0xe8, 0xeb, 0x0f, 0, 0, 0xc3];
    let mut writer = vec![0x48, 0x89, 0xf0, 0x48, 0x01, 0xd0]; // reads key and length
    if uses_value {
        writer.extend_from_slice(&[0x48, 0x8b, 0x01]);
    } // reads [RCX]
    writer.push(0xc3);
    let mut image = code_image(&emitter);
    let writer_offset = image.data.len();
    image.data.extend_from_slice(&writer);
    image.segments.push(Segment { va: 0x2000, offset: writer_offset, size: writer.len() });
    image.functions.push(0x2000..0x2000 + u64::try_from(writer.len()).unwrap());
    let key_offset = image.data.len();
    image.data.extend_from_slice(b"payload");
    image.segments.push(Segment { va: 0x3000, offset: key_offset, size: 7 });
    image
}

#[test]
fn unused_volatile_register_is_not_a_key_value_argument() {
    for (uses_value, expected) in [(false, false), (true, true)] {
        let image = key_value_image(uses_value);
        let mut catalog = Catalog::open(&image, "payload", Some(&image.functions[0]));
        let summaries = infer::summaries(&mut catalog);
        let found = summaries.get(&0x1000).is_some_and(|entries| {
            entries.iter().any(|entry| entry.name == "payload" && entry.argument == 0 && entry.offset == 24)
        });
        assert_eq!(found, expected, "mere leftover RCX is not recovered arity");
        if uses_value {
            assert!(summaries[&0x1000].iter().any(|entry| entry.read_width == Some(8)));
        }
    }
}

#[test]
fn wide_store_is_a_candidate_for_each_serialized_offset_it_covers() {
    use super::{
        FieldOptions, accessors,
        model::{LayoutCandidate, NamedField, OffsetCandidate},
    };
    let image = code_image(&[0x48, 0xc7, 0x07, 1, 0, 0, 0, 0xc3]); // mov qword ptr [rdi],1; ret
    let facts = Facts::analyze(&image, &image.functions[0]).unwrap();
    let fields = [("left", 0), ("right", 4)]
        .into_iter()
        .map(|(name, offset)| NamedField {
            name: name.to_owned(),
            offset,
            offset_hex: format!("{offset:#x}"),
            observed_read_widths: vec![],
            emissions: vec![],
        })
        .collect();
    let layout = LayoutCandidate {
        function: "0x1000..0x1008".to_owned(),
        base_argument: "rdi".to_owned(),
        fields,
        offsets: vec![OffsetCandidate { offset: 4, offset_hex: "0x4".to_owned() }],
        query_ambiguous: false,
        association_uncertain: false,
        layout_kind: "input_relative_key_value_candidate",
        field_order_evidence: "test fixture",
        size_bytes: None,
        minimum_observed_extent: 8,
        exact_size_unknown: true,
        caveats: vec![],
    };
    let rows = accessors::candidates(
        &facts,
        &[layout],
        &FieldOptions { write_only: true, min_offsets: 2, ..FieldOptions::default() },
    );
    assert_eq!(rows.len(), 1, "an 8-byte store at offset0 touches the named field at offset4");
    assert_eq!(rows[0].1.matched_offsets, vec![0, 4]);
    assert_eq!(rows[0].1.queried_field_accesses[0].width_bytes, 8);
}
