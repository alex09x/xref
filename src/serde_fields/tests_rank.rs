/*
 * XRef — Regression contracts for field writer ranking (#76, PR #118 review)
 * Copyright (c) 2026 Alexander Panasenko
 * Contact: alex@prod.codes
 * Author: https://prod.codes/about/
 * Project: https://github.com/alex09x/xref
 * SPDX-License-Identifier: MIT OR Apache-2.0
 */
#![allow(clippy::unwrap_used, clippy::expect_used)] // Exact test oracles.
use super::{
    FieldOptions, accessors,
    facts::Facts,
    model::{LayoutCandidate, NamedField, OffsetCandidate},
    writer_index::Entry,
    writer_rank::{Plan, writer_score},
};
use crate::image::{Image, Segment};

fn code_image(bytes: &[u8]) -> Image {
    Image {
        data: bytes.to_vec(),
        segments: vec![Segment { va: 0x1000, offset: 0, size: bytes.len() }],
        functions: std::iter::once(0x1000..0x1000 + u64::try_from(bytes.len()).unwrap()).collect(),
        ..Image::default()
    }
}

fn layout_cme() -> LayoutCandidate {
    LayoutCandidate {
        function: "0x1000..0x1020".to_owned(),
        base_argument: "rdi".to_owned(),
        fields: [("c", 0), ("m", 8), ("e", 16)]
            .into_iter()
            .map(|(name, offset)| NamedField {
                name: name.to_owned(),
                offset,
                offset_hex: format!("{offset:#x}"),
                observed_read_widths: vec![8],
                emissions: vec![],
            })
            .collect(),
        offsets: [0, 8, 16]
            .into_iter()
            .map(|offset| OffsetCandidate { offset, offset_hex: format!("{offset:#x}") })
            .collect(),
        matched_keys: None,
        missing_keys: None,
        query_ambiguous: false,
        association_uncertain: false,
        layout_kind: "test",
        field_order_evidence: "test",
        size_bytes: None,
        minimum_observed_extent: 24,
        exact_size_unknown: true,
        caveats: vec![],
    }
}

/// The cold (direct) pass and the cached index must give one function the same score, also without
/// `--writes-all-of`, where a comparison of a field still earns the conditional bonus.
#[test]
fn indexed_and_direct_scores_agree_without_writes_all_of() {
    let layout = layout_cme();
    let options = FieldOptions { write_only: true, ..FieldOptions::default() };
    let plan = Plan::new(&layout, &options);
    // cmp rbx, [rdi+8]; mov [rdi+8], rbx; mov [rdi+0x10], rdx; ret
    let image = code_image(&[0x48, 0x3b, 0x5f, 0x08, 0x48, 0x89, 0x5f, 0x08, 0x48, 0x89, 0x57, 0x10, 0xc3]);
    let facts = Facts::analyze(&image, &image.functions[0]).unwrap();
    let entry = Entry::new(&facts.range, Some(&facts));
    let direct = accessors::candidates(&facts, std::slice::from_ref(&layout), &options);
    let (colocated, conditional, _) = plan.score(&entry, 0, options.min_offsets).unwrap();
    assert_eq!(conditional, 1, "a cmp of a ranked field is conditional evidence");
    let indexed = writer_score(colocated, plan.precision(&entry, 0), conditional != 0);
    assert_eq!(direct[0].1.ranking_score, indexed);
}

/// Load roots share a slot every `MAX_LOAD_ROOTS` instructions. When two live loads mint the same slot,
/// a dereference through it is ambiguous and must not mark either field as a pointer.
#[test]
fn colliding_load_roots_do_not_mark_a_pointer_field() {
    let mut code = vec![0x48, 0x8b, 0x5f, 0x08]; // 0: mov rbx, [rdi+8]
    code.extend([0x90; 9]); // 1..=9: nop
    code.extend([0x48, 0x8b, 0x47, 0x10]); // 10: mov rax, [rdi+0x10] (same slot as instruction 0)
    code.extend([0x48, 0x89, 0x33]); // 11: mov [rbx], rsi (dereferences the +8 load, not +0x10)
    code.push(0xc3);
    let image = code_image(&code);
    let facts = Facts::analyze(&image, &image.functions[0]).unwrap();
    assert_eq!(facts.dereferenced, vec![], "ambiguous slot must not be attributed");

    // Without the colliding load the +8 slot is attributed.
    let mut single = vec![0x48, 0x8b, 0x5f, 0x08];
    single.extend([0x90; 9]);
    single.extend([0x48, 0x89, 0x33, 0xc3]);
    let image = code_image(&single);
    let facts = Facts::analyze(&image, &image.functions[0]).unwrap();
    assert_eq!(facts.dereferenced, vec![(0, 8)]);
}
