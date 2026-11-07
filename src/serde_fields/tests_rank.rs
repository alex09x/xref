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

/// #149: a lead names the next different function and the terms behind the gap; a row of the same
/// function (another layout) is skipped, and a missing next function says whether the limit hid it.
#[test]
fn leads_name_the_next_function_and_the_terms_of_the_gap() {
    use super::model::{AccessorCandidate, Lead, ScoreTerms};
    let row = |function: &str, callgraph: usize| {
        let score_terms = ScoreTerms { colocated: 16, precise: 16, covered: 8, callgraph, ..ScoreTerms::default() };
        AccessorCandidate {
            layout: 0,
            function: function.to_owned(),
            base_argument: "rdi".to_owned(),
            matched_offsets: vec![8, 16],
            queried_field_accesses: vec![],
            colocated_written_fields: 2,
            callgraph_distance: None,
            ranking_score: score_terms.total(),
            score_terms,
            lead: Lead::default(),
            confidence: "test",
        }
    };
    let mut rows = vec![row("0x1210..0x121d", 10), row("0x1210..0x121d", 10), row("0x121d..0x14a6", 0)];
    super::writer_rank::annotate_leads(&mut rows, 2, false);
    assert_eq!(rows.len(), 2, "the extra row only serves the last lead");
    for lead in [&rows[0].lead, &rows[1].lead] {
        assert_eq!(lead.over.as_deref(), Some("0x121d..0x14a6"));
        assert_eq!(lead.points, Some(10));
        assert_eq!(lead.terms.iter().map(|d| (d.term, d.points)).collect::<Vec<_>>(), vec![("callgraph", 10)]);
    }
    assert_eq!(super::render::lead(&rows[0].lead), "+10 over 0x121d..0x14a6 (callgraph +10)");
    let mut tied = vec![row("0x1210..0x121d", 10), row("0x121d..0x14a6", 10)];
    super::writer_rank::annotate_leads(&mut tied, 1, false);
    assert!(
        super::render::lead(&tied[0].lead).starts_with("tie with 0x121d..0x14a6 (no term differs;"),
        "equal scores"
    );
    let mut alone = vec![row("0x1210..0x121d", 10)];
    super::writer_rank::annotate_leads(&mut alone, 1, true);
    assert_eq!(alone[0].lead.missing, Some("no_other_candidate"));
    let mut cut = vec![row("0x1210..0x121d", 10)];
    super::writer_rank::annotate_leads(&mut cut, 1, false);
    assert_eq!(cut[0].lead.missing, Some("next_candidate_beyond_limit"));
}

/// Constant stores initialise a field (enum tags, empty values); only stores of computed values count as
/// field-precise update evidence.
#[test]
fn immediate_stores_are_not_field_precise_updates() {
    let layout = layout_cme();
    let options =
        FieldOptions { write_only: true, writes_all_of: vec!["m".into(), "e".into()], ..FieldOptions::default() };
    let plan = Plan::new(&layout, &options);
    let precision = |bytes: &[u8]| {
        let image = code_image(bytes);
        let facts = Facts::analyze(&image, &image.functions[0]).unwrap();
        plan.precision(&Entry::new(&facts.range, Some(&facts)), 0)
    };
    // mov qword ptr [rdi+8], 0; mov qword ptr [rdi+0x10], 1; ret
    let init = precision(&[0x48, 0xc7, 0x47, 0x08, 0, 0, 0, 0, 0x48, 0xc7, 0x47, 0x10, 1, 0, 0, 0, 0xc3]);
    // mov [rdi+8], rbx; mov [rdi+0x10], rdx; ret
    let update = precision(&[0x48, 0x89, 0x5f, 0x08, 0x48, 0x89, 0x57, 0x10, 0xc3]);
    assert_eq!((init.colocated, init.covered), (0, 0));
    assert_eq!((update.colocated, update.covered), (2, 2));
}

/// Parallel pre-analysis honours the cooperative deadline: once it has passed, no task analyzes a
/// function (the lazy path then applies the same budget and records coverage).
#[test]
fn prefetch_stops_at_an_expired_deadline() {
    let image = code_image(&[0x48, 0x89, 0x5f, 0x08, 0xc3]); // mov [rdi+8], rbx; ret
    let ranges = image.functions.clone();
    let live = super::catalog::prefetch_facts(
        &image,
        &ranges,
        4096,
        std::time::Instant::now() + std::time::Duration::from_secs(60),
    );
    assert_eq!(live.len(), 1);
    let expired = super::catalog::prefetch_facts(&image, &ranges, 4096, std::time::Instant::now());
    assert!(expired.is_empty(), "no analysis may start after the deadline");
}

/// Key matching over a reused whole-image scan honours the deadline and reports what it skipped.
#[test]
fn reused_scan_key_matching_stops_at_an_expired_deadline() {
    let image = code_image(b"cm\0e");
    let references = vec![(0x1000, vec![0x1000]), (0x1100, vec![0x1003])];
    let live = std::time::Instant::now() + std::time::Duration::from_secs(60);
    let (matched, skipped) = super::catalog_scan::match_references(&image, &references, &["c", "e"], live);
    assert_eq!((matched.len(), skipped), (2, 0));
    let (matched, skipped) =
        super::catalog_scan::match_references(&image, &references, &["c", "e"], std::time::Instant::now());
    assert_eq!((matched.len(), skipped), (0, 2), "no matching may start after the deadline");
}

/// The image identity never comes from the buffer address: bytes changed in place (outside any
/// sample) get a new digest, and a declared digest applies only inside its call for that buffer.
#[test]
fn identity_is_content_bound_not_address_bound() {
    let mut image = vec![0_u8; 1 << 20];
    let first = super::scan_index::Identity::new(&image, false).digest();
    image[123_457] ^= 1; // between any sampled windows
    let changed = super::scan_index::Identity::new(&image, false).digest();
    assert_ne!(first, changed, "same address and length must not reuse the old digest");

    let declared = super::with_image_digest(&image, [7; 32], || super::scan_index::Identity::new(&image, false));
    assert_eq!(declared.digest(), [7; 32]);
    let other = vec![1_u8; 64];
    let not_declared = super::with_image_digest(&image, [7; 32], || super::scan_index::Identity::new(&other, false));
    assert_ne!(not_declared.digest(), [7; 32], "a declaration covers only its own buffer");
    assert_eq!(super::scan_index::Identity::new(&image, false).digest(), changed, "declaration ends with the call");
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
