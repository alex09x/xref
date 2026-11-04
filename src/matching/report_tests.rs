/*
 * XRef — Cross-build matching regression tests
 * Copyright (c) 2026 Alexander Panasenko
 * Contact: alex@prod.codes
 * Author: https://prod.codes/about/
 * Project: https://github.com/alex09x/xref
 * SPDX-License-Identifier: MIT OR Apache-2.0
 */

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::float_cmp)] // Exact deterministic test oracles.
use super::ambiguity_status;
#[cfg(target_os = "linux")]
use super::{MatchOptions, match_images_report};
#[cfg(target_os = "linux")]
use crate::image::Image;
use crate::matching::comparison::line_similarity;

#[test]
fn matching_reports_exact_and_close_score_ambiguity() {
    assert_eq!(ambiguity_status(100, Some(100), 0.95), (0, 1.0, true));
    assert_eq!(ambiguity_status(100, Some(95), 0.95), (5, 0.95, true));
    assert_eq!(ambiguity_status(100, Some(94), 0.95), (6, 0.94, false));
}

#[test]
fn pseudo_c_only_resolves_ambiguity_with_distinct_complete_comparisons() {
    assert!(crate::matching::comparison::ambiguity_after_pseudo_c(true, Some(0.8), Some(0.8), true, 0.95));
    assert!(crate::matching::comparison::ambiguity_after_pseudo_c(true, Some(0.8), None, true, 0.95));
    assert!(crate::matching::comparison::ambiguity_after_pseudo_c(true, None, Some(0.2), true, 0.95));
    assert!(!crate::matching::comparison::ambiguity_after_pseudo_c(true, Some(0.9), Some(0.8), true, 0.95));
    assert!(crate::matching::comparison::ambiguity_after_pseudo_c(true, Some(0.9), Some(0.8), false, 0.95));
}

#[test]
fn matching_pseudo_c_similarity_is_order_independent_and_bounded() {
    let a = vec!["return 1;".to_owned(), "return 2;".to_owned()];
    let b = vec!["return 1;".to_owned(), "return 3;".to_owned()];
    assert_eq!(line_similarity(&a, &b), line_similarity(&b, &a));
    assert_eq!(line_similarity(&a, &a), 1.0);
    assert_eq!(line_similarity(&a, &b), 0.5);
}

#[cfg(target_os = "linux")]
#[test]
fn matching_compiled_elf_ambiguity_and_caller_anchor_survive_stripping() {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures");
    let temp = std::env::temp_dir().join(format!("xref-matching-fixtures-{}", std::process::id()));
    std::fs::create_dir_all(&temp).expect("temporary fixture directory is created");
    let a_path = compile_fixture(&root.join("matching_ambiguity_a.c"), &temp.join("matching_ambiguity_a.elf"));
    let b_path = compile_fixture(&root.join("matching_ambiguity_b.c"), &temp.join("matching_ambiguity_b.elf"));
    let a_stripped = strip_fixture(&a_path, &temp.join("matching_ambiguity_a_stripped.elf"));
    let b_stripped = strip_fixture(&b_path, &temp.join("matching_ambiguity_b_stripped.elf"));
    let target = symbol_address(&a_path, "target");
    let caller = symbol_address(&a_path, "caller");
    let unique_target = symbol_address(&a_path, "unique_target");
    let no_evidence = symbol_address(&a_path, "no_evidence");
    let twin_one = symbol_address(&b_path, "twin_one");
    let twin_two = symbol_address(&b_path, "twin_two");
    let twin_identical = symbol_address(&b_path, "twin_identical");
    let other_caller = symbol_address(&b_path, "other_caller");
    let unique_copy = symbol_address(&b_path, "unique_copy");
    let no_evidence_copy = symbol_address(&b_path, "no_evidence_copy");
    assert_ne!(target, twin_one, "fixtures should shift function addresses between builds");

    for (query_path, other_path) in [(&a_path, &b_path), (&a_stripped, &b_stripped)] {
        let image =
            Image::parse(std::fs::read(query_path).expect("query fixture reads")).expect("query ELF fixture parses");
        let other =
            Image::parse(std::fs::read(other_path).expect("other fixture reads")).expect("other ELF fixture parses");
        assert!(image.functions.iter().any(|r| r.start == target));
        assert!(image.functions.iter().any(|r| r.start == caller));
        assert!(image.functions.iter().any(|r| r.start == unique_target));
        assert!(image.functions.iter().any(|r| r.start == no_evidence));
        assert!(other.functions.iter().any(|r| r.start == twin_one));
        assert!(other.functions.iter().any(|r| r.start == twin_two));
        assert!(other.functions.iter().any(|r| r.start == twin_identical));
        assert!(other.functions.iter().any(|r| r.start == other_caller));
        assert!(other.functions.iter().any(|r| r.start == unique_copy));
        assert!(other.functions.iter().any(|r| r.start == no_evidence_copy));

        let spec = format!("{target:#x}");
        let ambiguous = match_images_report(
            &image,
            &other,
            std::slice::from_ref(&spec),
            super::MatchOptions { compare_pseudo_c: true, ..Default::default() },
        )
        .expect("ambiguity report succeeds")
        .remove(0);
        assert!(ambiguous.ambiguous, "an exact pseudo-C tie must remain ambiguous");
        assert!(ambiguous.selected.is_none());
        assert!(ambiguous.warnings.iter().any(|w| w.contains("heuristic inference")));
        let first = ambiguous.candidates.iter().find(|c| c.range.start == twin_one).unwrap();
        let second = ambiguous.candidates.iter().find(|c| c.range.start == twin_two).unwrap();
        let identical = ambiguous.candidates.iter().find(|c| c.range.start == twin_identical).unwrap();
        assert_eq!(
            first.pseudo_c_similarity, identical.pseudo_c_similarity,
            "identical logic must produce an exact tie"
        );
        assert!(
            first.pseudo_c_similarity > second.pseudo_c_similarity,
            "pseudo-C should rank the different logic below the twins"
        );
        assert!(
            second.pseudo_c_differences.iter().any(|d| d.feature == "operator"),
            "comparison should explain the distinguishing logic"
        );
        assert_eq!(first.pseudo_c_status.as_deref(), Some("compared: heuristic pseudo-C evidence"));

        let mut automatic = Vec::new();
        crate::diffc::diff_c(&image, &other, &[format!("{target:#x}")], None, false, &mut automatic)
            .expect("automatic diff-c reports ambiguity");
        assert!(String::from_utf8_lossy(&automatic).contains("ambiguous counterpart; specify an explicit --target"));
        let mut explicit = Vec::new();
        crate::diffc::diff_c(
            &image,
            &other,
            &[format!("{target:#x}")],
            Some(&format!("{twin_one:#x}")),
            false,
            &mut explicit,
        )
        .expect("explicit diff-c target works");
        let explicit = String::from_utf8_lossy(&explicit);
        assert!(explicit.contains("explicit --target"));
        assert!(!explicit.contains("ambiguous counterpart"));

        let anchored = match_images_report(
            &image,
            &other,
            &[spec],
            super::MatchOptions { context: Some((caller, other_caller)), ..Default::default() },
        )
        .expect("caller anchored report succeeds")
        .remove(0);
        assert!(!anchored.ambiguous);
        assert_eq!(anchored.selected.map(|c| c.range.start), Some(twin_one));

        let unique = match_images_report(&image, &other, &[format!("{unique_target:#x}")], MatchOptions::default())
            .expect("unique report succeeds")
            .remove(0);
        assert!(!unique.ambiguous);
        assert_eq!(unique.selected.map(|c| c.range.start), Some(unique_copy));

        let weak = match_images_report(&image, &other, &[format!("{no_evidence:#x}")], MatchOptions::default())
            .expect("low evidence report succeeds")
            .remove(0);
        assert!(weak.selected.is_none());
        assert!(weak.candidates.is_empty());
    }
}

#[cfg(target_os = "linux")]
fn symbol_address(binary: &std::path::Path, symbol: &str) -> u64 {
    let output =
        std::process::Command::new("nm").arg("-n").arg(binary).output().expect("nm runs on unstripped fixture");
    assert!(output.status.success(), "nm succeeds on {}", binary.display());
    String::from_utf8(output.stdout)
        .unwrap()
        .lines()
        .find_map(|line| {
            let mut columns = line.split_whitespace();
            let address = columns.next()?;
            let _kind = columns.next()?;
            (columns.next()? == symbol).then(|| u64::from_str_radix(address, 16).unwrap())
        })
        .unwrap_or_else(|| panic!("nm found symbol {symbol}"))
}

#[cfg(target_os = "linux")]
fn compile_fixture(source: &std::path::Path, binary: &std::path::Path) -> std::path::PathBuf {
    let output = std::process::Command::new("cc")
        .args(["-g", "-O0", "-fno-inline", "-fno-toplevel-reorder", "-fno-pie", "-no-pie"])
        .arg(source)
        .arg("-o")
        .arg(binary)
        .output()
        .expect("C compiler is available for ELF fixture tests");
    assert!(output.status.success(), "fixture compilation failed: {}", String::from_utf8_lossy(&output.stderr));
    binary.to_path_buf()
}

#[cfg(target_os = "linux")]
fn strip_fixture(binary: &std::path::Path, stripped: &std::path::Path) -> std::path::PathBuf {
    std::fs::copy(binary, stripped).expect("fixture binary copies before stripping");
    let output = std::process::Command::new("objcopy")
        .arg("--strip-all")
        .arg(stripped)
        .output()
        .expect("GNU objcopy is available for ELF fixture tests");
    assert!(output.status.success(), "fixture stripping failed: {}", String::from_utf8_lossy(&output.stderr));
    stripped.to_path_buf()
}
