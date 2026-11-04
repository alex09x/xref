/*
 * XRef — Instruction predicate and compiled ELF regression tests
 * Copyright (c) 2026 Alexander Panasenko
 * Contact: alex@prod.codes
 * Author: https://prod.codes/about/
 * Project: https://github.com/alex09x/xref
 * SPDX-License-Identifier: MIT OR Apache-2.0
 */

#![allow(clippy::unwrap_used, clippy::expect_used)] // Independent compiler-oracle assertions.
use super::*;

#[test]
fn validates_mnemonics_classes_and_bounds() {
    assert!(parse_pattern("DIVSD xmm*").is_ok());
    assert!(parse_pattern("").is_err());
    assert!(parse_pattern("notarealop").is_err());
    assert!(parse_pattern(&"a".repeat(33)).is_err());
    assert!(glob_matches(b"xmm*", b"xmm0,xmm1"));
    assert!(!glob_matches(b"xmm0", b"xmm1"));
    assert!(is_float_mnemonic("sqrtsd"));
    assert!(is_float_mnemonic("vdivsd"));
    assert!(is_float_mnemonic("vsqrtsd"));
    assert!(is_float_mnemonic("vcvtsi2sd"));
    assert!(is_float_mnemonic("vfmadd231ps"));
    assert!(is_float_mnemonic("faddp"));
    assert!(is_float_mnemonic("fisttp"));
    assert!(is_float_mnemonic("fyl2x"));
    assert!(is_float_mnemonic("fbld"));
    assert!(!is_float_mnemonic("paddd"));
    assert!(!is_float_mnemonic("vpaddd"));
}

#[cfg(target_os = "linux")]
#[test]
#[allow(clippy::too_many_lines)] // Keep symbol-oracle and stripped-copy evidence in one scenario.
fn compiled_elf_labels_drive_instruction_and_float_matches() -> Result<(), Box<dyn Error>> {
    let nonce = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH)?.as_nanos();
    let root = std::env::temp_dir().join(format!("xref-insn-find-{}-{nonce}", std::process::id()));
    std::fs::create_dir_all(&root)?;
    let source = root.join("fixture.S");
    let binary = root.join("fixture");
    let stripped = root.join("fixture-stripped");
    std::fs::write(&source, include_str!("fixtures/insn_find.S"))?;
    let compile = std::process::Command::new("cc")
        .args(["-nostdlib", "-no-pie", "-Wl,--build-id=none,-e,insn_div"])
        .arg(&source)
        .arg("-o")
        .arg(&binary)
        .output()?;
    assert!(compile.status.success(), "{}", String::from_utf8_lossy(&compile.stderr));
    let symbols = std::process::Command::new("nm").args(["-n", "-a"]).arg(&binary).output()?;
    assert!(symbols.status.success(), "{}", String::from_utf8_lossy(&symbols.stderr));
    let symbol_map = parse_symbols(&String::from_utf8_lossy(&symbols.stdout));
    let objcopy = std::process::Command::new("objcopy")
        .args(["--strip-all", "--keep-section=.eh_frame"])
        .arg(&binary)
        .arg(&stripped)
        .output()?;
    assert!(objcopy.status.success(), "{}", String::from_utf8_lossy(&objcopy.stderr));

    let image = Image::load(&stripped)?;
    assert!(
        !image.functions.is_empty(),
        "stripped ELF should retain .eh_frame function ranges; warnings: {:?}",
        image.metadata.warnings
    );
    let spec = FindSpec {
        calls: vec![],
        refs: vec![],
        imm: vec![],
        imm_mode: (false, false),
        disp: vec![],
        disp_mode: (false, false),
        src: vec![],
        size: None,
        any: Some(1),
        back: 16,
    };
    let patterns = vec!["divsd xmm*".to_owned(), "sqrtsd xmm*".to_owned(), "cvtsi2sd xmm*".to_owned()];
    let mut output = Vec::new();
    find_with_instructions(&image, &spec, &patterns, &["float".into()], &mut output)?;
    let rendered = String::from_utf8(output)?;
    for (function, label, mnemonic) in [
        ("insn_div", "insn_div_site", "divsd"),
        ("insn_sqrt", "insn_sqrt_site", "sqrtsd"),
        ("insn_convert", "insn_convert_site", "cvtsi2sd"),
    ] {
        let start = symbol(&symbol_map, function)?;
        let site = symbol(&symbol_map, label)?;
        let range = image
            .functions
            .iter()
            .find(|r| r.start == start)
            .ok_or_else(|| std::io::Error::other(format!("missing function {function} at {start:#x}")))?;
        assert!(rendered.contains(&format!("{:#x}..{:#x}", range.start, range.end)), "{function}: {rendered}");
        assert!(rendered.contains(&format!("insn:{mnemonic} xmm*=[{site:#x}]")), "{function}: {rendered}");
    }
    let integer = symbol(&symbol_map, "insn_integer")?;
    assert!(!rendered.contains(&format!("{integer:#x}..")), "integer SIMD must not match float class: {rendered}");
    assert!(
        rendered.contains("instruction hits 2:"),
        "float-class and one mnemonic should match per function: {rendered}"
    );

    let mixed = FindSpec {
        calls: vec![],
        refs: vec![],
        imm: vec![],
        imm_mode: (false, false),
        disp: vec![],
        disp_mode: (false, false),
        src: vec![],
        size: Some("0x1..0x100".into()),
        any: Some(2),
        back: 16,
    };
    let mut mixed_output = Vec::new();
    find_with_instructions(&image, &mixed, &patterns, &[], &mut mixed_output)?;
    let mixed_text = String::from_utf8(mixed_output)?;
    assert!(mixed_text.contains("(2/4:"), "size and instruction patterns should share the any threshold: {mixed_text}");
    assert!(
        !mixed_text.contains(&format!("{integer:#x}..")),
        "integer SIMD must not satisfy an instruction pattern: {mixed_text}"
    );
    assert!(find_with_instructions(&image, &spec, &[], &["unknown".into()], &mut Vec::new()).is_err());

    let avx = symbol(&symbol_map, "insn_avx_arithmetic")?;
    let avx_site = symbol(&symbol_map, "insn_avx_site")?;
    let avx_integer = symbol(&symbol_map, "insn_avx_integer")?;
    let mut avx_output = Vec::new();
    find_with_instructions(&image, &spec, &["vaddsd xmm*".into()], &["float".into()], &mut avx_output)?;
    let avx_text = String::from_utf8(avx_output)?;
    let avx_range = image
        .functions
        .iter()
        .find(|r| r.start == avx)
        .ok_or_else(|| std::io::Error::other("missing AVX arithmetic range"))?;
    assert!(
        avx_text.contains(&format!("{:#x}..{:#x}", avx_range.start, avx_range.end)),
        "AVX scalar float should match: {avx_text}"
    );
    assert!(
        avx_text.contains(&format!("insn:vaddsd xmm*=[{avx_site:#x}]")),
        "expected AVX arithmetic label: {avx_text}"
    );
    assert!(!avx_text.contains(&format!("{avx_integer:#x}..")), "integer AVX must not match float class: {avx_text}");

    let many_start = symbol(&symbol_map, "insn_many")?;
    let many_site = symbol(&symbol_map, "insn_many_site_0")?;
    let many_pattern = vec!["divsd xmm*".into()];
    let mut many_output = Vec::new();
    find_with_instructions(&image, &spec, &many_pattern, &[], &mut many_output)?;
    let many_text = String::from_utf8(many_output)?;
    assert!(
        many_text.contains(&format!("insn:divsd xmm*=[{many_site:#x}")),
        "expected nm-derived instruction label: {many_text}"
    );
    assert!(many_text.contains("instruction hits 10:"), "all sites should be counted: {many_text}");
    assert!(many_text.contains("omitted 2"), "site listing should report omitted sites: {many_text}");
    assert!(image.functions.iter().any(|range| range.start == many_start));
    let _ = std::fs::remove_dir_all(root);
    Ok(())
}

#[cfg(target_os = "linux")]
fn symbol(symbols: &std::collections::HashMap<String, u64>, name: &str) -> Result<u64, std::io::Error> {
    symbols.get(name).copied().ok_or_else(|| std::io::Error::other(format!("missing symbol {name}")))
}

#[cfg(target_os = "linux")]
fn parse_symbols(output: &str) -> std::collections::HashMap<String, u64> {
    output
        .lines()
        .filter_map(|line| {
            let mut fields = line.split_whitespace();
            let address = u64::from_str_radix(fields.next()?, 16).ok()?;
            let _kind = fields.next()?;
            let name = fields.next()?.to_owned();
            Some((name, address))
        })
        .collect()
}
