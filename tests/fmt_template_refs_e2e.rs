/*
 * XRef — x86-64 binary analysis and cross-reference tooling
 * Copyright (c) 2026 Alexander Panasenko
 *
 * Contact: alex@prod.codes
 * Author: https://prod.codes/about/
 * Project: https://github.com/alex09x/xref
 * SPDX-License-Identifier: MIT OR Apache-2.0
 */

#![cfg(all(target_os = "linux", target_arch = "x86_64"))]

//! `refs` on the text of a later `format!` piece finds the function that formats it, through the
//! `fmt::Arguments` byte template that rustc emits (the code references only the template start).

use object::{Object, ObjectSymbol};
use std::{
    error::Error,
    fs,
    path::{Path, PathBuf},
    process::Command,
    time::{SystemTime, UNIX_EPOCH},
};

struct Fixture {
    dir: PathBuf,
}

impl Fixture {
    fn new() -> Result<Self, Box<dyn Error>> {
        let nonce = SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos();
        let dir = std::env::temp_dir().join(format!("xref-fmt-template-{}-{nonce}", std::process::id()));
        fs::create_dir_all(&dir)?;
        let source = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/fmt_template.rs");
        let built =
            Command::new("rustc").args(["-C", "opt-level=2"]).arg(&source).arg("-o").arg(dir.join("bin")).output()?;
        assert!(built.status.success(), "{}", String::from_utf8_lossy(&built.stderr));
        let strip = Command::new("objcopy")
            .args(["--strip-all", "--keep-section=.eh_frame"])
            .arg(dir.join("bin"))
            .arg(dir.join("stripped"))
            .output()?;
        assert!(strip.status.success(), "{}", String::from_utf8_lossy(&strip.stderr));
        Ok(Self { dir })
    }

    fn report_range(&self) -> Result<(u64, u64), Box<dyn Error>> {
        let bytes = fs::read(self.dir.join("bin"))?;
        let file = object::File::parse(bytes.as_slice())?;
        let symbol = file.symbols().find(|s| s.name() == Ok("report")).ok_or("no report symbol")?;
        Ok((symbol.address(), symbol.address() + symbol.size()))
    }

    fn refs(&self, target: &str) -> Result<String, Box<dyn Error>> {
        let run = Command::new(env!("CARGO_BIN_EXE_xref"))
            .arg("-b")
            .arg(self.dir.join("stripped"))
            .args(["refs", target])
            .output()?;
        assert!(run.status.success(), "{}", String::from_utf8_lossy(&run.stderr));
        Ok(String::from_utf8(run.stdout)?)
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.dir);
    }
}

/// The hit line inside `report` that names a template piece, and that piece's index.
fn template_hit(out: &str, report: (u64, u64)) -> Option<(u64, usize)> {
    out.lines().find_map(|line| {
        let ip = u64::from_str_radix(line.split_whitespace().next()?.strip_prefix("0x")?, 16).ok()?;
        let (_, tail) = line.split_once("; fmt template ")?;
        let (start, piece) = tail.split_once(", piece ")?;
        ((report.0..report.1).contains(&ip)).then_some(())?;
        Some((u64::from_str_radix(start.strip_prefix("0x")?, 16).ok()?, piece.trim().parse().ok()?))
    })
}

#[test]
fn reloc_refs_template_finds_the_formatting_function_from_a_later_piece() -> Result<(), Box<dyn Error>> {
    let fixture = Fixture::new()?;
    let report = fixture.report_range()?;
    let beta = fixture.refs("beta_sum=")?;
    let (start, piece) =
        template_hit(&beta, report).ok_or_else(|| format!("no template hit inside report:\n{beta}"))?;
    assert_eq!(piece, 1, "{beta}");
    // The placeholder before " gamma=" carries width and precision fields; the parser must skip them.
    let gamma = fixture.refs("gamma=")?;
    assert_eq!(template_hit(&gamma, report), Some((start, 2)), "{gamma}");
    let alpha = fixture.refs("alpha=")?;
    assert_eq!(template_hit(&alpha, report), Some((start, 0)), "{alpha}");
    Ok(())
}

#[test]
fn reloc_refs_template_resolves_an_address_inside_a_piece() -> Result<(), Box<dyn Error>> {
    let fixture = Fixture::new()?;
    let report = fixture.report_range()?;
    let beta = fixture.refs("beta_sum=")?;
    let text_at = beta
        .lines()
        .find_map(|l| l.strip_prefix("text ").and_then(|r| r.split_whitespace().next()).map(str::to_owned))
        .ok_or("no text line")?;
    let by_address = fixture.refs(&text_at)?;
    assert_eq!(template_hit(&by_address, report).map(|(_, p)| p), Some(1), "{by_address}");
    // Text that is not in any template finds no template hit.
    let absent = fixture.refs("no such piece text")?;
    assert!(!absent.contains("fmt template"), "{absent}");
    Ok(())
}
