/*
 * xref — Ultra blazing fast cross-references of an x86-64 ELF binary
 * Copyright (c) 2026 Alexander Panasenko
 *
 * Contact: alex@prod.codes
 * Author: https://prod.codes/about/
 * Project: https://github.com/alex09x/xref
 * SPDX-License-Identifier: MIT OR Apache-2.0
 */

#![cfg(all(target_os = "linux", target_arch = "x86_64"))]

use std::collections::BTreeMap;
use std::error::Error;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::time::{SystemTime, UNIX_EPOCH};

use object::read::elf::SectionHeader;
use object::{Object, ObjectSegment, ObjectSymbol};

const BLOB: &[u8] = b"BLOB_HEAD::alpha= beta_sum= gamma=\n::BLOB_TAIL";
const BETA_OFFSET: u64 = 17;
const GAMMA_OFFSET: u64 = 27;
const SHT_PROGBITS: u32 = 0x1;
const SHT_RELR: u32 = 0x13;

struct BuildPair {
    unstripped: PathBuf,
    stripped: PathBuf,
}

struct TempFixture {
    dir: PathBuf,
    default_build: BuildPair,
    relr_build: BuildPair,
}

impl TempFixture {
    fn new() -> Result<Self, Box<dyn Error>> {
        let nonce = SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos();
        let dir = std::env::temp_dir().join(format!("xref-reloc-refs-{}-{nonce}", std::process::id()));
        fs::create_dir_all(&dir)?;
        let default_build = compile_variant(&dir, "default", &[])?;
        let relr_build = compile_variant(&dir, "relr", &["-C", "link-arg=-Wl,-z,pack-relative-relocs"])?;
        Ok(Self { dir, default_build, relr_build })
    }
}

impl Drop for TempFixture {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.dir);
    }
}

fn compile_variant(dir: &Path, label: &str, extra_args: &[&str]) -> Result<BuildPair, Box<dyn Error>> {
    let unstripped = dir.join(format!("reloc-refs-{label}"));
    let stripped = dir.join(format!("reloc-refs-{label}-stripped"));
    let rustc = std::env::var("RUSTC").unwrap_or_else(|_| "rustc".to_owned());
    let src = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/reloc_refs.rs");
    let compile = Command::new(rustc)
        .args(["--edition", "2021", "-C", "opt-level=2", "-C", "relocation-model=pic"])
        .args(extra_args)
        .arg(&src)
        .arg("-o")
        .arg(&unstripped)
        .output()?;
    if !compile.status.success() {
        return Err(format!("rustc ({label}) failed: {}", String::from_utf8_lossy(&compile.stderr)).into());
    }
    let strip = Command::new("objcopy")
        .args(["--strip-all", "--keep-section=.eh_frame"])
        .arg(&unstripped)
        .arg(&stripped)
        .output()?;
    if !strip.status.success() {
        return Err(format!("objcopy ({label}) failed: {}", String::from_utf8_lossy(&strip.stderr)).into());
    }
    Ok(BuildPair { unstripped, stripped })
}

fn symbol_map(path: &Path) -> Result<BTreeMap<String, (u64, u64)>, Box<dyn Error>> {
    let bytes = fs::read(path)?;
    let parsed = object::File::parse(bytes.as_slice())?;
    Ok(parsed.symbols().filter_map(|sym| Some((sym.name().ok()?.to_owned(), (sym.address(), sym.size())))).collect())
}

fn find_blob_va(path: &Path) -> Result<u64, Box<dyn Error>> {
    let bytes = fs::read(path)?;
    let parsed = object::File::parse(bytes.as_slice())?;
    for segment in parsed.segments() {
        let data = segment.data()?;
        if let Some(pos) = data.windows(BLOB.len()).position(|win| win == BLOB) {
            let offset = u64::try_from(pos)?;
            return segment.address().checked_add(offset).ok_or_else(|| "blob VA overflow".into());
        }
    }
    Err("RODATA_BLOB not found in stripped segments".into())
}

fn find_sht_relr_section(bytes: &[u8]) -> Result<(usize, usize, usize), Box<dyn Error>> {
    let parsed = object::File::parse(bytes)?;
    let object::File::Elf64(elf) = parsed else {
        return Err("expected 64-bit ELF".into());
    };
    let endian = elf.endian();
    let header = elf.elf_header();
    let shoff = usize::try_from(header.e_shoff.get(endian))?;
    let shentsize = usize::from(header.e_shentsize.get(endian));
    for (idx, section) in elf.elf_section_table().iter().enumerate() {
        if section.sh_type(endian) == SHT_RELR {
            let (offset, size) = section.file_range(endian).ok_or("missing SHT_RELR file range")?;
            let shdr_offset = shoff
                .checked_add(idx.checked_mul(shentsize).ok_or("section header index overflow")?)
                .ok_or("section header offset overflow")?;
            return Ok((shdr_offset, usize::try_from(offset)?, usize::try_from(size)?));
        }
    }
    Err("expected SHT_RELR section in packed-relocs binary".into())
}

fn run_xref(binary: &Path, args: &[&str]) -> Result<Output, Box<dyn Error>> {
    Ok(Command::new(env!("CARGO_BIN_EXE_xref")).arg("-b").arg(binary).args(args).output()?)
}

fn stdout_ok(output: Output) -> Result<String, Box<dyn Error>> {
    if !output.status.success() {
        return Err(format!("xref failed: {}", String::from_utf8_lossy(&output.stderr)).into());
    }
    Ok(String::from_utf8(output.stdout)?)
}

fn assert_piece_refs(
    report: &str,
    expected_slot: u64,
    expected_piece_va: u64,
    array_start: u64,
    piece_index: usize,
    fn_start: u64,
    fn_size: u64,
) -> Result<(), Box<dyn Error>> {
    let slot_line = format!("slot {expected_slot:#x} -> {expected_piece_va:#x}");
    assert!(report.contains(&slot_line), "missing `{slot_line}` in:\n{report}");

    let in_fn = format!("  in {fn_start:#x}  ");
    let piece_note = format!("; fmt pieces array {array_start:#x}, piece {piece_index}");
    let hit_line = report
        .lines()
        .find(|line| line.contains(&in_fn) && line.contains(&piece_note))
        .ok_or_else(|| format!("missing hit with `{in_fn}` and `{piece_note}` in:\n{report}"))?;

    let ip_hex = hit_line.split_whitespace().next().ok_or("missing hit IP")?;
    let ip = u64::from_str_radix(ip_hex.trim_start_matches("0x"), 16)?;
    assert!(
        (fn_start..fn_start + fn_size.max(1)).contains(&ip),
        "hit IP {ip:#x} outside formatting function {fn_start:#x}..{:#x}:\n{report}",
        fn_start + fn_size
    );
    Ok(())
}

#[test]
fn reloc_refs_stripped_pie_default_and_relr_resolve_middle_pieces() -> Result<(), Box<dyn Error>> {
    let fixture = TempFixture::new()?;

    let relr_bytes = fs::read(&fixture.relr_build.stripped)?;
    let (_, _, relr_size) = find_sht_relr_section(&relr_bytes)?;
    assert!(relr_size >= 8, "expected non-empty SHT_RELR section in packed build");

    for (name, pair) in [("default", &fixture.default_build), ("relr", &fixture.relr_build)] {
        let symbols = symbol_map(&pair.unstripped)?;
        let &(fn_start, fn_size) = symbols
            .get("format_reloc_message")
            .ok_or_else(|| format!("missing format_reloc_message symbol in {name}"))?;
        let (_, &(array_start, _)) = symbols
            .iter()
            .find(|(sym, _)| sym.contains("RELOC_REFS_PIECES"))
            .ok_or_else(|| format!("missing RELOC_REFS_PIECES symbol in {name}"))?;

        let blob_va = find_blob_va(&pair.stripped)?;
        let beta_piece_va = blob_va + BETA_OFFSET;
        let gamma_piece_va = blob_va + GAMMA_OFFSET;
        let beta_slot = array_start + 0x10;
        let gamma_slot = array_start + 0x20;

        let by_text = stdout_ok(run_xref(&pair.stripped, &["refs", "beta_sum=", "--back", "8"])?)?;
        assert_piece_refs(&by_text, beta_slot, beta_piece_va, array_start, 1, fn_start, fn_size)?;

        let beta_hex = format!("{beta_piece_va:#x}");
        let by_addr = stdout_ok(run_xref(&pair.stripped, &["refs", &beta_hex])?)?;
        assert_piece_refs(&by_addr, beta_slot, beta_piece_va, array_start, 1, fn_start, fn_size)?;

        let gamma_by_text = stdout_ok(run_xref(&pair.stripped, &["refs", "gamma=", "--back", "8"])?)?;
        assert_piece_refs(&gamma_by_text, gamma_slot, gamma_piece_va, array_start, 2, fn_start, fn_size)?;

        let gamma_hex = format!("{gamma_piece_va:#x}");
        let gamma_by_addr = stdout_ok(run_xref(&pair.stripped, &["refs", &gamma_hex])?)?;
        assert_piece_refs(&gamma_by_addr, gamma_slot, gamma_piece_va, array_start, 2, fn_start, fn_size)?;
    }
    Ok(())
}

#[test]
fn reloc_refs_dt_relr_fallback_and_malformed_relr_rejection() -> Result<(), Box<dyn Error>> {
    let fixture = TempFixture::new()?;
    let symbols = symbol_map(&fixture.relr_build.unstripped)?;
    let &(fn_start, fn_size) = symbols.get("format_reloc_message").ok_or("missing format_reloc_message symbol")?;
    let (_, &(array_start, _)) =
        symbols.iter().find(|(sym, _)| sym.contains("RELOC_REFS_PIECES")).ok_or("missing RELOC_REFS_PIECES symbol")?;
    let blob_va = find_blob_va(&fixture.relr_build.stripped)?;
    let beta_piece_va = blob_va + BETA_OFFSET;
    let beta_slot = array_start + 0x10;

    let original = fs::read(&fixture.relr_build.stripped)?;
    let (shdr_offset, relr_data_offset, _) = find_sht_relr_section(&original)?;

    // Overwrite SHT_RELR sh_type (at shdr + 4) with SHT_PROGBITS so only PT_DYNAMIC DT_RELR remains.
    let mut dt_only = original.clone();
    dt_only[shdr_offset + 4..shdr_offset + 8].copy_from_slice(&SHT_PROGBITS.to_le_bytes());
    let dt_only_path = fixture.dir.join("reloc-refs-dt-only");
    fs::write(&dt_only_path, &dt_only)?;

    let dt_report = stdout_ok(run_xref(&dt_only_path, &["refs", "beta_sum=", "--back", "8"])?)?;
    assert_piece_refs(&dt_report, beta_slot, beta_piece_va, array_start, 1, fn_start, fn_size)?;

    // Corrupt the first RELR word into a bitmap entry before any address entry. The table is ignored
    // with a warning: the binary stays analysable, nothing panics, and no pieces array is invented.
    let mut corrupt = original;
    corrupt[relr_data_offset..relr_data_offset + 8].copy_from_slice(&3u64.to_le_bytes());
    let corrupt_path = fixture.dir.join("reloc-refs-corrupt");
    fs::write(&corrupt_path, &corrupt)?;

    let report = run_xref(&corrupt_path, &["refs", "beta_sum=", "--back", "8"])?;
    assert_eq!(report.status.code(), Some(0), "corrupt RELR must not make the binary unreadable: {report:?}");
    let text = String::from_utf8(report.stdout)?;
    assert!(text.contains("beta_sum="), "the text itself is still found:\n{text}");
    assert!(!text.contains("fmt pieces array"), "no pieces array without the RELR pointers:\n{text}");
    let info = stdout_ok(run_xref(&corrupt_path, &["query", r#"{"operation":"info"}"#])?)?;
    assert!(info.contains("relr_table_malformed_ignored"), "the ignored table is reported:\n{info}");
    Ok(())
}
