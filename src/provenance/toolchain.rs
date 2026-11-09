/*
 * XRef Code — Toolchain `.comment` strings, Build-ID formatting, and entropy heuristics
 * Copyright (c) 2026 Alexander Panasenko
 *
 * Contact: alex@prod.codes
 * Author: https://prod.codes/about/
 * Project: https://github.com/alex09x/xref
 * SPDX-License-Identifier: MIT OR Apache-2.0
 */

use std::fmt::Write as _;

use object::{Object, ObjectSection, SectionFlags};
use serde::Serialize;

use crate::image::Image;

const MAX_TOOLCHAIN_ENTRIES: usize = 16;
const MAX_TOOLCHAIN_LEN: usize = 160;
const MIN_ENTROPY_BYTES: usize = 4096;
/// 7.20 bits/byte in milli-bits: compressed or encrypted code exceeds ~7.2 bits/byte,
/// whereas compiled x86-64 machine code typically measures 5.8..6.7 bits/byte.
pub const HIGH_ENTROPY_MILLI_THRESHOLD: u32 = 7200;

/// An executable section or segment whose byte distribution resembles packed/encrypted data.
#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
pub struct HighEntropySection {
    pub name: String,
    pub va: u64,
    pub size_bytes: usize,
    /// Shannon entropy in milli-bits per byte (e.g. `7650` = `7.650` bits/byte).
    pub entropy_milli: u32,
}

/// Format raw GNU Build-ID or Mach-O `LC_UUID` bytes as lowercase hexadecimal.
#[must_use]
pub fn hex_build_id(bytes: Option<&[u8]>) -> Option<String> {
    let bytes = bytes.filter(|b| !b.is_empty())?;
    let mut out = String::with_capacity(bytes.len() * 2);
    for &byte in bytes {
        let _ = write!(out, "{byte:02x}");
    }
    Some(out)
}

/// Extract deduplicated printable compiler and linker strings from `.comment` / `__comment`.
#[must_use]
pub fn extract_comments(file: &object::File<'_>) -> Vec<String> {
    let mut results = Vec::new();
    for section in file.sections() {
        let Ok(name) = section.name() else {
            continue;
        };
        if !matches!(name, ".comment" | "__comment") {
            continue;
        }
        let Ok(raw) = section.data() else {
            continue;
        };
        collect_comment_strings(raw, &mut results);
    }
    results
}

/// Parse NUL- or newline-delimited printable ASCII/UTF-8 toolchain strings from raw `.comment` bytes.
pub fn collect_comment_strings(raw: &[u8], out: &mut Vec<String>) {
    for chunk in raw.split(|&b| b == 0 || b == b'\n' || b == b'\r') {
        if out.len() >= MAX_TOOLCHAIN_ENTRIES {
            break;
        }
        let Ok(text) = std::str::from_utf8(chunk) else {
            continue;
        };
        let trimmed = text.trim();
        if trimmed.len() < 4
            || trimmed.len() > MAX_TOOLCHAIN_LEN
            || trimmed.chars().any(char::is_control)
            || out.iter().any(|existing| existing == trimmed)
        {
            continue;
        }
        out.push(trimmed.to_owned());
    }
}

/// Detect executable sections or segments with compressed/packed entropy (`>= 7.20` bits/byte).
#[must_use]
pub fn detect_high_entropy_executable(image: &Image, parsed: Option<&object::File<'_>>) -> Vec<HighEntropySection> {
    let mut flagged = Vec::new();
    if let Some(file) = parsed {
        for section in file.sections() {
            let is_exec = match section.flags() {
                SectionFlags::Elf { sh_flags } => (sh_flags & u64::from(object::elf::SHF_EXECINSTR)) != 0,
                SectionFlags::MachO { flags } => (flags & 0x8000_0000) != 0,
                _ => false,
            };
            if !is_exec {
                continue;
            }
            let Ok(bytes) = section.data() else {
                continue;
            };
            let name = section.name().unwrap_or("<exec>").to_owned();
            let packer_named = name.to_ascii_lowercase().contains("upx");
            if bytes.len() >= MIN_ENTROPY_BYTES || packer_named {
                let entropy_milli = shannon_entropy_milli(bytes);
                if entropy_milli >= HIGH_ENTROPY_MILLI_THRESHOLD || packer_named {
                    flagged.push(HighEntropySection {
                        name,
                        va: section.address(),
                        size_bytes: bytes.len(),
                        entropy_milli,
                    });
                }
            }
        }
    }
    if flagged.is_empty() {
        for seg in &image.metadata.load_segments {
            if !seg.executable {
                continue;
            }
            let Ok(offset) = usize::try_from(seg.file_offset) else {
                continue;
            };
            let Ok(size) = usize::try_from(seg.file_size) else {
                continue;
            };
            if size < MIN_ENTROPY_BYTES {
                continue;
            }
            let Some(bytes) = image.data.get(offset..offset.saturating_add(size)) else {
                continue;
            };
            let entropy_milli = shannon_entropy_milli(bytes);
            if entropy_milli >= HIGH_ENTROPY_MILLI_THRESHOLD {
                flagged.push(HighEntropySection {
                    name: format!("LOAD@{:#x}", seg.va),
                    va: seg.va,
                    size_bytes: bytes.len(),
                    entropy_milli,
                });
            }
        }
    }
    flagged
}

/// Compute Shannon byte entropy in milli-bits per byte (`0..=8000`).
#[must_use]
#[allow(clippy::cast_precision_loss, clippy::cast_possible_truncation, clippy::cast_sign_loss)]
pub fn shannon_entropy_milli(bytes: &[u8]) -> u32 {
    if bytes.is_empty() {
        return 0;
    }
    let mut counts = [0usize; 256];
    for &b in bytes {
        counts[usize::from(b)] += 1;
    }
    let total = bytes.len() as f64;
    let mut entropy = 0.0f64;
    for &count in &counts {
        if count > 0 {
            let p = (count as f64) / total;
            entropy = p.mul_add(-p.log2(), entropy);
        }
    }
    ((entropy * 1000.0).round() as u32).min(8000)
}
