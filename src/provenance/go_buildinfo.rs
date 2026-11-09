/*
 * XRef Code — Go `.go.buildinfo` toolchain and module manifest parser
 * Copyright (c) 2026 Alexander Panasenko
 *
 * Contact: alex@prod.codes
 * Author: https://prod.codes/about/
 * Project: https://github.com/alex09x/xref
 * SPDX-License-Identifier: MIT OR Apache-2.0
 */

use object::{Object, ObjectSection};
use serde::Serialize;

use crate::image::{Image, occurrence_iter};

const GO_BUILDINFO_MAGIC: &[u8; 14] = b"\xff Go buildinf:";
const INLINE_FLAG: u8 = 0x02;
const BIG_ENDIAN_FLAG: u8 = 0x01;
const MAX_GO_STRING_BYTES: usize = 4 * 1024 * 1024;
/// Aligned magic occurrences tried by the segment scan.
const MAX_SCAN_CANDIDATES: usize = 64;

const MOD_INFO_START: [u8; 16] =
    [0x30, 0x77, 0xaf, 0x0c, 0x92, 0x74, 0x08, 0x02, 0x41, 0xe1, 0xc1, 0x07, 0xe6, 0xd6, 0x18, 0xe6];
const MOD_INFO_END: [u8; 16] =
    [0xf9, 0x32, 0x43, 0x31, 0x86, 0x18, 0x20, 0x72, 0x00, 0x82, 0x42, 0x10, 0x41, 0x16, 0xd8, 0xf2];

/// A single Go module dependency from embedded `debug.BuildInfo`.
#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
pub struct GoModuleDep {
    pub path: String,
    pub version: String,
    pub sum: Option<String>,
    pub replaced_by: Option<(String, String)>,
}

/// Parsed Go compiler version, main module, dependencies, and build flags.
#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
pub struct GoBuildInfo {
    pub go_version: String,
    pub path: Option<String>,
    pub main_module: Option<(String, String)>,
    pub deps: Vec<GoModuleDep>,
    pub settings: Vec<(String, String)>,
}

/// Extract Go build metadata from `.go.buildinfo` / `__go_buildinfo` or segment scan fallback.
#[must_use]
pub fn extract(image: &Image, parsed: Option<&object::File<'_>>) -> Option<GoBuildInfo> {
    if let Some(file) = parsed {
        for section in file.sections() {
            if section.name().is_ok_and(|n| matches!(n, ".go.buildinfo" | "__go_buildinfo"))
                && let Ok(bytes) = section.data()
                && let Some(info) = parse_buildinfo_blob(bytes, Some(image))
            {
                return Some(info);
            }
        }
    }
    // Without a section header: the Go linker places the header 16-byte aligned; a magic string
    // elsewhere (a literal in another program's `.rodata`) is not one, and only a few are tried.
    let mut candidates = 0usize;
    for seg in &image.segments {
        let Some(slice) = image.data.get(seg.offset..seg.offset.saturating_add(seg.size)) else {
            continue;
        };
        for pos in occurrence_iter(slice, GO_BUILDINFO_MAGIC) {
            if u64::try_from(pos).map_or(true, |pos| seg.va.wrapping_add(pos) % 16 != 0) {
                continue;
            }
            candidates += 1;
            if candidates > MAX_SCAN_CANDIDATES {
                return None;
            }
            if let Some(info) = parse_buildinfo_blob(&slice[pos..], Some(image)) {
                return Some(info);
            }
        }
    }
    None
}

/// A Go toolchain version: `go1.22.3`, `devel go1.23-abc…`; short printable ASCII.
fn is_go_version(version: &[u8]) -> bool {
    (1..=128).contains(&version.len())
        && (version.starts_with(b"go") || version.starts_with(b"devel"))
        && version.iter().all(|b| b.is_ascii_graphic() || *b == b' ')
}

/// Parse a `.go.buildinfo` section or slice starting with `\xff Go buildinf:`.
#[must_use]
pub fn parse_buildinfo_blob(blob: &[u8], image: Option<&Image>) -> Option<GoBuildInfo> {
    if blob.len() < 32 || &blob[..14] != GO_BUILDINFO_MAGIC {
        return None;
    }
    let ptr_size = blob[14];
    let flags = blob[15];
    if !matches!(ptr_size, 4 | 8) || (flags & BIG_ENDIAN_FLAG) != 0 {
        return None;
    }
    // The version is checked before the module text is read, so a false header costs no allocation.
    let (go_version, raw_mod): (String, std::borrow::Cow<'_, [u8]>) = if (flags & INLINE_FLAG) != 0 {
        let (ver, after_ver) = read_uleb_bytes(blob.get(32..)?)?;
        if !is_go_version(ver) {
            return None;
        }
        let (mod_bytes, _) = read_uleb_bytes(after_ver).unwrap_or((&[], &[]));
        (std::str::from_utf8(ver).ok()?.to_owned(), mod_bytes.into())
    } else if ptr_size == 8 {
        let img = image?;
        let vers_ptr = u64::from_le_bytes(blob.get(16..24)?.try_into().ok()?);
        let mod_ptr = u64::from_le_bytes(blob.get(24..32)?.try_into().ok()?);
        let ver_bytes = read_go_string(img, vers_ptr, 128)?;
        if !is_go_version(ver_bytes) {
            return None;
        }
        let mod_bytes =
            if mod_ptr == 0 { &[][..] } else { read_go_string(img, mod_ptr, MAX_GO_STRING_BYTES).unwrap_or_default() };
        (std::str::from_utf8(ver_bytes).ok()?.to_owned(), mod_bytes.into())
    } else {
        return None;
    };
    let mod_text = unwrap_mod_sentinels(&raw_mod);
    Some(parse_mod_lines(go_version, mod_text))
}

fn read_uleb_bytes(mut input: &[u8]) -> Option<(&[u8], &[u8])> {
    let mut len = 0usize;
    let mut shift = 0u32;
    loop {
        let (&byte, rest) = input.split_first()?;
        input = rest;
        if shift >= 28 {
            return None;
        }
        len |= usize::from(byte & 0x7f) << shift;
        if (byte & 0x80) == 0 {
            break;
        }
        shift += 7;
    }
    if len > MAX_GO_STRING_BYTES || input.len() < len {
        return None;
    }
    Some(input.split_at(len))
}

/// The bytes of the Go string header at `header_va`, borrowed from the image, at most `max` long.
fn read_go_string(image: &Image, header_va: u64, max: usize) -> Option<&[u8]> {
    let header = image.read(header_va, 16)?;
    let data_va = u64::from_le_bytes(header.get(..8)?.try_into().ok()?);
    let len_u64 = u64::from_le_bytes(header.get(8..16)?.try_into().ok()?);
    let len = usize::try_from(len_u64).ok().filter(|&n| n <= max)?;
    if len == 0 {
        return Some(&[]);
    }
    image.read(data_va, len)
}

fn unwrap_mod_sentinels(raw: &[u8]) -> &str {
    let stripped = raw.strip_prefix(&MOD_INFO_START).unwrap_or(raw);
    let inner = stripped
        .strip_suffix(&MOD_INFO_END)
        .or_else(|| {
            (raw.starts_with(&MOD_INFO_START) && stripped.len() >= 16).then(|| &stripped[..stripped.len() - 16])
        })
        .unwrap_or(stripped);
    std::str::from_utf8(inner).unwrap_or_default().trim()
}

fn parse_mod_lines(go_version: String, mod_text: &str) -> GoBuildInfo {
    let mut path = None;
    let mut main_module = None;
    let mut deps: Vec<GoModuleDep> = Vec::new();
    let mut settings = Vec::new();

    for line in mod_text.lines() {
        let mut parts = line.split('\t');
        match parts.next() {
            Some("path") => {
                if let Some(p) = parts.next().filter(|s| !s.is_empty()) {
                    path = Some(p.to_owned());
                }
            }
            Some("mod") => {
                if let (Some(m), Some(v)) = (parts.next(), parts.next()) {
                    main_module = Some((m.to_owned(), v.to_owned()));
                }
            }
            Some("dep") => {
                if let (Some(m), Some(v)) = (parts.next(), parts.next()) {
                    let sum = parts.next().filter(|s| !s.is_empty()).map(str::to_owned);
                    deps.push(GoModuleDep { path: m.to_owned(), version: v.to_owned(), sum, replaced_by: None });
                }
            }
            Some("=>") => {
                if let (Some(repl_m), Some(repl_v), Some(last)) = (parts.next(), parts.next(), deps.last_mut()) {
                    last.replaced_by = Some((repl_m.to_owned(), repl_v.to_owned()));
                }
            }
            Some("build") => {
                if let Some(kv) = parts.next()
                    && let Some((k, v)) = kv.split_once('=')
                {
                    settings.push((k.to_owned(), v.to_owned()));
                }
            }
            _ => {}
        }
    }
    deps.sort_by(|a, b| a.path.cmp(&b.path).then_with(|| a.version.cmp(&b.version)));
    GoBuildInfo { go_version, path, main_module, deps, settings }
}
