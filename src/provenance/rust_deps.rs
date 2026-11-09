/*
 * XRef Code — Rust `.dep-v0` (`cargo-auditable`) manifest parser
 * Copyright (c) 2026 Alexander Panasenko
 *
 * Contact: alex@prod.codes
 * Author: https://prod.codes/about/
 * Project: https://github.com/alex09x/xref
 * SPDX-License-Identifier: MIT OR Apache-2.0
 */

use miniz_oxide::inflate::decompress_to_vec_zlib_with_limit;
use object::{Object, ObjectSection};
use serde::{Deserialize, Serialize};

/// Hard ceiling (16 MiB) on uncompressed `.dep-v0` JSON to defeat decompression bombs.
pub const MAX_AUDIT_JSON_BYTES: usize = 16 * 1024 * 1024;
/// Hard ceiling (4 MiB) on compressed `.dep-v0` section bytes.
const MAX_COMPRESSED_AUDIT_BYTES: usize = 4 * 1024 * 1024;

/// A single crate entry from an embedded `cargo-auditable` dependency graph.
#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
pub struct RustPackage {
    pub name: String,
    pub version: String,
    pub source: String,
    pub kind: String,
    pub root: bool,
    pub dependency_count: usize,
}

/// Parsed Rust dependency manifest recovered from `.dep-v0` / `__dep_v0`.
#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
pub struct RustAuditInfo {
    pub format: Option<u32>,
    pub root_name: Option<String>,
    pub root_version: Option<String>,
    pub runtime_count: usize,
    pub build_count: usize,
    pub packages: Vec<RustPackage>,
}

#[derive(Deserialize)]
struct RawAuditManifest {
    #[serde(default)]
    format: Option<u32>,
    packages: Vec<RawAuditPackage>,
}

#[derive(Deserialize)]
struct RawAuditPackage {
    name: String,
    version: String,
    #[serde(default)]
    source: String,
    #[serde(default)]
    kind: Option<String>,
    #[serde(default)]
    dependencies: Vec<usize>,
    #[serde(default)]
    root: bool,
}

/// Locate and decode `.dep-v0` or `__dep_v0` from a parsed object file.
pub fn extract_from_object(file: &object::File<'_>) -> Result<Option<RustAuditInfo>, String> {
    let section =
        file.sections().find(|sec| sec.name().is_ok_and(|name| matches!(name, ".dep-v0" | "__dep_v0" | ".dep_v0")));
    let Some(section) = section else {
        return Ok(None);
    };
    let compressed = section.data().map_err(|e| format!("failed to read .dep-v0 section: {e}"))?;
    if compressed.is_empty() {
        return Ok(None);
    }
    parse_compressed_dep_v0(compressed).map(Some)
}

/// Parse zlib-compressed `cargo-auditable` bytes with strict decompression bounds.
pub fn parse_compressed_dep_v0(compressed: &[u8]) -> Result<RustAuditInfo, String> {
    if compressed.len() > MAX_COMPRESSED_AUDIT_BYTES {
        return Err(format!(".dep-v0 compressed payload exceeds {MAX_COMPRESSED_AUDIT_BYTES} bytes"));
    }
    let json_bytes = decompress_to_vec_zlib_with_limit(compressed, MAX_AUDIT_JSON_BYTES)
        .map_err(|err| format!(".dep-v0 zlib decompression failed or exceeded {MAX_AUDIT_JSON_BYTES} bytes: {err}"))?;
    parse_audit_json(&json_bytes)
}

/// Parse uncompressed `cargo-auditable` UTF-8 JSON bytes.
pub fn parse_audit_json(json_bytes: &[u8]) -> Result<RustAuditInfo, String> {
    let raw: RawAuditManifest =
        serde_json::from_slice(json_bytes).map_err(|e| format!("invalid .dep-v0 JSON schema: {e}"))?;

    let mut referenced = vec![false; raw.packages.len()];
    for pkg in &raw.packages {
        for &dep_idx in &pkg.dependencies {
            if let Some(slot) = referenced.get_mut(dep_idx) {
                *slot = true;
            }
        }
    }
    let explicit_root = raw.packages.iter().position(|p| p.root);
    let fallback_root = explicit_root.or_else(|| {
        raw.packages
            .iter()
            .enumerate()
            .find(|(idx, p)| !referenced[*idx] && p.kind.as_deref().unwrap_or("runtime") == "runtime")
            .map(|(idx, _)| idx)
    });

    let mut runtime_count = 0usize;
    let mut build_count = 0usize;
    let mut root_name = None;
    let mut root_version = None;
    let mut packages = Vec::with_capacity(raw.packages.len());

    for (idx, pkg) in raw.packages.into_iter().enumerate() {
        let kind = pkg.kind.unwrap_or_else(|| "runtime".to_owned());
        if kind == "build" {
            build_count += 1;
        } else {
            runtime_count += 1;
        }
        let is_root = pkg.root || fallback_root == Some(idx);
        if is_root && root_name.is_none() {
            root_name = Some(pkg.name.clone());
            root_version = Some(pkg.version.clone());
        }
        packages.push(RustPackage {
            name: pkg.name,
            version: pkg.version,
            source: pkg.source,
            kind,
            root: is_root,
            dependency_count: pkg.dependencies.len(),
        });
    }
    packages
        .sort_by(|a, b| b.root.cmp(&a.root).then_with(|| a.name.cmp(&b.name)).then_with(|| a.version.cmp(&b.version)));

    Ok(RustAuditInfo { format: raw.format, root_name, root_version, runtime_count, build_count, packages })
}
