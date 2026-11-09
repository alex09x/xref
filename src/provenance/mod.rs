/*
 * XRef Code — Binary provenance, embedded dependency manifests, and toolchain metadata
 * Copyright (c) 2026 Alexander Panasenko
 *
 * Contact: alex@prod.codes
 * Author: https://prod.codes/about/
 * Project: https://github.com/alex09x/xref
 * SPDX-License-Identifier: MIT OR Apache-2.0
 */

//! Provenance extraction for ELF and Mach-O images: Rust `.dep-v0` (`cargo-auditable`),
//! Go `.go.buildinfo`, compiler/linker `.comment` strings, GNU Build-ID, and high-entropy
//! packed executable section detection.

pub mod cli;
pub mod go_buildinfo;
pub mod rust_deps;
pub mod toolchain;

#[cfg(test)]
mod tests;

use object::{Object, ObjectSection};

use self::go_buildinfo::GoBuildInfo;
use self::rust_deps::RustAuditInfo;
use self::toolchain::HighEntropySection;
use crate::image::Image;

/// Unified provenance snapshot recovered from an immutable binary image.
#[derive(Clone, Debug, Default)]
pub struct ProvenanceSummary {
    pub build_id: Option<String>,
    pub toolchains: Vec<String>,
    pub rust_audit: Option<RustAuditInfo>,
    pub rust_audit_error: Option<String>,
    pub go_build: Option<GoBuildInfo>,
    pub has_gopclntab: bool,
    pub high_entropy_executable: Vec<HighEntropySection>,
}

/// Extract all provenance signals from `image`. Never fails on malformed optional metadata.
#[must_use]
pub fn inspect(image: &Image) -> ProvenanceSummary {
    let build_id = toolchain::hex_build_id(image.metadata.build_id.as_deref());
    let parsed = object::File::parse(image.data.as_slice()).ok();

    let toolchains = parsed.as_ref().map_or_else(Vec::new, toolchain::extract_comments);
    let (rust_audit, rust_audit_error) = match parsed.as_ref().map(rust_deps::extract_from_object) {
        Some(Ok(info)) => (info, None),
        Some(Err(err)) => (None, Some(err)),
        None => (None, None),
    };
    let go_build = go_buildinfo::extract(image, parsed.as_ref());
    let has_gopclntab = parsed.as_ref().is_some_and(|file| {
        file.sections()
            .filter_map(|sec| sec.name().ok())
            .any(|name| matches!(name, ".gopclntab" | "__gopclntab" | ".gosymtab"))
    });
    let high_entropy_executable = toolchain::detect_high_entropy_executable(image, parsed.as_ref());

    ProvenanceSummary {
        build_id,
        toolchains,
        rust_audit,
        rust_audit_error,
        go_build,
        has_gopclntab,
        high_entropy_executable,
    }
}

/// Classify the primary implementation language from recovered provenance, panic locations, and symbols.
#[must_use]
pub fn detect_language(image: &Image, panic_locations: usize, prov: &ProvenanceSummary) -> &'static str {
    if prov.rust_audit.is_some()
        || panic_locations > 0
        || prov.toolchains.iter().any(|t| t.contains("rustc"))
        || image.symbols.iter().any(|(_, s)| s.starts_with("_RNv") || s.contains("17h"))
    {
        return "rust";
    }
    if prov.go_build.is_some()
        || prov.has_gopclntab
        || image.symbols.iter().any(|(_, s)| s.starts_with("runtime.") || s.starts_with("go:"))
    {
        return "go";
    }
    if image.symbols.iter().any(|(_, s)| s.starts_with("_Z"))
        || image.imports.iter().any(|(_, s)| {
            s.starts_with("_Z")
                || s.contains("__gxx_personality")
                || s.contains("__cxa_throw")
                || s.contains("__cxa_begin_catch")
        })
    {
        return "cpp";
    }
    if image.functions.is_empty() && image.segments.is_empty() {
        return "unknown";
    }
    "c_or_native"
}
