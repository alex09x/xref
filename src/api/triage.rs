/*
 * XRef Code — First-contact binary triage, confidence mapping, and evidence hashing
 * Copyright (c) 2026 Alexander Panasenko
 *
 * Contact: alex@prod.codes
 * Author: https://prod.codes/about/
 * Project: https://github.com/alex09x/xref
 * SPDX-License-Identifier: MIT OR Apache-2.0
 */

use std::collections::BTreeSet;
use std::fmt::Write as _;

use serde_json::json;
use sha2::{Digest, Sha256};

use super::agentic_types::{Confidence, EmbeddedDepsSummary, RecommendedQuery, TriageSummary};
use super::types::{Data, Query};
use crate::image::Image;
use crate::locations::locations;
use crate::provenance::{detect_language, inspect};

/// The largest function a `card` is suggested for without an entry point: its card stays small.
const MAX_SUGGESTED_CARD_BYTES: u64 = 0x1_0000;

/// Build the auto-triage summary and optional packer warning for `Query::Info`.
#[must_use]
pub fn build_triage(image: &Image) -> (TriageSummary, Vec<&'static str>) {
    let locs = locations(image);
    let unique_files: BTreeSet<&str> = locs.iter().map(|l| l.file.as_str()).collect();
    let prov = inspect(image);
    let language = detect_language(image, locs.len(), &prov);
    let stripped = image.symbols.is_empty();

    let embedded_dependencies = if let Some(rust) = &prov.rust_audit {
        Some(EmbeddedDepsSummary {
            ecosystem: "rust",
            root_package: rust.root_name.clone(),
            root_version: rust.root_version.clone(),
            go_version: None,
            count: rust.packages.len(),
        })
    } else {
        prov.go_build.as_ref().map(|go| {
            let (root_package, root_version) = go
                .main_module
                .as_ref()
                .map_or_else(|| (go.path.clone(), None), |(m, v)| (Some(m.clone()), Some(v.clone())));
            EmbeddedDepsSummary {
                ecosystem: "go",
                root_package,
                root_version,
                go_version: Some(go.go_version.clone()),
                count: go.deps.len(),
            }
        })
    };

    let high_entropy_executable = !prov.high_entropy_executable.is_empty();
    let mut warnings = Vec::new();
    if high_entropy_executable {
        warnings.push("high_entropy_executable_possible_packer");
    }

    let mut recommended_queries = Vec::new();
    if embedded_dependencies.is_some() {
        recommended_queries.push(RecommendedQuery {
            reason: "inspect_embedded_dependency_manifest",
            request: json!({"operation": "dependencies", "page": {"limit": 50}}),
        });
    }
    if !locs.is_empty() {
        recommended_queries.push(RecommendedQuery {
            reason: "map_recovered_rust_source_files",
            request: json!({"operation": "files", "page": {"limit": 50}}),
        });
    }
    if let Some(entry_fn) = image.metadata.entry.and_then(|e| image.function_at(e)) {
        recommended_queries.push(RecommendedQuery {
            reason: "summarize_entry_function_card",
            request: json!({"operation": "card", "address": format!("{:#x}", entry_fn.start)}),
        });
    } else if let Some(largest) =
        image.functions.iter().filter(|f| f.end - f.start <= MAX_SUGGESTED_CARD_BYTES).max_by_key(|f| f.end - f.start)
    {
        recommended_queries.push(RecommendedQuery {
            reason: "summarize_largest_function_card",
            request: json!({"operation": "card", "address": format!("{:#x}", largest.start)}),
        });
    }
    if stripped && locs.is_empty() {
        recommended_queries.push(RecommendedQuery {
            reason: "anchor_stripped_binary_via_diagnostic_strings",
            request: json!({"operation": "strings", "text": "error"}),
        });
    } else if !image.functions.is_empty() {
        recommended_queries.push(RecommendedQuery {
            reason: "search_functions_by_multi_predicate_filter",
            request: json!({"operation": "find", "size": "256..4096", "page": {"limit": 20}}),
        });
    }

    (
        TriageSummary {
            language,
            stripped,
            panic_locations: locs.len(),
            source_files: unique_files.len(),
            build_id: prov.build_id,
            toolchains: prov.toolchains,
            embedded_dependencies,
            high_entropy_executable,
            recommended_queries,
        },
        warnings,
    )
}

/// Map each structured query operation to its epistemic confidence tier.
#[must_use]
pub const fn query_confidence(query: &Query) -> Confidence {
    match query {
        Query::Info { .. }
        | Query::Strings { .. }
        | Query::Function { .. }
        | Query::Asm { .. }
        | Query::Dependencies { .. }
        | Query::Files { .. } => Confidence::Observed,
        Query::Refs { .. }
        | Query::Calls { .. }
        | Query::Callers { .. }
        | Query::Symbolize { .. }
        | Query::Find { .. }
        | Query::Where { .. } => Confidence::Derived,
        Query::CallContext { .. }
        | Query::Investigate { .. }
        | Query::FieldOrigin { .. }
        | Query::C { .. }
        | Query::Field { .. }
        | Query::Slice { .. }
        | Query::Card { .. }
        | Query::Layout { .. } => Confidence::Inferred,
    }
}

/// Compute a deterministic, verifiable citation digest (`ev_<16 hex>`) over image identity + operation + data.
#[must_use]
pub fn compute_evidence_id(image_sha256: &str, operation: &str, data: &Data) -> Option<String> {
    let encoded = serde_json::to_vec(data).ok()?;
    let mut hasher = Sha256::new();
    hasher.update(b"xref:evidence:v1\0");
    hasher.update(image_sha256.as_bytes());
    hasher.update(b"\0");
    hasher.update(operation.as_bytes());
    hasher.update(b"\0");
    hasher.update(&encoded);
    let digest = hasher.finalize();
    let mut id = String::with_capacity(19);
    id.push_str("ev_");
    for &byte in &digest[..8] {
        let _ = write!(id, "{byte:02x}");
    }
    Some(id)
}
