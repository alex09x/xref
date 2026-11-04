/*
 * XRef — `field` serialized-key search exposed through the query API and MCP
 * Copyright (c) 2026 Alexander Panasenko
 * Contact: alex@prod.codes
 * Author: https://prod.codes/about/
 * Project: https://github.com/alex09x/xref
 * SPDX-License-Identifier: MIT OR Apache-2.0
 */

//! In the MCP server the image stays loaded and the field search keeps its key-independent state
//! (whole-image scan, writer index, analyzed functions) between queries, so a new key set or filter
//! costs only key matching, context selection and ranking (#76).

use super::{Analysis, ApiError, field_types::FieldSearchRequest};
use crate::serde_fields::{FieldOptions, WriterRoot};
use sha2::Digest as _;

/// Accessor rows by default: 64 full rows can exceed the MCP response budget on large binaries.
const API_DEFAULT_LIMIT: usize = 16;

fn writer_root(name: Option<&str>) -> Result<WriterRoot, ApiError> {
    match name.unwrap_or("any") {
        "any" => Ok(WriterRoot::Any),
        "argument" => Ok(WriterRoot::Argument),
        "returned" => Ok(WriterRoot::Returned),
        "loaded" => Ok(WriterRoot::Loaded),
        other => Err(ApiError::new(
            "invalid_request",
            format!("writer_root `{other}` must be any, argument, returned or loaded"),
        )),
    }
}

impl Analysis {
    /// SHA-256 of the image without waiting on another thread's hashing: the lock is held only to read
    /// or store 32 bytes, never while hashing, so the warm-up and the first query may each compute it
    /// once but neither waits for the other.
    pub(in crate::api) fn image_digest(&self) -> [u8; 32] {
        let known = *self.field_digest.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        if let Some(digest) = known {
            return digest;
        }
        let digest: [u8; 32] = sha2::Sha256::digest(&self.image.data).into();
        self.field_digest.lock().unwrap_or_else(std::sync::PoisonError::into_inner).get_or_insert(digest);
        digest
    }

    /// Prepare the `field` session state in the background (called when the MCP server starts).
    #[cfg_attr(test, allow(dead_code))]
    pub fn warm_field_session(&self) {
        let digest = self.image_digest();
        crate::serde_fields::with_image_digest(&self.image.data, digest, || {
            crate::serde_fields::warm_session(&self.image);
        });
    }

    pub(in crate::api) fn field_search(&self, request: &FieldSearchRequest) -> Result<serde_json::Value, ApiError> {
        if request.keys.is_empty() || request.keys.len() > 16 {
            return Err(ApiError::new("invalid_request", "field requires 1..=16 keys"));
        }
        let writer_options = request.write || !request.writes_all_of.is_empty();
        let root = writer_root(request.writer_root.as_deref())?;
        if request.layout_only && (writer_options || root != WriterRoot::Any) {
            return Err(ApiError::new(
                "invalid_request",
                "layout_only skips the writer search; it conflicts with write, writes_all_of and writer_root",
            ));
        }
        if root != WriterRoot::Any && !writer_options {
            return Err(ApiError::new("invalid_request", "writer_root requires write or writes_all_of"));
        }
        let defaults = FieldOptions::default();
        let options = FieldOptions {
            min_offsets: request.min_offsets.unwrap_or(defaults.min_offsets),
            write_only: writer_options,
            writes_all_of: request.writes_all_of.clone(),
            writer_root: root,
            limit: request.limit.unwrap_or(API_DEFAULT_LIMIT),
            layout_only: request.layout_only,
            min_keys: request.min_keys,
            exhaustive_key_seeds: request.exhaustive_key_seeds,
            max_functions: request.max_functions.unwrap_or(defaults.max_functions),
            max_instructions: request.max_instructions.unwrap_or(defaults.max_instructions),
        };
        let digest = self.image_digest();
        let mut report = Vec::new();
        crate::serde_fields::with_image_digest(&self.image.data, digest, || {
            crate::serde_fields::field_by_keys(&self.image, &request.keys, None, true, &options, &mut report)
        })
        .map_err(|error| ApiError::new("invalid_request", error.to_string()))?;
        serde_json::from_slice(&report).map_err(|error| ApiError::new("internal_error", error.to_string()))
    }
}
