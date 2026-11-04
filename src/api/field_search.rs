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
    pub(in crate::api) fn field_search(&self, request: &FieldSearchRequest) -> Result<serde_json::Value, ApiError> {
        if request.keys.is_empty() || request.keys.len() > 16 {
            return Err(ApiError::new("invalid_request", "field requires 1..=16 keys"));
        }
        let defaults = FieldOptions::default();
        let options = FieldOptions {
            min_offsets: request.min_offsets.unwrap_or(defaults.min_offsets),
            write_only: request.write || !request.writes_all_of.is_empty(),
            writes_all_of: request.writes_all_of.clone(),
            writer_root: writer_root(request.writer_root.as_deref())?,
            limit: request.limit.unwrap_or(API_DEFAULT_LIMIT),
            layout_only: request.layout_only,
            min_keys: request.min_keys,
            exhaustive_key_seeds: request.exhaustive_key_seeds,
            max_functions: request.max_functions.unwrap_or(defaults.max_functions),
            max_instructions: request.max_instructions.unwrap_or(defaults.max_instructions),
        };
        let digest = *self.field_digest.get_or_init(|| sha2::Sha256::digest(&self.image.data).into());
        let mut report = Vec::new();
        crate::serde_fields::with_image_digest(&self.image.data, digest, || {
            crate::serde_fields::field_by_keys(&self.image, &request.keys, None, true, &options, &mut report)
        })
        .map_err(|error| ApiError::new("invalid_request", error.to_string()))?;
        serde_json::from_slice(&report).map_err(|error| ApiError::new("internal_error", error.to_string()))
    }
}
