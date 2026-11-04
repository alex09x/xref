/*
 * XRef Code — Versioned binary analysis queries
 * Copyright (c) 2026 Alexander Panasenko
 * Contact: alex@prod.codes
 * Author: https://prod.codes/about/
 * Project: https://github.com/alex09x/xref
 * SPDX-License-Identifier: MIT OR Apache-2.0
 */

mod callers;
mod context;
mod field_types;
mod investigate;
mod operations;
mod paging;
mod render;
mod symbolize;
pub mod types;

use crate::image::Image;
use sha2::{Digest, Sha256};
use std::fmt::Write as _;
use std::{
    fs::File,
    io::{Read, Write},
    path::Path,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
};
use types::{ApiError, Data, FunctionInfo, ImageIdentity, Pagination, Query, Response};

pub const MAX_IMAGE_BYTES: u64 = 256 * 1024 * 1024;
pub const MAX_RESPONSE_BYTES: usize = 65536;
const MAX_FUNCTION_BYTES: u64 = 32768;

#[derive(Clone, Default)]
pub struct Cancellation(Arc<AtomicBool>);
impl Cancellation {
    pub fn cancel(&self) {
        self.0.store(true, Ordering::Relaxed);
    }
    pub fn flag(&self) -> &AtomicBool {
        &self.0
    }
    pub fn checkpoint(&self) -> Result<(), ApiError> {
        if self.0.load(Ordering::Relaxed) { Err(ApiError::new("cancelled", "query cancelled")) } else { Ok(()) }
    }
}

pub struct Analysis {
    image: Image,
    identity: ImageIdentity,
    base: u64,
}

impl ApiError {
    pub fn new(code: &'static str, message: impl AsRef<str>) -> Self {
        Self { code, message: clipped(message.as_ref(), 512).0 }
    }
}

impl std::fmt::Display for ApiError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}: {}", self.code, self.message)
    }
}
impl std::error::Error for ApiError {}

pub fn clipped(text: &str, limit: usize) -> (String, bool) {
    let mut end = text.len().min(limit);
    while !text.is_char_boundary(end) {
        end -= 1;
    }
    (text[..end].to_owned(), end < text.len())
}

impl Response {
    fn success(
        operation: &str,
        image: ImageIdentity,
        data: Data,
        page: Option<Pagination>,
        warnings: Vec<&'static str>,
    ) -> Self {
        Self {
            schema_version: 1,
            tool: "xref",
            tool_version: env!("CARGO_PKG_VERSION"),
            build_revision: option_env!("XREF_BUILD_COMMIT"),
            image: Some(image),
            operation: operation.to_owned(),
            data: Some(data),
            error: None,
            warnings,
            page,
        }
    }

    pub fn failure(operation: &str, image: Option<ImageIdentity>, error: ApiError) -> Self {
        Self {
            schema_version: 1,
            tool: "xref",
            tool_version: env!("CARGO_PKG_VERSION"),
            build_revision: option_env!("XREF_BUILD_COMMIT"),
            image,
            operation: operation.to_owned(),
            data: None,
            error: Some(error),
            warnings: Vec::new(),
            page: None,
        }
    }

    pub fn json(&self) -> serde_json::Value {
        let Ok(value) = serde_json::to_value(self) else {
            return self.small_error("serialization_failed", "could not encode the query result");
        };
        if value.to_string().len() <= MAX_RESPONSE_BYTES {
            return value;
        }
        self.small_error("response_too_large", "reduce the page limit")
    }

    fn small_error(&self, code: &str, message: &str) -> serde_json::Value {
        serde_json::json!({"schema_version":1,"tool":"xref","tool_version":env!("CARGO_PKG_VERSION"),
            "build_revision":option_env!("XREF_BUILD_COMMIT"),"image":self.image,"operation":self.operation,"data":null,
            "error":{"code":code,"message":message},"warnings":[],"page":null})
    }
}

impl Analysis {
    pub fn open(path: &Path) -> Result<Self, ApiError> {
        let file = File::open(path).map_err(|e| ApiError::new("image_read_failed", e.to_string()))?;
        let mut data = Vec::new();
        file.take(MAX_IMAGE_BYTES + 1)
            .read_to_end(&mut data)
            .map_err(|e| ApiError::new("image_read_failed", e.to_string()))?;
        if data.len() as u64 > MAX_IMAGE_BYTES {
            return Err(ApiError::new("image_too_large", "maximum image size is 256 MiB"));
        }
        let mut sha256 = String::with_capacity(64);
        for byte in Sha256::digest(&data) {
            let _ = write!(sha256, "{byte:02x}");
        }
        let image = Image::parse(data).map_err(|e| {
            let unsupported = e.downcast_ref::<crate::image_format::InputError>().is_some_and(|e| e.unsupported);
            ApiError::new(if unsupported { "unsupported_image" } else { "invalid_image" }, e.to_string())
        })?;
        let base = image.metadata.base;
        let identity = ImageIdentity {
            sha256,
            bytes: image.data.len(),
            format: image.metadata.format(),
            architecture: "x86_64",
            base_address: format!("{base:#x}"),
            rva_basis: image.metadata.rva_basis(),
        };
        Ok(Self { image, identity, base })
    }

    pub fn query(&self, query: &Query, cancellation: &Cancellation) -> Response {
        let operation = query.name();
        match cancellation.checkpoint().and_then(|()| self.execute(query, cancellation)).and_then(|output| {
            cancellation.checkpoint()?;
            Ok(output)
        }) {
            Ok((data, page, mut warnings)) => {
                warnings.extend(self.image.metadata.warnings.iter().copied());
                if page.as_ref().is_some_and(|p| !p.complete && p.next_offset.is_none()) {
                    warnings.push("pagination_window_exhausted");
                }
                Response::success(operation, self.identity.clone(), data, page, warnings)
            }
            Err(error) => Response::failure(operation, Some(self.identity.clone()), error),
        }
    }

    pub fn failure(&self, operation: &str, error: ApiError) -> Response {
        Response::failure(operation, Some(self.identity.clone()), error)
    }

    #[must_use]
    pub const fn identity(&self) -> &ImageIdentity {
        &self.identity
    }

    fn address(text: &str) -> Result<u64, ApiError> {
        let digits = text.strip_prefix("0x").filter(|s| !s.is_empty() && s.len() <= 16).ok_or_else(|| {
            ApiError::new("invalid_address", "addresses must be hexadecimal strings starting with 0x")
        })?;
        u64::from_str_radix(digits, 16).map_err(|_| ApiError::new("invalid_address", "invalid hexadecimal address"))
    }

    fn function(&self, text: &str) -> Result<std::ops::Range<u64>, ApiError> {
        let address = Self::address(text)?;
        let range = self
            .image
            .function_at(address)
            .ok_or_else(|| ApiError::new("no_function", "no unwind function range covers this address"))?;
        if range.start < self.base || self.image.code(&range).is_none() {
            return Err(ApiError::new("invalid_function_range", "unwind range is not backed by mapped file bytes"));
        }
        Ok(range)
    }

    fn function_info(&self, range: &std::ops::Range<u64>) -> FunctionInfo {
        let name =
            self.image.symbols.iter().find(|(address, _)| *address == range.start).map(|(_, name)| clipped(name, 128));
        FunctionInfo {
            start: format!("{:#x}", range.start),
            end: format!("{:#x}", range.end),
            rva: format!("{:#x}", range.start.saturating_sub(self.base)),
            size_bytes: range.end.saturating_sub(range.start),
            range_origin: "eh_frame_fde",
            symbol: name.as_ref().map(|n| n.0.clone()),
            symbol_truncated: name.is_some_and(|n| n.1),
        }
    }
}

type Output = Result<(Data, Option<Pagination>, Vec<&'static str>), ApiError>;

pub fn run_cli(path: &Path, request: &str, out: &mut dyn Write) -> Result<bool, std::io::Error> {
    let response = if request.len() > 65536 {
        Response::failure("invalid_request", None, ApiError::new("invalid_request", "request exceeds 64 KiB"))
    } else {
        match serde_json::from_str::<Query>(request) {
            Err(e) => Response::failure("invalid_request", None, ApiError::new("invalid_request", e.to_string())),
            Ok(query) => match Analysis::open(path) {
                Ok(analysis) => analysis.query(&query, &Cancellation::default()),
                Err(e) => Response::failure(query.name(), None, e),
            },
        }
    };
    let value = response.json();
    writeln!(out, "{value}")?;
    out.flush()?;
    Ok(value["error"].is_null())
}

#[cfg(test)]
mod tests;
