/*
 * XRef — Whole-binary command reports (origin, callargs, data) as paged structured text
 * Copyright (c) 2026 Alexander Panasenko
 * Contact: alex@prod.codes
 * Author: https://prod.codes/about/
 * Project: https://github.com/alex09x/xref
 * SPDX-License-Identifier: MIT OR Apache-2.0
 */

//! `origin`, `callargs` and `data` answer with the same report the CLI prints, paged by UTF-8
//! bytes like pseudo-C: an agent reads the evidence the human reads, with continuation offsets.

use super::types::{Data, Pagination, TextPage};
use super::{Analysis, ApiError, Cancellation, Output};
use crate::cli::Command;

/// Rendered report bytes at most.
const MAX_REPORT_BYTES: usize = 2 * 1024 * 1024;
/// Elements one `data` query reads at most.
const MAX_DATA_COUNT: usize = 4096;
/// Bytes one `data` string may run to at most.
const MAX_DATA_STRING: usize = 65_536;

/// The page of `text` that `page` asks for, its pagination and whether it is a fragment.
pub(super) fn page_text(text: &str, page: &TextPage) -> Result<(String, Pagination, bool), ApiError> {
    if page.offset > text.len() || !text.is_char_boundary(page.offset) {
        return Err(ApiError::new("invalid_offset", "offset must name a UTF-8 boundary within the text"));
    }
    let mut end = text.len().min(page.offset.saturating_add(page.limit));
    while !text.is_char_boundary(end) {
        end -= 1;
    }
    let next_offset = (end < text.len()).then_some(end);
    let meta = Pagination {
        unit: "utf8_bytes",
        offset: page.offset,
        returned: end - page.offset,
        next_offset,
        complete: next_offset.is_none(),
    };
    Ok((text[page.offset..end].to_owned(), meta, page.offset > 0 || next_offset.is_some()))
}

impl Analysis {
    /// The text report of `command` (a CLI command over the whole image), one page of it.
    pub(super) fn report(
        &self,
        name: &'static str,
        command: Command,
        page: &TextPage,
        cancel: &Cancellation,
    ) -> Output {
        if !(4..=16384).contains(&page.limit) {
            return Err(ApiError::new("invalid_page", "text limit must be 4..16384 bytes"));
        }
        cancel.checkpoint()?;
        let mut out = Vec::new();
        crate::commands::run(&self.image, command, &mut out)
            .map_err(|e| ApiError::new("report_failed", e.to_string()))?;
        cancel.checkpoint()?;
        if out.len() > MAX_REPORT_BYTES {
            return Err(ApiError::new("report_too_large", "the report exceeds 2 MiB; narrow the request"));
        }
        let text = String::from_utf8(out).map_err(|e| ApiError::new("report_failed", e.to_string()))?;
        let (page_text, meta, fragment) = page_text(&text, page)?;
        // `data` prints the bytes as they are; the other reports are reconstructions.
        let mut warnings = if name == "data" { Vec::new() } else { vec!["heuristic_reconstruction"] };
        if fragment {
            warnings.push("text_is_a_fragment");
        }
        Ok((Data::Report { command: name, text: page_text, total_bytes: text.len(), fragment }, Some(meta), warnings))
    }

    /// `origin`: candidate checks that build an error message.
    pub(super) fn origin_report(&self, query: &OriginQuery, page: &TextPage, cancel: &Cancellation) -> Output {
        if query.target.is_empty() || query.target.len() > 256 {
            return Err(ApiError::new("invalid_text", "target must contain 1..256 UTF-8 bytes"));
        }
        if query.back > 64 || query.depth > 8 || !(1..=64).contains(&query.limit) || query.arg_depth > 8 {
            return Err(ApiError::new("invalid_request", "back <= 64, depth <= 8, limit 1..64 and arg_depth <= 8"));
        }
        let command = Command::Origin {
            target: query.target.clone(),
            back: query.back,
            depth: query.depth,
            limit: query.limit,
            slice: query.slice,
            arg_depth: query.arg_depth,
        };
        self.report("origin", command, page, cancel)
    }

    /// `callargs`: call sites passing a constant, grouped by callee.
    pub(super) fn callargs_report(&self, query: &CallargsQuery, page: &TextPage, cancel: &Cancellation) -> Output {
        let value = query.value.value().map_err(|e| ApiError::new("invalid_number", e))?;
        let arg = query
            .arg
            .as_deref()
            .map(crate::callargs::Slot::parse)
            .transpose()
            .map_err(|e| ApiError::new("invalid_argument", e))?;
        if !(1..=1000).contains(&query.limit) || query.callee.as_ref().is_some_and(|c| c.is_empty() || c.len() > 256) {
            return Err(ApiError::new("invalid_request", "limit 1..1000; callee 1..256 bytes"));
        }
        let command = Command::Callargs { value, arg, callee: query.callee.clone(), limit: query.limit };
        self.report("callargs", command, page, cancel)
    }

    /// `data`: typed values at a virtual address.
    pub(super) fn data_report(&self, query: &DataQuery, page: &TextPage, cancel: &Cancellation) -> Output {
        let va = crate::cli::parse_number(&query.address).map_err(|e| ApiError::new("invalid_address", e))?;
        let as_type = <crate::data::DataType as clap::ValueEnum>::from_str(&query.r#as, true)
            .map_err(|e| ApiError::new("invalid_type", e))?;
        // Bounded before reading: the report is built in memory, and a string read may run to
        // `max_len` bytes for each of `count` elements.
        let count = query.count.unwrap_or(1);
        let string_bytes =
            if matches!(as_type, crate::data::DataType::Str) { count.saturating_mul(query.max_len) } else { 0 };
        if !(1..=MAX_DATA_COUNT).contains(&count)
            || !(1..=MAX_DATA_STRING).contains(&query.max_len)
            || string_bytes > MAX_REPORT_BYTES
        {
            return Err(ApiError::new(
                "invalid_request",
                "count must be 1..4096, max_len 1..65536, and count * max_len at most 2 MiB for str",
            ));
        }
        let command = Command::Data { va, as_type, count: query.count, max_len: query.max_len };
        self.report("data", command, page, cancel)
    }
}

/// Arguments of `operation = "origin"` (as `xref origin`).
#[derive(Clone, Debug, serde::Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct OriginQuery {
    /// Text (or part of it) the error message contains, or an address inside its `Display` arm.
    pub target: String,
    /// Also accept references this many bytes before the text (default 1).
    #[serde(default = "one")]
    pub back: u64,
    /// Conversion levels followed from the message's enum inward (default 3).
    #[serde(default = "three")]
    pub depth: usize,
    /// Sites rendered with their guarding pseudo-C (default 12).
    #[serde(default = "twelve")]
    pub limit: usize,
    /// Also print the backward slice of every rendered site.
    #[serde(default)]
    pub slice: bool,
    /// Calls a passed tag is followed through after the function it is passed to (default 3).
    #[serde(default = "three")]
    pub arg_depth: usize,
}

/// Arguments of `operation = "callargs"` (as `xref callargs`).
#[derive(Clone, Debug, serde::Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct CallargsQuery {
    /// The constant: a number, or a decimal or `0x` string.
    pub value: super::types::Integer,
    /// Only this argument: rdi, rsi, rdx, rcx, r8, r9 or stack0..stack7.
    #[serde(default)]
    pub arg: Option<String>,
    /// Only calls to this function (address or symbol name).
    #[serde(default)]
    pub callee: Option<String>,
    /// Call sites listed; every callee is summarized (default 100).
    #[serde(default = "hundred")]
    pub limit: usize,
}

/// Arguments of `operation = "data"` (as `xref data`).
#[derive(Clone, Debug, serde::Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct DataQuery {
    /// Virtual address (`0x...` hex or decimal).
    pub address: String,
    /// f64, f32, u64, u32, u16, u8, i64, i32, i16, i8, bytes or str.
    pub r#as: String,
    /// Elements to read (byte count for bytes; default 1, or 64 for bytes).
    #[serde(default)]
    pub count: Option<usize>,
    /// Maximum string length up to the first NUL (default 256).
    #[serde(default = "two_fifty_six")]
    pub max_len: usize,
}

const fn one() -> u64 {
    1
}
const fn three() -> usize {
    3
}
const fn twelve() -> usize {
    12
}
const fn hundred() -> usize {
    100
}
const fn two_fifty_six() -> usize {
    256
}
