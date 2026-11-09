/*
 * XRef Code — Bounded pseudo-C and slice payloads
 * Copyright (c) 2026 Alexander Panasenko
 * Contact: alex@prod.codes
 * Author: https://prod.codes/about/
 * Project: https://github.com/alex09x/xref
 * SPDX-License-Identifier: MIT OR Apache-2.0
 */

use super::{
    Analysis, ApiError, Cancellation, MAX_FUNCTION_BYTES, Output,
    types::{Data, TextPage},
};
use crate::{
    c::{COptions, c_one_options},
    fields_c::apply_field_sugar,
    locations::locations,
    runtime::RuntimeMap,
    slice::slice_fn_with_mode,
};

impl Analysis {
    pub(super) fn render(
        &self,
        address: &str,
        target: Option<&str>,
        fields: bool,
        options: COptions,
        page: &TextPage,
        cancel: &Cancellation,
    ) -> Output {
        if !(4..=16384).contains(&page.limit) {
            return Err(ApiError::new("invalid_page", "text limit must be 4..16384 bytes"));
        }
        let function = self.function(address)?;
        if function.end.saturating_sub(function.start) > MAX_FUNCTION_BYTES {
            return Err(ApiError::new("function_too_large", "pseudo-C and slices support functions up to 32 KiB"));
        }
        if target.is_some_and(|t| t.is_empty() || t.len() > 256) {
            return Err(ApiError::new("invalid_target", "slice target must contain 1..256 bytes"));
        }
        cancel.checkpoint()?;
        let text = if let Some(target) = target {
            let mut out = Vec::new();
            slice_fn_with_mode(
                &self.image,
                &format!("{:#x}", function.start),
                target,
                fields,
                options.keep_gotos,
                &mut out,
            )
            .map_err(|e| ApiError::new("slice_failed", e.to_string()))?;
            String::from_utf8(out).map_err(|e| ApiError::new("render_failed", e.to_string()))?
        } else {
            let (locs, runtime) = (locations(&self.image), RuntimeMap::detect(&self.image));
            cancel.checkpoint()?;
            let (_, raw) = c_one_options(&self.image, &locs, &runtime, function.start, options)
                .map_err(|e| ApiError::new("render_failed", e))?;
            if fields { apply_field_sugar(&self.image, &function, &raw) } else { raw }
        };
        cancel.checkpoint()?;
        if text.len() > 2 * 1024 * 1024 {
            return Err(ApiError::new("render_too_large", "rendered text exceeds 2 MiB"));
        }
        let (shown, meta, fragment) = super::reports::page_text(&text, page)?;
        let mut warnings =
            vec!["heuristic_reconstruction", "fde_range_is_not_source_function", "cancellation_between_render_phases"];
        if fragment {
            warnings.push("text_is_a_fragment");
        }
        Ok((
            Data::Text {
                format: if target.is_some() { "slice" } else { "pseudo_c" },
                function: self.function_info(&function),
                text: shown,
                total_bytes: text.len(),
                fragment,
            },
            Some(meta),
            warnings,
        ))
    }
}
