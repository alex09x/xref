/*
 * XRef Code — Structured reverse call evidence
 * Copyright (c) 2026 Alexander Panasenko
 * Contact: alex@prod.codes
 * Author: https://prod.codes/about/
 * Project: https://github.com/alex09x/xref
 * SPDX-License-Identifier: MIT OR Apache-2.0
 */

use super::{Analysis, ApiError, Cancellation, Output, types::Page};

impl Analysis {
    pub(super) fn callers(&self, _address: &str, _page: &Page, cancel: &Cancellation) -> Output {
        cancel.checkpoint()?;
        Err(ApiError::new("not_implemented", "reverse call query implementation is pending"))
    }
}
