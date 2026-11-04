/*
 * XRef — Read-only inline symbolization for JSON and MCP
 * Copyright (c) 2026 Alexander Panasenko
 * Contact: alex@prod.codes
 * Author: https://prod.codes/about/
 * Project: https://github.com/alex09x/xref
 * SPDX-License-Identifier: MIT OR Apache-2.0
 */
use super::{Analysis, ApiError, Cancellation, Data, Output};
use crate::{
    trace_analysis::{batch::symbolize_batch, models::SymbolizeRequest},
    trace_frontend::adapter::build_index,
};

impl Analysis {
    pub(super) fn symbolize(&self, request: &SymbolizeRequest, cancel: &Cancellation) -> Output {
        cancel.checkpoint()?;
        let index = build_index(&self.image, Some(cancel.flag()));
        cancel.checkpoint()?;
        let index = index.map_err(|message| ApiError::new("analysis_failed", message))?;
        let result = symbolize_batch(&index, request, Some(cancel.flag()));
        cancel.checkpoint()?;
        let result = result.map_err(|message| ApiError::new("invalid_request", message))?;
        Ok((Data::Symbolize { result: Box::new(result) }, None, vec![]))
    }
}
