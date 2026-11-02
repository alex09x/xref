/*
 * XRef Code — evidence-producing binary analysis
 * Copyright (c) 2026 Alexander Panasenko
 * Contact: alex@prod.codes
 * Author: https://prod.codes/about/
 * Project: https://github.com/alex09x/xref
 * SPDX-License-Identifier: MIT OR Apache-2.0
 */
mod run;
#[cfg(test)]
pub mod tests;
pub mod types;

use super::types::{Data, Query};
use super::{Analysis, ApiError, Cancellation, Output};
use types::{Investigation, Request, Step};

struct Trail<'a> {
    analysis: &'a Analysis,
    cancel: &'a Cancellation,
    request: &'a Request,
    result: Investigation,
}
impl<'a> Trail<'a> {
    const fn new(analysis: &'a Analysis, cancel: &'a Cancellation, request: &'a Request) -> Self {
        Self {
            analysis,
            cancel,
            request,
            result: Investigation {
                scope: "bounded_static_fde_graph_not_a_proof_of_absence",
                evidence: vec![],
                string_matches: vec![],
                ambiguities: vec![],
                functions: vec![],
                call_sites: vec![],
                selected: None,
                stops: vec![],
            },
        }
    }
    fn stop(&mut self, reason: &'static str) {
        if !self.result.stops.contains(&reason) {
            self.result.stops.push(reason);
        }
    }
    fn fits(&self) -> bool {
        serde_json::to_vec(&self.result)
            .is_ok_and(|bytes| bytes.len() <= self.request.limits.output_bytes.saturating_sub(512))
    }
    fn query(
        &mut self,
        query: &Query,
        parent: Option<usize>,
        address: Option<String>,
        target: Option<String>,
    ) -> Result<Option<usize>, ApiError> {
        self.cancel.checkpoint()?;
        if self.result.stops.contains(&"output_limit") {
            return Ok(None);
        }
        if self.result.evidence.len() >= self.request.limits.steps {
            self.stop("step_limit");
            return Ok(None);
        }
        let response = self.analysis.query(query, self.cancel);
        if response.error.as_ref().is_some_and(|e| e.code == "cancelled") {
            return Err(ApiError::new("cancelled", "investigation cancelled"));
        }
        if response.page.as_ref().is_some_and(|page| !page.complete) {
            self.stop("row_or_text_limit");
        }
        let id = self.result.evidence.len();
        self.result.evidence.push(Step {
            id,
            parent,
            operation: query.name(),
            address,
            target,
            data: response.data.map(Box::new),
            error: response.error,
            warnings: response.warnings,
            page: response.page,
        });
        if !self.fits() {
            self.result.evidence.pop();
            self.stop("output_limit");
            return Ok(None);
        }
        Ok(Some(id))
    }
}
impl Analysis {
    pub(super) fn investigate(&self, request: &Request, cancel: &Cancellation) -> Output {
        request.limits.validate()?;
        // Every full-image primitive has a deterministic input/work cap for this compound request.
        let bytes = self
            .image
            .functions
            .iter()
            .try_fold(0u64, |sum, r| sum.checked_add(r.end.saturating_sub(r.start)))
            .ok_or_else(|| ApiError::new("scan_budget", "FDE scan work overflows"))?;
        if self.image.functions.len() > 100_000
            || (matches!(request.seed, types::Seed::Text { .. }) && bytes > 64 * 1024 * 1024)
        {
            return Err(ApiError::new(
                "scan_budget",
                "compound inputs support at most 100000 ranges; text-seed reference scans support 64 MiB total range bytes",
            ));
        }
        if let Some(choice) = &request.selection {
            if choice.image_sha256 != self.identity.sha256 {
                return Err(ApiError::new("image_mismatch", "selection belongs to different input bytes"));
            }
            Self::address(&choice.function)?;
            Self::address(&choice.call_site)?;
        }
        if let Some(callee) = &request.callee {
            self.function(callee)?;
        }
        let mut trail = Trail::new(self, cancel, request);
        trail.run()?;
        if trail.result.string_matches.len() > 1 {
            trail.result.ambiguities.push("multiple_string_matches");
        }
        if trail.result.functions.iter().filter(|f| f.depth == 0).count() > 1 {
            trail.result.ambiguities.push("multiple_seed_functions");
        }
        if trail.result.call_sites.len() > 1 {
            trail.result.ambiguities.push("multiple_call_sites");
        }
        if trail.result.call_sites.is_empty() {
            trail.stop("not_found_under_limits");
        } else if trail.result.selected.is_none() {
            trail.stop("selection_required");
        }
        if trail.result.stops.is_empty() {
            trail.stop("bounded_traversal_complete");
        }
        Ok((
            Data::Investigation { investigation: Box::new(trail.result) },
            None,
            vec!["bounded_static_investigation", "unresolved_indirect_targets_and_unwind_gaps_may_hide_relationships"],
        ))
    }
}
