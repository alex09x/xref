/*
 * XRef Code — Structured reverse call evidence
 * Copyright (c) 2026 Alexander Panasenko
 * Contact: alex@prod.codes
 * Author: https://prod.codes/about/
 * Project: https://github.com/alex09x/xref
 * SPDX-License-Identifier: MIT OR Apache-2.0
 */

use super::{
    Analysis, Cancellation, Output, clipped,
    paging::Rows,
    types::{CallRow, CallerRow, Data, Page},
};
use crate::{graph, listing, scan};
use iced_x86::FlowControl;

pub const MAX_SCANNED_BYTES: u64 = 64 * 1024 * 1024;

impl Analysis {
    pub(super) fn callers(&self, address: &str, page: &Page, cancel: &Cancellation) -> Output {
        cancel.checkpoint()?;
        let callee = self.function(address)?;
        let mut rows = Rows::new(page)?;
        let mut unresolved_indirect = 0;
        let mut scanned_bytes: u64 = 0;
        let mut skipped_functions = 0;

        for caller in &self.image.functions {
            cancel.checkpoint()?;
            if caller.start < self.base {
                continue;
            }
            let Some(code) = self.image.code(caller) else {
                continue;
            };
            let code_len = code.len() as u64;
            if scanned_bytes.saturating_add(code_len) > MAX_SCANNED_BYTES {
                skipped_functions += 1;
                continue;
            }
            scanned_bytes = scanned_bytes.saturating_add(code_len);

            scan::decode(code, caller.start, |ins| {
                if cancel.checkpoint().is_err() {
                    return;
                }
                let is_call_branch = listing::is_call(ins, caller);
                if is_call_branch {
                    if let Some(target) = graph::call_target(&self.image, ins) {
                        if let Some(target_fde) = self.image.function_at(target) {
                            if target_fde.start == callee.start {
                                rows.insert(ins.ip(), || {
                                    let (description, description_truncated) =
                                        clipped(&listing::describe_branch(&self.image, ins), 256);
                                    CallerRow {
                                        caller: self.function_info(caller),
                                        call: CallRow {
                                            address: format!("{:#x}", ins.ip()),
                                            rva: format!("{:#x}", ins.ip().saturating_sub(self.base)),
                                            kind: match ins.flow_control() {
                                                FlowControl::Call => "direct_call",
                                                FlowControl::IndirectCall => "indirect_call",
                                                _ => "tail_jump",
                                            },
                                            target: Some(format!("{target:#x}")),
                                            description,
                                            description_truncated,
                                        },
                                    }
                                });
                            }
                        } else if matches!(ins.flow_control(), FlowControl::IndirectCall | FlowControl::IndirectBranch)
                        {
                            unresolved_indirect += 1;
                        }
                    } else if matches!(ins.flow_control(), FlowControl::IndirectCall | FlowControl::IndirectBranch) {
                        unresolved_indirect += 1;
                    }
                } else if ins.flow_control() == FlowControl::IndirectBranch {
                    unresolved_indirect += 1;
                }
            });
            cancel.checkpoint()?;
        }

        let (callers, page_meta) = rows.finish(page)?;
        let mut warnings = vec!["fde_range_is_not_source_function", "not_found_under_model_never_absence"];
        if unresolved_indirect > 0 {
            warnings.push("indirect_branches_not_resolved_as_calls");
        }
        if skipped_functions > 0 {
            warnings.push("scan_budget_exceeded_functions_skipped");
        }

        Ok((
            Data::Callers {
                function: self.function_info(&callee),
                callers,
                unresolved_indirect_edges: unresolved_indirect,
            },
            Some(page_meta),
            warnings,
        ))
    }
}

#[cfg(test)]
mod tests;
