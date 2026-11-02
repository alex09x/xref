/*
 * XRef Code — evidence-producing binary analysis
 * Copyright (c) 2026 Alexander Panasenko
 * Contact: alex@prod.codes
 * Author: https://prod.codes/about/
 * Project: https://github.com/alex09x/xref
 * SPDX-License-Identifier: MIT OR Apache-2.0
 */
use super::super::{
    Analysis, ApiError, Cancellation, Output,
    field_types::{FieldReport, FieldRequest, Hop, LayoutHint, ScopeError, signed_hex},
    investigate::types::Step,
    types::Data,
    types::TextPage,
};
use super::{facts, field_scan::Scope};
use crate::layout;
use iced_x86::{InstructionInfoFactory, OpAccess, Register};
use std::collections::{BTreeMap, BTreeSet, VecDeque};

struct Engine<'a> {
    analysis: &'a Analysis,
    request: &'a FieldRequest,
    cancel: &'a Cancellation,
    offsets: Vec<i64>,
    report: FieldReport,
}
impl Engine<'_> {
    fn stop(&mut self, reason: &'static str) {
        self.report.complete_under_model = false;
        if !self.report.stops.contains(&reason) {
            self.report.stops.push(reason);
        }
    }
    fn fits(&self) -> bool {
        serde_json::to_vec(&self.report).is_ok_and(|v| v.len() <= self.request.limits.output_bytes.saturating_sub(512))
    }
    fn scan(&mut self, scope: &Scope<'_>) -> Result<Vec<(String, usize, i64, Hop)>, ApiError> {
        if !scope.complete() {
            self.stop("incomplete_cfg_or_dataflow_budget");
        }
        let mut hops = vec![];
        let mut info = InstructionInfoFactory::new();
        for (i, ins) in scope.insns.iter().enumerate() {
            self.cancel.checkpoint()?;
            if self.report.stops.contains(&"output_limit") {
                break;
            }
            if scope.complete() && scope.states.as_ref().is_some_and(|states| states[i].is_none()) {
                continue;
            }
            if let Some((offset, access)) = scope.memory(self.analysis, i) {
                if self.offsets.is_empty() || self.offsets.contains(&offset) {
                    if self.report.accesses.len() >= self.request.limits.rows {
                        self.stop("access_row_limit");
                    } else {
                        self.report.accesses.push(access);
                        if !self.fits() {
                            self.report.accesses.pop();
                            self.stop("output_limit");
                            break;
                        }
                    }
                }
            } else if !ins.is_ip_rel_memory_operand() {
                self.report.unresolved_memory_operands += info
                    .info(ins)
                    .used_memory()
                    .iter()
                    .filter(|m| m.base().full_register() != Register::RSP && m.access() != OpAccess::NoMemAccess)
                    .count();
            }
            if !scope.is_call(i, self.analysis) {
                continue;
            }
            self.report.calls_examined += 1;
            let Some(call) = scope.call(self.analysis, i, &self.offsets, self.cancel)? else { continue };
            if self.report.calls.len() >= self.request.limits.rows {
                self.stop("call_row_limit");
                continue;
            }
            if !call.guards_complete {
                self.stop("guard_evidence_incomplete");
            }
            let next = scope.hops(self.analysis, &call);
            self.report.calls.push(call);
            if !self.fits() {
                self.report.calls.pop();
                self.stop("output_limit");
                break;
            }
            let n = self.report.calls.len() - 1;
            self.render_selected(n)?;
            if self.request.callees {
                if scope.via.is_some() || next.is_empty() {
                    self.stop(if self.report.calls[n].arguments.iter().all(|a| a.load_address.is_some()) {
                        "loaded_value_pointee_not_followed"
                    } else if scope.via.is_some() {
                        "callee_depth_limit"
                    } else {
                        "callee_target_or_entry_unavailable"
                    });
                }
                if scope.via.is_none() {
                    hops.extend(next);
                }
            }
        }
        Ok(hops)
    }
    fn render_selected(&mut self, i: usize) -> Result<(), ApiError> {
        if self.report.selected.is_some() {
            return Ok(());
        }
        let Some(choice) = &self.request.selection else { return Ok(()) };
        let token = &self.report.calls[i].selection;
        if Analysis::address(&choice.function)? != Analysis::address(&token.function)?
            || Analysis::address(&choice.call_site)? != Analysis::address(&token.call_site)?
        {
            return Ok(());
        }
        let token = token.clone();
        self.report.selected = Some(token.clone());
        let output = self.analysis.render(
            &token.function,
            Some(&token.call_site),
            false,
            false,
            &TextPage { offset: 0, limit: self.request.limits.slice_bytes },
            self.cancel,
        );
        let (data, page, warnings, error) = match output {
            Ok((data, page, warnings)) => (Some(Box::new(data)), page, warnings, None),
            Err(error) if error.code == "cancelled" => return Err(error),
            Err(error) => (None, None, vec![], Some(error)),
        };
        if error.is_some() {
            self.stop("selected_slice_failed");
        }
        if page.as_ref().is_some_and(|p| !p.complete) {
            self.stop("selected_slice_fragment");
        }
        self.report.slice = Some(Step {
            id: 0,
            parent: None,
            operation: "slice",
            address: Some(token.function),
            target: Some(token.call_site),
            data,
            error,
            warnings,
            page,
        });
        if !self.fits() {
            self.report.slice = None;
            self.stop("output_limit");
        }
        Ok(())
    }
    fn hints(&mut self, scope: &Scope<'_>) {
        if scope.via.is_some() || self.report.stops.contains(&"output_limit") {
            return;
        }
        let mut fields = BTreeMap::new();
        layout::scan_fn(
            &self.analysis.image,
            &scope.range,
            facts::REGS[scope.entry],
            0,
            None,
            &mut fields,
            &mut vec![],
        );
        for (offset, info) in fields {
            let Ok(offset) = i64::try_from(offset) else { continue };
            if !self.offsets.is_empty() && !self.offsets.contains(&offset) {
                continue;
            }
            if self.report.layout_hints.len() >= self.request.limits.rows {
                self.stop("hint_row_limit");
                break;
            }
            self.report.layout_hints.push(LayoutHint {
                displacement: signed_hex(offset),
                width_hint_bytes: info.width,
                stride_hint: info.stride.map(|v| format!("{v:#x}")),
                status: "heuristic_path_insensitive_not_a_type_or_forwarding_proof",
            });
            if !self.fits() {
                self.report.layout_hints.pop();
                self.stop("output_limit");
                break;
            }
        }
    }
    fn run(&mut self, root: &str, register: usize) -> Result<(), ApiError> {
        let mut queue = VecDeque::from([(root.to_owned(), register, 0, None)]);
        let mut seen = BTreeSet::new();
        let mut admitted = 0;
        while let Some((address, entry, delta, via)) = queue.pop_front() {
            self.cancel.checkpoint()?;
            if self.report.stops.contains(&"output_limit") {
                break;
            }
            let scope = match Scope::open(self.analysis, &address, entry, delta, via.clone(), self.cancel) {
                Ok(scope) => scope,
                Err(error) if error.code == "cancelled" => return Err(error),
                Err(error) => {
                    self.report.scope_errors.push(ScopeError { function: address, error, via });
                    if !self.fits() {
                        self.report.scope_errors.pop();
                        self.stop("output_limit");
                        break;
                    }
                    self.stop("scope_unavailable_or_over_budget");
                    continue;
                }
            };
            if let Some(hop) = &via {
                self.report.callee_scopes.push(hop.clone());
                if !self.fits() {
                    self.report.callee_scopes.pop();
                    self.stop("output_limit");
                    break;
                }
            }
            let hops = self.scan(&scope)?;
            self.hints(&scope);
            for (address, entry, delta, hop) in hops {
                if !seen.insert((hop.call_site.clone(), address.clone(), entry, delta)) {
                    continue;
                }
                if admitted >= self.request.limits.callees {
                    self.stop("callee_scope_limit");
                    continue;
                }
                admitted += 1;
                queue.push_back((address, entry, delta, Some(hop)));
            }
        }
        if self.report.unresolved_memory_operands > 0 {
            self.stop("unresolved_memory_origins");
        }
        if self.request.selection.is_some() && self.report.selected.is_none() {
            self.stop("selection_not_reached_under_limits");
        }
        if self.report.accesses.is_empty() && self.report.calls.is_empty() {
            self.stop("not_found_under_limits");
        }
        Ok(())
    }
}
impl Analysis {
    pub(in crate::api) fn field_origin(&self, request: &FieldRequest, cancel: &Cancellation) -> Output {
        request.limits.validate()?;
        if request.offsets.len() > 8 {
            return Err(ApiError::new("invalid_offsets", "at most eight nonnegative field offsets"));
        }
        let root = self.function(&request.address)?;
        let register = layout::parse_reg(&request.register).map_err(|e| ApiError::new("invalid_register", e))?;
        let entry =
            facts::reg_index(register).ok_or_else(|| ApiError::new("invalid_register", "expected a full-width GPR"))?;
        let offsets: Vec<_> = request
            .offsets
            .iter()
            .map(|s| {
                Self::address(s).and_then(|v| {
                    i64::try_from(v)
                        .map_err(|_| ApiError::new("invalid_offsets", "field offsets must fit nonnegative i64"))
                })
            })
            .collect::<Result<_, _>>()?;
        if let Some(choice) = &request.selection {
            if choice.image_sha256 != self.identity.sha256 {
                return Err(ApiError::new("image_mismatch", "selection belongs to different input bytes"));
            }
            Self::address(&choice.function)?;
            Self::address(&choice.call_site)?;
        }
        let mut engine = Engine {
            analysis: self,
            request,
            cancel,
            offsets,
            report: FieldReport {
                function: self.function_info(&root),
                entry_register: facts::NAMES[entry].into(),
                scope: "entry_relative_machine_evidence_under_direct_cfg_and_sysv_returning_call_model",
                accesses: vec![],
                calls: vec![],
                callee_scopes: vec![],
                layout_hints: vec![],
                slice: None,
                selected: None,
                complete_under_model: true,
                unresolved_memory_operands: 0,
                calls_examined: 0,
                scope_errors: vec![],
                stops: vec![],
            },
        };
        engine.run(&format!("{:#x}", root.start), entry)?;
        Ok((
            Data::FieldOrigin { report: Box::new(engine.report) },
            None,
            vec![
                "sysv_register_candidates_not_recovered_signature",
                "entry_relative_addresses_not_object_bounds_or_source_types",
                "layout_hints_are_path_insensitive",
                "loaded_pointer_is_not_the_original_base",
                "not_found_under_limits_never_absence",
            ],
        ))
    }
}

#[cfg(test)]
mod tests;
