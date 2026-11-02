/*
 * XRef Code — evidence-producing binary analysis
 * Copyright (c) 2026 Alexander Panasenko
 * Contact: alex@prod.codes
 * Author: https://prod.codes/about/
 * Project: https://github.com/alex09x/xref
 * SPDX-License-Identifier: MIT OR Apache-2.0
 */
use super::super::{
    ApiError,
    types::{Data, Page, Query, TextPage},
};
use super::{
    Trail,
    types::{Candidate, Direction, FunctionCandidate, Seed, Selection, StringMatch},
};
use std::collections::{BTreeSet, VecDeque};

impl Trail<'_> {
    fn add_function(
        &mut self,
        address: &str,
        step: usize,
        depth: usize,
        queue: &mut VecDeque<(String, usize, usize)>,
        seen: &mut BTreeSet<String>,
    ) {
        let Ok(range) = self.analysis.function(address) else {
            self.stop("callee_without_fde");
            return;
        };
        let info = self.analysis.function_info(&range);
        if seen.contains(&info.start) {
            return;
        }
        if seen.len() >= self.request.limits.functions {
            self.stop("function_limit");
            return;
        }
        self.result.functions.push(FunctionCandidate { function: info.clone(), evidence_step: step, depth });
        if !self.fits() {
            self.result.functions.pop();
            self.stop("output_limit");
            return;
        }
        seen.insert(info.start.clone());
        queue.push_back((info.start, step, depth));
    }
    fn seed_functions(
        &mut self,
        page: &Page,
        queue: &mut VecDeque<(String, usize, usize)>,
        seen: &mut BTreeSet<String>,
    ) -> Result<(), ApiError> {
        match &self.request.seed {
            Seed::Function { address } => {
                let address = address.clone();
                if let Some(step) =
                    self.query(&Query::Function { address: address.clone() }, None, Some(address.clone()), None)?
                {
                    self.add_function(&address, step, 0, queue, seen);
                }
            }
            Seed::Text { text } => {
                let text = text.clone();
                if let Some(step) = self.query(
                    &Query::Strings { text: text.clone(), page: page.clone() },
                    None,
                    None,
                    Some(text.clone()),
                )? {
                    let locations = match self.result.evidence[step].data.as_deref() {
                        Some(Data::Strings { locations }) => locations.clone(),
                        _ => vec![],
                    };
                    for location in locations {
                        let start = super::super::Analysis::address(&location)?;
                        self.result.string_matches.push(StringMatch {
                            start: location.clone(),
                            end_exclusive: format!("{:#x}", start.saturating_add(text.len() as u64)),
                            evidence_step: step,
                        });
                        if !self.fits() {
                            self.result.string_matches.pop();
                            self.stop("output_limit");
                            break;
                        }
                        let Some(ref_step) = self.query(
                            &Query::Refs { address: location.clone(), back: 0, page: page.clone() },
                            Some(step),
                            Some(location),
                            None,
                        )?
                        else {
                            break;
                        };
                        let functions: Vec<_> = match self.result.evidence[ref_step].data.as_deref() {
                            Some(Data::Refs { references, .. }) => {
                                references.iter().map(|r| r.function.start.clone()).collect()
                            }
                            _ => vec![],
                        };
                        for address in functions {
                            self.add_function(&address, ref_step, 0, queue, seen);
                        }
                    }
                }
            }
        }
        Ok(())
    }
    pub(super) fn run(&mut self) -> Result<(), ApiError> {
        let page = Page { offset: 0, limit: self.request.limits.rows };
        let mut queue = VecDeque::new();
        let mut seen = BTreeSet::new();
        self.seed_functions(&page, &mut queue, &mut seen)?;
        while let Some((address, parent, depth)) = queue.pop_front() {
            self.cancel.checkpoint()?;
            // Calls in every discovered FDE are candidates even when reverse traversal was requested.
            if let Some(step) = self.query(
                &Query::Calls { address: address.clone(), page: page.clone() },
                Some(parent),
                Some(address.clone()),
                None,
            )? {
                let calls: Vec<_> = match self.result.evidence[step].data.as_deref() {
                    Some(Data::Calls { calls, .. }) => {
                        calls.iter().map(|c| (c.address.clone(), c.target.clone())).collect()
                    }
                    _ => vec![],
                };
                for (site, target) in calls {
                    self.candidate(&address, site, target.clone(), step);
                    if !matches!(self.request.direction, Direction::Callers) {
                        if depth < self.request.limits.depth {
                            if let Some(target) = target {
                                self.add_function(&target, step, depth + 1, &mut queue, &mut seen);
                            } else {
                                self.stop("unresolved_call_target");
                            }
                        } else {
                            self.stop("depth_limit");
                        }
                    }
                }
            }
            self.render_selection()?;
            if !matches!(self.request.direction, Direction::Callees) {
                if depth < self.request.limits.depth {
                    if let Some(step) = self.query(
                        &Query::Callers { address: address.clone(), page: page.clone() },
                        Some(parent),
                        Some(address),
                        None,
                    )? {
                        let callers: Vec<_> = match self.result.evidence[step].data.as_deref() {
                            Some(Data::Callers { callers, .. }) => callers
                                .iter()
                                .map(|r| (r.caller.start.clone(), r.call.address.clone(), r.call.target.clone()))
                                .collect(),
                            _ => vec![],
                        };
                        for (address, site, target) in callers {
                            self.add_function(&address, step, depth + 1, &mut queue, &mut seen);
                            self.candidate(&address, site, target, step);
                        }
                        self.render_selection()?;
                    }
                } else {
                    self.stop("depth_limit");
                }
            }
        }
        self.contexts_and_slice()
    }
    fn candidate(&mut self, function: &str, site: String, target: Option<String>, step: usize) {
        if let Some(filter) = &self.request.callee {
            let expected = self.analysis.function(filter).ok().map(|r| r.start);
            let actual = target.as_ref().and_then(|s| self.analysis.function(s).ok()).map(|r| r.start);
            if expected != actual {
                return;
            }
        }
        if self.result.call_sites.iter().any(|c| c.selection.function == function && c.selection.call_site == site) {
            return;
        }
        self.result.call_sites.push(Candidate {
            selection: Selection {
                image_sha256: self.analysis.identity.sha256.clone(),
                function: function.into(),
                call_site: site,
            },
            target,
            evidence_step: step,
            context_step: None,
        });
        if !self.fits() {
            self.result.call_sites.pop();
            self.stop("output_limit");
        }
    }
    fn selected_index(&self) -> Option<usize> {
        self.request.selection.as_ref().and_then(|choice| {
            self.result.call_sites.iter().position(|c| {
                super::super::Analysis::address(&c.selection.function).ok()
                    == super::super::Analysis::address(&choice.function).ok()
                    && super::super::Analysis::address(&c.selection.call_site).ok()
                        == super::super::Analysis::address(&choice.call_site).ok()
            })
        })
    }
    fn render_selection(&mut self) -> Result<(), ApiError> {
        if self.result.selected.is_some() {
            return Ok(());
        }
        if let Some(i) = self.selected_index() {
            let token = self.result.call_sites[i].selection.clone();
            self.result.selected = Some(token.clone());
            // Selected expensive work goes before optional contexts for other candidates.
            let parent = self.result.call_sites[i].evidence_step;
            self.query(
                &Query::Slice {
                    address: token.function.clone(),
                    to: token.call_site.clone(),
                    fields: false,
                    keep_gotos: false,
                    page: TextPage { offset: 0, limit: self.request.limits.slice_bytes },
                },
                Some(parent),
                Some(token.function.clone()),
                Some(token.call_site.clone()),
            )?;
            self.result.call_sites[i].context_step = self.query(
                &Query::CallContext { address: token.function.clone(), call_site: token.call_site.clone() },
                Some(parent),
                Some(token.function),
                Some(token.call_site),
            )?;
        }
        Ok(())
    }
    fn contexts_and_slice(&mut self) -> Result<(), ApiError> {
        let selected = self.selected_index();
        if self.request.selection.is_some() && selected.is_none() {
            self.stop("selection_not_reached_under_limits");
        }
        self.render_selection()?;
        let mut count = usize::from(selected.is_some());
        for i in 0..self.result.call_sites.len() {
            if Some(i) == selected {
                continue;
            }
            if count >= self.request.limits.contexts {
                self.stop("context_limit");
                break;
            }
            let c = &self.result.call_sites[i];
            let query =
                Query::CallContext { address: c.selection.function.clone(), call_site: c.selection.call_site.clone() };
            let (address, target, parent) =
                (c.selection.function.clone(), c.selection.call_site.clone(), c.evidence_step);
            self.result.call_sites[i].context_step = self.query(&query, Some(parent), Some(address), Some(target))?;
            count += 1;
        }
        Ok(())
    }
}
