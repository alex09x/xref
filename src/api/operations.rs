/*
 * XRef Code — Structured analysis operations
 * Copyright (c) 2026 Alexander Panasenko
 * Contact: alex@prod.codes
 * Author: https://prod.codes/about/
 * Project: https://github.com/alex09x/xref
 * SPDX-License-Identifier: MIT OR Apache-2.0
 */

use super::{
    Analysis, ApiError, Cancellation, Output, clipped,
    paging::Rows,
    types::{CallRow, Data, InstructionRow, Page, PointerSlot, Query, ReferenceRow},
};
use crate::{graph, image::occurrence_iter, listing, reach, scan};
use iced_x86::FlowControl;
use std::fmt::Write as _;

impl Analysis {
    pub(super) fn execute(&self, query: &Query, cancel: &Cancellation) -> Output {
        match query {
            Query::Info { .. } => Ok((
                Data::Info {
                    functions: self.image.functions.len(),
                    segments: self.image.segments.len(),
                    symbols: self.image.symbols.len(),
                    imports: self.image.imports.len(),
                    pointers: self.image.pointers.len(),
                    format_details: (self.image.metadata.kind == crate::image_format::Kind::MachO).then(|| {
                        super::types::FormatDetails {
                            entry_point: self.image.metadata.entry.map(|v| format!("{v:#x}")),
                            recorded_function_starts: self.image.metadata.function_starts.len(),
                            starts_without_fde: self.image.metadata.uncovered_starts,
                            return_contract: "not_proven_from_recorded_callers",
                        }
                    }),
                },
                None,
                vec![],
            )),
            Query::Strings { text, page } => self.strings(text, page, cancel),
            Query::Refs { address, back, page } => self.refs(Self::address(address)?, *back, page, cancel),
            Query::Function { address } => {
                let range = self.function(address)?;
                Ok((
                    Data::Function { function: self.function_info(&range) },
                    None,
                    vec!["fde_range_is_not_source_function"],
                ))
            }
            Query::Calls { address, page } => self.calls(address, page, cancel),
            Query::Callers { address, page } => self.callers(address, page, cancel),
            Query::CallContext { address, call_site } => self.call_context(address, call_site, cancel),
            Query::Investigate { request } => self.investigate(request, cancel),
            Query::FieldOrigin { request } => self.field_origin(request, cancel),
            Query::Symbolize { request } => self.symbolize(request, cancel),
            Query::Asm { address, page } => self.assembly(address, page, cancel),
            Query::C { address, only_paths_to, fields, keep_gotos, page } => {
                let only_paths = only_paths_to
                    .as_deref()
                    .map(crate::cli::parse_number)
                    .transpose()
                    .map_err(|e| ApiError::new("invalid_address", e))?;
                let options =
                    crate::c::COptions { keep_gotos: *keep_gotos, only_paths_to: only_paths, ..Default::default() };
                self.render(address, None, *fields, options, page, cancel)
            }
            Query::Slice { address, to, to_field, fields, keep_gotos, page } => {
                let target = to_field.as_deref().or(to.as_deref());
                let options = crate::c::COptions { keep_gotos: *keep_gotos, ..Default::default() };
                self.render(address, target, *fields, options, page, cancel)
            }
        }
    }

    fn strings(&self, text: &str, page: &Page, cancel: &Cancellation) -> Output {
        if text.is_empty() || text.len() > 512 {
            return Err(ApiError::new("invalid_text", "text must contain 1..512 UTF-8 bytes"));
        }
        let mut rows = Rows::new(page)?;
        for segment in self.image.searchable_segments() {
            let Some(bytes) = self.image.data.get(segment.offset..segment.offset + segment.size) else {
                continue;
            };
            for start in (0..bytes.len()).step_by(65536) {
                cancel.checkpoint()?;
                let end = bytes.len().min(start.saturating_add(65536 + text.len() - 1));
                for at in occurrence_iter(&bytes[start..end], text.as_bytes()).take_while(|&at| at < 65536) {
                    let address = segment.va + (start + at) as u64;
                    rows.insert(address, || format!("{address:#x}"));
                }
            }
        }
        let (locations, page) = rows.finish(page)?;
        Ok((Data::Strings { locations }, Some(page), vec![]))
    }

    fn refs(&self, address: u64, back: u64, page: &Page, cancel: &Cancellation) -> Output {
        if back > 64 {
            return Err(ApiError::new("invalid_window", "back must be at most 64 bytes"));
        }
        let mut rows = Rows::new(page)?;
        let targets = reach::reach(&self.image, std::iter::once(address.saturating_sub(back)..=address));
        let query = scan::Query::Ref(targets.addresses);
        for function in &self.image.functions {
            cancel.checkpoint()?;
            let Some(code) = self.image.code(function) else {
                continue;
            };
            scan::decode(code, function.start, |ins| {
                if cancel.checkpoint().is_ok() && scan::matches(&query, ins) {
                    rows.insert(ins.ip(), || ReferenceRow {
                        address: format!("{:#x}", ins.ip()),
                        rva: format!("{:#x}", ins.ip().saturating_sub(self.base)),
                        function: self.function_info(function),
                        memory_address: format!("{:#x}", ins.ip_rel_memory_address()),
                        text: scan::format(ins),
                    });
                }
            });
        }
        cancel.checkpoint()?;
        let pointer_slots_truncated = targets.slots.len() > 100;
        let pointer_slots = targets
            .slots
            .into_iter()
            .take(100)
            .map(|(address, target)| PointerSlot { address: format!("{address:#x}"), target: format!("{target:#x}") })
            .collect();
        let (references, page) = rows.finish(page)?;
        let mut warnings = vec!["refs_exclude_direct_branch_operands"];
        if pointer_slots_truncated {
            warnings.push("pointer_slot_list_truncated");
        }
        Ok((Data::Refs { references, pointer_slots, pointer_slots_truncated }, Some(page), warnings))
    }

    fn code(&self, range: &std::ops::Range<u64>) -> Result<&[u8], ApiError> {
        if range.end.saturating_sub(range.start) > 1024 * 1024 {
            return Err(ApiError::new("function_too_large", "instruction queries support ranges up to 1 MiB"));
        }
        self.image
            .code(range)
            .ok_or_else(|| ApiError::new("invalid_function_range", "function range is not backed by file bytes"))
    }

    fn calls(&self, address: &str, page: &Page, cancel: &Cancellation) -> Output {
        let function = self.function(address)?;
        let mut rows = Rows::new(page)?;
        let mut unresolved = 0;
        scan::decode(self.code(&function)?, function.start, |ins| {
            if cancel.checkpoint().is_err() {
                return;
            }
            if listing::is_call(ins, &function) {
                rows.insert(ins.ip(), || {
                    let (description, description_truncated) =
                        clipped(&listing::describe_branch(&self.image, ins), 256);
                    CallRow {
                        address: format!("{:#x}", ins.ip()),
                        rva: format!("{:#x}", ins.ip().saturating_sub(self.base)),
                        kind: match ins.flow_control() {
                            FlowControl::Call => "direct_call",
                            FlowControl::IndirectCall => "indirect_call",
                            _ => "tail_jump",
                        },
                        target: graph::call_target(&self.image, ins).map(|target| format!("{target:#x}")),
                        description,
                        description_truncated,
                    }
                });
            } else if ins.flow_control() == FlowControl::IndirectBranch {
                unresolved += 1;
            }
        });
        cancel.checkpoint()?;
        let (calls, page) = rows.finish(page)?;
        let mut warnings = vec!["fde_range_is_not_source_function"];
        if unresolved > 0 {
            warnings.push("indirect_branches_not_resolved_as_calls");
        }
        Ok((
            Data::Calls { function: self.function_info(&function), calls, unresolved_indirect_branches: unresolved },
            Some(page),
            warnings,
        ))
    }

    fn assembly(&self, address: &str, page: &Page, cancel: &Cancellation) -> Output {
        let function = self.function(address)?;
        let code = self.code(&function)?;
        let mut rows = Rows::new(page)?;
        scan::decode(code, function.start, |ins| {
            if cancel.checkpoint().is_err() {
                return;
            }
            rows.insert(ins.ip(), || {
                let offset = usize::try_from(ins.ip() - function.start).unwrap_or(0);
                let mut bytes = String::with_capacity(ins.len() * 2);
                for byte in code.get(offset..offset + ins.len()).unwrap_or_default() {
                    let _ = write!(bytes, "{byte:02x}");
                }
                InstructionRow {
                    address: format!("{:#x}", ins.ip()),
                    rva: format!("{:#x}", ins.ip().saturating_sub(self.base)),
                    size_bytes: ins.len(),
                    bytes,
                    valid: !ins.is_invalid(),
                    text: scan::format(ins),
                    memory_address: ins
                        .is_ip_rel_memory_operand()
                        .then(|| format!("{:#x}", ins.ip_rel_memory_address())),
                    direct_branch_target: scan::branch_target(ins).map(|target| format!("{target:#x}")),
                }
            });
        });
        cancel.checkpoint()?;
        let (instructions, page) = rows.finish(page)?;
        Ok((
            Data::Asm { function: self.function_info(&function), instructions },
            Some(page),
            vec!["fde_range_is_not_source_function"],
        ))
    }
}
