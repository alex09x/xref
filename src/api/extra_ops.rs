/*
 * XRef Code — Extended structured operations: dependencies, card, find, layout, files, where
 * Copyright (c) 2026 Alexander Panasenko
 *
 * Contact: alex@prod.codes
 * Author: https://prod.codes/about/
 * Project: https://github.com/alex09x/xref
 * SPDX-License-Identifier: MIT OR Apache-2.0
 */

use std::collections::{BTreeMap, BTreeSet};

use super::agentic_types::{
    DependencyRow, FindMatchRow, FindQueryArgs, LayoutFieldRow, LayoutHopRow, SourceFileRow, SourceWhereRow,
};
use super::types::{ApiError, Data, Page, Pagination};
use super::{Analysis, Cancellation, Output};
use crate::find::{FindSpec, structured};
use crate::layout::{FieldInfo, parse_reg, scan_fn};
use crate::locations::{Location, locations};
use crate::provenance::inspect;
use crate::scan::{self, Query as ScanQuery};
use crate::source::location_at;

pub(super) fn paginate_vec<T>(items: Vec<T>, page: &Page) -> Result<(Vec<T>, Pagination), ApiError> {
    if !(1..=100).contains(&page.limit) || page.offset > 10000 {
        return Err(ApiError::new("invalid_page", "limit must be 1..100 and offset at most 10000"));
    }
    if page.offset > items.len() {
        return Err(ApiError::new("invalid_offset", "offset is past the result set"));
    }
    let more = items.len() > page.offset + page.limit;
    let rows: Vec<T> = items.into_iter().skip(page.offset).take(page.limit).collect();
    let next_offset = more.then_some(page.offset + rows.len()).filter(|&offset| offset <= 10000);
    let meta = Pagination { unit: "items", offset: page.offset, returned: rows.len(), next_offset, complete: !more };
    Ok((rows, meta))
}

impl Analysis {
    pub(super) fn dependencies(&self, filter: Option<&str>, page: &Page, cancel: &Cancellation) -> Output {
        if let Some(f) = filter
            && f.len() > 256
        {
            return Err(ApiError::new("invalid_text", "filter must be at most 256 UTF-8 bytes"));
        }
        cancel.checkpoint()?;
        let prov = inspect(&self.image);
        let needle = filter.map(str::to_ascii_lowercase);
        let matches = |name: &str| needle.as_ref().is_none_or(|sub| name.to_ascii_lowercase().contains(sub));

        let (ecosystem, root_package, root_version, go_version, total_packages, all_rows) =
            if let Some(rust) = prov.rust_audit {
                let total = rust.packages.len();
                let rows = rust
                    .packages
                    .into_iter()
                    .filter(|p| matches(&p.name))
                    .map(|p| DependencyRow {
                        name: p.name,
                        version: p.version,
                        kind: if p.kind == "build" { "build" } else { "runtime" },
                        source: (!p.source.is_empty()).then_some(p.source),
                        root: p.root,
                        replaced_by: None,
                    })
                    .collect();
                (Some("rust"), rust.root_name, rust.root_version, None, total, rows)
            } else if let Some(go) = prov.go_build {
                let total = go.deps.len();
                let (root_name, root_ver) = go.main_module.map_or((go.path, None), |(m, v)| (Some(m), Some(v)));
                let rows = go
                    .deps
                    .into_iter()
                    .filter(|d| matches(&d.path))
                    .map(|d| DependencyRow {
                        name: d.path,
                        version: d.version,
                        kind: "module",
                        source: d.sum,
                        root: false,
                        replaced_by: d.replaced_by.map(|(m, v)| format!("{m}@{v}")),
                    })
                    .collect();
                (Some("go"), root_name, root_ver, Some(go.go_version), total, rows)
            } else {
                let mut warnings = Vec::new();
                if prov.rust_audit_error.is_some() {
                    warnings.push("corrupt_or_oversized_dep_v0_section");
                }
                let (packages, meta) = paginate_vec(Vec::new(), page)?;
                return Ok((
                    Data::Dependencies {
                        ecosystem: None,
                        root_package: None,
                        root_version: None,
                        go_version: None,
                        total_packages: 0,
                        packages,
                    },
                    Some(meta),
                    warnings,
                ));
            };

        let (packages, meta) = paginate_vec(all_rows, page)?;
        Ok((
            Data::Dependencies { ecosystem, root_package, root_version, go_version, total_packages, packages },
            Some(meta),
            vec![],
        ))
    }

    pub(super) fn card_query(&self, address: &str, cancel: &Cancellation) -> Output {
        cancel.checkpoint()?;
        let range = self.function(address)?;
        let card = crate::card::analyze_card(&self.image, &range);
        Ok((
            Data::Card { function: self.function_info(&range), card: Box::new(card) },
            None,
            vec!["fde_range_is_not_source_function"],
        ))
    }

    pub(super) fn find_functions(&self, args: &FindQueryArgs<'_>, page: &Page, cancel: &Cancellation) -> Output {
        let back = args.back.unwrap_or(16);
        if back > 64 {
            return Err(ApiError::new("invalid_window", "back must be at most 64 bytes"));
        }
        cancel.checkpoint()?;
        let spec = FindSpec {
            calls: args.calls.to_vec(),
            refs: args.refs.to_vec(),
            imm: args.imm.to_vec(),
            imm_mode: args.imm_mode,
            disp: args.disp.to_vec(),
            disp_mode: args.disp_mode,
            src: args.src.to_vec(),
            size: args.size.map(str::to_owned),
            any: args.any,
            back,
        };
        let report = structured::search(&self.image, &spec, args.insn, args.class, cancel.flag()).map_err(|e| {
            if cancel.checkpoint().is_err() {
                ApiError::new("cancelled", "query cancelled")
            } else {
                ApiError::new("invalid_request", e.to_string())
            }
        })?;
        cancel.checkpoint()?;
        let total_matches = report.matches.len();
        let all_rows: Vec<FindMatchRow> = report
            .matches
            .into_iter()
            .map(|m| FindMatchRow {
                function: self.function_info(&m.function),
                satisfied: m.satisfied,
                predicate_count: report.predicate_count,
                matched_predicates: m.matched_predicates,
                instruction_hits: m.instruction_hit_count,
            })
            .collect();
        let (matches, meta) = paginate_vec(all_rows, page)?;
        Ok((
            Data::Find {
                predicate_count: report.predicate_count,
                min_satisfied: report.min_satisfied,
                total_matches,
                matches,
            },
            Some(meta),
            vec!["fde_range_is_not_source_function"],
        ))
    }

    pub(super) fn layout_query(
        &self,
        address: &str,
        reg_opt: Option<&str>,
        follow_callees: bool,
        cancel: &Cancellation,
    ) -> Output {
        cancel.checkpoint()?;
        let root = self.function(address)?;
        let reg_name = reg_opt.unwrap_or("rdi");
        let reg = parse_reg(reg_name).map_err(|e| ApiError::new("invalid_register", e))?;

        let mut fields: BTreeMap<u64, FieldInfo> = BTreeMap::new();
        let mut forwarded = Vec::new();
        scan_fn(&self.image, &root, reg, 0, None, &mut fields, &mut forwarded);

        let mut hops = BTreeSet::new();
        if follow_callees {
            for (ct, abi_r, aname, delta) in forwarded {
                cancel.checkpoint()?;
                if ct != root.start
                    && hops.insert((delta, ct, aname))
                    && let Some(cf) = self.image.function_at(ct).filter(|cf| cf.start == ct)
                {
                    let mut dummy = Vec::new();
                    scan_fn(&self.image, &cf, abi_r, delta, Some((ct, aname)), &mut fields, &mut dummy);
                }
            }
        }

        let field_rows: Vec<LayoutFieldRow> = fields
            .into_iter()
            .take(256)
            .map(|(off, info)| LayoutFieldRow {
                offset: format!("+{off:#x}"),
                offset_bytes: off,
                width_bytes: if info.width == 0 { 8 } else { info.width },
                inferred_type: if info.ty.is_empty() { "ptr" } else { info.ty },
                reads: info.reads,
                writes: info.writes,
                leas: info.leas,
                array_stride: info.stride.map(|s| format!("{s:#x}")),
                pointer_callees: info.ptr_callees.into_iter().map(|(c, r)| format!("{c:#x}({r})")).collect(),
                value_callees: info.val_callees.into_iter().map(|(c, r)| format!("{c:#x}({r})")).collect(),
                via_callees: info.via_callees.into_iter().map(|(c, r)| format!("{c:#x}({r})")).collect(),
            })
            .collect();

        let forwarded_hops: Vec<LayoutHopRow> = hops
            .into_iter()
            .take(64)
            .map(|(delta, callee, register)| LayoutHopRow {
                delta: if delta < 0 { format!("-{:#x}", delta.unsigned_abs()) } else { format!("+{delta:#x}") },
                callee: format!("{callee:#x}"),
                register,
            })
            .collect();

        Ok((
            Data::Layout {
                function: self.function_info(&root),
                register: reg_name.to_ascii_lowercase(),
                fields: field_rows,
                forwarded_hops,
            },
            None,
            vec!["fde_range_is_not_source_function"],
        ))
    }

    pub(super) fn source_files(&self, pattern: Option<&str>, page: &Page, cancel: &Cancellation) -> Output {
        if let Some(p) = pattern
            && p.len() > 256
        {
            return Err(ApiError::new("invalid_text", "pattern must be at most 256 UTF-8 bytes"));
        }
        cancel.checkpoint()?;
        let all = locations(&self.image);
        let mut counts: BTreeMap<&str, usize> = BTreeMap::new();
        let mut matched_locs = 0usize;
        for loc in all.iter().filter(|l| pattern.is_none_or(|p| l.file.contains(p))) {
            *counts.entry(loc.file.as_str()).or_default() += 1;
            matched_locs += 1;
        }
        let total_files = counts.len();
        let rows: Vec<SourceFileRow> = counts
            .into_iter()
            .map(|(file, panic_locations)| SourceFileRow { file: file.to_owned(), panic_locations })
            .collect();
        let (files, meta) = paginate_vec(rows, page)?;
        Ok((Data::Files { total_files, total_locations: matched_locs, files }, Some(meta), vec![]))
    }

    pub(super) fn source_where(&self, pattern: &str, line: Option<u32>, page: &Page, cancel: &Cancellation) -> Output {
        if pattern.is_empty() || pattern.len() > 256 {
            return Err(ApiError::new("invalid_text", "pattern must contain 1..256 UTF-8 bytes"));
        }
        cancel.checkpoint()?;
        let all = locations(&self.image);
        let matched: Vec<&Location> =
            all.iter().filter(|l| l.file.contains(pattern) && line.is_none_or(|w| l.line == w)).collect();
        let mut addresses: Vec<u64> = matched.iter().map(|l| l.place).collect();
        addresses.sort_unstable();
        addresses.dedup();

        let hits =
            if addresses.is_empty() { Vec::new() } else { scan::search(&self.image, &ScanQuery::Ref(addresses)) };
        cancel.checkpoint()?;

        let mut by_function: BTreeMap<(u64, u64), Vec<String>> = BTreeMap::new();
        for hit in &hits {
            if let Some(loc) = hit.memory.and_then(|addr| location_at(&all, addr)) {
                by_function
                    .entry((hit.function.start, hit.function.end))
                    .or_default()
                    .push(format!("{}:{}:{}", loc.file, loc.line, loc.col));
            }
        }
        let rows: Vec<SourceWhereRow> = by_function
            .into_iter()
            .map(|((start, end), mut locs)| {
                locs.sort_unstable();
                locs.dedup();
                locs.truncate(32);
                SourceWhereRow { function: self.function_info(&(start..end)), locations: locs }
            })
            .collect();
        let (functions, meta) = paginate_vec(rows, page)?;
        Ok((
            Data::Where { matched_locations: matched.len(), total_references: hits.len(), functions },
            Some(meta),
            vec!["fde_range_is_not_source_function"],
        ))
    }
}
