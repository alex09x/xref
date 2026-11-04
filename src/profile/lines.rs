/*
 * XRef — Binary analysis
 * Copyright (c) 2026 Alexander Panasenko
 * Contact: alex@prod.codes
 * Author: https://prod.codes/about/
 * Project: https://github.com/alex09x/xref
 * SPDX-License-Identifier: MIT OR Apache-2.0
 */
use super::aggregate::Aggregate;
use crate::image::Image;
use object::{Object, ObjectSection};
use serde::Serialize;
use std::collections::BTreeMap;

#[derive(Serialize)]
pub struct LineRow {
    pub file: String,
    pub line: u64,
    pub samples: u64,
    pub percent: f64,
}

pub fn collect(image: &Image, aggregate: &Aggregate) -> Result<(Vec<LineRow>, u64, bool), String> {
    let file = object::File::parse(image.data.as_slice()).map_err(|e| e.to_string())?;
    let sections = gimli::DwarfSections::load(|id: gimli::SectionId| -> Result<std::borrow::Cow<'_, [u8]>, String> {
        file.section_by_name(id.name()).map_or(Ok(std::borrow::Cow::Borrowed(&[])), |section| {
            section.uncompressed_data().map_err(|e| e.to_string())
        })
    })?;
    let dwarf = sections.borrow(|section| gimli::EndianSlice::new(section, gimli::LittleEndian));
    let mut sampled = BTreeMap::new();
    for ((key, address), count) in &aggregate.instructions {
        if key.module == 1 {
            *sampled.entry(*address).or_insert(0_u64) += count;
        }
    }
    let mut locations: BTreeMap<u64, Option<(String, u64)>> = BTreeMap::new();
    let mut units = dwarf.units();
    let mut row_count = 0_usize;
    let mut truncated = false;
    while let Some(header) = units.next().map_err(|e| e.to_string())? {
        let unit = dwarf.unit(header).map_err(|e| e.to_string())?;
        let Some(program) = unit.line_program.clone() else { continue };
        let mut rows = program.rows();
        let mut previous: Option<(u64, String, u64)> = None;
        while let Some((header, row)) = rows.next_row().map_err(|e| e.to_string())? {
            row_count += 1;
            if row_count > 2_000_000 {
                truncated = true;
                break;
            }
            if let Some((start, path, line)) = previous.take()
                && start < row.address()
            {
                for (&address, _) in sampled.range(start..row.address()) {
                    let site = (path.clone(), line);
                    locations
                        .entry(address)
                        .and_modify(|old| {
                            if old.as_ref() != Some(&site) {
                                *old = None;
                            }
                        })
                        .or_insert(Some(site));
                }
            }
            if row.end_sequence() {
                continue;
            }
            let Some(entry) = row.file(header) else { continue };
            let Some(line) = row.line() else { continue };
            let path =
                dwarf.attr_string(&unit, entry.path_name()).map_err(|e| e.to_string())?.to_string_lossy().into_owned();
            let directory = entry
                .directory(header)
                .and_then(|dir| dwarf.attr_string(&unit, dir).ok())
                .map(|dir| dir.to_string_lossy().into_owned());
            let path = directory.map_or_else(
                || path.clone(),
                |directory| std::path::Path::new(&directory).join(&path).to_string_lossy().into_owned(),
            );
            previous = Some((row.address(), path, line.get()));
        }
        if truncated {
            break;
        }
    }
    let mut groups: BTreeMap<(String, u64), u64> = BTreeMap::new();
    let mut unresolved = 0_u64;
    for (address, count) in sampled {
        if let Some(Some(site)) = locations.get(&address) {
            *groups.entry(site.clone()).or_default() += count;
        } else {
            unresolved = unresolved.saturating_add(count);
        }
    }
    let mut result: Vec<_> = groups
        .into_iter()
        .map(|((file, line), samples)| LineRow {
            file,
            line,
            samples,
            percent: super::report::percent(samples, aggregate.samples),
        })
        .collect();
    result.sort_by(|a, b| b.samples.cmp(&a.samples).then(a.file.cmp(&b.file)).then(a.line.cmp(&b.line)));
    Ok((result, unresolved, truncated))
}
