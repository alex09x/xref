/*
 * XRef — Static instruction index for runtime stacks
 * Copyright (c) 2026 Alexander Panasenko
 * Contact: alex@prod.codes
 * Author: https://prod.codes/about/
 * Project: https://github.com/alex09x/xref
 * SPDX-License-Identifier: MIT OR Apache-2.0
 */
use crate::trace_analysis::{
    index::{IndexedCall, IndexedFunction, IndexedSegment, SymbolIndex},
    models::{SourceHint, TraceIdentity},
};
use crate::{
    image::Image,
    locations::{Location, file_name},
    source::location_at,
};
use iced_x86::{Decoder, DecoderOptions, FlowControl};
use sha2::{Digest, Sha256};
use std::{
    collections::{BTreeMap, BTreeSet},
    sync::atomic::{AtomicBool, Ordering},
};

const MAX_INDEX_CODE_BYTES: usize = 32 * 1024 * 1024;
const MAX_INDEX_CALLS: usize = 262_144;
const MAX_LOCATION_POINTERS: usize = 262_144;

fn image_identity(image: &Image) -> TraceIdentity {
    let hex = crate::trace_analysis::index::hex_bytes;
    TraceIdentity { sha256: hex(&Sha256::digest(&image.data)), build_id: image.metadata.build_id.as_deref().map(hex) }
}

pub fn build_index(image: &Image, cancel: Option<&AtomicBool>) -> Result<SymbolIndex, String> {
    let identity = image_identity(image);
    let locations: Vec<_> = image
        .pointers
        .iter()
        .take(MAX_LOCATION_POINTERS)
        .filter_map(|&(place, target)| {
            let len =
                usize::try_from(image.read_u64(place.checked_add(8)?)?).ok().filter(|len| (4..=1024).contains(len))?;
            let line = image.read_u32(place.checked_add(16)?)?;
            let col = image.read_u32(place.checked_add(20)?)?;
            let file = file_name(image.read(target, len)?, line, col)?;
            Some(Location { place, file, line, col })
        })
        .collect();
    let mut calls = BTreeMap::new();
    let mut conflicting_returns = BTreeSet::new();
    let mut remaining = MAX_INDEX_CODE_BYTES;
    let mut limited = false;
    let mut functions = Vec::with_capacity(image.functions.len());
    for range in &image.functions {
        if cancel.is_some_and(|flag| flag.load(Ordering::Relaxed)) {
            return Err("symbol index cancelled".to_owned());
        }
        let mut source_sites = Vec::new();
        if let Some(bytes) = image.code(range) {
            if bytes.len() <= remaining {
                remaining -= bytes.len();
                let mut decoder = Decoder::with_ip(64, bytes, range.start, DecoderOptions::NONE);
                while decoder.can_decode() {
                    if cancel.is_some_and(|flag| flag.load(Ordering::Relaxed)) {
                        return Err("symbol index cancelled".to_owned());
                    }
                    let instruction = decoder.decode();
                    if matches!(instruction.flow_control(), FlowControl::Call | FlowControl::IndirectCall) {
                        let key = instruction.next_ip();
                        let value = IndexedCall { instruction: instruction.ip(), caller: range.start };
                        if calls.len() >= MAX_INDEX_CALLS {
                            limited = true;
                        } else if let Some(old) = calls.get(&key) {
                            if old != &value {
                                conflicting_returns.insert(key);
                            }
                        } else {
                            calls.insert(key, value);
                        }
                    }
                    if instruction.is_ip_rel_memory_operand()
                        && let Some(location) = location_at(&locations, instruction.ip_rel_memory_address())
                    {
                        source_sites.push((
                            instruction.ip(),
                            SourceHint {
                                file: location.file.clone(),
                                line: location.line,
                                evidence: "nearby_panic_location_reference_not_dwarf_line".to_owned(),
                            },
                        ));
                    }
                }
            } else {
                limited = true;
            }
        }
        let symbol =
            image.symbols.binary_search_by_key(&range.start, |(address, _)| *address).ok().and_then(|position| {
                let name = &image.symbols[position].1;
                (name.len() <= 256).then(|| name.clone())
            });
        functions.push(IndexedFunction { start: range.start, end: range.end, symbol, source_sites });
    }
    for key in conflicting_returns {
        calls.remove(&key);
    }
    let segments = image
        .metadata
        .load_segments
        .iter()
        .map(|s| IndexedSegment {
            va: s.va,
            file_offset: s.file_offset,
            file_size: s.file_size,
            mem_size: s.mem_size,
            executable: s.executable,
        })
        .collect();
    let mut index = SymbolIndex::new(identity, image.metadata.base, functions, calls, segments);
    if limited {
        index.warnings.push("call_site_and_source_index_budget_exhausted_some_hints_unavailable".to_owned());
    }
    if image.pointers.len() > MAX_LOCATION_POINTERS {
        index.warnings.push("panic_location_reference_index_budget_exhausted".to_owned());
    }
    if image.symbols.iter().any(|(_, name)| name.len() > 256) {
        index.warnings.push("long_symbol_names_omitted_use_static_addresses".to_owned());
    }
    Ok(index)
}
