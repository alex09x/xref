/*
 * XRef — Imported stack adjacency, distinct from static call proof
 * Copyright (c) 2026 Alexander Panasenko
 * Contact: alex@prod.codes
 * Author: https://prod.codes/about/
 * Project: https://github.com/alex09x/xref
 * SPDX-License-Identifier: MIT OR Apache-2.0
 */

use std::collections::BTreeMap;

use super::{
    index::{SymbolIndex, parse_hex},
    models::{ObservedEdge, ObservedStore, SymbolizedFrame},
};

pub const EDGE_SEMANTICS: &str = "adjacent_resolved_stack_frames_not_direct_call_proof";
pub const COUNT_UNIT: &str = "stack_samples";
pub const MAX_STORED_EDGES: usize = 65_536;
pub const MAX_STORE_BYTES: usize = 32 * 1024 * 1024;

#[derive(Default)]
pub struct EdgeAccumulator {
    edges: BTreeMap<(u64, u64, Option<u64>), u64>,
    pub truncated: bool,
}

impl EdgeAccumulator {
    #[allow(clippy::similar_names)] // Preserve graph-domain caller/callee terminology.
    pub fn add(&mut self, frames: &[SymbolizedFrame], weight: u64) -> Result<(), String> {
        // Frames are leaf first. Never bridge an unknown or foreign frame.
        for pair in frames.windows(2) {
            let (Some(callee), Some(caller)) = (&pair[0].function, &pair[1].function) else { continue };
            let key = (
                parse_hex(&caller.start)?,
                parse_hex(&callee.start)?,
                pair[1].call_site.as_deref().map(parse_hex).transpose()?,
            );
            if !self.edges.contains_key(&key) && self.edges.len() >= MAX_STORED_EDGES {
                self.truncated = true;
                continue;
            }
            let count = self.edges.entry(key).or_default();
            *count = count.checked_add(weight).ok_or("observed sample count overflow")?;
        }
        Ok(())
    }

    pub fn into_edges(self) -> Vec<ObservedEdge> {
        self.edges
            .into_iter()
            .map(|((caller, callee, site), count)| ObservedEdge {
                caller: format!("{caller:#x}"),
                callee: format!("{callee:#x}"),
                sample_count: count,
                caller_call_site: site.map(|value| format!("{value:#x}")),
                evidence: EDGE_SEMANTICS.to_owned(),
            })
            .collect()
    }
}

#[allow(clippy::similar_names)] // Caller and callee are distinct schema coordinates.
pub fn validate_store(store: &ObservedStore, index: &SymbolIndex) -> Result<(), String> {
    if store.schema_version != 1 || store.count_unit != COUNT_UNIT || store.edge_semantics != EDGE_SEMANTICS {
        return Err("unsupported observed-edge schema or semantics".to_owned());
    }
    if store.image != index.identity {
        return Err("observed store image identity does not match selected binary".to_owned());
    }
    if store.edges.len() > MAX_STORED_EDGES || store.warnings.len() > 64 {
        return Err("observed store exceeds limits".to_owned());
    }
    let mut keys = std::collections::BTreeSet::new();
    let function_starts: std::collections::BTreeSet<_> =
        index.functions.iter().map(|function| function.start).collect();
    let call_sites: std::collections::BTreeSet<_> =
        index.calls_by_return.values().map(|call| (call.caller, call.instruction)).collect();
    for edge in &store.edges {
        let caller = parse_hex(&edge.caller)?;
        let callee = parse_hex(&edge.callee)?;
        if edge.sample_count == 0 || edge.evidence != EDGE_SEMANTICS {
            return Err("invalid observed edge evidence/count".to_owned());
        }
        if !function_starts.contains(&caller) || !function_starts.contains(&callee) {
            return Err("observed edge does not identify indexed function starts".to_owned());
        }
        let site = edge.caller_call_site.as_deref().map(parse_hex).transpose()?;
        if !keys.insert((caller, callee, site)) {
            return Err("duplicate observed edge".to_owned());
        }
        if let Some(site) = site
            && !call_sites.contains(&(caller, site))
        {
            return Err("observed call-site address is not a decoded call in its caller".to_owned());
        }
    }
    Ok(())
}
