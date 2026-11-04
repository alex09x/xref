/*
 * XRef — in-process session state shared by field searches over one image
 * Copyright (c) 2026 Alexander Panasenko
 * Contact: alex@prod.codes
 * Author: https://prod.codes/about/
 * Project: https://github.com/alex09x/xref
 * SPDX-License-Identifier: MIT OR Apache-2.0
 */

//! A long-lived process (the MCP server, `xref -b BIN mcp`) answers many `field` queries over the same
//! image. Everything that does not depend on the requested keys is computed once per image and kept
//! here: the image digest, the whole-image scan (call graph, write functions, references per function),
//! the writer index and analyzed function facts. A new key set or filter then only pays for key
//! matching, context selection and ranking (#76: tens of milliseconds per query).
//!
//! State is keyed by the image digest; a different image replaces it. The image digest itself is
//! memoised by the address, length and a content sample of the image bytes.

use super::{
    catalog::CallGraph,
    facts::{AnalysisFailure, Facts},
    scan_index::Identity,
    writer_index::Entry,
};
use std::{
    collections::{BTreeMap, BTreeSet},
    ops::Range,
    sync::{Arc, Mutex, PoisonError},
};

/// Facts kept per session; beyond this, new analyses are not remembered.
const MAX_REMEMBERED_FACTS: usize = 65_536;

/// Key-independent outcome of a complete whole-image scan.
pub(super) struct FullScan {
    pub starts: BTreeMap<u64, Range<u64>>,
    pub write_functions: BTreeSet<u64>,
    pub forward: Arc<CallGraph>,
    pub reverse: Arc<CallGraph>,
    /// Functions with static references, in scan order.
    pub references: Vec<(u64, Vec<u64>)>,
    pub scanned_functions: usize,
    pub skipped_functions: usize,
    pub scanned_code_bytes: u64,
    pub edges_truncated: bool,
    pub complete: bool,
    /// Built on the first reuse, so a one-shot CLI search does not pay for it.
    pub dense: std::sync::OnceLock<Option<Arc<super::dense_graph::DenseGraph>>>,
}

impl FullScan {
    pub fn dense(&self) -> Option<Arc<super::dense_graph::DenseGraph>> {
        self.dense
            .get_or_init(|| super::dense_graph::DenseGraph::new(&self.forward, &self.reverse).map(Arc::new))
            .clone()
    }
}

#[derive(Default)]
struct Session {
    image: Option<[u8; 32]>,
    scan: Option<Arc<FullScan>>,
    writers: BTreeMap<usize, Arc<Vec<Entry>>>,
    facts: BTreeMap<(usize, u64), Result<Arc<Facts>, AnalysisFailure>>,
}

static SESSION: Mutex<Session> =
    Mutex::new(Session { image: None, scan: None, writers: BTreeMap::new(), facts: BTreeMap::new() });

fn with_session<T>(identity: &Identity, f: impl FnOnce(&mut Session) -> T) -> T {
    let mut session = SESSION.lock().unwrap_or_else(PoisonError::into_inner);
    if session.image != Some(identity.digest()) {
        *session = Session { image: Some(identity.digest()), ..Session::default() };
    }
    let output = f(&mut session);
    drop(session);
    output
}

pub(super) fn full_scan(identity: &Identity) -> Option<Arc<FullScan>> {
    with_session(identity, |session| session.scan.clone())
}

pub(super) fn remember_full_scan(identity: &Identity, scan: FullScan) -> Arc<FullScan> {
    let scan = Arc::new(scan);
    with_session(identity, |session| session.scan = Some(Arc::clone(&scan)));
    scan
}

pub(super) fn writers(identity: &Identity, max_instructions: usize) -> Option<Arc<Vec<Entry>>> {
    with_session(identity, |session| session.writers.get(&max_instructions).cloned())
}

pub(super) fn remember_writers(identity: &Identity, max_instructions: usize, entries: Vec<Entry>) -> Arc<Vec<Entry>> {
    let entries = Arc::new(entries);
    with_session(identity, |session| session.writers.insert(max_instructions, Arc::clone(&entries)));
    entries
}

pub(super) type FactsMap = BTreeMap<u64, Result<Arc<Facts>, AnalysisFailure>>;

/// Facts already analyzed for `ranges`, and the ranges still to analyze.
pub(super) fn known_facts(
    identity: &Identity,
    max_instructions: usize,
    ranges: Vec<Range<u64>>,
) -> (FactsMap, Vec<Range<u64>>) {
    with_session(identity, |session| {
        let mut known = BTreeMap::new();
        let mut missing = Vec::new();
        for range in ranges {
            match session.facts.get(&(max_instructions, range.start)) {
                Some(outcome) => {
                    known.insert(range.start, outcome.clone());
                }
                None => missing.push(range),
            }
        }
        (known, missing)
    })
}

pub(super) fn remember_facts(identity: &Identity, max_instructions: usize, fresh: &FactsMap) {
    with_session(identity, |session| {
        for (start, outcome) in fresh {
            if session.facts.len() >= MAX_REMEMBERED_FACTS {
                break;
            }
            session.facts.insert((max_instructions, *start), outcome.clone());
        }
    });
}
