/*
 * XRef — Explicit static and observed graph evidence
 * Copyright (c) 2026 Alexander Panasenko
 * Contact: alex@prod.codes
 * Author: https://prod.codes/about/
 * Project: https://github.com/alex09x/xref
 * SPDX-License-Identifier: MIT OR Apache-2.0
 */
use super::{adapter::build_index, io::load_store};
use crate::{
    commands::Res,
    graph::{CallGraph, resolve},
    image::Image,
    trace_analysis::index::parse_hex,
};
use std::{
    collections::{BTreeMap, BTreeSet, VecDeque},
    io::Write,
    path::Path,
};

#[derive(Clone)]
struct Edge {
    caller: u64,
    callee: u64,
    site: Option<u64>,
    is_static: bool,
    samples: u64,
}
struct EvidenceGraph {
    outgoing: BTreeMap<u64, Vec<Edge>>,
    incoming: BTreeMap<u64, Vec<Edge>>,
    warnings: Vec<String>,
    stats: crate::trace_analysis::models::TraceStats,
}

impl EvidenceGraph {
    #[allow(clippy::similar_names)] // Caller/callee names follow the persisted graph schema.
    fn load(image: &Image, path: &Path) -> Result<Self, Box<dyn std::error::Error>> {
        let index = build_index(image, None)?;
        let store = load_store(path, &index)?;
        let mut edges: BTreeMap<(u64, u64, Option<u64>), Edge> = BTreeMap::new();
        for (caller, targets) in CallGraph::build(image).callees {
            for (site, callee) in targets {
                edges.entry((caller, callee, Some(site))).or_insert(Edge {
                    caller,
                    callee,
                    site: Some(site),
                    is_static: true,
                    samples: 0,
                });
            }
        }
        for entry in store.edges {
            let caller = parse_hex(&entry.caller)?;
            let callee = parse_hex(&entry.callee)?;
            let site = entry.caller_call_site.as_deref().map(parse_hex).transpose()?;
            let edge = edges.entry((caller, callee, site)).or_insert(Edge {
                caller,
                callee,
                site,
                is_static: false,
                samples: 0,
            });
            edge.samples = edge.samples.checked_add(entry.sample_count).ok_or("observed sample count overflow")?;
        }
        let mut graph =
            Self { outgoing: BTreeMap::new(), incoming: BTreeMap::new(), warnings: store.warnings, stats: store.stats };
        for edge in edges.into_values() {
            graph.outgoing.entry(edge.caller).or_default().push(edge.clone());
            graph.incoming.entry(edge.callee).or_default().push(edge);
        }
        Ok(graph)
    }
    fn notes(&self, out: &mut dyn Write) -> Res {
        let partial = self.stats.input_truncated
            || self.stats.aggregation_truncated
            || self.stats.unresolved_frames > 0
            || self.stats.malformed_lines > 0
            || self.stats.lost_events > 0;
        writeln!(
            out,
            "observed scope: samples={} weight={} unresolved_frames={} lost_events={} malformed_lines={} partial_import={partial}",
            self.stats.samples,
            self.stats.weight,
            self.stats.unresolved_frames,
            self.stats.lost_events,
            self.stats.malformed_lines
        )?;
        writeln!(
            out,
            "evidence: static = resolved binary call edge; observed = adjacent stack frames, not direct-call proof; samples are not invocation counts"
        )?;
        writeln!(
            out,
            "absence means not found in this static/imported subset; unknown/foreign frames are never bridged"
        )?;
        for warning in &self.warnings {
            writeln!(out, "warning: {warning}")?;
        }
        Ok(())
    }
}

fn evidence(edge: &Edge) -> String {
    let kind = match (edge.is_static, edge.samples > 0) {
        (true, true) => "static+observed",
        (true, false) => "static",
        (false, _) => "observed",
    };
    format!(
        "[{kind} samples={} call_site={}]",
        edge.samples,
        edge.site.map_or_else(|| "unknown".to_owned(), |s| format!("{s:#x}"))
    )
}

pub fn callers(image: &Image, spec: &str, observed: &Path, out: &mut dyn Write) -> Res {
    let function = resolve(image, spec)?;
    let graph = EvidenceGraph::load(image, observed)?;
    writeln!(out, "callers of {:#x}..{:#x} with observed evidence", function.start, function.end)?;
    let callers = graph.incoming.get(&function.start).map_or(&[][..], Vec::as_slice);
    for edge in callers {
        writeln!(out, "  fn_{:x} -> fn_{:x} {}", edge.caller, edge.callee, evidence(edge))?;
    }
    writeln!(out, "{} evidence rows", callers.len())?;
    graph.notes(out)
}

struct TreeView<'a> {
    graph: &'a EvidenceGraph,
    reverse: bool,
    remaining: usize,
    truncated: bool,
}
impl TreeView<'_> {
    fn write(
        &mut self,
        node: u64,
        depth: usize,
        prefix: &str,
        ancestors: &mut BTreeSet<u64>,
        out: &mut dyn Write,
    ) -> Res {
        if depth == 0 {
            return Ok(());
        }
        let edges = if self.reverse { self.graph.incoming.get(&node) } else { self.graph.outgoing.get(&node) };
        for edge in edges.into_iter().flatten() {
            if self.remaining == 0 {
                self.truncated = true;
                break;
            }
            self.remaining -= 1;
            let next = if self.reverse { edge.caller } else { edge.callee };
            let cycle = ancestors.contains(&next);
            writeln!(out, "{prefix}  fn_{next:x} {}{}", evidence(edge), if cycle { " [cycle]" } else { "" })?;
            if !cycle {
                ancestors.insert(next);
                self.write(next, depth - 1, &format!("{prefix}  "), ancestors, out)?;
                ancestors.remove(&next);
            }
        }
        Ok(())
    }
}

#[allow(clippy::similar_names)] // Flags distinguish caller and callee directions.
pub fn tree(
    image: &Image,
    spec: &str,
    callers: bool,
    callees: bool,
    depth: usize,
    observed: &Path,
    out: &mut dyn Write,
) -> Res {
    if depth > 32 {
        return Err("observed tree depth must be <=32".into());
    }
    let function = resolve(image, spec)?;
    let graph = EvidenceGraph::load(image, observed)?;
    writeln!(out, "fn_{:x} with observed evidence", function.start)?;
    for reverse in [true, false] {
        if (reverse && !callers) || (!reverse && !callees) {
            continue;
        }
        writeln!(out, "{}:", if reverse { "callers" } else { "callees" })?;
        let mut view = TreeView { graph: &graph, reverse, remaining: 4096, truncated: false };
        view.write(function.start, depth, "", &mut BTreeSet::from([function.start]), out)?;
        if view.truncated {
            writeln!(out, "truncated after 4096 displayed evidence rows")?;
        }
    }
    graph.notes(out)
}

pub fn path(image: &Image, from: &str, to: &str, depth: usize, observed: &Path, out: &mut dyn Write) -> Res {
    if depth > 64 {
        return Err("observed path depth must be <=64".into());
    }
    let from = resolve(image, from)?.start;
    let to = resolve(image, to)?.start;
    let graph = EvidenceGraph::load(image, observed)?;
    let mut queue = VecDeque::from([(from, 0usize)]);
    let mut seen = BTreeSet::from([from]);
    let mut previous: BTreeMap<u64, Edge> = BTreeMap::new();
    while let Some((node, distance)) = queue.pop_front() {
        if node == to {
            break;
        }
        if distance >= depth {
            continue;
        }
        for edge in graph.outgoing.get(&node).into_iter().flatten() {
            if seen.insert(edge.callee) {
                previous.insert(edge.callee, edge.clone());
                queue.push_back((edge.callee, distance + 1));
            }
        }
    }
    if seen.contains(&to) {
        let mut path = Vec::new();
        let mut node = to;
        while node != from {
            let edge = previous.get(&node).ok_or("incomplete observed path")?;
            path.push(edge);
            node = edge.caller;
        }
        writeln!(out, "one shortest evidence path (may contain non-direct observed adjacencies):")?;
        writeln!(out, "fn_{from:x}")?;
        for edge in path.into_iter().rev() {
            writeln!(out, "  -> fn_{:x} {}", edge.callee, evidence(edge))?;
        }
    } else {
        writeln!(out, "no path found in static/imported subset within depth {depth}")?;
    }
    graph.notes(out)
}
