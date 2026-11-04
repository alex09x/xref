/*
 * XRef — compact call graph for repeated field searches in one process
 * Copyright (c) 2026 Alexander Panasenko
 * Contact: alex@prod.codes
 * Author: https://prod.codes/about/
 * Project: https://github.com/alex09x/xref
 * SPDX-License-Identifier: MIT OR Apache-2.0
 */

//! The same direct-call graph as `catalog::CallGraph`, stored as sorted node ids with compressed
//! adjacency (CSR). Built once per session; seed propagation and call distances then run over dense
//! arrays instead of `BTreeMap` lookups, with results identical to the map-based versions.

use super::catalog::CallGraph;
use std::collections::{BTreeMap, BTreeSet, VecDeque};

pub(super) struct DenseGraph {
    /// Every function start or call target, ascending; a node id is its index here.
    nodes: Vec<u64>,
    forward_offsets: Vec<u32>,
    forward: Vec<u32>,
    reverse_offsets: Vec<u32>,
    reverse: Vec<u32>,
}

fn compress(nodes: &[u64], graph: &CallGraph) -> Option<(Vec<u32>, Vec<u32>)> {
    let mut offsets = Vec::with_capacity(nodes.len() + 1);
    let mut targets = Vec::new();
    offsets.push(0);
    for node in nodes {
        // BTreeSet iteration is ascending, so adjacency stays in the map-based order.
        for target in graph.get(node).into_iter().flatten() {
            targets.push(u32::try_from(nodes.binary_search(target).ok()?).ok()?);
        }
        offsets.push(u32::try_from(targets.len()).ok()?);
    }
    Some((offsets, targets))
}

impl DenseGraph {
    pub fn new(forward: &CallGraph, reverse: &CallGraph) -> Option<Self> {
        let nodes: Vec<u64> = forward
            .iter()
            .chain(reverse.iter())
            .flat_map(|(node, edges)| std::iter::once(*node).chain(edges.iter().copied()))
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect();
        let (forward_offsets, forward) = compress(&nodes, forward)?;
        let (reverse_offsets, reverse) = compress(&nodes, reverse)?;
        Some(Self { nodes, forward_offsets, forward, reverse_offsets, reverse })
    }

    fn id(&self, address: u64) -> Option<usize> {
        self.nodes.binary_search(&address).ok()
    }

    fn neighbours<'a>(offsets: &[u32], edges: &'a [u32], node: usize) -> &'a [u32] {
        let start = offsets.get(node).map_or(0, |v| *v as usize);
        let end = offsets.get(node + 1).map_or(start, |v| *v as usize);
        edges.get(start..end).unwrap_or(&[])
    }

    fn callers(&self, node: usize) -> &[u32] {
        Self::neighbours(&self.reverse_offsets, &self.reverse, node)
    }

    fn callees(&self, node: usize) -> &[u32] {
        Self::neighbours(&self.forward_offsets, &self.forward, node)
    }

    /// Same contract as `seeds::select`, over this graph.
    #[allow(clippy::too_many_arguments)]
    pub fn select(
        &self,
        direct: &BTreeMap<u64, u16>,
        minimum: usize,
        limit: usize,
        depth_limit: usize,
        exhaustive: bool,
    ) -> (BTreeSet<u64>, bool, bool, usize) {
        let mut masks = vec![0_u16; self.nodes.len()];
        let mut touched = Vec::new();
        // Seeds that are not graph nodes (no calls in or out) keep their own mask.
        let mut isolated: BTreeMap<u64, u16> = BTreeMap::new();
        let mut propagation = VecDeque::new();
        for (&function, &mask) in direct {
            match self.id(function) {
                Some(node) => {
                    if masks[node] == 0 {
                        touched.push(node);
                    }
                    masks[node] |= mask;
                    propagation.push_back((node, mask, 0));
                }
                None => {
                    isolated.insert(function, mask);
                }
            }
        }
        if !exhaustive {
            while let Some((node, mask, depth)) = propagation.pop_front() {
                if depth >= depth_limit {
                    continue;
                }
                for &parent in self.callers(node) {
                    let parent = parent as usize;
                    let added = mask & !masks[parent];
                    if added != 0 {
                        if masks[parent] == 0 {
                            touched.push(parent);
                        }
                        masks[parent] |= added;
                        propagation.push_back((parent, added, depth + 1));
                    }
                }
            }
        }
        let direct_count = |function: u64| direct.get(&function).copied().unwrap_or(0).count_ones();
        let mut roots: Vec<(u64, u32)> = touched
            .iter()
            .map(|&node| (self.nodes[node], masks[node]))
            .chain(isolated.iter().map(|(&function, &mask)| (function, mask)))
            .filter(|(_, mask)| mask.count_ones() as usize >= minimum)
            .map(|(function, mask)| (function, mask.count_ones()))
            .collect();
        let fallback = !exhaustive && roots.is_empty();
        let use_partial = fallback || exhaustive;
        if use_partial {
            roots = direct.iter().map(|(&function, &mask)| (function, mask.count_ones())).collect();
        }
        // Same order as `seeds::select`, with the direct-key count computed once per root.
        roots.sort_by_cached_key(|&(function, count)| {
            (std::cmp::Reverse(count), std::cmp::Reverse(direct_count(function)), function)
        });
        let mask_of = |function: u64| {
            self.id(function).map_or_else(|| isolated.get(&function).copied().unwrap_or(0), |node| masks[node])
        };
        let mut pending: VecDeque<u64> = roots.into_iter().map(|(function, _)| function).collect();
        let mut selected = BTreeSet::new();
        let mut truncated = false;
        while let Some(function) = pending.pop_front() {
            if selected.contains(&function) {
                continue;
            }
            if selected.len() >= limit {
                truncated = true;
                break;
            }
            selected.insert(function);
            let Some(node) = self.id(function) else { continue };
            if use_partial {
                pending.extend(self.callers(node).iter().map(|&parent| self.nodes[parent as usize]));
            } else {
                for &child in self.callees(node) {
                    let child = self.nodes[child as usize];
                    if mask_of(child) != 0 {
                        pending.push_back(child);
                    }
                }
            }
        }
        let excluded =
            if use_partial { 0 } else { direct.keys().filter(|function| !selected.contains(function)).count() };
        (selected, truncated, fallback, excluded)
    }

    #[cfg(test)]
    pub const fn node_count(&self) -> usize {
        self.nodes.len()
    }

    /// Undirected call distance (at most 6 edges) from `start`, as `accessors::call_distances`.
    pub fn distances(&self, start: u64) -> BTreeMap<u64, usize> {
        let mut distance = BTreeMap::from([(start, 0)]);
        let Some(origin) = self.id(start) else { return distance };
        let mut seen = vec![u8::MAX; self.nodes.len()];
        seen[origin] = 0;
        let mut queue = VecDeque::from([origin]);
        while let Some(node) = queue.pop_front() {
            let next = seen[node] + 1;
            if next > 6 {
                continue;
            }
            for &neighbour in self.callees(node).iter().chain(self.callers(node)) {
                let neighbour = neighbour as usize;
                if seen[neighbour] == u8::MAX {
                    seen[neighbour] = next;
                    distance.insert(self.nodes[neighbour], usize::from(next));
                    queue.push_back(neighbour);
                }
            }
        }
        distance
    }
}

#[cfg(test)]
mod tests {
    use super::{CallGraph, DenseGraph};
    use std::collections::{BTreeMap, BTreeSet, VecDeque};

    /// Deterministic pseudo-random call graph with seeds; xorshift keeps the test reproducible.
    fn graph(seed: u64, nodes: u64, edges: usize) -> (CallGraph, CallGraph, BTreeMap<u64, u16>) {
        let mut state = seed;
        let mut next = move || {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            state
        };
        let (mut forward, mut reverse) = (CallGraph::new(), CallGraph::new());
        for _ in 0..edges {
            let (from, to) = (0x1000 + next() % nodes * 16, 0x1000 + next() % nodes * 16);
            forward.entry(from).or_default().insert(to);
            reverse.entry(to).or_default().insert(from);
        }
        let mut direct = BTreeMap::new();
        for _ in 0..nodes / 4 {
            direct.insert(0x1000 + next() % (nodes + 8) * 16, u16::try_from(1 + next() % 7).unwrap_or(1));
        }
        (forward, reverse, direct)
    }

    fn map_distances(forward: &CallGraph, reverse: &CallGraph, start: u64) -> BTreeMap<u64, usize> {
        let mut distance = BTreeMap::from([(start, 0)]);
        let mut queue = VecDeque::from([start]);
        while let Some(function) = queue.pop_front() {
            let next = distance[&function] + 1;
            if next > 6 {
                continue;
            }
            for &neighbor in
                forward.get(&function).into_iter().flatten().chain(reverse.get(&function).into_iter().flatten())
            {
                distance.entry(neighbor).or_insert_with(|| {
                    queue.push_back(neighbor);
                    next
                });
            }
        }
        distance
    }

    #[test]
    fn dense_selection_and_distances_match_the_map_based_versions() {
        for seed in 1..=40 {
            let (forward, reverse, direct) = graph(seed * 7919, 60 + seed * 3, usize::try_from(seed * 9).unwrap_or(0));
            let Some(dense) = DenseGraph::new(&forward, &reverse) else { panic!("graph fits u32 ids") };
            assert!(dense.node_count() <= forward.len() + reverse.len() + direct.len() + 1_000);
            for (minimum, limit, depth, exhaustive) in [(2, 8, 12, false), (3, 64, 2, false), (1, 4, 12, true)] {
                assert_eq!(
                    dense.select(&direct, minimum, limit, depth, exhaustive),
                    super::super::seeds::select(&direct, &reverse, &forward, minimum, limit, depth, exhaustive),
                    "seed {seed} minimum {minimum} limit {limit} depth {depth} exhaustive {exhaustive}"
                );
            }
            for start in direct.keys().take(5).copied().chain([0x1000, 0xdead_0000]) {
                assert_eq!(
                    dense.distances(start),
                    map_distances(&forward, &reverse, start),
                    "seed {seed} start {start:#x}"
                );
            }
            let _: BTreeSet<u64> = BTreeSet::new();
        }
    }
}
