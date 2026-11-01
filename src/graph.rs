/*
 * xref — Ultra blazing fast cross-references of an x86-64 ELF binary
 * Copyright (c) 2026 Alexander Panasenko
 *
 * Contact: alex@prod.codes
 * Author: https://prod.codes/about/
 * SPDX-License-Identifier: MIT OR Apache-2.0
 */

//! Parallel whole-binary call graph, shortest call chains (`path`) and caller/callee trees (`tree`).

use std::collections::{HashMap, VecDeque};
use std::error::Error;
use std::io::Write;
use std::ops::Range;

use rayon::prelude::*;

use crate::cli::parse_number;
use crate::commands::{Res, function};
use crate::image::{Image, Slot};
use crate::listing::is_call;
use crate::locations::{Location, locations};
use crate::scan::{branch_target, decode};
use crate::source::location_at;

pub struct CallGraph {
    pub callees: HashMap<u64, Vec<(u64, u64)>>,
    pub callers: HashMap<u64, Vec<(u64, u64)>>,
}

impl CallGraph {
    pub fn build(image: &Image) -> Self {
        let edges: Vec<(u64, u64, u64)> = image
            .functions
            .par_iter()
            .filter_map(|f| Some((f, image.code(f)?)))
            .flat_map_iter(|(f, bytes)| {
                let mut out = Vec::new();
                decode(bytes, f.start, |instruction| {
                    if !is_call(instruction, f) {
                        return;
                    }
                    let target = branch_target(instruction).or_else(|| {
                        if instruction.is_ip_rel_memory_operand()
                            && let Some(Slot::Pointer(t)) = image.slot(instruction.ip_rel_memory_address())
                        {
                            Some(t)
                        } else {
                            None
                        }
                    });
                    if let Some(callee) = target.and_then(|t| image.function_at(t)) {
                        out.push((f.start, instruction.ip(), callee.start));
                    }
                });
                out
            })
            .collect();
        let mut out_edges: HashMap<u64, Vec<(u64, u64)>> = HashMap::new();
        let mut in_edges: HashMap<u64, Vec<(u64, u64)>> = HashMap::new();
        for (caller, ip, callee) in edges {
            out_edges.entry(caller).or_default().push((ip, callee));
            in_edges.entry(callee).or_default().push((ip, caller));
        }
        Self { callees: out_edges, callers: in_edges }
    }
}

pub fn resolve(image: &Image, spec: &str) -> Result<Range<u64>, Box<dyn Error>> {
    if let Ok(addr) = parse_number(spec) {
        return function(image, addr);
    }
    let &(addr, _) = image
        .symbols
        .iter()
        .find(|(_, name)| name == spec)
        .or_else(|| image.symbols.iter().find(|(_, name)| name.contains(spec)))
        .ok_or_else(|| format!("no function matches {spec:?}"))?;
    function(image, addr)
}

fn unique_edges(list: &[(u64, u64)]) -> Vec<(u64, u64, usize)> {
    let mut out: Vec<(u64, u64, usize)> = Vec::new();
    for &(ip, target) in list {
        if let Some(entry) = out.iter_mut().find(|(_, t, _)| *t == target) {
            entry.2 += 1;
        } else {
            out.push((ip, target, 1));
        }
    }
    out
}

struct PathSearch<'a> {
    to: u64,
    target_hops: usize,
    graph: &'a CallGraph,
    dist: &'a HashMap<u64, usize>,
}

fn dfs_paths(
    u: u64,
    search: &PathSearch<'_>,
    nodes: &mut Vec<u64>,
    sites: &mut Vec<u64>,
    chains: &mut Vec<(Vec<u64>, Vec<u64>)>,
) {
    if sites.len() == search.target_hops {
        if u == search.to && chains.len() < 32 {
            chains.push((nodes.clone(), sites.clone()));
        }
        return;
    }
    let Some(list) = search.graph.callees.get(&u) else { return };
    for (ip, v, _) in unique_edges(list) {
        if !nodes.contains(&v) && search.dist.get(&v).is_some_and(|&d| sites.len() + 1 + d <= search.target_hops) {
            nodes.push(v);
            sites.push(ip);
            dfs_paths(v, search, nodes, sites, chains);
            sites.pop();
            nodes.pop();
        }
    }
}

pub fn path(image: &Image, from_spec: &str, to_spec: &str, depth: usize, out: &mut dyn Write) -> Res {
    let from = resolve(image, from_spec)?.start;
    let to = resolve(image, to_spec)?.start;
    let graph = CallGraph::build(image);
    let mut dist: HashMap<u64, usize> = HashMap::new();
    let mut queue = VecDeque::new();
    dist.insert(to, 0);
    queue.push_back(to);
    while let Some(cur) = queue.pop_front() {
        let d = dist[&cur];
        if d >= depth {
            continue;
        }
        if let Some(preds) = graph.callers.get(&cur) {
            for &(_, caller) in preds {
                if let std::collections::hash_map::Entry::Vacant(e) = dist.entry(caller) {
                    e.insert(d + 1);
                    queue.push_back(caller);
                }
            }
        }
    }
    let mut chains = Vec::new();
    if let Some(&min_hops) = dist.get(&from) {
        let max_hops = depth.min(min_hops + 2);
        let mut nodes = vec![from];
        let mut sites = Vec::new();
        for target_hops in min_hops..=max_hops {
            let search = PathSearch { to, target_hops, graph: &graph, dist: &dist };
            dfs_paths(from, &search, &mut nodes, &mut sites, &mut chains);
        }
    }
    for (nodes, sites) in &chains {
        let nodes_str: Vec<String> = nodes.iter().map(|n| format!("{n:#x}")).collect();
        let sites_str: Vec<String> = sites.iter().map(|s| format!("{s:#x}")).collect();
        writeln!(out, "{}  (via {})", nodes_str.join(" -> "), sites_str.join(", "))?;
    }
    writeln!(out, "{} paths", chains.len())?;
    Ok(())
}

fn first_loc(image: &Image, all_locations: &[Location], f: &Range<u64>) -> String {
    let Some(bytes) = image.code(f) else { return String::new() };
    let mut found = None;
    decode(bytes, f.start, |instruction| {
        if found.is_some() || !instruction.is_ip_rel_memory_operand() {
            return;
        }
        if let Some(loc) = location_at(all_locations, instruction.ip_rel_memory_address()) {
            found = Some(format!("  {}:{}:{}", loc.file, loc.line, loc.col));
        }
    });
    found.unwrap_or_default()
}

struct TreeCtx<'a> {
    image: &'a Image,
    adj: &'a HashMap<u64, Vec<(u64, u64)>>,
    locations: &'a [Location],
    depth: usize,
}

fn write_tree(ctx: &TreeCtx<'_>, node: u64, level: usize, ancestors: &mut Vec<u64>, out: &mut dyn Write) -> Res {
    if level > ctx.depth {
        return Ok(());
    }
    let Some(list) = ctx.adj.get(&node) else { return Ok(()) };
    let indent = "  ".repeat(level);
    for (ip, next, count) in unique_edges(list) {
        let f = ctx.image.function_at(next).unwrap_or(next..next);
        let mult = if count > 1 { format!(" x{count}") } else { String::new() };
        if ancestors.contains(&next) {
            writeln!(out, "{indent}{:#x}..{:#x}  at {ip:#x}{mult} (cycle)", f.start, f.end)?;
        } else {
            let src = first_loc(ctx.image, ctx.locations, &f);
            writeln!(out, "{indent}{:#x}..{:#x}  at {ip:#x}{mult}{src}", f.start, f.end)?;
            ancestors.push(next);
            write_tree(ctx, next, level + 1, ancestors, out)?;
            ancestors.pop();
        }
    }
    Ok(())
}

pub fn tree(image: &Image, spec: &str, callers_mode: bool, depth: usize, out: &mut dyn Write) -> Res {
    let root = resolve(image, spec)?;
    let graph = CallGraph::build(image);
    let all_locations = locations(image);
    let adj = if callers_mode { &graph.callers } else { &graph.callees };
    writeln!(out, "{:#x}..{:#x}{}", root.start, root.end, first_loc(image, &all_locations, &root))?;
    let ctx = TreeCtx { image, adj, locations: &all_locations, depth };
    let mut ancestors = vec![root.start];
    write_tree(&ctx, root.start, 1, &mut ancestors, out)
}

#[cfg(test)]
mod tests {
    use super::{path, resolve, tree};
    use crate::image::{Image, Segment};

    #[test]
    fn finds_shortest_paths_and_renders_trees_with_cycles_and_locations() {
        let mut data = vec![0xc3u8; 0x300];
        // 0x1000 (fn_a): call 0x1020 (2x), call [rip + ...] -> 0x1200 (Pointer to 0x1040), ret
        data[0x00..0x05].copy_from_slice(&[0xe8, 0x1b, 0x00, 0x00, 0x00]); // 0x1000: call 0x1020
        data[0x05..0x0a].copy_from_slice(&[0xe8, 0x16, 0x00, 0x00, 0x00]); // 0x1005: call 0x1020
        data[0x0a..0x10].copy_from_slice(&[0xff, 0x15, 0xea, 0x01, 0x00, 0x00]); // 0x100a: call [0x11fa] -> 0x1040
        // 0x1020 (fn_b): call 0x1000 (cycle), jmp 0x1040 (tail call)
        data[0x20..0x25].copy_from_slice(&[0xe8, 0xdb, 0xff, 0xff, 0xff]); // 0x1020: call 0x1000
        data[0x25..0x2a].copy_from_slice(&[0xe9, 0x16, 0x00, 0x00, 0x00]); // 0x1025: jmp 0x1040
        // 0x1040 (fn_c): lea rdi, [rip + 0x1b9] -> 0x1200 (panic Location "src/lib.rs":10:5), ret
        data[0x40..0x47].copy_from_slice(&[0x48, 0x8d, 0x3d, 0xb9, 0x01, 0x00, 0x00]);
        data[0x208..0x210].copy_from_slice(&10u64.to_le_bytes());
        data[0x210..0x214].copy_from_slice(&10u32.to_le_bytes());
        data[0x214..0x218].copy_from_slice(&5u32.to_le_bytes());
        data[0x220..0x22a].copy_from_slice(b"src/lib.rs");

        let image = Image {
            data,
            segments: vec![Segment { va: 0x1000, offset: 0, size: 0x300 }],
            functions: vec![0x1000..0x1011, 0x1020..0x102a, 0x1040..0x1048],
            pointers: vec![(0x11fa, 0x1040), (0x1200, 0x1220)],
            imports: Vec::new(),
            symbols: vec![(0x1000, "fn_a".to_owned()), (0x1020, "prefix_fn_b".to_owned()), (0x1040, "fn_c".to_owned())],
        };

        assert!(resolve(&image, "fn_a").is_ok());
        assert!(resolve(&image, "fn_b").is_ok());
        assert!(resolve(&image, "missing").is_err());

        let mut path_buf = Vec::new();
        assert!(path(&image, "fn_a", "0x1040", 4, &mut path_buf).is_ok());
        let p_text = String::from_utf8_lossy(&path_buf);
        assert!(p_text.contains("0x1000 -> 0x1040  (via 0x100a)"), "{p_text}");
        assert!(p_text.contains("0x1000 -> 0x1020 -> 0x1040  (via 0x1000, 0x1025)"), "{p_text}");

        let mut empty_buf = Vec::new();
        assert!(path(&image, "0x1040", "0x1000", 1, &mut empty_buf).is_ok());
        assert!(String::from_utf8_lossy(&empty_buf).contains("0 paths"));

        let mut t_out = Vec::new();
        assert!(tree(&image, "fn_a", false, 2, &mut t_out).is_ok());
        let t_text = String::from_utf8_lossy(&t_out);
        assert!(t_text.contains("0x1020..0x102a  at 0x1000 x2") && t_text.contains("(cycle)"), "{t_text}");
        assert!(t_text.contains("src/lib.rs:10:5"), "{t_text}");

        let mut callers_out = Vec::new();
        assert!(tree(&image, "fn_c", true, 1, &mut callers_out).is_ok());
        assert!(String::from_utf8_lossy(&callers_out).contains("0x1000..0x1011"));
    }
}
