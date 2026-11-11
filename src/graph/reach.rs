/*
 * xref — Ultra blazing fast cross-references of an x86-64 ELF binary
 * Copyright (c) 2026 Alexander Panasenko
 *
 * Contact: alex@prod.codes
 * Author: https://prod.codes/about/
 * Project: https://github.com/alex09x/xref
 * SPDX-License-Identifier: MIT OR Apache-2.0
 */

//! `path FROM --to-any A,B,...`: which of many functions (or code addresses inside them) one
//! function reaches within a depth, each with its shortest call chain.

use std::collections::{HashMap, VecDeque};
use std::io::Write;

use super::{CallGraph, resolve, resolve_addr};
use crate::commands::Res;
use crate::image::Image;

/// Shortest-chain tree from `from`: each reached function with its caller and call site.
fn shortest(graph: &CallGraph, from: u64, depth: usize) -> HashMap<u64, (usize, u64, u64)> {
    let mut seen = HashMap::from([(from, (0, from, 0))]);
    let mut queue = VecDeque::from([from]);
    while let Some(cur) = queue.pop_front() {
        let hops = seen[&cur].0;
        if hops >= depth {
            continue;
        }
        for &(ip, callee) in graph.callees.get(&cur).map_or(&[][..], Vec::as_slice) {
            seen.entry(callee).or_insert_with(|| {
                queue.push_back(callee);
                (hops + 1, cur, ip)
            });
        }
    }
    seen
}

fn chain(seen: &HashMap<u64, (usize, u64, u64)>, from: u64, to: u64) -> (Vec<u64>, Vec<u64>) {
    let (mut nodes, mut sites) = (vec![to], Vec::new());
    let mut cur = to;
    while cur != from {
        let (_, parent, ip) = seen[&cur];
        sites.push(ip);
        nodes.push(parent);
        cur = parent;
    }
    nodes.reverse();
    sites.reverse();
    (nodes, sites)
}

fn hex_list(values: &[u64]) -> Vec<String> {
    values.iter().map(|v| format!("{v:#x}")).collect()
}

pub fn reach_any(image: &Image, from_spec: &str, targets: &[String], depth: usize, out: &mut dyn Write) -> Res {
    let from = resolve(image, from_spec)?.start;
    let graph = CallGraph::build(image);
    let seen = shortest(&graph, from, depth);
    let mut rows = Vec::new();
    let mut missing = Vec::new();
    for spec in targets {
        let addr = resolve_addr(image, spec)?;
        let Some(function) = image.function_at(addr) else {
            missing.push(format!("{spec}  not in a function"));
            continue;
        };
        let label =
            if addr == function.start { format!("{addr:#x}") } else { format!("{addr:#x} (in {:#x})", function.start) };
        match seen.get(&function.start) {
            Some(&(hops, ..)) => rows.push((hops, label, chain(&seen, from, function.start))),
            None => missing.push(format!("{label}  not reached within {depth}")),
        }
    }
    rows.sort_by_key(|(hops, ..)| *hops);
    for (hops, label, (nodes, sites)) in &rows {
        let via = if sites.is_empty() { String::new() } else { format!("  (via {})", hex_list(sites).join(", ")) };
        writeln!(out, "{label}  {hops} hops  {}{via}", hex_list(nodes).join(" -> "))?;
    }
    for line in &missing {
        writeln!(out, "{line}")?;
    }
    writeln!(out, "{} of {} reached from {from:#x} within {depth}", rows.len(), targets.len())?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::image::Segment;

    #[test]
    fn to_any_lists_shortest_chains_and_unreached_targets() {
        let mut data = vec![0xc3u8; 0x100];
        // 0x1000: call 0x1010; jmp 0x1020 (tail call)
        data[..10].copy_from_slice(&[0xe8, 0x0b, 0, 0, 0, 0xe9, 0x16, 0, 0, 0]);
        // 0x1010: call 0x1030
        data[0x10..0x15].copy_from_slice(&[0xe8, 0x1b, 0, 0, 0]);
        let image = Image {
            data,
            segments: vec![Segment { va: 0x1000, offset: 0, size: 0x100 }],
            functions: vec![0x1000..0x1010, 0x1010..0x1020, 0x1020..0x1030, 0x1030..0x1040, 0x1040..0x1050],
            pointers: Vec::new(),
            imports: Vec::new(),
            symbols: Vec::new(),
            metadata: crate::image_format::Metadata::default(),
        };
        let targets = ["0x1032", "0x1020", "0x1040", "0x2000"].map(str::to_owned);
        let mut out = Vec::new();
        assert!(reach_any(&image, "0x1000", &targets, 3, &mut out).is_ok());
        let text = String::from_utf8_lossy(&out);
        assert!(text.contains("0x1020  1 hops  0x1000 -> 0x1020  (via 0x1005)"), "{text}");
        assert!(
            text.contains("0x1032 (in 0x1030)  2 hops  0x1000 -> 0x1010 -> 0x1030  (via 0x1000, 0x1010)"),
            "{text}"
        );
        assert!(text.contains("0x1040  not reached within 3"), "{text}");
        assert!(text.contains("0x2000  not in a function"), "{text}");
        assert!(text.contains("2 of 4 reached from 0x1000 within 3"), "{text}");
        out.clear();
        assert!(reach_any(&image, "0x1000", &targets, 1, &mut out).is_ok());
        assert!(String::from_utf8_lossy(&out).contains("1 of 4 reached"));
    }
}

#[cfg(test)]
mod cli_tests {
    use clap::Parser;

    use crate::cli::Cli;

    #[test]
    fn path_takes_to_or_to_any() {
        assert!(Cli::try_parse_from(["xref", "-b", "x", "path", "a", "--to-any", "b,c", "--depth", "3"]).is_ok());
        assert!(Cli::try_parse_from(["xref", "-b", "x", "path", "a", "b"]).is_ok());
        assert!(Cli::try_parse_from(["xref", "-b", "x", "path", "a"]).is_err());
        assert!(Cli::try_parse_from(["xref", "-b", "x", "path", "a", "b", "--to-any", "c"]).is_err());
    }
}
