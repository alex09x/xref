/*
 * xref — Ultra blazing fast cross-references of an x86-64 ELF binary
 * Copyright (c) 2026 Alexander Panasenko
 *
 * Contact: alex@prod.codes
 * Author: https://prod.codes/about/
 * SPDX-License-Identifier: MIT OR Apache-2.0
 */

//! Single-pass multi-predicate function search (`find`).

use std::error::Error;
use std::io::Write;
use std::ops::{Range, RangeInclusive};

use iced_x86::Instruction;
use rayon::prelude::*;

use crate::cli::{hex_address, parse_number};
use crate::commands::Res;
use crate::graph::{call_target, resolve_addr};
use crate::image::Image;
use crate::listing::is_call;
use crate::locations::locations;
use crate::reach::{reach, windows};
use crate::scan::{Query, decode, matches};

mod instructions;
pub use instructions::find_with_instructions;

pub struct FindSpec {
    pub calls: Vec<String>,
    pub refs: Vec<String>,
    pub imm: Vec<u64>,
    pub imm_mode: (bool, bool),
    pub disp: Vec<u64>,
    pub disp_mode: (bool, bool),
    pub src: Vec<String>,
    pub size: Option<String>,
    pub any: Option<usize>,
    pub back: u64,
}

enum PredKind {
    Calls(u64),
    Refs(Vec<u64>),
    Imm { value: u64, store: bool, cmp: bool },
    Disp { value: u64, write: bool, lea: bool },
    Src(Vec<u64>),
    Size(RangeInclusive<u64>),
}

struct Pred {
    label: String,
    kind: PredKind,
}

type FindResult = (usize, Range<u64>, Vec<Option<u64>>, Vec<InstructionHits>);

struct InstructionHits {
    sites: Vec<u64>,
    total: usize,
}

impl Pred {
    fn matches_inst(&self, image: &Image, f: &Range<u64>, instruction: &Instruction) -> bool {
        match &self.kind {
            PredKind::Calls(target) => is_call(instruction, f) && call_target(image, instruction) == Some(*target),
            PredKind::Refs(addrs) => matches(&Query::Ref(addrs.clone()), instruction),
            PredKind::Imm { value, store, cmp } => {
                matches(&Query::Imm { value: *value, store: *store, cmp: *cmp }, instruction)
            }
            PredKind::Disp { value, write, lea } => {
                matches(&Query::Disp { value: *value, write: *write, lea: *lea }, instruction)
            }
            PredKind::Src(addrs) => {
                instruction.is_ip_rel_memory_operand()
                    && addrs.binary_search(&instruction.ip_rel_memory_address()).is_ok()
            }
            PredKind::Size(_) => false,
        }
    }
}

pub fn parse_size(spec: &str) -> Result<RangeInclusive<u64>, String> {
    if let Some((lo, hi)) = spec.split_once("..") {
        let min = if lo.is_empty() { 0 } else { parse_number(lo)? };
        let max = if hi.is_empty() { u64::MAX } else { parse_number(hi)? };
        Ok(min..=max)
    } else {
        let exact = parse_number(spec)?;
        Ok(exact..=exact)
    }
}

fn build_preds(image: &Image, spec: &FindSpec) -> Result<Vec<Pred>, Box<dyn Error>> {
    let mut preds = Vec::new();
    for c in &spec.calls {
        let raw = resolve_addr(image, c)?;
        let target = image.function_at(raw).map_or(raw, |f| f.start);
        preds.push(Pred { label: format!("calls:{target:#x}"), kind: PredKind::Calls(target) });
    }
    for r in &spec.refs {
        let reached = hex_address(r).map_or_else(
            || reach(image, windows(&image.find(r.as_bytes()), spec.back)),
            |addr| reach(image, std::iter::once(addr..=addr)),
        );
        preds.push(Pred { label: format!("refs:{r}"), kind: PredKind::Refs(reached.addresses) });
    }
    for &value in &spec.imm {
        let (store, cmp) = spec.imm_mode;
        preds.push(Pred { label: format!("imm:{value:#x}"), kind: PredKind::Imm { value, store, cmp } });
    }
    for &value in &spec.disp {
        let (write, lea) = spec.disp_mode;
        preds.push(Pred { label: format!("disp:{value:#x}"), kind: PredKind::Disp { value, write, lea } });
    }
    if !spec.src.is_empty() {
        let all_locs = locations(image);
        for pat in &spec.src {
            let mut addrs: Vec<u64> = all_locs
                .iter()
                .filter(|loc| format!("{}:{}", loc.file, loc.line).contains(pat))
                .map(|loc| loc.place)
                .collect();
            addrs.sort_unstable();
            addrs.dedup();
            preds.push(Pred { label: format!("src:{pat}"), kind: PredKind::Src(addrs) });
        }
    }
    if let Some(sz) = &spec.size {
        let range = parse_size(sz)?;
        preds.push(Pred { label: format!("size:{sz}"), kind: PredKind::Size(range) });
    }
    Ok(preds)
}

pub fn find(image: &Image, spec: &FindSpec, out: &mut dyn Write) -> Res {
    find_with_instructions(image, spec, &[], &[], out)
}

pub(in crate::find) fn find_impl(
    image: &Image,
    spec: &FindSpec,
    instruction_patterns: &[instructions::InstructionPredicate],
    out: &mut dyn Write,
) -> Res {
    let preds = build_preds(image, spec)?;
    let total = preds.len() + instruction_patterns.len();
    if total == 0 {
        return Err("at least one predicate is required".into());
    }
    let min_req = spec.any.unwrap_or(total).clamp(1, total);
    let mut results: Vec<FindResult> = image
        .functions
        .par_iter()
        .filter_map(|f| {
            let bytes = image.code(f)?;
            let mut hits: Vec<Option<u64>> = preds
                .iter()
                .map(|p| match &p.kind {
                    PredKind::Size(r) if r.contains(&(f.end - f.start)) => Some(f.start),
                    _ => None,
                })
                .collect();
            let mut instruction_hits: Vec<InstructionHits> = (0..instruction_patterns.len())
                .map(|_| InstructionHits { sites: Vec::with_capacity(instructions::MAX_SITES), total: 0 })
                .collect();
            decode(bytes, f.start, |instruction| {
                for (slot, pred) in hits.iter_mut().zip(&preds) {
                    if slot.is_none() && pred.matches_inst(image, f, instruction) {
                        *slot = Some(instruction.ip());
                    }
                }
                for (hits, pred) in instruction_hits.iter_mut().zip(instruction_patterns) {
                    if pred.matches(instruction) {
                        hits.total += 1;
                        if hits.sites.len() < instructions::MAX_SITES {
                            hits.sites.push(instruction.ip());
                        }
                    }
                }
            });
            let satisfied = hits.iter().filter(|h| h.is_some()).count()
                + instruction_hits.iter().filter(|hits| hits.total != 0).count();
            (satisfied >= min_req).then_some((satisfied, f.clone(), hits, instruction_hits))
        })
        .collect();
    results.sort_by(|a, b| b.0.cmp(&a.0).then_with(|| a.1.start.cmp(&b.1.start)));
    for (satisfied, f, hits, instruction_hits) in &results {
        let parts: Vec<String> =
            preds.iter().zip(hits).filter_map(|(p, ip)| Some(format!("{}@{:#x}", p.label, (*ip)?))).collect();
        let (start, end, sz, joined) = (f.start, f.end, f.end - f.start, parts.join(", "));
        if instruction_patterns.is_empty() {
            writeln!(out, "{start:#x}..{end:#x}  size {sz:#x}  ({satisfied}/{total}: {joined})")?;
        } else {
            let mut all_hits = 0usize;
            let mut site_parts = Vec::new();
            for (pred, sites) in instruction_patterns.iter().zip(instruction_hits) {
                all_hits += sites.total;
                if sites.total == 0 {
                    continue;
                }
                let shown = sites.sites.iter().map(|ip| format!("{ip:#x}")).collect::<Vec<_>>().join(",");
                let omitted = sites.total - sites.sites.len();
                let suffix = if omitted == 0 { String::new() } else { format!("; omitted {omitted}") };
                site_parts.push(format!("{}=[{}{}]", pred.label, shown, suffix));
            }
            writeln!(
                out,
                "{start:#x}..{end:#x}  size {sz:#x}  ({satisfied}/{total}: {joined})  instruction hits {all_hits}: {}",
                site_parts.join("; ")
            )?;
        }
    }
    writeln!(out, "{} functions", results.len())?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{FindSpec, find, parse_size};
    use crate::image::{Image, Segment};

    #[test]
    fn evaluates_multiple_predicates_in_one_pass() {
        assert_eq!(parse_size("0x10..0x20"), Ok(0x10..=0x20));
        assert_eq!(parse_size("..0x20"), Ok(0..=0x20));
        assert_eq!(parse_size("0x10.."), Ok(0x10..=u64::MAX));
        assert_eq!(parse_size("0x15"), Ok(0x15..=0x15));

        let mut data = vec![0xc3u8; 0x400];
        // Function at 0x1000 (size 0x22):
        // 0x1000: call 0x1100
        // 0x1005: lea rdi, [rip+0x1f4] -> 0x1200 (Location "src/twap.rs:50:1")
        // 0x100c: lea rsi, [rip+0x22d] -> 0x1240 ("stopped")
        // 0x1013: cmp rax, 5
        // 0x1017: mov rdx, [rbx+0x40]
        // 0x101b: ret
        let code: &[u8] = &[
            0xe8, 0xfb, 0x00, 0x00, 0x00, // call 0x1100
            0x48, 0x8d, 0x3d, 0xf4, 0x01, 0x00, 0x00, // lea rdi, [0x1200]
            0x48, 0x8d, 0x35, 0x2d, 0x02, 0x00, 0x00, // lea rsi, [0x1240]
            0x48, 0x83, 0xf8, 0x05, // cmp rax, 5
            0x48, 0x8b, 0x53, 0x40, // mov rdx, [rbx+0x40]
            0xc3,
        ];
        data[..code.len()].copy_from_slice(code);
        data[0x208..0x210].copy_from_slice(&11u64.to_le_bytes());
        data[0x210..0x214].copy_from_slice(&50u32.to_le_bytes());
        data[0x214..0x218].copy_from_slice(&1u32.to_le_bytes());
        data[0x220..0x22b].copy_from_slice(b"src/twap.rs");
        data[0x240..0x247].copy_from_slice(b"stopped");

        let image = Image {
            data,
            segments: vec![Segment { va: 0x1000, offset: 0, size: 0x400 }],
            functions: vec![0x1000..0x1000 + code.len() as u64, 0x1100..0x1101],
            pointers: vec![(0x1200, 0x1220)],
            imports: Vec::new(),
            symbols: vec![(0x1100, "callee_fn".to_owned())],
            metadata: crate::image_format::Metadata::default(),
        };

        let empty_spec = FindSpec {
            calls: Vec::new(),
            refs: Vec::new(),
            imm: Vec::new(),
            imm_mode: (false, false),
            disp: Vec::new(),
            disp_mode: (false, false),
            src: Vec::new(),
            size: None,
            any: None,
            back: 16,
        };
        assert!(find(&image, &empty_spec, &mut Vec::new()).is_err());

        let spec = FindSpec {
            calls: vec!["callee_fn".to_owned()],
            refs: vec!["stopped".to_owned(), "0x1240".to_owned()],
            imm: vec![5],
            imm_mode: (false, true),
            disp: vec![0x40],
            disp_mode: (false, false),
            src: vec!["twap.rs".to_owned()],
            size: Some("0x10..0x30".to_owned()),
            any: None,
            back: 16,
        };
        let mut out = Vec::new();
        assert!(find(&image, &spec, &mut out).is_ok());
        let text = String::from_utf8_lossy(&out);
        assert!(text.contains("0x1000..0x101c  size 0x1c  (7/7:"), "{text}");
        assert!(text.contains("1 functions"), "{text}");
    }
}
