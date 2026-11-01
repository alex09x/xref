/*
 * xref — Ultra blazing fast cross-references of an x86-64 ELF binary
 * Copyright (c) 2026 Alexander Panasenko
 *
 * Contact: alex@prod.codes
 * Author: https://prod.codes/about/
 * SPDX-License-Identifier: MIT OR Apache-2.0
 */

//! Cross-build function matching (`match`): scores candidates in another binary by shared panic
//! locations, referenced strings, inline immediates, struct displacements, and call neighborhood.

use std::collections::HashMap;
use std::io::Write;
use std::ops::Range;

use iced_x86::{OpKind, Register};
use rayon::prelude::*;

use crate::commands::Res;
use crate::graph::{CallGraph, resolve};
use crate::image::{Image, Slot};
use crate::locations::{Location, locations};
use crate::scan::{decode, immediates};
use crate::source::location_at;

struct FnSig {
    range: Range<u64>,
    locs: Vec<(String, u32)>,
    strings: Vec<u64>,
    imms: Vec<u64>,
    disps: Vec<u64>,
    callees: Vec<u64>,
    caller_files: Vec<String>,
    callee_files: Vec<String>,
    callee_imms64: Vec<u64>,
}

fn fnv1a(bytes: &[u8]) -> u64 {
    let mut h = 0xcbf2_9ce4_8422_2325u64;
    for &b in bytes {
        h ^= u64::from(b);
        h = h.wrapping_mul(0x0100_0000_01b3);
    }
    h
}

const fn nontrivial_imm(v: u64) -> bool {
    v > 64 && !v.is_power_of_two() && v != u32::MAX as u64 && v != u64::MAX
}

fn extract_one(image: &Image, all_locs: &[Location], graph: &CallGraph, f: &Range<u64>) -> FnSig {
    let mut locs = Vec::new();
    let mut strings = Vec::new();
    let mut imms = Vec::new();
    let mut disps = Vec::new();
    let bytes = image.code(f).unwrap_or_default();
    decode(bytes, f.start, |instruction| {
        for imm in immediates(instruction) {
            if nontrivial_imm(imm) && (imm > 0xffff_ffff || imms.len() < 64) && !imms.contains(&imm) {
                imms.push(imm);
            }
        }
        if !instruction.is_ip_rel_memory_operand() {
            if (0..instruction.op_count()).any(|i| instruction.op_kind(i) == OpKind::Memory)
                && instruction.memory_base() != Register::RSP
                && instruction.memory_base() != Register::None
            {
                let d = instruction.memory_displacement64();
                if (0x20..0x10_0000).contains(&d) && disps.len() < 64 && !disps.contains(&d) {
                    disps.push(d);
                }
            }
            return;
        }
        let place = instruction.ip_rel_memory_address();
        if let Some(loc) = location_at(all_locs, place) {
            if !locs.iter().any(|(file, line)| file == &loc.file && *line == loc.line) {
                locs.push((loc.file.clone(), loc.line));
            }
            return;
        }
        let target = match image.slot(place) {
            Some(Slot::Pointer(t)) => t,
            Some(Slot::Import(_)) => return,
            None => place,
        };
        if strings.len() < 64
            && let Some(text) = image.preview(target)
        {
            let h = fnv1a(text.as_bytes());
            if !strings.contains(&h) {
                strings.push(h);
            }
        }
    });
    let mut callees: Vec<u64> =
        graph.callees.get(&f.start).map(|v| v.iter().map(|(_, c)| *c).collect()).unwrap_or_default();
    callees.sort_unstable();
    callees.dedup();
    FnSig {
        range: f.clone(),
        locs,
        strings,
        imms,
        disps,
        callees,
        caller_files: Vec::new(),
        callee_files: Vec::new(),
        callee_imms64: Vec::new(),
    }
}

fn build_sigs(image: &Image) -> (Vec<FnSig>, CallGraph) {
    let (all_locs, graph) = rayon::join(|| locations(image), || CallGraph::build(image));
    let mut sigs: Vec<FnSig> = image.functions.par_iter().map(|f| extract_one(image, &all_locs, &graph, f)).collect();
    let by_start: HashMap<u64, usize> = sigs.iter().enumerate().map(|(i, s)| (s.range.start, i)).collect();
    let files_of: Vec<Vec<String>> = sigs
        .iter()
        .map(|s| {
            let mut v: Vec<String> =
                s.locs.iter().filter(|(f, _)| !f.starts_with("/rustc/")).map(|(f, _)| f.clone()).collect();
            v.sort();
            v.dedup();
            v
        })
        .collect();
    let imms64_of: Vec<Vec<u64>> =
        sigs.iter().map(|s| s.imms.iter().copied().filter(|&x| x > 0xffff_ffff).collect()).collect();
    for (idx, sig) in sigs.iter_mut().enumerate() {
        let start = sig.range.start;
        if let Some(callers) = graph.callers.get(&start) {
            for &(_, caller) in callers {
                for f in by_start.get(&caller).into_iter().flat_map(|&c_idx| &files_of[c_idx]) {
                    if !sig.caller_files.contains(f) {
                        sig.caller_files.push(f.clone());
                    }
                }
            }
        }
        for &callee in &sig.callees {
            if let Some(&c_idx) = by_start.get(&callee)
                && c_idx != idx
            {
                for f in &files_of[c_idx] {
                    if !sig.callee_files.contains(f) {
                        sig.callee_files.push(f.clone());
                    }
                }
                for &imm in &imms64_of[c_idx] {
                    if !sig.callee_imms64.contains(&imm) {
                        sig.callee_imms64.push(imm);
                    }
                }
            }
        }
    }
    (sigs, graph)
}

struct Freqs {
    file: HashMap<String, usize>,
    str_h: HashMap<u64, usize>,
    imm: HashMap<u64, usize>,
    disp: HashMap<u64, usize>,
}

impl Freqs {
    fn from_sigs(sigs: &[FnSig]) -> Self {
        let mut file = HashMap::new();
        let mut str_h = HashMap::new();
        let mut imm = HashMap::new();
        let mut disp = HashMap::new();
        for s in sigs {
            let mut seen_files: Vec<&str> = Vec::new();
            for (f, _) in &s.locs {
                if !seen_files.contains(&f.as_str()) {
                    seen_files.push(f);
                    *file.entry(f.clone()).or_insert(0) += 1;
                }
            }
            for &h in &s.strings {
                *str_h.entry(h).or_insert(0) += 1;
            }
            for &v in &s.imms {
                *imm.entry(v).or_insert(0) += 1;
            }
            for &d in &s.disps {
                *disp.entry(d).or_insert(0) += 1;
            }
        }
        Self { file, str_h, imm, disp }
    }
}

fn score_pair(q: &FnSig, c: &FnSig, freqs: &Freqs) -> (u64, String) {
    let mut loc_pts = 0u64;
    for (qf, ql) in q.locs.iter().filter(|(qf, _)| !qf.starts_with("/rustc/")) {
        let f_freq = freqs.file.get(qf).copied().unwrap_or(1);
        if f_freq <= 200
            && let Some(diff) = c.locs.iter().filter(|(cf, _)| cf == qf).map(|(_, cl)| cl.abs_diff(*ql)).min()
        {
            let weight = 1 + u64::from(f_freq <= 30);
            let pts = if diff == 0 {
                40
            } else if diff <= 40 {
                25
            } else {
                12
            };
            loc_pts += pts * weight;
        }
    }
    let mut str_pts = 0u64;
    for &h in &q.strings {
        let freq = freqs.str_h.get(&h).copied().unwrap_or(1) as u64;
        if c.strings.contains(&h) && freq <= 100 {
            str_pts += 50 / freq.min(10);
        }
    }
    let mut imm_pts = 0u64;
    for &v in &q.imms {
        let freq = freqs.imm.get(&v).copied().unwrap_or(1) as u64;
        if c.imms.contains(&v) && freq <= 100 {
            let base = if v > 0xffff_ffff { 70 } else { 25 };
            imm_pts += base / freq.min(10);
        }
    }
    let mut disp_pts = 0u64;
    for &d in &q.disps {
        let freq = freqs.disp.get(&d).copied().unwrap_or(1) as u64;
        if d >= 0x40 && c.disps.contains(&d) && freq <= 200 {
            disp_pts += 25 / freq.min(10);
        }
    }
    let mut nbr_pts = 0u64;
    for f in &q.caller_files {
        if c.caller_files.contains(f) && freqs.file.get(f).copied().unwrap_or(1) <= 50 {
            nbr_pts += 25;
        }
    }
    for f in &q.callee_files {
        if c.callee_files.contains(f) && freqs.file.get(f).copied().unwrap_or(1) <= 50 {
            nbr_pts += 20;
        }
    }
    for &v in &q.callee_imms64 {
        if c.callee_imms64.contains(&v) && freqs.imm.get(&v).copied().unwrap_or(1) <= 20 {
            nbr_pts += 35;
        }
    }
    let base = loc_pts + str_pts + imm_pts + disp_pts + nbr_pts;
    if base == 0 {
        return (0, String::new());
    }
    let q_sz = (q.range.end - q.range.start).max(1);
    let c_sz = (c.range.end - c.range.start).max(1);
    let sz_pts = 15 * q_sz.min(c_sz) / q_sz.max(c_sz);
    let cal_pts = 10u64.saturating_sub(q.callees.len().abs_diff(c.callees.len()) as u64 * 3);
    let total = base + sz_pts + cal_pts;
    let info = format!(
        "locs:{loc_pts} strs:{str_pts} imms:{imm_pts} disps:{disp_pts} nbrs:{nbr_pts} size:{c_sz:#x} callees:{}",
        c.callees.len()
    );
    (total, info)
}

pub type MatchHit = (Range<u64>, Option<(u64, Range<u64>, String)>);

pub fn best_matches(
    image: &Image,
    other: &Image,
    specs: &[String],
) -> Result<Vec<MatchHit>, Box<dyn std::error::Error>> {
    let ((sigs_a, _), (sigs_b, _)) = rayon::join(|| build_sigs(image), || build_sigs(other));
    let freqs_b = Freqs::from_sigs(&sigs_b);
    let map_a: HashMap<u64, &FnSig> = sigs_a.iter().map(|s| (s.range.start, s)).collect();
    let mut out = Vec::with_capacity(specs.len());
    for spec in specs {
        let f = resolve(image, spec)?;
        let hit = map_a.get(&f.start).and_then(|q| {
            sigs_b
                .par_iter()
                .filter_map(|c| {
                    let (pts, info) = score_pair(q, c, &freqs_b);
                    (pts > 0).then_some((pts, c.range.clone(), info))
                })
                .max_by(|a, b| a.0.cmp(&b.0).then_with(|| b.1.start.cmp(&a.1.start)))
        });
        out.push((f, hit));
    }
    Ok(out)
}

pub fn match_images(image: &Image, other: &Image, specs: &[String], top: usize, out: &mut dyn Write) -> Res {
    let ((sigs_a, _), (sigs_b, _)) = rayon::join(|| build_sigs(image), || build_sigs(other));
    let freqs_b = Freqs::from_sigs(&sigs_b);
    let map_a: HashMap<u64, &FnSig> = sigs_a.iter().map(|s| (s.range.start, s)).collect();
    for spec in specs {
        let f = resolve(image, spec)?;
        let Some(&q) = map_a.get(&f.start) else { continue };
        let (start, end, sz, cals) = (q.range.start, q.range.end, q.range.end - q.range.start, q.callees.len());
        writeln!(out, "query {start:#x}..{end:#x} (size {sz:#x}, {cals} callees)")?;
        let mut scored: Vec<(u64, &Range<u64>, String)> = sigs_b
            .par_iter()
            .filter_map(|c| {
                let (pts, info) = score_pair(q, c, &freqs_b);
                (pts > 0).then_some((pts, &c.range, info))
            })
            .collect();
        scored.sort_by(|a, b| b.0.cmp(&a.0).then_with(|| a.1.start.cmp(&b.1.start)));
        for (pts, range, info) in scored.into_iter().take(top) {
            writeln!(out, "  {:#x}..{:#x}  score {pts}  ({info})", range.start, range.end)?;
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::match_images;
    use crate::image::{Image, Segment};

    #[test]
    fn matches_functions_across_shifted_builds_by_locations_strings_immediates_and_neighbors() {
        let build = |shift: u32, line_shift: u32| -> Image {
            let mut data = vec![0xc3u8; 0x500];
            let s = shift as usize;
            let base1 = 0x1000 + u64::from(shift);
            let base2 = 0x1100 + u64::from(shift);
            let rel_call = 0xfbi32;
            data[s] = 0xe8;
            data[s + 1..s + 5].copy_from_slice(&rel_call.to_le_bytes());
            data[s + 5..s + 12].copy_from_slice(&[0x48, 0x8b, 0x85, 0xd0, 0x06, 0x00, 0x00]);
            let caller_loc = 0x300i32 - shift.cast_signed() - 19;
            data[s + 12..s + 15].copy_from_slice(&[0x48, 0x8d, 0x3d]);
            data[s + 15..s + 19].copy_from_slice(&caller_loc.to_le_bytes());
            data[s + 19] = 0xc3;

            let s2 = 0x100 + s;
            data[s2..s2 + 2].copy_from_slice(&[0x48, 0xb9]);
            data[s2 + 2..s2 + 10].copy_from_slice(b"token mi");
            let loc_rel = 0x200i32 - shift.cast_signed() - 17;
            data[s2 + 10..s2 + 13].copy_from_slice(&[0x48, 0x8d, 0x3d]);
            data[s2 + 13..s2 + 17].copy_from_slice(&loc_rel.to_le_bytes());
            let str_rel = 0x240i32 - shift.cast_signed() - 24;
            data[s2 + 17..s2 + 20].copy_from_slice(&[0x48, 0x8d, 0x35]);
            data[s2 + 20..s2 + 24].copy_from_slice(&str_rel.to_le_bytes());
            data[s2 + 24..s2 + 31].copy_from_slice(&[0x48, 0x81, 0xfe, 0x99, 0x01, 0x00, 0x00]); // cmp rsi, 0x199
            data[s2 + 31] = 0xc3;

            // Panic location at 0x1300 -> "src/core.rs"
            data[0x308..0x310].copy_from_slice(&11u64.to_le_bytes());
            data[0x310..0x314].copy_from_slice(&(100 + line_shift).to_le_bytes());
            data[0x314..0x318].copy_from_slice(&1u32.to_le_bytes());
            data[0x320..0x32b].copy_from_slice(b"src/core.rs");
            data[0x340..0x350].copy_from_slice(b"unique error msg");

            Image {
                data,
                segments: vec![Segment { va: 0x1000, offset: 0, size: 0x500 }],
                functions: vec![base1..base1 + 20, base2..base2 + 32],
                pointers: vec![(0x1300, 0x1320)],
                imports: Vec::new(),
                symbols: Vec::new(),
            }
        };
        let img_a = build(0, 0);
        let img_b = build(0x20, 5);
        let img_c = build(0x20, 60);
        let mut out = Vec::new();
        assert!(match_images(&img_a, &img_b, &["0x1000".to_owned(), "0x1100".to_owned()], 3, &mut out).is_ok());
        assert!(match_images(&img_a, &img_a, &["0x1100".to_owned()], 1, &mut out).is_ok());
        assert!(match_images(&img_a, &img_c, &["0x1100".to_owned()], 1, &mut out).is_ok());
        let text = String::from_utf8_lossy(&out);
        assert!(text.contains("0x1020..0x1034  score ") && text.contains("0x1120..0x1140  score "));
        assert!(text.contains("locs:50 strs:50 imms:95") && text.contains("locs:80") && text.contains("locs:24"));
    }
}
