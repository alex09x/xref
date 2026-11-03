/*
 * xref — Ultra blazing fast cross-references of an x86-64 ELF binary
 * Copyright (c) 2026 Alexander Panasenko
 *
 * Contact: alex@prod.codes
 * Author: https://prod.codes/about/
 * SPDX-License-Identifier: MIT OR Apache-2.0
 */

//! Inline strings built from immediate `mov` stores (`movabs` / `mov [mem], imm`).

use std::io::Write;
use std::ops::Range;

use iced_x86::{Instruction, Mnemonic, OpKind};
use rayon::prelude::*;

use crate::commands::Res;
use crate::image::Image;
use crate::scan::decode;

pub struct InlineHit {
    pub ips: Vec<u64>,
    pub function: Range<u64>,
    pub matched: usize,
    pub total: usize,
}

fn imm_bytes(instruction: &Instruction) -> Option<([u8; 8], usize)> {
    if instruction.mnemonic() != Mnemonic::Mov {
        return None;
    }
    let idx = (0..instruction.op_count()).find(|&i| {
        matches!(
            instruction.op_kind(i),
            OpKind::Immediate8
                | OpKind::Immediate16
                | OpKind::Immediate32
                | OpKind::Immediate64
                | OpKind::Immediate32to64
        )
    })?;
    let val = instruction.immediate(idx);
    let len = match instruction.op_kind(idx) {
        OpKind::Immediate64 => 8,
        OpKind::Immediate32 | OpKind::Immediate32to64 => 4,
        OpKind::Immediate16 => 2,
        _ => 1,
    };
    Some((val.to_le_bytes(), len))
}

fn bit_range(start: usize, end: usize) -> u128 {
    let s = start.min(128);
    let e = end.min(128);
    if e <= s {
        0
    } else if e - s == 128 {
        u128::MAX
    } else {
        ((1u128 << (e - s)) - 1) << s
    }
}

fn chunk_mask(needle: &[u8], chunk: &[u8]) -> u128 {
    let n = needle.len();
    let w = chunk.len();
    let mut mask = 0u128;
    if w <= n {
        for off in 0..=n - w {
            if needle[off..off + w] == *chunk {
                mask |= bit_range(off, off + w);
            }
        }
    }
    if w >= 4 && chunk.iter().all(|b| (0x20..0x7f).contains(b)) {
        if n < w {
            for p in 0..=w - n {
                if chunk[p..p + n] == *needle {
                    mask |= bit_range(0, n);
                }
            }
        }
        for k in 2..n.min(w) {
            if chunk[w - k..] == needle[..k] {
                mask |= bit_range(0, k);
            }
            if chunk[..k] == needle[n - k..] {
                mask |= bit_range(n - k, n);
            }
        }
    }
    mask
}

pub fn search_inline(image: &Image, text: &str) -> Vec<InlineHit> {
    let needle = text.as_bytes();
    let target_len = needle.len().min(128);
    if target_len == 0 {
        return Vec::new();
    }
    let mut hits: Vec<InlineHit> = image
        .functions
        .par_iter()
        .filter_map(|f| Some((f, image.code(f)?)))
        .flat_map_iter(|(function, bytes)| {
            let mut pairs: Vec<(u64, u128)> = Vec::new();
            decode(bytes, function.start, |instruction| {
                if let Some((buf, len)) = imm_bytes(instruction) {
                    let m = chunk_mask(needle, &buf[..len]);
                    if m != 0 {
                        pairs.push((instruction.ip(), m));
                    }
                }
            });
            let mut found = Vec::new();
            let mut i = 0;
            while i < pairs.len() {
                let mut combined = 0u128;
                let mut matched_end = None;
                for (j, &(ip, m)) in pairs[i..].iter().enumerate() {
                    if ip - pairs[i].0 > 64 {
                        break;
                    }
                    combined |= m;
                    if combined.count_ones() as usize == target_len {
                        matched_end = Some(i + j);
                        break;
                    }
                }
                if let Some(end) = matched_end {
                    let ips: Vec<u64> = pairs[i..=end].iter().map(|(ip, _)| *ip).collect();
                    found.push(InlineHit { ips, function: function.clone(), matched: target_len, total: target_len });
                    i = end + 1;
                } else {
                    i += 1;
                }
            }
            found
        })
        .collect();
    hits.sort_by_key(|h| h.ips[0]);
    hits
}

pub fn refs_inline(image: &Image, targets: &[String], out: &mut dyn Write) -> Res {
    let mut total_hits = 0usize;
    for target in targets {
        let hits = search_inline(image, target);
        if hits.is_empty() {
            writeln!(out, "inline {target:?}: not found")?;
        }
        for hit in &hits {
            let joined = hit.ips.iter().map(|ip| format!("{ip:#x}")).collect::<Vec<_>>().join(", ");
            let (ip, start, end, m, tot) = (hit.ips[0], hit.function.start, hit.function.end, hit.matched, hit.total);
            writeln!(out, "{ip:#x}  in {start:#x}..{end:#x}  {target:?} ({m}/{tot} bytes at {joined})")?;
        }
        total_hits += hits.len();
    }
    writeln!(out, "{total_hits} hits")?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{bit_range, refs_inline, search_inline};
    use crate::image::{Image, Segment};

    #[test]
    fn finds_overlapping_and_sub_qword_inline_string_stores() {
        assert_eq!(bit_range(5, 3), 0);
        assert_eq!(bit_range(0, 128), u128::MAX);
        assert!(
            search_inline(
                &Image {
                    data: Vec::new(),
                    segments: Vec::new(),
                    functions: Vec::new(),
                    pointers: Vec::new(),
                    imports: Vec::new(),
                    symbols: Vec::new(),
                    metadata: crate::image_format::Metadata::default()
                },
                ""
            )
            .is_empty()
        );

        // 0x1000: mov rcx, 0x686374616d73696d ("mismatch", offset 6..14 stored first!)
        // 0x100a: mov [rax+6], rcx
        // 0x100e: mov rcx, 0x696d206e656b6f74 ("token mi", offset 0..8 stored second!)
        // 0x1018: mov [rax], rcx
        // 0x101b: mov dword ptr [rax+16], 0x64636261 ("abcd")
        // 0x1022: mov word ptr [rax+20], 0x6665 ("ef")
        // 0x1028: mov byte ptr [rax+22], 0x21 ("!")
        // 0x102c: ret
        let mut code = Vec::new();
        code.extend_from_slice(&[0x48, 0xb9]);
        code.extend_from_slice(b"mismatch");
        code.extend_from_slice(&[0x48, 0x89, 0x48, 0x06, 0x48, 0xb9]);
        code.extend_from_slice(b"token mi");
        code.extend_from_slice(&[0x48, 0x89, 0x08]);
        code.extend_from_slice(&[0xc7, 0x40, 0x10, b'a', b'b', b'c', b'd']);
        code.extend_from_slice(&[0x66, 0xc7, 0x40, 0x14, b'e', b'f']);
        code.extend_from_slice(&[0xc6, 0x40, 0x16, b'!', 0x90, 0xc3]);

        // Add a second function at 0x1100 with a single partial chunk (>64 bytes apart from anything)
        let mut data = vec![0x90u8; 0x200];
        data[..code.len()].copy_from_slice(&code);
        data[0x100..0x102].copy_from_slice(&[0x48, 0xb9]);
        data[0x102..0x10a].copy_from_slice(b"token mi");
        data[0x160] = 0xc6;
        data[0x161] = 0x00;
        data[0x162] = b'h';
        data[0x163] = 0xc3;

        let image = Image {
            data,
            segments: vec![Segment { va: 0x1000, offset: 0, size: 0x200 }],
            functions: vec![0x1000..0x1000 + code.len() as u64, 0x1100..0x1164],
            pointers: Vec::new(),
            imports: Vec::new(),
            symbols: Vec::new(),
            metadata: crate::image_format::Metadata::default(),
        };

        let mut out = Vec::new();
        assert!(
            refs_inline(
                &image,
                &[
                    "token mismatch".to_owned(),
                    "ken mism".to_owned(),
                    "token".to_owned(),
                    "abcdef!".to_owned(),
                    "absent".to_owned()
                ],
                &mut out
            )
            .is_ok()
        );
        let text = String::from_utf8_lossy(&out);
        assert!(text.contains("0x1000  in 0x1000..") && text.contains("\"token mismatch\" (14/14 bytes"), "{text}");
        assert!(text.contains("\"ken mism\" (8/8 bytes") && text.contains("\"token\" (5/5 bytes"), "{text}");
        assert!(text.contains("\"abcdef!\" (7/7 bytes") && text.contains("inline \"absent\": not found"), "{text}");
    }
}
