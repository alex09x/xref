/*
 * xref — Ultra blazing fast cross-references of an x86-64 ELF binary
 * Copyright (c) 2026 Alexander Panasenko
 *
 * Contact: alex@prod.codes
 * Author: https://prod.codes/about/
 * Project: https://github.com/alex09x/xref
 * SPDX-License-Identifier: MIT OR Apache-2.0
 */

//! Parallel single/batch pseudo-C output (`c`) and whole-module source-tree dump (`xref dump`).

use std::collections::BTreeMap;
use std::io::Write;
use std::ops::Range;
use std::path::{Path, PathBuf};
use std::time::Instant;

use rayon::prelude::*;

use crate::c::c_one;
use crate::commands::Res;
use crate::fields_c::apply_field_sugar;
use crate::image::Image;
use crate::locations::{Location, locations};
use crate::runtime::RuntimeMap;
use crate::scan::decode;
use crate::source::location_at;

pub fn decomp(
    image: &Image,
    addrs: &[u64],
    from: Option<u64>,
    to: Option<u64>,
    use_fields: bool,
    out_dir: Option<&Path>,
    out: &mut dyn Write,
) -> Res {
    let all_locs = locations(image);
    let runtime = RuntimeMap::detect(image);
    let rendered: Vec<Result<(u64, String, std::time::Duration), String>> = addrs
        .par_iter()
        .map(|&addr| {
            let t0 = Instant::now();
            let (start, raw) = c_one(image, &all_locs, &runtime, addr, from, to)?;
            let body = if use_fields && let Some(f) = image.function_at(start) {
                apply_field_sugar(image, &f, &raw)
            } else {
                raw
            };
            Ok((start, body, t0.elapsed()))
        })
        .collect();
    if let Some(dir) = out_dir {
        std::fs::create_dir_all(dir)?;
    }
    for item in rendered {
        let (start, body, elapsed) = item?;
        if let Some(dir) = out_dir {
            let path = dir.join(format!("{start:#x}.c"));
            std::fs::write(&path, &body)?;
            writeln!(out, "{}  {} bytes  {elapsed:.1?}", path.display(), body.len())?;
        } else {
            out.write_all(body.as_bytes())?;
        }
    }
    Ok(())
}

fn sanitize_rel_c_path(src_file: &str) -> PathBuf {
    let mut clean = PathBuf::new();
    for comp in src_file.trim_start_matches('/').split(['/', '\\']) {
        if comp.is_empty() || comp == "." || comp == ".." {
            continue;
        }
        let safe: String = comp
            .chars()
            .map(|c| if c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-') { c } else { '_' })
            .collect();
        if !safe.is_empty() {
            clean.push(safe);
        }
    }
    if clean.as_os_str().is_empty() {
        clean.push("unmapped.c");
    } else {
        clean.set_extension("c");
    }
    clean
}

fn primary_source_file(image: &Image, all_locs: &[Location], f: &Range<u64>) -> Option<String> {
    let bytes = image.code(f)?;
    let mut found = None;
    decode(bytes, f.start, |ins| {
        if found.is_none()
            && ins.is_ip_rel_memory_operand()
            && let Some(l) = location_at(all_locs, ins.ip_rel_memory_address())
        {
            found = Some(l.file.clone());
        }
    });
    found
}

pub fn dump_tree(
    image: &Image,
    out_dir: &Path,
    src_filter: Option<&str>,
    use_fields: bool,
    out: &mut dyn Write,
) -> Res {
    let t0 = Instant::now();
    let all_locs = locations(image);
    let runtime = RuntimeMap::detect(image);
    let sym_map: BTreeMap<u64, &str> = image.symbols.iter().map(|(a, s)| (*a, s.as_str())).collect();

    let selected: Vec<(Range<u64>, PathBuf)> = image
        .functions
        .par_iter()
        .filter_map(|f| {
            let src = primary_source_file(image, &all_locs, f);
            if let Some(pat) = src_filter {
                let sym = sym_map.get(&f.start).copied().unwrap_or("");
                let hit = src.as_deref().is_some_and(|s| s.contains(pat)) || sym.contains(pat);
                if !hit {
                    return None;
                }
            }
            let rel = src.map_or_else(
                || PathBuf::from("unmapped").join(format!("bucket_{:04x}.c", (f.start >> 16) & 0xffff)),
                |s| sanitize_rel_c_path(&s),
            );
            Some((f.clone(), rel))
        })
        .collect();

    let rendered: Vec<(PathBuf, u64, String)> = selected
        .into_par_iter()
        .filter_map(|(f, rel)| {
            let (start, raw) = c_one(image, &all_locs, &runtime, f.start, None, None).ok()?;
            let body = if use_fields { apply_field_sugar(image, &f, &raw) } else { raw };
            Some((rel, start, body))
        })
        .collect();

    let mut grouped: BTreeMap<PathBuf, Vec<(u64, String)>> = BTreeMap::new();
    for (rel, start, body) in rendered {
        grouped.entry(rel).or_default().push((start, body));
    }

    let mut total_fns = 0usize;
    let mut total_bytes = 0usize;
    let files_cnt = grouped.len();
    for (rel, mut items) in grouped {
        items.sort_by_key(|(start, _)| *start);
        let full_path = out_dir.join(&rel);
        if let Some(parent) = full_path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let mut buf = String::new();
        for (_, body) in items {
            total_fns += 1;
            buf.push_str(&body);
            buf.push('\n');
        }
        total_bytes += buf.len();
        std::fs::write(&full_path, buf.as_bytes())?;
    }
    writeln!(
        out,
        "dumped {total_fns} functions into {files_cnt} files ({total_bytes} bytes) in {} ({:.1?})",
        out_dir.display(),
        t0.elapsed()
    )?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{decomp, dump_tree, sanitize_rel_c_path};
    use crate::image::{Image, Segment};
    use std::path::PathBuf;

    #[test]
    fn sanitizes_paths_and_dumps_grouped_source_files() {
        assert_eq!(sanitize_rel_c_path("../src/engine/book.rs"), PathBuf::from("src/engine/book.c"));
        let mut data = vec![0xc3u8; 0x80];
        data[0..4].copy_from_slice(&[0x48, 0x89, 0xf8, 0xc3]);
        let image = Image {
            data,
            segments: vec![Segment { va: 0x1000, offset: 0, size: 0x80 }],
            functions: std::iter::once(0x1000..0x1004).collect(),
            pointers: Vec::new(),
            imports: Vec::new(),
            symbols: vec![(0x1000, "demo_entry".to_owned())],
        };
        let dir = std::env::temp_dir().join(format!("xref_dump_test_{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let mut out = Vec::new();
        assert!(dump_tree(&image, &dir, Some("demo"), false, &mut out).is_ok());
        assert!(String::from_utf8_lossy(&out).contains("dumped 1 functions into 1 files"));
        assert!(decomp(&image, &[0x1000], None, None, true, Some(&dir), &mut out).is_ok());
        let _ = std::fs::remove_dir_all(&dir);
    }
}
