/*
 * XRef — Binary analysis
 * Copyright (c) 2026 Alexander Panasenko
 * Contact: alex@prod.codes
 * Author: https://prod.codes/about/
 * Project: https://github.com/alex09x/xref
 * SPDX-License-Identifier: MIT OR Apache-2.0
 */
use super::types::Mapping;
use crate::image::Image;
use std::path::Path;

pub fn resolve(
    image: &Image,
    bin: &Path,
    base: Option<&str>,
    maps: Option<&Path>,
    target_path: Option<&Path>,
    pid: u32,
) -> Result<(i64, Vec<Mapping>, &'static str), Box<dyn std::error::Error>> {
    if base.is_some() && maps.is_some() {
        return Err("use either --base or --maps, not both".into());
    }
    if target_path.is_some() && maps.is_none() {
        return Err("--target-path requires --maps".into());
    }
    let (slide, ranges, provenance) = if let Some(path) = maps {
        let text = crate::trace_frontend::io::read_text(path, 16 * 1024 * 1024)?;
        let target = target_path
            .map_or_else(|| bin.canonicalize().unwrap_or_else(|_| bin.to_path_buf()), std::path::Path::to_path_buf);
        let index = crate::trace_frontend::adapter::build_index(image, None)?;
        let mut state = crate::trace_analysis::mapping::MappingState::default();
        state.set_proc_maps(&index, &text, &target.to_string_lossy())?;
        let mut slide = None;
        let mut ranges = Vec::new();
        for mapping in state.explicit {
            let candidate = i64::try_from(i128::from(mapping.start) - i128::from(mapping.static_start))
                .map_err(|_| "mapping slide overflow")?;
            if slide.is_some_and(|previous| previous != candidate) {
                return Err("maps snapshot has inconsistent target slides".into());
            }
            slide = Some(candidate);
            ranges.push((mapping.start, mapping.end - mapping.start, 0));
        }
        (slide.ok_or("no target mappings")?, ranges, "caller_supplied_maps_unverified")
    } else {
        let base = crate::trace_analysis::index::parse_hex(base.ok_or("profile import requires --base or --maps")?)?;
        let slide = i64::try_from(i128::from(base) - i128::from(image.metadata.base))
            .map_err(|_| "base exceeds supported slide")?;
        let mut ranges = Vec::new();
        for segment in &image.metadata.load_segments {
            if !segment.executable || segment.mem_size == 0 {
                continue;
            }
            let start =
                u64::try_from(i128::from(segment.va) + i128::from(slide)).map_err(|_| "segment address overflow")?;
            ranges.push((start, segment.mem_size, segment.file_offset));
        }
        (slide, ranges, "caller_supplied_base_unverified")
    };
    let mappings = ranges
        .into_iter()
        .map(|(start, length, file_offset)| Mapping {
            timestamp_ns: 0,
            pid,
            tid: pid,
            start,
            length,
            file_offset,
            device_major: 0,
            device_minor: 0,
            inode: 1,
            executable: true,
            sha256: None,
            path: "[caller-supplied target mapping]".to_owned(),
        })
        .collect();
    Ok((slide, mappings, provenance))
}
