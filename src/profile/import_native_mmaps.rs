/*
 * XRef — derive imported profile mappings from perf sideband
 * Copyright (c) 2026 Alexander Panasenko
 * Contact: alex@prod.codes
 * Author: https://prod.codes/about/
 * Project: https://github.com/alex09x/xref
 * SPDX-License-Identifier: MIT OR Apache-2.0
 */
use crate::image::Image;
use linux_perf_data::{
    PerfFileReader, PerfFileRecord,
    linux_perf_event_reader::{EventRecord, RecordType},
};
use std::io::{BufReader, Seek, SeekFrom};

/// Establish one consistent target slide from the initial MMAP2 records.
/// The recorded build ID is checked independently by the normal importer.
type DerivedMappings = (i64, Vec<super::types::Mapping>, &'static str, String);

#[allow(clippy::too_many_lines)] // One pass ties mapping identity and process lifecycle together.
pub(super) fn derive(
    file: &mut std::fs::File,
    image: &Image,
    pid: u32,
    target: &str,
    allow_id_lookup: bool,
) -> Result<DerivedMappings, Box<dyn std::error::Error>> {
    file.seek(SeekFrom::Start(0))?;
    let scan = file.try_clone()?;
    let PerfFileReader { mut perf_file, mut record_iter } = PerfFileReader::parse_file(BufReader::new(scan))?;
    super::import_native_identity::verify_target(&perf_file, image, target)?;
    let build_ids = perf_file.build_ids()?;
    let mut slide = None;
    let mut mappings = Vec::new();
    let mut identity = None;
    let mut recorded_path: Option<String> = None;
    let mut scanned = 0_u64;
    while let Some(entry) = record_iter.next_record(&mut perf_file)? {
        scanned += 1;
        if scanned > 50_000_000 {
            return Err("perf mapping discovery budget exceeded".into());
        }
        let PerfFileRecord::EventRecord { record, .. } = entry else { continue };
        if record.record_type == RecordType::SAMPLE {
            let data = super::import_native_read::strip(&record)?;
            let mut sample = record.clone();
            if let Some(ref data) = data {
                sample.data = data.as_slice().into();
                sample.parse_info.sample_format.remove(linux_perf_data::linux_perf_event_reader::SampleFormat::READ);
            }
            if matches!(sample.parse()?, EventRecord::Sample(value) if value.pid.and_then(|value| u32::try_from(value).ok()) == Some(pid))
            {
                break;
            }
            continue;
        }
        if !matches!(record.record_type, RecordType::MMAP2 | RecordType::COMM) {
            continue;
        }
        match record.parse()? {
            EventRecord::Mmap2(map) if u32::try_from(map.pid).ok() == Some(pid) && map.protection & 4 != 0 => {
                use linux_perf_data::{DsoKey, linux_perf_event_reader::Mmap2FileId};
                let path = map.path.as_slice();
                let embedded_id = match &map.file_id {
                    Mmap2FileId::BuildId(value) => Some(value.as_slice()),
                    Mmap2FileId::InodeAndVersion(_) => None,
                };
                let global_id = DsoKey::detect(&path, map.cpu_mode)
                    .and_then(|key| build_ids.get(&key))
                    .map(|info| info.build_id.as_slice());
                let matches_id = image
                    .metadata
                    .build_id
                    .as_deref()
                    .is_some_and(|id| embedded_id == Some(id) || global_id == Some(id));
                let same_path = path.as_ref() == target.as_bytes();
                if !(same_path || allow_id_lookup && matches_id) {
                    continue;
                }
                let path = std::str::from_utf8(&path)?.to_owned();
                if recorded_path.as_ref().is_some_and(|previous| previous != &path) {
                    return Err("multiple recorded target paths match the executable build ID".into());
                }
                recorded_path = Some(path);
                if map.length == 0 || map.address.checked_add(map.length).is_none() {
                    return Err("invalid target MMAP2 range".into());
                }
                super::pt_mapping::file_identity(
                    &mut identity,
                    &map.file_id,
                    image.metadata.build_id.as_deref().unwrap_or_default(),
                )?;
                let candidate = mapping_slide(image, map.address, map.page_offset)?;
                if slide.is_some_and(|previous| previous != candidate) {
                    return Err("perf target mappings have inconsistent slides".into());
                }
                slide = Some(candidate);
                mappings.push(super::types::Mapping {
                    timestamp_ns: 0,
                    pid,
                    tid: pid,
                    start: map.address,
                    length: map.length,
                    file_offset: map.page_offset,
                    device_major: 0,
                    device_minor: 0,
                    inode: 1,
                    executable: true,
                    sha256: None,
                    path: "[perf MMAP2 target mapping]".into(),
                });
            }
            EventRecord::Comm(event) if event.is_execve && u32::try_from(event.pid).ok() == Some(pid) => {
                mappings.clear();
                slide = None;
                identity = None;
                recorded_path = None;
            }
            _ => {}
        }
    }
    drop(record_iter);
    drop(perf_file);
    file.seek(SeekFrom::Start(0))?;
    Ok((
        slide.ok_or("no target executable MMAP2 before the first sample; supply --base or --maps")?,
        mappings,
        "perf_data_mmap_unverified",
        recorded_path.ok_or("missing recorded target path")?,
    ))
}

fn mapping_slide(image: &Image, start: u64, offset: u64) -> Result<i64, &'static str> {
    let mut candidate = None;
    for segment in &image.metadata.load_segments {
        if !segment.executable {
            continue;
        }
        let file_start = segment.file_offset & !4095;
        let Some(relative) = offset.checked_sub(file_start) else { continue };
        let Some(file_end) = segment.file_offset.checked_add(segment.file_size) else { continue };
        if offset >= file_end {
            continue;
        }
        let Some(static_start) = (segment.va & !4095).checked_add(relative) else { continue };
        let value =
            i64::try_from(i128::from(start) - i128::from(static_start)).map_err(|_| "perf mapping slide overflow")?;
        if candidate.is_some_and(|other| other != value) {
            return Err("ambiguous target MMAP2 slide");
        }
        candidate = Some(value);
    }
    candidate.ok_or("target MMAP2 does not match an executable ELF segment")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn derives_page_aligned_slide_and_rejects_unrelated_offsets() -> Result<(), &'static str> {
        let mut image = Image::default();
        image.metadata.load_segments.push(crate::image_format::LoadSegment {
            va: 0x1234,
            file_offset: 0x234,
            file_size: 0x1800,
            mem_size: 0x2000,
            executable: true,
            writable: false,
        });
        assert_eq!(mapping_slide(&image, 0x51_1000, 0)?, 0x51_0000);
        assert_eq!(mapping_slide(&image, 0x51_2000, 0x1000)?, 0x51_0000);
        assert!(mapping_slide(&image, 0x51_3000, 0x3000).is_err());
        Ok(())
    }
}
