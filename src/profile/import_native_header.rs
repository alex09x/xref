/*
 * XRef — Binary analysis
 * Copyright (c) 2026 Alexander Panasenko
 * Contact: alex@prod.codes
 * Author: https://prod.codes/about/
 * Project: https://github.com/alex09x/xref
 * SPDX-License-Identifier: MIT OR Apache-2.0
 */
use std::fs::File;
use std::io::{BufReader, Read, Seek, SeekFrom};

const MAX_FEATURE_BYTES: u64 = 64 * 1024 * 1024;
const MAX_ROUND_BYTES: u64 = 64 * 1024 * 1024;

/// Validate allocation-bearing metadata and record boundaries before parsing.
pub fn validate(file: &mut File) -> Result<(), Box<dyn std::error::Error>> {
    let length = file.metadata()?.len();
    let mut head = [0_u8; 104];
    file.read_exact(&mut head)?;
    if &head[..8] != b"PERFILE2" {
        return Err("native import requires little-endian perf.data".into());
    }
    let header_size = word(&head, 8)?;
    if !(104..=1_048_576).contains(&header_size) || header_size > length {
        return Err("invalid perf header size".into());
    }
    let attr_size = word(&head, 16)?;
    let attr_offset = word(&head, 24)?;
    let attr_length = word(&head, 32)?;
    let data_offset = word(&head, 40)?;
    let data_length = word(&head, 48)?;
    let event_types_length = word(&head, 64)?;
    if event_types_length != 0 {
        return Err("legacy perf event-types sections are not supported".into());
    }
    if !(64..=4096).contains(&attr_size) || attr_length / attr_size > 64 || attr_length % attr_size != 0 {
        return Err("invalid perf attribute section".into());
    }
    range(attr_offset, attr_length, length)?;
    let data_end = range(data_offset, data_length, length)?;
    let flags = [word(&head, 72)?, word(&head, 80)?, word(&head, 88)?, word(&head, 96)?];
    if flags[2] != 0 || flags[3] != 0 {
        return Err("simpleperf feature sections are not supported".into());
    }
    if flags[0] & (1 << 27) != 0 {
        return Err("compressed perf.data is not supported".into());
    }
    let mut descriptors = BufReader::new(file.try_clone()?);
    descriptors.seek(SeekFrom::Start(data_end))?;
    let mut feature_total = 0_u64;
    let mut event_desc = None;
    for bit in 0..128 {
        if flags[bit / 64] & (1_u64 << (bit % 64)) == 0 {
            continue;
        }
        let mut descriptor = [0_u8; 16];
        descriptors.read_exact(&mut descriptor)?;
        let offset = word(&descriptor, 0)?;
        let size = word(&descriptor, 8)?;
        range(offset, size, length)?;
        feature_total = feature_total.checked_add(size).ok_or("perf feature size overflow")?;
        if size > MAX_FEATURE_BYTES || feature_total > MAX_FEATURE_BYTES {
            return Err("perf feature sections exceed 64 MiB".into());
        }
        if bit == 12 {
            event_desc = Some((offset, size));
        }
    }
    if let Some((offset, size)) = event_desc {
        validate_event_desc(file, offset, size)?;
    } else {
        if attr_length / attr_size == 0 {
            return Err("perf.data must have at least one event attribute".into());
        }
        let mut attr = vec![0_u8; usize::try_from(attr_size)?];
        file.seek(SeekFrom::Start(attr_offset))?;
        for _ in 0..attr_length / attr_size {
            file.read_exact(&mut attr)?;
            validate_attr(&attr)?;
        }
    }
    validate_rounds(file, data_offset, data_length)?;
    file.seek(SeekFrom::Start(0))?;
    Ok(())
}

fn validate_event_desc(file: &mut File, offset: u64, length: u64) -> Result<(), Box<dyn std::error::Error>> {
    if length > 4 * 1024 * 1024 {
        return Err("perf event descriptions exceed 4 MiB".into());
    }
    let mut bytes = vec![0_u8; usize::try_from(length)?];
    file.seek(SeekFrom::Start(offset))?;
    file.read_exact(&mut bytes)?;
    let count = dword(&bytes, 0)?;
    let attr_size = usize::try_from(dword(&bytes, 4)?)?;
    if !(1..=64).contains(&count) || !(64..=4096).contains(&attr_size) {
        return Err("perf.data must have bounded event descriptions".into());
    }
    let mut offset = 8_usize;
    for _ in 0..count {
        let ids_offset = offset.checked_add(attr_size).ok_or("perf attribute size overflow")?;
        validate_attr(bytes.get(offset..ids_offset).ok_or("truncated perf attribute")?)?;
        let ids = usize::try_from(dword(&bytes, ids_offset)?)?;
        let name = usize::try_from(dword(&bytes, ids_offset.checked_add(4).ok_or("perf offset overflow")?)?)?;
        if ids > 65_536 || name > 4096 {
            return Err("perf event metadata exceeds limits".into());
        }
        offset = ids_offset
            .checked_add(8)
            .and_then(|n| n.checked_add(name))
            .and_then(|n| ids.checked_mul(8).and_then(|id_bytes| n.checked_add(id_bytes)))
            .ok_or("perf event metadata overflow")?;
        if offset > bytes.len() {
            return Err("truncated perf event description".into());
        }
    }
    Ok(())
}

fn validate_attr(bytes: &[u8]) -> Result<(), &'static str> {
    let declared = usize::try_from(dword(bytes, 4)?).map_err(|_| "perf attribute size overflow")?;
    if declared < 64 || declared > bytes.len() {
        return Err("invalid perf attribute size");
    }
    if word(bytes, 24)? & !((1_u64 << 25) - 1) != 0 {
        return Err("unsupported perf sample fields");
    }
    if word(bytes, 24)? & (1 << 4) != 0 && word(bytes, 32)? & !15 != 0 {
        return Err("unsupported perf read format");
    }
    if declared >= 80 && word(bytes, 72)? & !((1_u64 << 18) - 1) != 0 {
        return Err("unsupported perf branch sample format");
    }
    Ok(())
}

fn validate_rounds(file: &File, start: u64, length: u64) -> Result<(), Box<dyn std::error::Error>> {
    let mut input = BufReader::with_capacity(1024 * 1024, file.try_clone()?);
    input.seek(SeekFrom::Start(start))?;
    let mut remaining = length;
    let mut round = 0_u64;
    let mut records = 0_u64;
    while remaining > 0 {
        if remaining < 8 {
            return Err("truncated perf event header".into());
        }
        let mut header = [0_u8; 8];
        input.read_exact(&mut header)?;
        let kind = dword(&header, 0)?;
        let size = u64::from(u16::from_le_bytes([header[6], header[7]]));
        if size < 8 || size > remaining {
            return Err("invalid perf event size".into());
        }
        if matches!(kind, 71 | 81 | 83) {
            return Err("compressed and AUX trace records are not supported".into());
        }
        if kind == 68 && size != 8 {
            return Err("invalid perf finished-round record".into());
        }
        if kind == 68 {
            round = 0;
            records = 0;
        } else {
            round = round.checked_add(size).ok_or("perf round size overflow")?;
            records = records.saturating_add(1);
            if round > MAX_ROUND_BYTES || records > 131_072 {
                return Err("perf event round exceeds processing limits".into());
            }
        }
        let copied = std::io::copy(&mut (&mut input).take(size - 8), &mut std::io::sink())?;
        if copied != size - 8 {
            return Err("truncated perf event body".into());
        }
        remaining -= size;
    }
    Ok(())
}

fn range(offset: u64, size: u64, length: u64) -> Result<u64, &'static str> {
    offset.checked_add(size).filter(|end| *end <= length).ok_or("perf section outside file")
}
fn word(bytes: &[u8], offset: usize) -> Result<u64, &'static str> {
    let end = offset.checked_add(8).ok_or("perf offset overflow")?;
    Ok(u64::from_le_bytes(
        bytes.get(offset..end).ok_or("truncated perf metadata")?.try_into().map_err(|_| "invalid perf word")?,
    ))
}
fn dword(bytes: &[u8], offset: usize) -> Result<u32, &'static str> {
    let end = offset.checked_add(4).ok_or("perf offset overflow")?;
    Ok(u32::from_le_bytes(
        bytes.get(offset..end).ok_or("truncated perf metadata")?.try_into().map_err(|_| "invalid perf dword")?,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn rejects_oversized_feature_before_reader_allocates() -> Result<(), Box<dyn std::error::Error>> {
        let dir = std::env::temp_dir().join(format!("xref-invalid-perf-{}", std::process::id()));
        std::fs::create_dir_all(&dir)?;
        let path = dir.join("bad.data");
        let mut bytes = vec![0_u8; 264];
        bytes[..8].copy_from_slice(b"PERFILE2");
        for (offset, value) in [
            (8, 104_u64),
            (16, 144),
            (24, 104),
            (32, 144),
            (40, 248),
            (48, 0),
            (72, 1_u64 << 12),
            (248, 264),
            (256, u64::MAX),
        ] {
            bytes[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
        }
        std::fs::write(&path, bytes)?;
        assert!(validate(&mut File::open(&path)?).is_err());
        let mut compressed = vec![0_u8; 248];
        compressed[..8].copy_from_slice(b"PERFILE2");
        for (offset, value) in [(8, 104_u64), (16, 144), (24, 104), (32, 144), (40, 248), (48, 0), (72, 1_u64 << 27)] {
            compressed[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
        }
        std::fs::write(&path, compressed)?;
        let Err(error) = validate(&mut File::open(&path)?) else {
            return Err("compressed data was accepted".into());
        };
        assert!(error.to_string().contains("compressed"));
        std::fs::remove_dir_all(dir)?;
        Ok(())
    }

    #[test]
    fn rejects_forged_event_counts_and_unbounded_rounds() -> Result<(), Box<dyn std::error::Error>> {
        let dir = std::env::temp_dir().join(format!("xref-invalid-perf-round-{}", std::process::id()));
        std::fs::create_dir_all(&dir)?;
        let path = dir.join("bad.data");
        let mut feature = vec![0_u8; 16];
        feature[..4].copy_from_slice(&u32::MAX.to_le_bytes());
        std::fs::write(&path, feature)?;
        assert!(validate_event_desc(&mut File::open(&path)?, 0, 16).is_err());
        let mut event = [0_u8; 8];
        event[..4].copy_from_slice(&9_u32.to_le_bytes());
        event[6..8].copy_from_slice(&8_u16.to_le_bytes());
        let bytes = event.repeat(131_073);
        std::fs::write(&path, &bytes)?;
        assert!(validate_rounds(&File::open(&path)?, 0, u64::try_from(bytes.len())?).is_err());
        let mut bad_round = [0_u8; 16];
        bad_round[..4].copy_from_slice(&68_u32.to_le_bytes());
        bad_round[6..8].copy_from_slice(&16_u16.to_le_bytes());
        std::fs::write(&path, bad_round)?;
        assert!(validate_rounds(&File::open(&path)?, 0, 16).is_err());
        std::fs::remove_dir_all(dir)?;
        Ok(())
    }

    #[test]
    fn rejects_unknown_sample_and_branch_layout_bits() {
        let mut attr = vec![0_u8; 128];
        attr[4..8].copy_from_slice(&128_u32.to_le_bytes());
        assert!(validate_attr(&attr).is_ok());
        attr[24..32].copy_from_slice(&(1_u64 << 63).to_le_bytes());
        assert!(validate_attr(&attr).is_err());
        attr[24..32].fill(0);
        attr[72..80].copy_from_slice(&(1_u64 << 19).to_le_bytes());
        assert!(validate_attr(&attr).is_err());
    }
}
