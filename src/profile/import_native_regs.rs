/*
 * XRef — Binary analysis
 * Copyright (c) 2026 Alexander Panasenko
 * Contact: alex@prod.codes
 * Author: https://prod.codes/about/
 * Project: https://github.com/alex09x/xref
 * SPDX-License-Identifier: MIT OR Apache-2.0
 */
use super::types::Branch;
use linux_perf_data::linux_perf_event_reader::{BranchSampleFormat, Endianness, RawEventRecord, SampleFormat};

pub fn abi(record: &RawEventRecord<'_>) -> Result<u64, &'static str> {
    if record.parse_info.endian != Endianness::LittleEndian {
        return Err("native perf import requires little-endian samples");
    }
    abi_from_bytes(&record.data.as_slice(), record.parse_info.sample_format, record.parse_info.branch_sample_format)
}

pub fn validate_prefix(record: &RawEventRecord<'_>) -> Result<(), &'static str> {
    if record.parse_info.endian != Endianness::LittleEndian {
        return Err("native perf import requires little-endian samples");
    }
    let _ = prefix(&record.data.as_slice(), record.parse_info.sample_format)?;
    Ok(())
}

fn abi_from_bytes(bytes: &[u8], format: SampleFormat, branch_format: BranchSampleFormat) -> Result<u64, &'static str> {
    if !format.contains(SampleFormat::REGS_USER) {
        return Err("cannot locate perf user register ABI for this sample format");
    }
    let mut offset = prefix(bytes, format)?;
    if format.contains(SampleFormat::BRANCH_STACK) {
        let _ = parse_branches(bytes, &mut offset, branch_format)?;
    }
    word(bytes, offset)
}

pub fn branches(record: &RawEventRecord<'_>) -> Result<(Vec<Branch>, bool), &'static str> {
    if record.parse_info.endian != Endianness::LittleEndian {
        return Err("native perf import requires little-endian samples");
    }
    let bytes = record.data.as_slice();
    let mut offset = prefix(&bytes, record.parse_info.sample_format)?;
    parse_branches(&bytes, &mut offset, record.parse_info.branch_sample_format)
}

fn prefix(bytes: &[u8], format: SampleFormat) -> Result<usize, &'static str> {
    if format.contains(SampleFormat::READ) {
        return Err("cannot locate perf sample fields when READ is present");
    }
    let mut offset = 0_usize;
    for field in [
        SampleFormat::IDENTIFIER,
        SampleFormat::IP,
        SampleFormat::TID,
        SampleFormat::TIME,
        SampleFormat::ADDR,
        SampleFormat::ID,
        SampleFormat::STREAM_ID,
        SampleFormat::CPU,
        SampleFormat::PERIOD,
    ] {
        if format.contains(field) {
            skip(&mut offset, 8, bytes.len())?;
        }
    }
    if format.contains(SampleFormat::CALLCHAIN) {
        let count = usize::try_from(word(bytes, offset)?).map_err(|_| "perf callchain length overflow")?;
        skip(&mut offset, 8, bytes.len())?;
        skip(&mut offset, count.checked_mul(8).ok_or("perf callchain length overflow")?, bytes.len())?;
    }
    if format.contains(SampleFormat::RAW) {
        let end = offset.checked_add(4).ok_or("perf sample length overflow")?;
        let size = u32::from_le_bytes(
            bytes
                .get(offset..end)
                .ok_or("truncated perf RAW header")?
                .try_into()
                .map_err(|_| "invalid perf RAW header")?,
        );
        offset = end;
        skip(&mut offset, usize::try_from(size).map_err(|_| "perf RAW length overflow")?, bytes.len())?;
    }
    Ok(offset)
}

fn parse_branches(
    bytes: &[u8],
    offset: &mut usize,
    format: BranchSampleFormat,
) -> Result<(Vec<Branch>, bool), &'static str> {
    let count = usize::try_from(word(bytes, *offset)?).map_err(|_| "perf branch count overflow")?;
    skip(offset, 8, bytes.len())?;
    if format.contains(BranchSampleFormat::HW_INDEX) {
        skip(offset, 8, bytes.len())?;
    }
    let end = offset
        .checked_add(count.checked_mul(24).ok_or("perf branch count overflow")?)
        .filter(|end| *end <= bytes.len())
        .ok_or("truncated perf branch stack")?;
    let mut result = Vec::with_capacity(count.min(512));
    for _ in 0..count.min(512) {
        result.push(Branch {
            from: word(bytes, *offset)?,
            to: word(bytes, *offset + 8)?,
            flags: word(bytes, *offset + 16)?,
        });
        *offset += 24;
    }
    *offset = end;
    Ok((result, count > 512))
}

fn skip(offset: &mut usize, amount: usize, limit: usize) -> Result<(), &'static str> {
    *offset = offset.checked_add(amount).filter(|end| *end <= limit).ok_or("truncated perf sample")?;
    Ok(())
}

fn word(bytes: &[u8], offset: usize) -> Result<u64, &'static str> {
    let end = offset.checked_add(8).ok_or("perf sample length overflow")?;
    Ok(u64::from_le_bytes(
        bytes.get(offset..end).ok_or("truncated perf sample")?.try_into().map_err(|_| "invalid perf word")?,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn locates_abi_after_variable_length_fields_and_rejects_truncation() {
        let format = SampleFormat::IDENTIFIER
            | SampleFormat::IP
            | SampleFormat::TID
            | SampleFormat::CALLCHAIN
            | SampleFormat::RAW
            | SampleFormat::REGS_USER;
        let mut bytes = vec![0_u8; 24];
        bytes.extend_from_slice(&2_u64.to_le_bytes());
        bytes.extend_from_slice(&[0; 16]);
        bytes.extend_from_slice(&3_u32.to_le_bytes());
        bytes.extend_from_slice(&[1, 2, 3]);
        bytes.extend_from_slice(&2_u64.to_le_bytes());
        assert_eq!(abi_from_bytes(&bytes, format, BranchSampleFormat::empty()), Ok(2));
        bytes.pop();
        assert!(abi_from_bytes(&bytes, format, BranchSampleFormat::empty()).is_err());
        let mut overflow = vec![0_u8; 8];
        overflow.extend_from_slice(&u64::MAX.to_le_bytes());
        assert!(prefix(&overflow, SampleFormat::IP | SampleFormat::CALLCHAIN).is_err());
    }

    #[test]
    fn extracts_branch_stack_and_locates_register_abi_after_it() -> Result<(), Box<dyn std::error::Error>> {
        let format = SampleFormat::IP | SampleFormat::BRANCH_STACK | SampleFormat::REGS_USER;
        let branch_format = BranchSampleFormat::HW_INDEX;
        let mut bytes = Vec::new();
        for word in [0x1000_u64, 2, 7, 0x1111, 0x2222, 0xaa, 0x3333, 0x4444, 0xbb, 2] {
            bytes.extend_from_slice(&word.to_le_bytes());
        }
        let mut offset = prefix(&bytes, format)?;
        let (branches, truncated) = parse_branches(&bytes, &mut offset, branch_format)?;
        assert!(!truncated);
        assert_eq!(
            branches.iter().map(|branch| (branch.from, branch.to, branch.flags)).collect::<Vec<_>>(),
            vec![(0x1111, 0x2222, 0xaa), (0x3333, 0x4444, 0xbb)]
        );
        assert_eq!(abi_from_bytes(&bytes, format, branch_format), Ok(2));
        assert!(parse_branches(&bytes[..20], &mut 8, branch_format).is_err());
        Ok(())
    }
}
