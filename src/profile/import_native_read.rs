/*
 * XRef — Binary analysis
 * Copyright (c) 2026 Alexander Panasenko
 * Contact: alex@prod.codes
 * Author: https://prod.codes/about/
 * Project: https://github.com/alex09x/xref
 * SPDX-License-Identifier: MIT OR Apache-2.0
 */
use linux_perf_data::linux_perf_event_reader::{Endianness, RawEventRecord, ReadFormat, RecordType, SampleFormat};

/// Remove READ values before passing samples to the upstream parser, which
/// currently interchanges the grouped and non-grouped layouts. Values are not
/// used in profile aggregation; all remaining sample fields are preserved.
pub fn strip(record: &RawEventRecord<'_>) -> Result<Option<Vec<u8>>, &'static str> {
    if record.record_type != RecordType::SAMPLE || !record.parse_info.sample_format.contains(SampleFormat::READ) {
        return Ok(None);
    }
    if record.parse_info.endian != Endianness::LittleEndian {
        return Err("native perf import requires little-endian samples");
    }
    let data = record.data.as_slice();
    let format = record.parse_info.sample_format;
    let mut start = 0_usize;
    for flag in [
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
        if format.contains(flag) {
            start += 8;
        }
    }
    let flags = record.parse_info.read_format;
    let value = data.get(start..start + 8).ok_or("truncated perf READ")?;
    let count = if flags.contains(ReadFormat::GROUP) {
        usize::try_from(u64::from_le_bytes(value.try_into().map_err(|_| "invalid perf READ")?))
            .map_err(|_| "perf READ count overflow")?
    } else {
        1
    };
    let each = 8_usize + if flags.contains(ReadFormat::ID) { 8 } else { 0 };
    let fixed = (if flags.contains(ReadFormat::GROUP) { 8 } else { 0 })
        + (if flags.contains(ReadFormat::TOTAL_TIME_ENABLED) { 8 } else { 0 })
        + (if flags.contains(ReadFormat::TOTAL_TIME_RUNNING) { 8 } else { 0 });
    let end = start
        .checked_add(fixed)
        .and_then(|n| count.checked_mul(each).and_then(|size| n.checked_add(size)))
        .ok_or("perf READ length overflow")?;
    if end > data.len() {
        return Err("truncated perf READ values");
    }
    let mut output = Vec::with_capacity(data.len() - (end - start));
    output.extend_from_slice(&data[..start]);
    output.extend_from_slice(&data[end..]);
    Ok(Some(output))
}

#[cfg(test)]
mod tests {
    use super::*;
    use linux_perf_data::linux_perf_event_reader::{BranchSampleFormat, RawData, RecordIdParseInfo, RecordParseInfo};

    fn info(read_format: ReadFormat) -> RecordParseInfo {
        RecordParseInfo {
            endian: Endianness::LittleEndian,
            sample_format: SampleFormat::IP | SampleFormat::TID | SampleFormat::READ | SampleFormat::CALLCHAIN,
            branch_sample_format: BranchSampleFormat::empty(),
            read_format,
            common_data_offset_from_end: None,
            sample_regs_user: 0,
            user_regs_count: 0,
            sample_regs_intr: 0,
            intr_regs_count: 0,
            id_parse_info: RecordIdParseInfo {
                nonsample_record_id_offset_from_end: None,
                sample_record_id_offset_from_start: None,
            },
            nonsample_record_time_offset_from_end: None,
            sample_record_time_offset_from_start: None,
        }
    }

    #[test]
    fn strips_group_and_single_read_without_changing_callchain() -> Result<(), Box<dyn std::error::Error>> {
        for grouped in [false, true] {
            let mut words = vec![0x1234_u64, (0x2b_u64 << 32) | 0x2a];
            if grouped {
                words.extend([2, 88, 99, 10, 11, 20, 21]);
            } else {
                words.extend([10, 88, 99, 11]);
            }
            words.extend([1, 0x9876]);
            let bytes: Vec<u8> = words.iter().flat_map(|w| w.to_le_bytes()).collect();
            let mut flags = ReadFormat::TOTAL_TIME_ENABLED | ReadFormat::TOTAL_TIME_RUNNING | ReadFormat::ID;
            if grouped {
                flags |= ReadFormat::GROUP;
            }
            let record = RawEventRecord::new(RecordType::SAMPLE, 0, RawData::from(bytes.as_slice()), info(flags));
            let output = strip(&record)?.ok_or("READ was not removed")?;
            let expected: Vec<u8> =
                [0x1234_u64, (0x2b_u64 << 32) | 0x2a, 1, 0x9876].iter().flat_map(|w| w.to_le_bytes()).collect();
            assert_eq!(output, expected);
            let mut normalized = record.clone();
            normalized.data = output.as_slice().into();
            normalized.parse_info.sample_format.remove(SampleFormat::READ);
            let parsed = normalized.parse()?;
            match parsed {
                linux_perf_data::linux_perf_event_reader::EventRecord::Sample(sample) => {
                    assert_eq!(sample.ip, Some(0x1234));
                    assert_eq!(sample.callchain.ok_or("missing callchain")?.get(0), Some(0x9876));
                }
                _ => panic!("expected sample"),
            }
            let truncated = &bytes[..bytes.len() - 17];
            let bad = RawEventRecord::new(RecordType::SAMPLE, 0, RawData::from(truncated), info(flags));
            assert!(strip(&bad).is_err());
        }
        Ok(())
    }

    #[test]
    fn rejects_group_count_overflow() {
        let bytes: Vec<u8> = [1_u64, 2, u64::MAX].iter().flat_map(|w| w.to_le_bytes()).collect();
        let record =
            RawEventRecord::new(RecordType::SAMPLE, 0, RawData::from(bytes.as_slice()), info(ReadFormat::GROUP));
        assert!(strip(&record).is_err());
    }
}
