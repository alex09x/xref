/*
 * XRef — Binary analysis
 * Copyright (c) 2026 Alexander Panasenko
 * Contact: alex@prod.codes
 * Author: https://prod.codes/about/
 * Project: https://github.com/alex09x/xref
 * SPDX-License-Identifier: MIT OR Apache-2.0
 */
use super::codec::ProfileWriter;
use super::types::{Mapping, Record, Sample};
use linux_perf_data::linux_perf_event_reader::{EventRecord, Mmap2FileId, RawEventRecord, RecordType, SampleFormat};
use linux_perf_data::{DsoInfo, DsoKey};
use std::collections::HashMap;
use std::io::Write;

pub struct NativeState {
    pid: u32,
    target_path: String,
    registers_mask: u64,
    callchain: &'static str,
    build_ids: HashMap<DsoKey, DsoInfo>,
    module_hashes: HashMap<(String, Vec<u8>), Option<String>>,
    module_bytes: u64,
    pub samples: u64,
    pub dropped: u64,
    pub latest_ns: u64,
    pub partial: bool,
    pub aux_ignored: bool,
    pub stop_reason: &'static str,
}

impl NativeState {
    pub fn new(
        pid: u32,
        target_path: String,
        registers_mask: u64,
        callchain: &'static str,
        build_ids: HashMap<DsoKey, DsoInfo>,
    ) -> Self {
        Self {
            pid,
            target_path,
            registers_mask,
            callchain,
            samples: 0,
            dropped: 0,
            latest_ns: 0,
            build_ids,
            module_hashes: HashMap::new(),
            module_bytes: 0,
            partial: true,
            aux_ignored: false,
            stop_reason: "imported_perf_data_unverified_mapping",
        }
    }

    fn module_hash(
        &mut self,
        path: &str,
        cpu_mode: linux_perf_data::linux_perf_event_reader::CpuMode,
    ) -> Option<String> {
        let key = DsoKey::detect(path.as_bytes(), cpu_mode)?;
        let expected = self.build_ids.get(&key)?.build_id.clone();
        self.module_hash_with_id(path, expected)
    }

    fn module_hash_with_id(&mut self, path: &str, expected: Vec<u8>) -> Option<String> {
        let cache_key = (path.to_owned(), expected);
        if let Some(cached) = self.module_hashes.get(&cache_key) {
            return cached.clone();
        }
        if self.module_hashes.len() >= 256 {
            return None;
        }
        let hash = super::import_native_identity::verified_module(
            path,
            &cache_key.1,
            (256_u64 * 1024 * 1024).saturating_sub(self.module_bytes),
        );
        if let Some((_, size)) = &hash {
            self.module_bytes = self.module_bytes.saturating_add(*size);
        }
        let hash = hash.map(|(hash, _)| hash);
        self.module_hashes.insert(cache_key, hash.clone());
        hash
    }

    #[allow(clippy::too_many_lines)] // One dispatch keeps each perf record and its metadata together.
    pub fn record<W: Write>(
        &mut self,
        record: &RawEventRecord<'_>,
        writer: &mut ProfileWriter<W>,
    ) -> Result<bool, Box<dyn std::error::Error>> {
        let timestamp = record.timestamp().unwrap_or(0);
        self.latest_ns = self.latest_ns.max(timestamp);
        if record.record_type == RecordType::LOST_SAMPLES {
            if record.parse_info.endian != linux_perf_data::linux_perf_event_reader::Endianness::LittleEndian {
                return Err("native perf import requires little-endian records".into());
            }
            let data = record.data.as_slice();
            let count = u64::from_le_bytes(data.get(..8).ok_or("truncated lost-samples record")?.try_into()?);
            let common = record.common_data()?;
            if common.pid.and_then(|pid| u32::try_from(pid).ok()).is_none_or(|pid| pid == self.pid) {
                writer.write_record(&Record::Lost {
                    timestamp_ns: timestamp,
                    tid: common.tid.and_then(|tid| u32::try_from(tid).ok()).unwrap_or(self.pid),
                    count,
                })?;
            }
            self.partial = true;
            return Ok(true);
        }
        if !matches!(
            record.record_type,
            RecordType::SAMPLE
                | RecordType::MMAP2
                | RecordType::LOST
                | RecordType::FORK
                | RecordType::EXIT
                | RecordType::COMM
        ) {
            return Ok(true);
        }
        if record.record_type == RecordType::SAMPLE {
            super::import_native_regs::validate_prefix(record)?;
        }
        if record.record_type == RecordType::SAMPLE && self.callchain == "dwarf" {
            match super::import_native_regs::abi(record)? {
                0 | 2 => {}
                _ => return Err("perf.data has unsupported user register ABI".into()),
            }
        }
        let branches = if record.record_type == RecordType::SAMPLE
            && record.parse_info.sample_format.contains(SampleFormat::BRANCH_STACK)
        {
            let (branches, truncated) = super::import_native_regs::branches(record)?;
            self.partial |= truncated;
            branches
        } else {
            Vec::new()
        };
        let common = record.common_data()?;
        let misc = record.misc;
        match record.parse()? {
            EventRecord::Sample(sample) => {
                if sample.pid.and_then(|pid| u32::try_from(pid).ok()) != Some(self.pid) {
                    return Ok(true);
                }
                let Some(ip) = sample.ip else {
                    return Err("perf.data sample lacks IP".into());
                };
                let tid = sample.tid.and_then(|tid| u32::try_from(tid).ok()).ok_or("perf.data sample lacks TID")?;
                let mut registers = Vec::new();
                let mut mask = 0_u64;
                if let Some(regs) = sample.user_regs {
                    for bit in 0..64 {
                        if self.registers_mask & (1_u64 << bit) != 0 {
                            let value = regs.get(bit).ok_or("incomplete perf register record")?;
                            registers.push(value);
                            mask |= 1_u64 << bit;
                        }
                    }
                }
                let mut stack = Vec::new();
                if let Some((data, dynamic_size)) = sample.user_stack {
                    let raw = data.as_slice();
                    let size = usize::try_from(dynamic_size).map_err(|_| "invalid dynamic stack size")?;
                    if size > raw.len() {
                        return Err("perf stack length exceeds record".into());
                    }
                    if size > 65_528 {
                        self.partial = true;
                    }
                    stack.extend_from_slice(&raw[..size.min(65_528)]);
                }
                let mut callchain = Vec::new();
                if let Some(frames) = sample.callchain {
                    if frames.len() > 512 {
                        self.partial = true;
                    }
                    for index in 0..frames.len().min(512) {
                        callchain.push(frames.get(index).ok_or("incomplete callchain")?);
                    }
                }
                if sample.timestamp.is_none() || sample.period.is_none() {
                    self.partial = true;
                }
                if self.samples >= 10_000_000 {
                    return Err("perf.data exceeds the 10000000 sample limit".into());
                }
                writer.write_record(&Record::Sample(Sample {
                    timestamp_ns: sample.timestamp.unwrap_or(0),
                    pid: self.pid,
                    tid,
                    cpu_mode: misc & 7,
                    ip,
                    period: sample.period.unwrap_or(1),
                    registers_mask: mask,
                    registers,
                    user_stack: stack,
                    callchain,
                    branches,
                }))?;
                self.samples += 1;
            }
            EventRecord::Mmap2(mapping) if u32::try_from(mapping.pid).ok() == Some(self.pid) => {
                let path_bytes = mapping.path.as_slice();
                if path_bytes.len() > 4096 {
                    return Err("perf mapping path exceeds limit".into());
                }
                let path = std::str::from_utf8(&path_bytes)?.to_owned();
                if path.trim_end_matches(" (deleted)") == self.target_path {
                    return Ok(true);
                }
                if mapping.length == 0 || mapping.address.checked_add(mapping.length).is_none() {
                    return Err("invalid perf mapping range".into());
                }
                let (major, minor, inode, sha256) = match mapping.file_id {
                    Mmap2FileId::InodeAndVersion(id) => {
                        (id.major, id.minor, id.inode, self.module_hash(&path, mapping.cpu_mode))
                    }
                    Mmap2FileId::BuildId(id) => (0, 0, 0, self.module_hash_with_id(&path, id)),
                };
                writer.write_record(&Record::Mapping(Mapping {
                    timestamp_ns: timestamp,
                    pid: self.pid,
                    tid: u32::try_from(mapping.tid).unwrap_or(self.pid),
                    start: mapping.address,
                    length: mapping.length,
                    file_offset: mapping.page_offset,
                    device_major: major,
                    device_minor: minor,
                    inode,
                    executable: mapping.protection & 4 != 0,
                    sha256,
                    path,
                }))?;
            }
            EventRecord::Lost(lost) => {
                if common.pid.and_then(|pid| u32::try_from(pid).ok()).is_none_or(|pid| pid == self.pid) {
                    writer.write_record(&Record::Lost {
                        timestamp_ns: timestamp,
                        tid: common.tid.and_then(|tid| u32::try_from(tid).ok()).unwrap_or(self.pid),
                        count: lost.count,
                    })?;
                }
            }
            EventRecord::Fork(event) if u32::try_from(event.pid).ok() == Some(self.pid) => {
                writer.write_record(&Record::Fork {
                    timestamp_ns: event.timestamp,
                    pid: self.pid,
                    tid: u32::try_from(event.tid)?,
                    parent_pid: u32::try_from(event.ppid)?,
                    parent_tid: u32::try_from(event.ptid)?,
                })?;
            }
            EventRecord::Exit(event) if u32::try_from(event.pid).ok() == Some(self.pid) => {
                let tid = u32::try_from(event.tid)?;
                writer.write_record(&Record::Exit { timestamp_ns: event.timestamp, pid: self.pid, tid })?;
                if tid == self.pid {
                    self.stop_reason = "import_target_exit_boundary";
                    return Ok(false);
                }
            }
            EventRecord::Comm(event) if event.is_execve && u32::try_from(event.pid).ok() == Some(self.pid) => {
                self.stop_reason = "import_target_exec_boundary";
                return Ok(false);
            }
            _ => {}
        }
        Ok(true)
    }
}

#[cfg(test)]
mod tests {
    use super::super::codec::ProfileReader;
    use super::super::types::Header;
    use super::*;
    use linux_perf_data::linux_perf_event_reader::{
        BranchSampleFormat, Endianness, RawData, ReadFormat, RecordIdParseInfo, RecordParseInfo,
    };

    #[test]
    fn preserves_native_lost_record_with_sample_identity() -> Result<(), Box<dyn std::error::Error>> {
        let header = Header {
            schema_version: 1,
            image_sha256: "ab".repeat(32),
            process_exe_sha256: None,
            binary_match: "caller_supplied_base_unverified".into(),
            pie_slide: 0,
            exe_device_major: 0,
            exe_device_minor: 0,
            exe_inode: 1,
            pid: 42,
            starttime_ticks: 0,
            event: "perf_data:test".into(),
            frequency_hz: None,
            period: None,
            callchain: "none".into(),
            started_monotonic_ns: 0,
            trigger_static_va: None,
            trigger_window_ns: None,
        };
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&7_u64.to_le_bytes());
        bytes.extend_from_slice(&9_u64.to_le_bytes());
        bytes.extend_from_slice(&42_u32.to_le_bytes());
        bytes.extend_from_slice(&43_u32.to_le_bytes());
        bytes.extend_from_slice(&123_u64.to_le_bytes());
        let info = RecordParseInfo {
            endian: Endianness::LittleEndian,
            sample_format: SampleFormat::TID | SampleFormat::TIME,
            branch_sample_format: BranchSampleFormat::empty(),
            read_format: ReadFormat::empty(),
            common_data_offset_from_end: Some(16),
            sample_regs_user: 0,
            user_regs_count: 0,
            sample_regs_intr: 0,
            intr_regs_count: 0,
            id_parse_info: RecordIdParseInfo {
                nonsample_record_id_offset_from_end: None,
                sample_record_id_offset_from_start: None,
            },
            nonsample_record_time_offset_from_end: Some(8),
            sample_record_time_offset_from_start: Some(8),
        };
        let raw = RawEventRecord::new(RecordType::LOST, 0, RawData::from(bytes.as_slice()), info);
        let mut writer = ProfileWriter::new(Vec::new(), &header)?;
        let mut state = NativeState::new(42, String::new(), 0, "none", HashMap::new());
        assert!(state.record(&raw, &mut writer)?);
        let mut lost_samples = Vec::new();
        lost_samples.extend_from_slice(&11_u64.to_le_bytes());
        lost_samples.extend_from_slice(&42_u32.to_le_bytes());
        lost_samples.extend_from_slice(&43_u32.to_le_bytes());
        lost_samples.extend_from_slice(&124_u64.to_le_bytes());
        let raw = RawEventRecord::new(RecordType::LOST_SAMPLES, 0, RawData::from(lost_samples.as_slice()), info);
        assert!(state.record(&raw, &mut writer)?);
        let encoded = writer.finish(124, 0, true, "fixture", None, 0)?;
        let mut reader = ProfileReader::new(std::io::Cursor::new(encoded))?;
        assert!(matches!(reader.read_record()?, Some(Record::Lost { timestamp_ns: 123, tid: 43, count: 9 })));
        assert!(matches!(reader.read_record()?, Some(Record::Lost { timestamp_ns: 124, tid: 43, count: 11 })));
        assert!(matches!(reader.read_record()?, Some(Record::End(footer)) if footer.lost == 20));
        Ok(())
    }
}
