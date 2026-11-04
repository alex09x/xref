/*
 * XRef — bounded Intel PT import
 * Copyright (c) 2026 Alexander Panasenko
 * Contact: alex@prod.codes
 * Author: https://prod.codes/about/
 * Project: https://github.com/alex09x/xref
 * SPDX-License-Identifier: MIT OR Apache-2.0
 */
use super::codec::ProfileWriter;
use super::import_text::{Options, OutputGuard};
use super::pt_aux_identity::{intel_pt_info, mapping_matches, verified_build_id};
use super::types::{Header, Mapping, Record, SYNTHETIC_PT_EVENT};
use crate::image::Image;
use linux_perf_data::linux_perf_event_reader::{CpuMode, EventRecord, RecordType};
use linux_perf_data::{DsoInfo, DsoKey, PerfFile, PerfFileRecord, PerfRecordIter, UserRecord, UserRecordType};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::fs::OpenOptions;
use std::io::Read;

#[allow(clippy::too_many_arguments, clippy::too_many_lines)]
pub(super) fn run<R: Read>(
    file: &mut PerfFile,
    iter: &mut PerfRecordIter<R>,
    image: &Image,
    options: &Options<'_>,
    slide: i64,
    mappings: Vec<Mapping>,
    target_path: &str,
    build_ids: &HashMap<DsoKey, DsoInfo>,
) -> Result<(), Box<dyn std::error::Error>> {
    let pid = options.pid.ok_or("missing target PID")?;
    let key = DsoKey::detect(target_path.as_bytes(), CpuMode::User).ok_or("unverified PT target path")?;
    let recorded = build_ids.get(&key).map(|info| info.build_id.as_slice());
    if !verified_build_id(recorded, image.metadata.build_id.as_deref()) {
        return Err("unverified PT target build ID".into());
    }
    let configurations: Vec<_> = file
        .event_attributes()
        .iter()
        .filter_map(|entry| match entry.attr.type_ {
            linux_perf_data::linux_perf_event_reader::PerfEventType::DynamicPmu(pmu, config, _, _) => {
                Some((pmu, config))
            }
            _ => None,
        })
        .collect();
    let ordinary: Vec<_> = file
        .event_attributes()
        .iter()
        .enumerate()
        .filter(|(_, entry)| {
            !matches!(entry.attr.type_, linux_perf_data::linux_perf_event_reader::PerfEventType::DynamicPmu(..))
        })
        .map(|(index, entry)| (index, entry.attr, entry.name.clone()))
        .collect();
    if ordinary.len() > 1 {
        return Err("multiple ordinary event types alongside PT are unsupported".into());
    }
    let ordinary_event = ordinary.first();
    let callchain = ordinary_event.map_or("fp", |(_, attr, _)| {
        use linux_perf_data::linux_perf_event_reader::SampleFormat;
        let format = attr.sample_format;
        if format.contains(SampleFormat::REGS_USER | SampleFormat::STACK_USER) {
            "dwarf"
        } else if format.contains(SampleFormat::BRANCH_STACK) {
            "lbr"
        } else if format.contains(SampleFormat::CALLCHAIN) {
            "fp"
        } else {
            "none"
        }
    });
    if let Some((_, attr, _)) = ordinary_event {
        use linux_perf_data::linux_perf_event_reader::SampleFormat;
        if !attr.sample_format.contains(SampleFormat::IP | SampleFormat::TID) {
            return Err("ordinary perf samples require IP and PID/TID".into());
        }
        super::import_native::validate_arch(file.arch()?, callchain)?;
    }
    let header = Header {
        schema_version: if ordinary_event.is_some() { 2 } else { 1 },
        image_sha256: crate::trace_analysis::index::hex_bytes(&Sha256::digest(&image.data)),
        process_exe_sha256: None,
        binary_match: "caller_supplied_base_unverified".into(),
        pie_slide: slide,
        exe_device_major: 0,
        exe_device_minor: 0,
        exe_inode: 1,
        pid,
        starttime_ticks: 0,
        event: ordinary_event.map_or_else(
            || SYNTHETIC_PT_EVENT.into(),
            |(_, _, name)| format!("perf_data:{}", name.as_deref().unwrap_or("unknown")),
        ),
        frequency_hz: None,
        period: None,
        callchain: callchain.into(),
        started_monotonic_ns: 0,
        trigger_static_va: None,
        trigger_window_ns: None,
    };
    let mut output = OpenOptions::new();
    output.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        output.mode(0o600);
    }
    let output = output.open(options.output)?;
    let mut guard = OutputGuard { path: options.output, keep: false };
    let mut writer = ProfileWriter::new(std::io::BufWriter::new(output), &header)?;
    for mapping in mappings {
        writer.write_record(&Record::Mapping(mapping))?;
    }
    let mut ordinary_state = if let Some((_, attr, _)) = ordinary_event {
        Some(super::import_native_records::NativeState::new(
            pid,
            target_path.to_owned(),
            attr.sample_regs_user,
            callchain,
            file.build_ids()?,
        ))
    } else {
        None
    };
    let mut return_compression = None;
    let mut target_mappings = super::pt_mapping::Mappings::default();
    let mut target_file_identity = None;
    let mut stream = Vec::new();
    let mut next_offset = None;
    let mut stream_index = None;
    while let Some(entry) = iter.next_record(file)? {
        match entry {
            PerfFileRecord::UserRecord(record) if record.record_type == UserRecordType::PERF_AUXTRACE_INFO => {
                let data = record.data.as_slice();
                if !intel_pt_info(&data)? {
                    return Err("non-Intel PT AUX format".into());
                }
                let pmu = u32::try_from(u64::from_le_bytes(
                    data.get(8..16).ok_or("truncated Intel PT PMU metadata")?.try_into()?,
                ))?;
                let mut matches = configurations.iter().filter(|(candidate, _)| *candidate == pmu);
                let config = matches.next().ok_or("Intel PT PMU does not match an event attribute")?.1;
                if matches.next().is_some() {
                    return Err("ambiguous Intel PT PMU attributes".into());
                }
                // perf's Intel PT private metadata slot 6 is the no-return-compression bit.
                let bit = u64::from_le_bytes(data.get(56..64).ok_or("truncated Intel PT metadata")?.try_into()?);
                return_compression = Some(config & bit == 0);
            }
            PerfFileRecord::UserRecord(record) if record.record_type == UserRecordType::PERF_AUXTRACE_ERROR => {
                return Err("PT AUXTRACE error or loss".into());
            }
            PerfFileRecord::UserRecord(record) if record.record_type == UserRecordType::PERF_AUXTRACE => {
                if return_compression.is_none() {
                    return Err("PT AUX before Intel PT metadata".into());
                }
                let UserRecord::Auxtrace(aux) = record.parse()? else {
                    return Err("invalid AUXTRACE".into());
                };
                if aux.tid != pid {
                    return Err("PT AUX thread is not the selected process leader".into());
                }
                if stream_index.is_some_and(|index| index != aux.index)
                    || next_offset.is_some_and(|offset| offset != aux.offset)
                {
                    return Err("multiple or discontinuous PT AUX streams".into());
                }
                let bytes = aux.aux_data.as_slice();
                if u64::try_from(bytes.len())? != aux.size {
                    return Err("invalid PT AUX length".into());
                }
                if stream.len().checked_add(bytes.len()).is_none_or(|len| len > 64 * 1024 * 1024) {
                    return Err("PT AUX exceeds 64 MiB".into());
                }
                stream.extend_from_slice(&bytes);
                stream_index = Some(aux.index);
                next_offset = Some(aux.offset.checked_add(aux.size).ok_or("PT AUX offset overflow")?);
            }
            PerfFileRecord::EventRecord { attr_index, record } => {
                if matches!(record.record_type, RecordType::LOST | RecordType::LOST_SAMPLES) {
                    return Err("PT capture has loss or unverified AUX status".into());
                }
                if record.record_type == RecordType::AUX {
                    let data = record.data.as_slice();
                    let offset = u64::from_le_bytes(data.get(..8).ok_or("truncated AUX status")?.try_into()?);
                    let size = u64::from_le_bytes(data.get(8..16).ok_or("truncated AUX status")?.try_into()?);
                    let flags = u64::from_le_bytes(data.get(16..24).ok_or("truncated AUX status")?.try_into()?);
                    if flags != 0 || size > 64 * 1024 * 1024 || offset.checked_add(size).is_none() {
                        return Err("PT AUX status reports loss, unsupported flags, or invalid range".into());
                    }
                    continue;
                }
                if record.record_type == RecordType::SAMPLE {
                    if ordinary_event.is_none_or(|(index, _, _)| *index != attr_index) {
                        return Err("sample from an unsupported event alongside PT".into());
                    }
                    let data = super::import_native_read::strip(&record)?;
                    let mut normalized = record.clone();
                    if let Some(ref data) = data {
                        normalized.data = data.as_slice().into();
                        normalized
                            .parse_info
                            .sample_format
                            .remove(linux_perf_data::linux_perf_event_reader::SampleFormat::READ);
                    }
                    ordinary_state.as_mut().ok_or("missing ordinary event state")?.record(&normalized, &mut writer)?;
                    continue;
                }
                if record.record_type == RecordType::MMAP2
                    && record.misc & (1 << 14) != 0
                    && record.data.as_slice().get(32).is_none_or(|length| *length > 20)
                {
                    return Err("invalid perf mmap build ID length".into());
                }
                match record.parse()? {
                    EventRecord::Mmap2(map) if u32::try_from(map.pid).ok() == Some(pid) => {
                        let path = std::str::from_utf8(&map.path.as_slice())?.to_owned();
                        if path == target_path {
                            super::pt_mapping::file_identity(
                                &mut target_file_identity,
                                &map.file_id,
                                image.metadata.build_id.as_deref().ok_or("missing PT target build ID")?,
                            )?;
                            let mapping = Mapping {
                                timestamp_ns: record.timestamp().unwrap_or(0),
                                pid,
                                tid: u32::try_from(map.tid)?,
                                start: map.address,
                                length: map.length,
                                file_offset: map.page_offset,
                                device_major: 0,
                                device_minor: 0,
                                inode: 1,
                                executable: map.protection & 4 != 0,
                                sha256: None,
                                path,
                            };
                            if mapping.executable {
                                if !mapping_matches(&mapping, image, pid, slide) {
                                    return Err("PT target mapping does not match ELF and slide".into());
                                }
                                target_mappings.add(mapping.start, mapping.length, true)?;
                            } else {
                                target_mappings.add(mapping.start, mapping.length, false)?;
                            }
                        } else {
                            target_mappings.add(map.address, map.length, false)?;
                        }
                    }
                    EventRecord::Exit(event)
                        if u32::try_from(event.pid).ok() == Some(pid) && u32::try_from(event.tid).ok() == Some(pid) =>
                    {
                        return Err("PT target exited within recording".into());
                    }
                    EventRecord::Comm(event) if event.is_execve && u32::try_from(event.pid).ok() == Some(pid) => {
                        return Err("PT target exec within recording".into());
                    }
                    _ => {}
                }
                if let Some(state) = ordinary_state.as_mut()
                    && !state.record(&record, &mut writer)?
                {
                    return Err("ordinary sample sideband crosses a target boundary".into());
                }
            }
            PerfFileRecord::UserRecord(_) => {}
        }
    }
    if target_mappings.is_empty() {
        return Err("recorded PT target executable mapping missing".into());
    }
    let synthetic = super::pt_synthesis::synthesize(
        &stream,
        image,
        slide,
        pid,
        pid,
        return_compression.ok_or("missing PT metadata")?,
        None,
    )?;
    if !synthetic.untimed || !synthetic.instruction_events {
        return Err("invalid PT synthesis metadata".into());
    }
    if synthetic.samples.iter().any(|sample| {
        !target_mappings.contains(sample.ip)
            || sample
                .callchain
                .iter()
                .any(|address| address.checked_sub(1).is_none_or(|value| !target_mappings.contains(value)))
    }) {
        return Err("PT instruction or caller outside recorded executable mappings".into());
    }
    for sample in synthetic.samples {
        writer.write_record(&if ordinary_event.is_some() {
            Record::PtInstruction(sample)
        } else {
            Record::Sample(sample)
        })?;
    }
    let latest = ordinary_state.as_ref().map_or(0, |state| state.latest_ns);
    let dropped = ordinary_state.as_ref().map_or(0, |state| state.dropped);
    let reason = if synthetic.truncated {
        "intel_pt_instruction_budget_exhausted"
    } else {
        "intel_pt_instruction_events_untimed"
    };
    writer.finish(latest, dropped, true, reason, None, 0)?;
    guard.keep = true;
    Ok(())
}
