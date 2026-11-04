/*
 * XRef — Binary analysis
 * Copyright (c) 2026 Alexander Panasenko
 * Contact: alex@prod.codes
 * Author: https://prod.codes/about/
 * Project: https://github.com/alex09x/xref
 * SPDX-License-Identifier: MIT OR Apache-2.0
 */
use super::codec::ProfileWriter;
use super::import_native_records::NativeState;
use super::import_text::{Options, OutputGuard};
use super::types::{Header, Record};
use crate::image::Image;
use linux_perf_data::linux_perf_event_reader::{RecordType, SampleFormat};
use linux_perf_data::{PerfFileReader, PerfFileRecord};
use sha2::{Digest, Sha256};
use std::fs::{File, OpenOptions};
use std::io::{BufReader, Read, Seek, SeekFrom};

#[allow(clippy::too_many_lines)] // Event import and output cleanup share one transaction.
pub fn run(image: &Image, options: &Options<'_>) -> Result<(), Box<dyn std::error::Error>> {
    let pid = options.pid.filter(|pid| *pid != 0).ok_or("profile import requires a nonzero --pid")?;
    let mut file = snapshot(options.input)?;
    let (nested_aux, intel_pt) = super::import_native_header::validate(&mut file)?;
    if nested_aux {
        let mut expanded = tempfile::tempfile()?;
        super::nested_aux_relocate::rewrite(&mut file, &mut expanded)?;
        file = expanded;
    }
    let mut target_path = options
        .target_path
        .map_or_else(
            || options.bin.canonicalize().unwrap_or_else(|_| options.bin.to_path_buf()),
            std::path::Path::to_path_buf,
        )
        .to_string_lossy()
        .into_owned();
    let (slide, mappings, provenance) = if options.base.is_none() && options.maps.is_none() {
        let (slide, mappings, provenance, recorded_path) =
            super::import_native_mmaps::derive(&mut file, image, pid, &target_path, options.target_path.is_none())?;
        target_path = recorded_path;
        (slide, mappings, provenance)
    } else {
        let mapping_target = if options.maps.is_some() { options.target_path } else { None };
        super::import_maps::resolve(image, options.bin, options.base, options.maps, mapping_target, pid)?
    };
    let PerfFileReader { mut perf_file, mut record_iter } = PerfFileReader::parse_file(BufReader::new(file))?;
    let build_ids = super::import_native_identity::verify_target(&perf_file, image, &target_path)?;
    if intel_pt {
        return super::import_native_pt::run(
            &mut perf_file,
            &mut record_iter,
            image,
            options,
            slide,
            mappings,
            &target_path,
            &build_ids,
            provenance,
        );
    }
    let attrs = perf_file.event_attributes();
    if attrs.is_empty() {
        return Err("native perf.data import requires an event type".into());
    }
    let attr = attrs[0].attr;
    let format = attr.sample_format;
    if !format.contains(SampleFormat::IP | SampleFormat::TID) {
        return Err("perf.data must include sample IP and PID/TID".into());
    }
    let callchain = if format.contains(SampleFormat::REGS_USER | SampleFormat::STACK_USER) {
        "dwarf"
    } else if format.contains(SampleFormat::BRANCH_STACK) {
        "lbr"
    } else if format.contains(SampleFormat::CALLCHAIN) {
        "fp"
    } else {
        "none"
    };
    validate_arch(perf_file.arch()?, callchain)?;
    let event_name = attrs[0].name.clone().unwrap_or_else(|| "unknown".to_owned());
    let header = Header {
        schema_version: 1,
        image_sha256: crate::trace_analysis::index::hex_bytes(&Sha256::digest(&image.data)),
        process_exe_sha256: None,
        binary_match: provenance.to_owned(),
        pie_slide: slide,
        exe_device_major: 0,
        exe_device_minor: 0,
        exe_inode: 1,
        pid,
        starttime_ticks: 0,
        event: format!("perf_data:{event_name}"),
        frequency_hz: None,
        period: None,
        callchain: callchain.to_owned(),
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
    let mut state = NativeState::new(pid, target_path, attr.sample_regs_user, callchain, build_ids);
    state.partial = attrs.len() > 1;
    while let Some(entry) = record_iter.next_record(&mut perf_file)? {
        match entry {
            PerfFileRecord::EventRecord { attr_index, record } => {
                if record.record_type == linux_perf_data::linux_perf_event_reader::RecordType::AUX {
                    state.partial = true;
                    state.aux_ignored = true;
                }
                if attr_index != 0 {
                    continue;
                }
                if record.record_type == RecordType::MMAP2 && record.misc & (1 << 14) != 0 {
                    let bytes = record.data.as_slice();
                    if bytes.get(32).is_none_or(|length| *length > 20) {
                        return Err("invalid perf mmap build ID length".into());
                    }
                }
                let data = super::import_native_read::strip(&record)?;
                let mut normalized = record.clone();
                if let Some(ref data) = data {
                    normalized.data = data.as_slice().into();
                    normalized.parse_info.sample_format.remove(SampleFormat::READ);
                }
                if !state.record(&normalized, &mut writer)? {
                    break;
                }
            }
            PerfFileRecord::UserRecord(record) => {
                if matches!(
                    record.record_type,
                    linux_perf_data::UserRecordType::PERF_AUXTRACE
                        | linux_perf_data::UserRecordType::PERF_AUXTRACE_INFO
                        | linux_perf_data::UserRecordType::PERF_AUXTRACE_ERROR
                ) {
                    state.partial = true;
                    state.aux_ignored = true;
                }
            }
        }
    }
    if state.samples == 0 {
        if intel_pt {
            return Err("Intel PT instruction decoding is not yet available for this recording".into());
        }
        if state.aux_ignored {
            return Err("AUX trace is not decoded and the recording has no regular samples".into());
        }
        return Err("no samples for the selected PID in perf.data".into());
    }
    let reason = final_reason(state.aux_ignored, state.stop_reason);
    writer.finish(state.latest_ns, state.dropped, state.partial, reason, None, 0)?;
    guard.keep = true;
    Ok(())
}

fn final_reason(aux_ignored: bool, reason: &'static str) -> &'static str {
    if !aux_ignored {
        return reason;
    }
    match reason {
        "import_target_exit_boundary" => "import_aux_trace_not_decoded_target_exit_boundary",
        "import_target_exec_boundary" => "import_aux_trace_not_decoded_target_exec_boundary",
        _ => "import_aux_trace_not_decoded",
    }
}

fn snapshot(path: &std::path::Path) -> Result<File, Box<dyn std::error::Error>> {
    const MAX_INPUT: u64 = 16_u64 * 1024 * 1024 * 1024;
    let source = File::open(path)?;
    if source.metadata()?.len() > MAX_INPUT {
        return Err("perf.data exceeds 16 GiB".into());
    }
    // Validate and parse the same private snapshot despite concurrent writers.
    let mut file = tempfile::tempfile()?;
    if std::io::copy(&mut source.take(MAX_INPUT + 1), &mut file)? > MAX_INPUT {
        return Err("perf.data exceeds 16 GiB".into());
    }
    file.seek(SeekFrom::Start(0))?;
    Ok(file)
}

pub(super) fn validate_arch(arch: Option<&str>, callchain: &str) -> Result<(), &'static str> {
    match arch {
        Some("x86_64" | "amd64") => Ok(()),
        Some(_) => Err("perf.data architecture is not x86-64"),
        None if callchain == "dwarf" => Err("perf.data lacks the architecture needed to interpret user registers"),
        None => Ok(()),
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn aux_warning_preserves_target_boundaries() {
        assert_eq!(
            super::final_reason(true, "import_target_exit_boundary"),
            "import_aux_trace_not_decoded_target_exit_boundary"
        );
        assert_eq!(
            super::final_reason(true, "import_target_exec_boundary"),
            "import_aux_trace_not_decoded_target_exec_boundary"
        );
        assert_eq!(super::final_reason(false, "import_target_exit_boundary"), "import_target_exit_boundary");
    }
    #[test]
    fn requires_matching_architecture_for_recorded_registers() {
        assert!(super::validate_arch(Some("x86_64"), "dwarf").is_ok());
        assert!(super::validate_arch(Some("aarch64"), "dwarf").is_err());
        assert!(super::validate_arch(None, "dwarf").is_err());
        assert!(super::validate_arch(None, "fp").is_ok());
    }
}
