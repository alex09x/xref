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
use std::io::BufReader;

#[allow(clippy::too_many_lines)] // Event import and output cleanup share one transaction.
pub fn run(image: &Image, options: &Options<'_>) -> Result<(), Box<dyn std::error::Error>> {
    let pid = options.pid.filter(|pid| *pid != 0).ok_or("profile import requires a nonzero --pid")?;
    let mapping_target = if options.maps.is_some() { options.target_path } else { None };
    let (slide, mappings, provenance) =
        super::import_maps::resolve(image, options.bin, options.base, options.maps, mapping_target, pid)?;
    let mut file = File::open(options.input)?;
    if file.metadata()?.len() > 16_u64 * 1024 * 1024 * 1024 {
        return Err("perf.data exceeds 16 GiB".into());
    }
    super::import_native_header::validate(&mut file)?;
    let PerfFileReader { mut perf_file, mut record_iter } = PerfFileReader::parse_file(BufReader::new(file))?;
    let target_path = options
        .target_path
        .map_or_else(
            || options.bin.canonicalize().unwrap_or_else(|_| options.bin.to_path_buf()),
            std::path::Path::to_path_buf,
        )
        .to_string_lossy()
        .into_owned();
    let build_ids = super::import_native_identity::verify_target(&perf_file, image, &target_path)?;
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
            PerfFileRecord::UserRecord(_) => {}
        }
    }
    if state.samples == 0 {
        return Err("no samples for the selected PID in perf.data".into());
    }
    writer.finish(state.latest_ns, state.dropped, state.partial, state.stop_reason, None, 0)?;
    guard.keep = true;
    Ok(())
}

fn validate_arch(arch: Option<&str>, callchain: &str) -> Result<(), &'static str> {
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
    fn requires_matching_architecture_for_recorded_registers() {
        assert!(super::validate_arch(Some("x86_64"), "dwarf").is_ok());
        assert!(super::validate_arch(Some("aarch64"), "dwarf").is_err());
        assert!(super::validate_arch(None, "dwarf").is_err());
        assert!(super::validate_arch(None, "fp").is_ok());
    }
}
