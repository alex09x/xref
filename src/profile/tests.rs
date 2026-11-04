/*
 * XRef — sampling profile codec tests
 * Copyright (c) 2026 Alexander Panasenko
 * Contact: alex@prod.codes
 * Author: https://prod.codes/about/
 * Project: https://github.com/alex09x/xref
 * SPDX-License-Identifier: MIT OR Apache-2.0
 */
#![allow(clippy::unwrap_used, clippy::expect_used)] // Controlled fixture and codec test oracles.
use super::aggregate::{Aggregate, Frame, FunctionKey, Limits};
use super::config::{Config, parse_duration};
use super::perf_decode::{
    self, SAMPLE_BRANCH_STACK, SAMPLE_CALLCHAIN, SAMPLE_IP, SAMPLE_PERIOD, SAMPLE_REGS_USER, SAMPLE_STACK_USER,
    SAMPLE_TID, SAMPLE_TIME,
};
use super::{
    codec::{ProfileReader, ProfileWriter},
    types::{Branch, Header, Mapping, Record, Sample},
};
use std::io::Write as _;
use std::io::{self, Cursor};

pub(super) fn header() -> Header {
    Header {
        schema_version: 1,
        image_sha256: "ab".repeat(32),
        process_exe_sha256: Some("ab".repeat(32)),
        binary_match: "verified_sha256".into(),
        pie_slide: 0,
        exe_device_major: 8,
        exe_device_minor: 1,
        exe_inode: 73,
        pid: 42,
        starttime_ticks: 100,
        event: "cycles".to_owned(),
        frequency_hz: Some(4000),
        period: None,
        callchain: "dwarf".to_owned(),
        started_monotonic_ns: 123,
        trigger_static_va: None,
        trigger_window_ns: None,
    }
}

pub(super) fn sample() -> Sample {
    Sample {
        timestamp_ns: 101,
        pid: 42,
        tid: 43,
        cpu_mode: 2,
        ip: 0x1000,
        period: 100,
        registers_mask: 0b101,
        registers: vec![10, 20],
        user_stack: vec![1, 2, 3],
        callchain: vec![0x1000, 0x2000],
        branches: vec![Branch { from: 0x2001, to: 0x1000, flags: 3 }],
    }
}

#[test]
fn profile_stream_round_trips_raw_samples_mappings_and_lifecycle() -> io::Result<()> {
    let records = vec![
        Record::Sample(sample()),
        Record::Mapping(Mapping {
            timestamp_ns: 90,
            pid: 42,
            tid: 43,
            start: 0x1000,
            length: 0x1000,
            file_offset: 0x2000,
            device_major: 8,
            device_minor: 1,
            inode: 73,
            executable: true,
            sha256: Some("cd".repeat(32)),
            path: "/fixture/module".to_owned(),
        }),
        Record::Lost { timestamp_ns: 102, tid: 43, count: 9 },
        Record::Fork { timestamp_ns: 103, pid: 42, tid: 44, parent_pid: 42, parent_tid: 43 },
        Record::Exit { timestamp_ns: 104, pid: 42, tid: 44 },
    ];
    let mut writer = ProfileWriter::new(Vec::new(), &header())?;
    for record in &records {
        writer.write_record(record)?;
    }
    let bytes = writer.finish(105, 0, true, "duration", None, 0)?;
    let mut reader = ProfileReader::new(Cursor::new(bytes))?;
    assert_eq!(reader.header, header());
    for expected in records {
        assert_eq!(reader.read_record()?, Some(expected));
    }
    assert!(
        matches!(reader.read_record()?, Some(Record::End(footer)) if footer.samples == 1 && footer.lost == 9 && footer.partial_coverage && footer.stop_reason == "duration")
    );
    assert_eq!(reader.read_record()?, None);
    Ok(())
}

#[test]
fn profile_stream_rejects_truncation_bad_lengths_and_invalid_samples() -> io::Result<()> {
    let mut writer = ProfileWriter::new(Vec::new(), &header())?;
    writer.write_record(&Record::Sample(sample()))?;
    let bytes = writer.finish(105, 0, true, "duration", None, 0)?;
    let header_only = 12 + u32::from_le_bytes(bytes[8..12].try_into().unwrap()) as usize;
    for end in header_only + 1..bytes.len() {
        let mut reader = ProfileReader::new(Cursor::new(&bytes[..end]))?;
        while let Ok(Some(_)) = reader.read_record() {}
        assert!(reader.read_record().is_err(), "truncation at byte {end} was accepted");
    }
    let mut oversized = bytes;
    oversized[header_only..header_only + 4].copy_from_slice(&u32::MAX.to_le_bytes());
    let mut reader = ProfileReader::new(Cursor::new(oversized))?;
    assert_eq!(reader.read_record().unwrap_err().kind(), io::ErrorKind::InvalidData);
    let mut invalid = sample();
    invalid.registers.pop();
    let mut writer = ProfileWriter::new(Vec::new(), &header())?;
    assert_eq!(writer.write_record(&Record::Sample(invalid)).unwrap_err().kind(), io::ErrorKind::InvalidData);
    Ok(())
}

#[test]
fn aggregation_keeps_unknown_frames_and_counts_recursion_once_per_sample() {
    let key = |module, start| FunctionKey { module, start };
    let target = key(1, Some(0x1000));
    let unknown = key(2, None);
    let frames = vec![
        Frame { function: target, instruction: Some(0x1010) },
        Frame { function: unknown, instruction: None },
        Frame { function: target, instruction: Some(0x1018) },
    ];
    let mut result = Aggregate::new(Limits::default());
    result.add(&frames, 7);
    result.add(&frames, 11);
    result.add_lost(3);
    assert_eq!(result.samples, 2);
    assert_eq!(result.total_period, 18);
    assert_eq!(result.functions[&target].self_samples, 2);
    assert_eq!(result.functions[&target].total_samples, 2);
    assert_eq!(result.functions[&unknown].total_samples, 2);
    assert_eq!(result.instructions[&(target, 0x1010)], 2);
    assert_eq!(result.paths[&vec![target, unknown, target]], 2);
    assert_eq!(result.lost, 3);
    assert!(result.incomplete);
}

#[test]
fn aggregation_exposes_truncation_when_cardinality_is_bounded() {
    let mut result = Aggregate::new(Limits { functions: 1, instructions: 1, paths: 1, depth: 1, path_frames: 1 });
    let frame = |start| Frame { function: FunctionKey { module: 1, start: Some(start) }, instruction: Some(start) };
    result.add(&[frame(1), frame(2)], 1);
    result.add(&[frame(3)], 1);
    assert_eq!(result.samples, 2);
    assert_eq!(result.functions.len(), 1);
    assert_eq!(result.instructions.len(), 1);
    assert_eq!(result.paths.len(), 1);
    assert!(result.incomplete);
}

#[test]
fn perf_sample_layout_preserves_callchains_branches_and_bounded_stack() {
    fn word(bytes: &mut Vec<u8>, value: u64) {
        bytes.extend_from_slice(&value.to_le_bytes());
    }
    let fields = SAMPLE_IP
        | SAMPLE_TID
        | SAMPLE_TIME
        | SAMPLE_PERIOD
        | SAMPLE_CALLCHAIN
        | SAMPLE_BRANCH_STACK
        | SAMPLE_REGS_USER
        | SAMPLE_STACK_USER;
    let mut bytes = Vec::new();
    word(&mut bytes, 0x1000);
    bytes.extend_from_slice(&42_u32.to_le_bytes());
    bytes.extend_from_slice(&43_u32.to_le_bytes());
    word(&mut bytes, 123);
    word(&mut bytes, 456);
    word(&mut bytes, 2);
    word(&mut bytes, 0x1000);
    word(&mut bytes, 0x2000);
    word(&mut bytes, 1);
    word(&mut bytes, 0x2001);
    word(&mut bytes, 0x1000);
    word(&mut bytes, 3);
    word(&mut bytes, 2);
    word(&mut bytes, 10);
    word(&mut bytes, 20);
    word(&mut bytes, 4);
    bytes.extend_from_slice(&[1, 2, 3, 4]);
    word(&mut bytes, 2);
    let sample = perf_decode::decode_sample(&bytes, fields, 0b101).unwrap();
    assert_eq!((sample.pid, sample.tid, sample.ip, sample.period), (42, 43, 0x1000, 456));
    assert_eq!(sample.callchain, vec![0x1000, 0x2000]);
    assert_eq!(sample.branches, vec![Branch { from: 0x2001, to: 0x1000, flags: 3 }]);
    assert_eq!((sample.registers_mask, sample.registers), (0b101, vec![10, 20]));
    assert_eq!(sample.user_stack, vec![1, 2]);
    for end in 0..bytes.len() {
        assert!(
            perf_decode::decode_sample(&bytes[..end], fields, 0b101).is_err(),
            "accepted truncated sample at {end}"
        );
    }
    assert!(perf_decode::decode_sample(&bytes, fields | (1 << 3), 0b101).is_err());
}

#[test]
fn perf_mmap2_keeps_device_inode_and_timestamp_without_guessing_identity() {
    fn dword(bytes: &mut Vec<u8>, value: u32) {
        bytes.extend_from_slice(&value.to_le_bytes());
    }
    fn word(bytes: &mut Vec<u8>, value: u64) {
        bytes.extend_from_slice(&value.to_le_bytes());
    }
    let mut bytes = Vec::new();
    dword(&mut bytes, 42);
    dword(&mut bytes, 43);
    word(&mut bytes, 0x1000);
    word(&mut bytes, 0x2000);
    word(&mut bytes, 0x3000);
    dword(&mut bytes, 8);
    dword(&mut bytes, 1);
    word(&mut bytes, 73);
    word(&mut bytes, 0);
    dword(&mut bytes, 5);
    dword(&mut bytes, 2);
    bytes.extend_from_slice(b"/module\0");
    dword(&mut bytes, 42);
    dword(&mut bytes, 43);
    word(&mut bytes, 123);
    let mapping = perf_decode::decode_mmap2(&bytes, 0, true).unwrap();
    assert_eq!((mapping.pid, mapping.tid, mapping.timestamp_ns), (42, 43, 123));
    assert_eq!((mapping.start, mapping.length, mapping.file_offset), (0x1000, 0x2000, 0x3000));
    assert_eq!((mapping.device_major, mapping.device_minor, mapping.inode), (8, 1, 73));
    assert!(mapping.executable);
    assert_eq!(mapping.path, "/module");
    assert!(mapping.sha256.is_none());
    assert!(perf_decode::decode_mmap2(&bytes, 1 << 14, true).is_err());
    assert!(perf_decode::decode_mmap2(&bytes[..20], 0, true).is_err());
}

#[test]
fn sampled_mapping_attribution_uses_time_device_and_inode() {
    let image =
        crate::image::Image { functions: std::iter::once(0x1000..0x1100).collect(), ..crate::image::Image::default() };
    let mapping = |timestamp_ns, inode, path: &str| Mapping {
        timestamp_ns,
        pid: 42,
        tid: 42,
        start: 0x1000,
        length: 0x100,
        file_offset: 0,
        device_major: 8,
        device_minor: 1,
        inode,
        executable: true,
        sha256: None,
        path: path.to_owned(),
    };
    let index =
        super::resolve::MappingIndex::new(vec![mapping(10, 74, "/other.so"), mapping(0, 73, "/target")], &header());
    let before = index.frame(&image, &header(), 42, 5, 0x1010, false, false);
    let after = index.frame(&image, &header(), 42, 11, 0x1010, false, false);
    assert_eq!(before.function, FunctionKey { module: 1, start: Some(0x1000) });
    assert_eq!(after.function.start, None);
    assert_ne!(after.function.module, 1);
    let ambiguous =
        super::resolve::MappingIndex::new(vec![mapping(0, 73, "/target"), mapping(0, 74, "/other.so")], &header());
    assert_eq!(ambiguous.frame(&image, &header(), 42, 5, 0x1010, false, false).function.module, 0);
}

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
#[test]
fn verified_shared_object_is_symbolized_and_changed_file_is_not() -> Result<(), Box<dyn std::error::Error>> {
    use object::{Object, ObjectSymbol};
    use sha2::{Digest, Sha256};
    use std::{fs, process::Command};
    let nonce = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH)?.as_nanos();
    let dir = std::env::temp_dir().join(format!("xref-profile-dso-{}-{nonce}", std::process::id()));
    fs::create_dir_all(&dir)?;
    let source = dir.join("fixture.c");
    let original = dir.join("original.so");
    let stripped = dir.join("stripped.so");
    fs::write(&source, b"__attribute__((noinline)) unsigned long shared_hot(unsigned long x) { return x * 3 + 1; }\n")?;
    assert!(
        Command::new("cc").args(["-O2", "-fPIC", "-shared"]).arg(&source).arg("-o").arg(&original).status()?.success()
    );
    let bytes = fs::read(&original)?;
    let object = object::File::parse(bytes.as_slice())?;
    let hot = object
        .dynamic_symbols()
        .find(|symbol| symbol.name().ok() == Some("shared_hot"))
        .ok_or("missing symbol")?
        .address();
    assert!(Command::new("objcopy").arg("--strip-all").arg(&original).arg(&stripped).status()?.success());
    let dso_bytes = fs::read(&stripped)?;
    let dso = crate::image::Image::parse(dso_bytes.clone())?;
    let segment = dso
        .metadata
        .load_segments
        .iter()
        .find(|segment| segment.executable && hot >= segment.va && hot < segment.va + segment.mem_size)
        .ok_or("missing executable segment")?;
    let static_base = segment.va & !4095;
    let mapping = Mapping {
        timestamp_ns: 0,
        pid: 42,
        tid: 42,
        start: 0x7000_0000 + static_base,
        length: (segment.mem_size + 8191) & !4095,
        file_offset: segment.file_offset & !4095,
        device_major: 8,
        device_minor: 1,
        inode: 74,
        executable: true,
        sha256: Some(crate::trace_analysis::index::hex_bytes(&Sha256::digest(&dso_bytes))),
        path: stripped.to_string_lossy().into_owned(),
    };
    let runtime_ip = mapping.start + hot - static_base;
    let index = super::resolve::MappingIndex::new(vec![mapping.clone()], &header());
    let frame = index.frame(&crate::image::Image::default(), &header(), 42, 1, runtime_ip, false, false);
    assert_ne!(frame.function.module, 0);
    assert_eq!(frame.function.start, Some(hot));
    assert!(index.modules.iter().any(|module| module.id == frame.function.module && module.symbols_loaded));
    fs::OpenOptions::new().append(true).open(&stripped)?.write_all(b"modified")?;
    let index = super::resolve::MappingIndex::new(vec![mapping], &header());
    let frame = index.frame(&crate::image::Image::default(), &header(), 42, 1, runtime_ip, false, false);
    assert_eq!(frame.function.start, None, "modified library must not be symbolized using stale identity");
    fs::remove_dir_all(dir)?;
    Ok(())
}

#[test]
fn capture_config_rejects_invalid_frequency_duration_and_thread_sets() {
    let mut config = Config::default();
    assert!(config.validate().is_ok());
    config.period = Some(1);
    assert!(config.validate().is_err());
    config.frequency_hz = None;
    assert!(config.validate().is_ok());
    config.tids = vec![7, 7];
    assert!(config.validate().is_err());
    config.tids = vec![0];
    assert!(config.validate().is_err());
    assert_eq!(parse_duration("10s").unwrap().as_millis(), 10_000);
    assert_eq!(parse_duration("200ms").unwrap().as_millis(), 200);
    assert!(parse_duration("0s").is_err());
    assert!(parse_duration("10").is_err());
    assert!(parse_duration("18446744073709551615s").is_err());
}

#[test]
fn flight_recorder_selects_out_of_order_trigger_window_and_reports_loss() {
    let mut flight = super::flight::Flight::new(40, 1_000_000);
    for timestamp in [120, 80, 110, 90, 100, 130] {
        let mut value = sample();
        value.timestamp_ns = timestamp;
        flight.push(value);
    }
    flight.trigger(100);
    assert!(!flight.coverage_gap);
    assert_eq!(
        flight.into_window().iter().map(|sample| sample.timestamp_ns).collect::<Vec<_>>(),
        vec![80, 90, 100, 110, 120]
    );
    let mut limited = super::flight::Flight::new(40, 1);
    limited.trigger(100);
    let mut value = sample();
    value.timestamp_ns = 100;
    limited.push(value);
    assert_eq!(limited.evicted, 1);
    assert!(limited.coverage_gap);
    let mut late = super::flight::Flight::new(40, 1_000_000);
    let mut old = sample();
    old.timestamp_ns = 10;
    late.push(old);
    let mut new = sample();
    new.timestamp_ns = 200;
    late.push(new);
    late.trigger(20);
    assert!(late.coverage_gap, "a late trigger must not claim a complete pre-window");
}
