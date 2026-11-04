/*
 * XRef — Binary analysis
 * Copyright (c) 2026 Alexander Panasenko
 * Contact: alex@prod.codes
 * Author: https://prod.codes/about/
 * Project: https://github.com/alex09x/xref
 * SPDX-License-Identifier: MIT OR Apache-2.0
 */
use super::aggregate::{Aggregate, Frame, FunctionKey, Limits};

#[test]
#[ignore = "performance measurement; run with optimized test profile"]
fn aggregate_million_four_frame_samples() {
    let mut aggregate = Aggregate::new(Limits::default());
    let frames: Vec<_> = (0..4)
        .map(|i| Frame {
            function: FunctionKey { module: 1, start: Some(0x1000 + i * 0x100) },
            instruction: Some(0x1000 + i * 0x100),
        })
        .collect();
    let start = std::time::Instant::now();
    for _ in 0..1_000_000 {
        aggregate.add(std::hint::black_box(&frames), 1);
    }
    let elapsed = start.elapsed();
    assert_eq!(aggregate.samples, 1_000_000);
    assert!(!aggregate.incomplete);
    eprintln!("aggregated 1000000 four-frame samples in {elapsed:?}");
}

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
#[test]
#[ignore = "performance measurement; run with optimized test profile"]
fn analyze_million_samples_against_compiled_elf() -> Result<(), Box<dyn std::error::Error>> {
    use super::codec::ProfileWriter;
    use super::types::{Header, Mapping, Record, Sample};
    use object::{Object, ObjectSymbol};
    use sha2::{Digest, Sha256};
    let nonce = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH)?.as_nanos();
    let dir = std::env::temp_dir().join(format!("xref-prof-bench-{}-{nonce}", std::process::id()));
    std::fs::create_dir_all(&dir)?;
    let binary = dir.join("target");
    let source = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/profile_unwind.S");
    assert!(
        std::process::Command::new("cc")
            .args(["-nostdlib", "-no-pie", "-Wl,-e,profile_leaf"])
            .arg(source)
            .arg("-o")
            .arg(&binary)
            .status()?
            .success()
    );
    let bytes = std::fs::read(&binary)?;
    let file = object::File::parse(bytes.as_slice())?;
    let ip = file
        .symbols()
        .find(|symbol| symbol.name().ok() == Some("profile_leaf"))
        .ok_or("missing fixture function")?
        .address();
    let parent = file
        .symbols()
        .find(|symbol| symbol.name().ok() == Some("profile_parent"))
        .ok_or("missing fixture parent")?
        .address();
    let image = crate::image::Image::load(&binary)?;
    let hash = crate::trace_analysis::index::hex_bytes(&Sha256::digest(&image.data));
    let header = Header {
        schema_version: 1,
        image_sha256: hash.clone(),
        process_exe_sha256: Some(hash),
        binary_match: "verified_sha256".into(),
        pie_slide: 0,
        exe_device_major: 8,
        exe_device_minor: 1,
        exe_inode: 73,
        pid: 42,
        starttime_ticks: 1,
        event: "cycles".into(),
        frequency_hz: Some(4000),
        period: None,
        callchain: "dwarf".into(),
        started_monotonic_ns: 0,
        trigger_static_va: None,
        trigger_window_ns: None,
    };
    let seg = image.metadata.load_segments.iter().find(|segment| segment.executable).ok_or("missing code segment")?;
    let mapping = Mapping {
        timestamp_ns: 0,
        pid: 42,
        tid: 42,
        start: seg.va & !4095,
        length: (seg.mem_size + 8191) & !4095,
        file_offset: seg.file_offset & !4095,
        device_major: 8,
        device_minor: 1,
        inode: 73,
        executable: true,
        sha256: None,
        path: binary.display().to_string(),
    };
    let mut stack = Vec::new();
    stack.extend_from_slice(&(parent + 1).to_le_bytes());
    stack.extend_from_slice(&0_u64.to_le_bytes());
    let sample = Sample {
        timestamp_ns: 1,
        pid: 42,
        tid: 42,
        cpu_mode: 2,
        ip,
        period: 1,
        registers_mask: 1 << 7,
        registers: vec![0x7000],
        user_stack: stack,
        callchain: vec![],
        branches: vec![],
    };
    let mut writer = ProfileWriter::new(Vec::new(), &header)?;
    writer.write_record(&Record::Mapping(mapping))?;
    for _ in 0..1_000_000 {
        writer.write_record(&Record::Sample(sample.clone()))?;
    }
    let bytes = writer.finish(1, 0, false, "complete", None, 0)?;
    let started = std::time::Instant::now();
    let analysis =
        super::analyze::analyze(&mut std::io::Cursor::new(bytes), &image, &std::collections::BTreeSet::new())?;
    eprintln!("analyzed 1000000 recorded CFI samples in {:?}", started.elapsed());
    assert_eq!(analysis.aggregate.samples, 1_000_000);
    assert_eq!(analysis.unresolved_frames, 0);
    assert!(analysis.aggregate.paths.keys().any(|path| path.len() == 2));
    std::fs::remove_dir_all(dir)?;
    Ok(())
}
