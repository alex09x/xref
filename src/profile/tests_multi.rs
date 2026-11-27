/*
 * XRef — Binary analysis
 * Copyright (c) 2026 Alexander Panasenko
 * Contact: alex@prod.codes
 * Author: https://prod.codes/about/
 * Project: https://github.com/alex09x/xref
 * SPDX-License-Identifier: MIT OR Apache-2.0
 */
use super::types::{Header, Mapping, Sample};
use object::{Object, ObjectSymbol};
use sha2::{Digest, Sha256};
use std::{fs, process::Command};

#[test]
#[allow(clippy::too_many_lines)] // Both samples share the one compiled target and shared object.
fn cfi_unwinds_across_verified_shared_object_and_target() -> Result<(), Box<dyn std::error::Error>> {
    let nonce = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH)?.as_nanos();
    let dir = std::env::temp_dir().join(format!("xref-cfi-modules-{}-{nonce}", std::process::id()));
    fs::create_dir_all(&dir)?;
    let source = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/profile_unwind.S");
    let main = dir.join("target");
    let shared = dir.join("module.so");
    assert!(
        Command::new("cc")
            .args(["-nostdlib", "-no-pie", "-Wl,-e,profile_leaf"])
            .arg(&source)
            .arg("-o")
            .arg(&main)
            .status()?
            .success()
    );
    assert!(Command::new("cc").args(["-nostdlib", "-shared"]).arg(&source).arg("-o").arg(&shared).status()?.success());
    let main_bytes = fs::read(&main)?;
    let shared_bytes = fs::read(&shared)?;
    let sym = |bytes: &[u8], name: &str| -> Result<u64, Box<dyn std::error::Error>> {
        let file = object::File::parse(bytes)?;
        Ok(file.symbols().find(|symbol| symbol.name().ok() == Some(name)).ok_or("missing symbol")?.address())
    };
    let parent = sym(&main_bytes, "profile_parent")?;
    let leaf = sym(&shared_bytes, "profile_leaf")?;
    assert!(Command::new("objcopy").args(["--strip-all"]).arg(&main).status()?.success());
    assert!(Command::new("objcopy").args(["--strip-all"]).arg(&shared).status()?.success());
    let image = crate::image::Image::load(&main)?;
    let module = crate::image::Image::load(&shared)?;
    let hash = |bytes: &[u8]| crate::trace_analysis::index::hex_bytes(&Sha256::digest(bytes));
    let header = Header {
        schema_version: 1,
        image_sha256: hash(&image.data),
        process_exe_sha256: Some(hash(&image.data)),
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
    let slide = 0x1000_0000_u64;
    let make_mapping = |image: &crate::image::Image,
                        bias: u64,
                        inode,
                        path: String,
                        sha256: Option<String>|
     -> Result<Mapping, Box<dyn std::error::Error>> {
        let seg = image.metadata.load_segments.iter().find(|seg| seg.executable).ok_or("no code segment")?;
        Ok(Mapping {
            timestamp_ns: 0,
            pid: 42,
            tid: 42,
            start: (seg.va & !4095) + bias,
            length: (seg.mem_size + 8191) & !4095,
            file_offset: seg.file_offset & !4095,
            device_major: 8,
            device_minor: 1,
            inode,
            executable: true,
            sha256,
            path,
        })
    };
    let mappings = vec![
        make_mapping(&image, 0, 73, main.display().to_string(), Some(hash(&image.data)))?,
        make_mapping(&module, slide, 74, shared.display().to_string(), Some(hash(&module.data)))?,
    ];
    let index = super::resolve::MappingIndex::new(mappings, &header);
    let unwinders = index.unwinders(&image, &header);
    let mut stack = Vec::new();
    stack.extend_from_slice(&(parent + 1).to_le_bytes());
    stack.extend_from_slice(&0_u64.to_le_bytes());
    let sample = Sample {
        timestamp_ns: 1,
        pid: 42,
        tid: 42,
        cpu_mode: 2,
        ip: leaf + slide,
        period: 1,
        registers_mask: 1 << 7,
        registers: vec![0x7000],
        user_stack: stack,
        callchain: vec![],
        branches: vec![],
    };
    let result = super::unwind::unwind_with(&sample, 16, |ip, ret| {
        index.unwinder_key(&image, &header, 42, 1, ip, ret).and_then(|key| unwinders.get(&key))
    });
    assert_eq!(result.frames, vec![leaf + slide, parent + 1]);
    assert_eq!(result.stop_reason, "end_of_stack");
    // The same thread sampled in the kernel (a syscall from the leaf): the user stack unwinds from
    // the saved user IP (PERF_REG_X86_IP, bit 8), after the kernel part of the callchain.
    let in_kernel = Sample {
        cpu_mode: 1,
        ip: 0xffff_ffff_8100_0040,
        registers_mask: (1 << 7) | (1 << 8),
        registers: vec![0x7000, leaf + slide],
        callchain: vec![super::analyze::CONTEXT_KERNEL, 0xffff_ffff_8100_0040, 0xffff_ffff_8100_0100],
        ..sample
    };
    assert_eq!(super::unwind::user_ip(&in_kernel), Some(leaf + slide));
    let mut warnings = std::collections::BTreeSet::new();
    let frames = super::analyze::sample_frames(&index, &image, &header, &in_kernel, &unwinders, &mut warnings);
    let modules: Vec<u32> = frames.iter().map(|frame| frame.function.module).collect();
    // Kernel frames first (named when kallsyms is readable), then the shared object's leaf and
    // the target's caller.
    let user = modules.iter().position(|module| *module != 2).ok_or("no user frames")?;
    assert!(user >= 1, "{frames:?}");
    assert_eq!(&modules[user..], &[3, 1], "{frames:?} {warnings:?}");
    fs::remove_dir_all(dir)?;
    Ok(())
}
