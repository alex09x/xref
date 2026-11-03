/*
 * XRef — Stage L2 stripped-Rust ELF CFI, caller verification, and stream/TGID integration tests
 * Copyright (c) 2026 Alexander Panasenko
 * Contact: alex@prod.codes
 * Author: https://prod.codes/about/
 * Project: https://github.com/alex09x/xref
 * SPDX-License-Identifier: MIT OR Apache-2.0
 */

use std::collections::BTreeSet;
use std::error::Error;
use std::fs::File;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use iced_x86::{Decoder, DecoderOptions, Instruction, Mnemonic};

use crate::image::Image;
use crate::live::probe::caller::attribute_caller;
use crate::live::probe::trace_parse::StreamingTraceLineBuffer;
use crate::live::probe::tracefs::ProbeRunConfig;
use crate::live::probe::tracefs_stream::{StreamState, build_probe_results, drain_available_nonblocking};
use crate::live::probe::types::{ProbeTargetSpec, UnwindEntryStatus};
use crate::live::probe::validate::{evaluate_unwind_at, validate_probe_targets};
use crate::live::procfs::{LiveSession, load_elf_image};
use crate::live::types::{BinaryMatch, HexAddr, ProcessMeta, RegionEntry, ScanStatus, apply_slide};

type TestResult = Result<(), Box<dyn Error>>;

fn fixture_src() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/live_target_app.rs")
}

fn compile_stripped_linux_elf_if_supported() -> Result<Option<(PathBuf, Image)>, Box<dyn Error>> {
    if !cfg!(target_os = "linux") {
        return Ok(None);
    }
    let nanos = SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos();
    let dir = std::env::temp_dir().join(format!("xref-probe-elf-{}-{nanos}", std::process::id()));
    std::fs::create_dir_all(&dir)?;
    let bin_path = dir.join("live_target_app");

    let rustc = std::env::var("RUSTC").unwrap_or_else(|_| "rustc".to_owned());
    let status = Command::new(rustc)
        .arg("--edition=2021")
        .arg("-C")
        .arg("opt-level=2")
        .arg("-C")
        .arg("strip=symbols")
        .arg(fixture_src())
        .arg("-o")
        .arg(&bin_path)
        .status()?;
    if !status.success() {
        let _ = std::fs::remove_dir_all(&dir);
        return Err("rustc failed to compile stripped live_target_app fixture".into());
    }
    let image = load_elf_image(&bin_path)?;
    Ok(Some((dir, image)))
}

fn build_exec_regions_for_image(image: &Image, slide: i64) -> Vec<RegionEntry> {
    image
        .metadata
        .load_segments
        .iter()
        .filter(|seg| seg.executable && seg.file_size > 0)
        .filter_map(|seg| {
            let start = apply_slide(seg.va, slide)?;
            let end = start.checked_add(seg.mem_size)?;
            Some(RegionEntry {
                start: HexAddr(start),
                end: HexAddr(end),
                perms: "r-xp".to_owned(),
                offset: HexAddr(seg.file_offset),
                dev: "08:01".to_owned(),
                inode: 4242,
                pathname: Some("/tmp/live_target_app".to_owned()),
                vm_flags: Some(vec!["rd".to_owned(), "ex".to_owned(), "mr".to_owned()]),
                is_target_image: true,
                scan_status: ScanStatus::SkippedNonWritable,
            })
        })
        .collect()
}

fn find_function_with_call_and_multibyte_entry(image: &Image) -> Option<(u64, u64, u64, u64)> {
    for func in &image.functions {
        let bytes = image.code(func)?;
        let mut decoder = Decoder::with_ip(64, bytes, func.start, DecoderOptions::NONE);
        let mut instr = Instruction::default();
        let mut mid_pc = None;
        let mut call_pair = None;
        while decoder.can_decode() {
            decoder.decode_out(&mut instr);
            if instr.is_invalid() {
                break;
            }
            if mid_pc.is_none() && instr.len() >= 2 {
                mid_pc = Some(instr.ip() + 1);
            }
            if instr.mnemonic() == Mnemonic::Call
                && let Some(target_fn) = image.function_at(instr.near_branch_target())
                && target_fn.start == instr.near_branch_target()
            {
                call_pair = Some((instr.ip(), instr.next_ip()));
                break;
            }
        }
        if let (Some(mid), Some((call_ip, ret_va))) = (mid_pc, call_pair) {
            return Some((func.start, mid, call_ip, ret_va));
        }
    }
    None
}

#[test]
fn stripped_rust_elf_validates_cfi_entry_mid_insn_and_real_call_sites() -> TestResult {
    let Some((dir, image)) = compile_stripped_linux_elf_if_supported()? else {
        return Ok(());
    };
    let result = verify_stripped_elf_contracts(&dir, image);
    let _ = std::fs::remove_dir_all(&dir);
    result
}

fn verify_stripped_elf_contracts(dir: &Path, image: Image) -> TestResult {
    let slide = 0x5555_5555_0000_i64;
    let regions = build_exec_regions_for_image(&image, slide);
    let (caller_fn_start, mid_insn_va, call_site_va, return_static_va) =
        find_function_with_call_and_multibyte_entry(&image)
            .ok_or("expected stripped Rust binary to contain at least one direct CALL between FDE functions")?;

    // 1. Function entry evaluates effective CIE+FDE row to StandardRsp8RaMinus8 (+0(%sp):x64).
    let (entry_cfi, ra_fetch) = evaluate_unwind_at(&image, caller_fn_start);
    assert_eq!(entry_cfi, UnwindEntryStatus::StandardRsp8RaMinus8);
    assert_eq!(ra_fetch.as_deref(), Some("+0(%sp):x64"));

    // 2. Mid-instruction offset is rejected before touching tracefs.
    let mid_err = validate_probe_targets(&image, slide, &regions, &[mid_insn_va])
        .err()
        .ok_or("expected mid-instruction rejection")?;
    assert!(mid_err.contains("lands mid-instruction"), "unexpected error: {mid_err}");

    // 3. Valid entry address succeeds and resolves file-backed PF_X offset.
    let specs = validate_probe_targets(&image, slide, &regions, &[caller_fn_start])?;
    assert_eq!(specs.len(), 1);
    assert_eq!(specs[0].static_va, caller_fn_start);
    assert_eq!(specs[0].unwind_entry_abi, UnwindEntryStatus::StandardRsp8RaMinus8);

    // 4. Real CALL site attribution recovers exact caller FDE and call_site_static_va.
    let return_runtime_va = apply_slide(return_static_va, slide).ok_or("slide overflow")?;
    let attributed =
        attribute_caller(&image, slide, &regions, &UnwindEntryStatus::StandardRsp8RaMinus8, return_runtime_va, 12);
    assert_eq!(attributed.caller_function, Some(HexAddr(caller_fn_start)));
    assert_eq!(attributed.call_site_static_va, Some(HexAddr(call_site_va)));
    assert!(attributed.call_verified);
    assert_eq!(attributed.hits, 12);

    // 5. Deterministic stream consumer + pthread inclusion + fork-child TGID exclusion test.
    verify_stream_tgid_filter_and_callers(dir, image, slide, regions, &specs, call_site_va, return_runtime_va)
}

fn verify_stream_tgid_filter_and_callers(
    dir: &Path,
    image: Image,
    slide: i64,
    regions: Vec<RegionEntry>,
    specs: &[ProbeTargetSpec],
    expected_call_site: u64,
    return_runtime_va: u64,
) -> TestResult {
    let proc_root = dir.join("mock_proc");
    std::fs::create_dir_all(proc_root.join("5000/task/5000"))?;
    std::fs::create_dir_all(proc_root.join("5000/task/5002"))?;
    std::fs::create_dir_all(proc_root.join("6000"))?;
    std::fs::write(proc_root.join("6000/status"), "Name:\tfork_child\nTgid:\t6000\nPid:\t6000\n")?;

    let prefix = "xp_1122334455667788_";
    let short_ev = "xp_1122334455667788_0";
    let probe_rva = specs[0].runtime_va;
    let pipe_file = dir.join("trace_pipe_sample");
    let sample = format!(
        "# tracer: nop\n\
         main-5000 ( 5000) [000] d..1. 1.0: {short_ev}: ({probe_rva:#x}) ra={return_runtime_va:#x} rdi=0xaa rsi=0xbb rdx=0xcc rcx=0xdd r8=0x11 r9=0x22 rax=0x33 rsp=0x7fff0000\n\
         new-thr-5002 (  -----) [001] d..1. 1.1: {short_ev}: ({probe_rva:#x}) ra={return_runtime_va:#x} rdi=0xef rsi=0xbb rdx=0xcc rcx=0xdd r8=0x11 r9=0x22 rax=0x33 rsp=0x7fff1000\n\
         fork-ch-6000 ( 6000) [002] d..1. 1.2: {short_ev}: ({probe_rva:#x}) ra={return_runtime_va:#x} rdi=0x1 rsi=0x2 rdx=0x3 rcx=0x4 r8=0x5 r9=0x6 rax=0x7 rsp=0x8\n\
         fork-dash-6000 (  -----) [003] d..1. 1.3: {short_ev}: ({probe_rva:#x}) ra={return_runtime_va:#x} rdi=0x1 rsi=0x2 rdx=0x3 rcx=0x4 r8=0x5 r9=0x6 rax=0x7 rsp=0x8\n"
    );
    std::fs::write(&pipe_file, sample)?;

    let mut fd = File::open(&pipe_file)?;
    let mut line_buf = StreamingTraceLineBuffer::default();
    let mut seeded = BTreeSet::new();
    seeded.insert(5000);
    let mut state = StreamState::new(5000, seeded, specs.len());
    let cfg = ProbeRunConfig {
        duration: Duration::from_millis(50),
        max_events: 100,
        want_callers: true,
        want_regs: true,
        spawn_watchdog: false,
    };

    drain_available_nonblocking(&mut fd, &mut line_buf, &mut state, &proc_root, prefix, &cfg);
    assert_eq!(state.total_accepted, 2, "main thread + new sibling thread 5002 must be accepted");
    assert_eq!(state.excluded_other_tgid, 2, "both fork-child 6000 events must be excluded");

    let mut session = LiveSession {
        image,
        process: ProcessMeta {
            pid: 5000,
            starttime_ticks: 999,
            pid_alive_after: true,
            process_changed: false,
            binary_match: BinaryMatch::ProcExeAuto,
            exe_sha256: Some("deadbeef".to_owned()),
            pie_slide: slide,
            warnings: Vec::new(),
        },
        regions,
        #[cfg(target_os = "linux")]
        exe_dev_ino: Some((1, 2)),
    };
    let results = build_probe_results(&mut session, specs, state.accumulators, true);
    assert_eq!(results[0].accepted_hits, 2);
    assert_eq!(results[0].callers.len(), 1);
    assert_eq!(results[0].callers[0].hits, 2);
    assert_eq!(results[0].callers[0].call_site_static_va, Some(HexAddr(expected_call_site)));
    assert!(results[0].callers[0].call_verified);
    assert_eq!(results[0].register_samples.len(), 2);
    assert_eq!(results[0].register_samples[0].rdi, HexAddr(0xaa));
    assert_eq!(results[0].register_samples[1].tid, 5002);
    Ok(())
}
