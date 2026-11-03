/*
 * XRef — Live Linux procfs inspection and xref-aware memory scanning
 * Copyright (c) 2026 Alexander Panasenko
 * Contact: alex@prod.codes
 * Author: https://prod.codes/about/
 * Project: https://github.com/alex09x/xref
 * SPDX-License-Identifier: MIT OR Apache-2.0
 */

//! Regression tests for Stage L1 review findings (self-mmaps, slide ambiguity, inode strictness,
//! cooperative context-read deadlines, and `.eh_frame`-less ELF live inspection).

use std::error::Error;
use std::io;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use crate::image::Image;
use crate::live::classify::{WordMeta, classify_word, resolve_address};
use crate::live::cli::encode_values_le;
use crate::live::memscan::{ReadAt, ScanConfig, scan_memory};
use crate::live::procfs::parse_elf_image_bytes;
use crate::live::procparse::{TargetIdentity, compute_pie_slide, parse_maps};
use crate::live::tests::{load_seg, make_region, synthetic_image};
use crate::live::types::{ContextWordKind, HexAddr, ResolveDirection, ScanStatus, StopReason};

type TestResult = Result<(), Box<dyn Error>>;

#[test]
fn live_target_identity_rejects_wrong_inode_same_path_and_unverified_paths() -> TestResult {
    let target =
        TargetIdentity { dev_major_minor: Some((8, 1)), inode: Some(11), pathname: Some("/tmp/app".to_owned()) };
    assert!(target.has_verified_file_id());
    assert!(target.matches_region("08:01", 11, Some("/tmp/app")));
    assert!(target.matches_region("08:01", 11, Some("/tmp/app (deleted)")));
    assert!(!target.matches_region("08:01", 22, Some("/tmp/app")));
    assert!(!target.matches_region("08:01", 22, Some("/tmp/app (deleted)")));
    assert!(!target.matches_region("08:02", 11, Some("/tmp/app")));
    assert!(!target.matches_region("00:00", 0, Some("/tmp/app")));

    let replaced_maps = b"\
555555555000-555555556000 r-xp 00001000 08:01 11 /tmp/app (deleted)
7f0000000000-7f0000001000 rw-p 00000000 08:01 22 /tmp/app
";
    let smaps = b"7f0000000000-7f0000001000 rw-p 00000000 08:01 22 /tmp/app\nVmFlags: rd wr mr mw\n";
    let parsed = parse_maps(replaced_maps, Some(smaps), &target)?;
    assert!(parsed[0].is_target_image);
    assert!(!parsed[1].is_target_image);
    assert_eq!(parsed[1].scan_status, ScanStatus::SkippedUnclassifiedFile);

    let path_only = TargetIdentity { dev_major_minor: None, inode: None, pathname: Some("/tmp/app".to_owned()) };
    assert!(!path_only.has_verified_file_id());
    assert!(!path_only.matches_region("08:01", 11, Some("/tmp/app")));
    Ok(())
}

#[test]
fn live_load_bias_ignores_shared_exec_and_writable_additional_self_mmaps() -> TestResult {
    let segs = [
        load_seg(0x0, 0x0, 0x10_480, 0x10_480, false, false),
        load_seg(0x11_480, 0x10_480, 0x40_380, 0x40_380, true, false),
        load_seg(0x52_800, 0x50_800, 0x3_000, 0x5_000, false, true),
    ];
    let maps = b"\
5564a7c07000-5564a7c18000 r--p 00000000 fe:01 777 /opt/app
5564a7c18000-5564a7c59000 r-xp 00010000 fe:01 777 /opt/app
5564a7c59000-5564a7c5b000 r--p 00050000 fe:01 777 /opt/app
5564a7c5b000-5564a7c5d000 rw-p 00052000 fe:01 777 /opt/app
7f0000100000-7f0000101000 r--p 00000000 fe:01 777 /opt/app
7f0000200000-7f0000201000 r--s 00000000 fe:01 777 /opt/app
7f0000300000-7f0000301000 r-xp 00000000 fe:01 777 /opt/app
7f0000400000-7f0000401000 r-xp 00010000 fe:01 777 /opt/app
7f0000500000-7f0000501000 rw-p 00052000 fe:01 777 /opt/app
";
    let smaps = b"\
5564a7c5b000-5564a7c5d000 rw-p 00052000 fe:01 777 /opt/app\nVmFlags: rd wr mr mw me ac
7f0000500000-7f0000501000 rw-p 00052000 fe:01 777 /opt/app\nVmFlags: rd wr mr mw me ac
";
    let target = TargetIdentity { dev_major_minor: Some((0xfe, 1)), inode: Some(777), pathname: None };
    let mut regions = parse_maps(maps, Some(smaps), &target)?;
    let slide = compute_pie_slide(&segs, &mut regions)?;
    assert_eq!(slide, 0x5564_a7c0_7000);
    assert!(regions[0..4].iter().all(|r| r.is_target_image));
    assert!(regions[4..9].iter().all(|r| !r.is_target_image));
    assert_eq!(regions[3].scan_status, ScanStatus::ScannableRwp);
    assert_eq!(regions[8].scan_status, ScanStatus::SkippedUnclassifiedFile);
    Ok(())
}

#[test]
fn live_load_bias_rejects_ambiguous_candidate_slides() -> TestResult {
    let target = TargetIdentity { dev_major_minor: Some((8, 1)), inode: Some(42), pathname: None };
    let two_nonexec =
        [load_seg(0x1000, 0x0, 0x1000, 0x1000, false, false), load_seg(0x2000, 0x0, 0x1000, 0x1000, false, false)];

    let single_map = b"00007000-00008000 r--p 00000000 08:01 42 /tmp/ambig\n";
    let mut partial_regs = parse_maps(single_map, None, &target)?;
    let Err(err_partial) = compute_pie_slide(&two_nonexec, &mut partial_regs) else {
        return Err("expected partial load bias ambiguity error".into());
    };
    assert!(err_partial.contains("ambiguous"), "expected ambiguity error, got: {err_partial}");

    let triple_map = b"\
00007000-00008000 r--p 00000000 08:01 42 /tmp/ambig
00008000-00009000 r--p 00000000 08:01 42 /tmp/ambig
00009000-0000a000 r--p 00000000 08:01 42 /tmp/ambig
";
    let mut full_regs = parse_maps(triple_map, None, &target)?;
    let Err(err_full) = compute_pie_slide(&two_nonexec, &mut full_regs) else {
        return Err("expected full load bias ambiguity error".into());
    };
    assert!(err_full.contains("ambiguous"), "expected ambiguity error, got: {err_full}");
    Ok(())
}

struct SlowZeroMem {
    delay: Duration,
    fail_window_reads_above: usize,
    calls: AtomicUsize,
}

impl ReadAt for SlowZeroMem {
    fn read_at(&self, buf: &mut [u8], _offset: u64) -> io::Result<usize> {
        let call_no = self.calls.fetch_add(1, Ordering::SeqCst) + 1;
        std::thread::sleep(self.delay);
        if call_no > 1 && buf.len() > self.fail_window_reads_above {
            return Err(io::Error::from_raw_os_error(5));
        }
        buf.fill(0);
        Ok(buf.len())
    }
}

#[test]
fn live_memscan_enforces_cooperative_deadline_across_hits_and_context_reads() -> TestResult {
    let img = synthetic_image();
    let region = make_region(0x7000_0000, 0x7001_0000, "rw-p", Some("[heap]"), ScanStatus::ScannableRwp);
    let needle = encode_values_le(&[0]);

    // 1. Exact reviewer scenario: 10ms per read, 25ms timeout, max_hits=8 -> stops on Timeout, never reaches 8 hits.
    let slow = SlowZeroMem {
        delay: Duration::from_millis(10),
        fail_window_reads_above: usize::MAX,
        calls: AtomicUsize::new(0),
    };
    let cfg = ScanConfig {
        align: 8,
        before_words: 0,
        after_words: 0,
        max_hits: 8,
        max_bytes: u64::MAX,
        timeout: Duration::from_millis(25),
    };
    let out = scan_memory(&slow, &img, 0, std::slice::from_ref(&region), &needle, &cfg)?;
    assert_eq!(out.stop_reason, StopReason::Timeout);
    assert!(out.hits.len() < 8, "expected early timeout before max_hits=8, got {} hits", out.hits.len());
    assert!(
        slow.calls.load(Ordering::SeqCst) <= 4,
        "unexpected extra post-deadline reads: {}",
        slow.calls.load(Ordering::SeqCst)
    );

    // 2. Fallback word-by-word context read hits deadline mid-window -> preserves hit & marks window_truncated.
    let slow_fb =
        SlowZeroMem { delay: Duration::from_millis(10), fail_window_reads_above: 8, calls: AtomicUsize::new(0) };
    let fb_cfg = ScanConfig { before_words: 2, after_words: 2, timeout: Duration::from_millis(25), ..cfg };
    let fb_out = scan_memory(&slow_fb, &img, 0, std::slice::from_ref(&region), &needle, &fb_cfg)?;
    assert_eq!(fb_out.stop_reason, StopReason::Timeout);
    assert_eq!(fb_out.hits.len(), 1);
    assert!(fb_out.hits[0].window_truncated);
    assert!(fb_out.hits[0].context.iter().any(|w| w.kind == ContextWordKind::Unreadable));
    Ok(())
}

fn minimal_elf64_without_eh_frame() -> Vec<u8> {
    let mut b = vec![0_u8; 128];
    b[0..4].copy_from_slice(b"\x7fELF");
    b[4] = 2;
    b[5] = 1;
    b[6] = 1;
    b[16..18].copy_from_slice(&3_u16.to_le_bytes());
    b[18..20].copy_from_slice(&62_u16.to_le_bytes());
    b[20..24].copy_from_slice(&1_u32.to_le_bytes());
    b[24..32].copy_from_slice(&0x1078_u64.to_le_bytes());
    b[32..40].copy_from_slice(&64_u64.to_le_bytes());
    b[52..54].copy_from_slice(&64_u16.to_le_bytes());
    b[54..56].copy_from_slice(&56_u16.to_le_bytes());
    b[56..58].copy_from_slice(&1_u16.to_le_bytes());
    b[64..68].copy_from_slice(&1_u32.to_le_bytes());
    b[68..72].copy_from_slice(&5_u32.to_le_bytes());
    b[80..88].copy_from_slice(&0x1000_u64.to_le_bytes());
    b[88..96].copy_from_slice(&0x1000_u64.to_le_bytes());
    b[96..104].copy_from_slice(&128_u64.to_le_bytes());
    b[104..112].copy_from_slice(&128_u64.to_le_bytes());
    b[112..120].copy_from_slice(&0x1000_u64.to_le_bytes());
    b[0x78] = 0xc3;
    b
}

#[test]
fn live_loader_accepts_elf_without_eh_frame_while_static_parser_stays_strict() -> TestResult {
    let raw = minimal_elf64_without_eh_frame();
    assert!(Image::parse(raw.clone()).is_err(), "static Image::parse must still require .eh_frame");

    let live_img = parse_elf_image_bytes(raw)?;
    assert!(live_img.functions.is_empty());
    assert!(live_img.metadata.warnings.contains(&"missing_eh_frame"));
    assert_eq!(live_img.metadata.load_segments.len(), 1);

    let slide = 0x5555_5555_0000_i64;
    let mut rx =
        make_region(0x5555_5555_1000, 0x5555_5555_2000, "r-xp", Some("/bin/noeh"), ScanStatus::SkippedNonWritable);
    rx.is_target_image = true;
    let regions = [rx];

    let resolved = resolve_address(&live_img, slide, &regions, 0x5555_5555_1078);
    assert_eq!((resolved.direction, resolved.static_va), (ResolveDirection::RuntimeToStatic, Some(HexAddr(0x1078))));
    assert!(resolved.executable && resolved.function_start.is_none());

    let word = classify_word(
        &live_img,
        slide,
        &regions,
        &WordMeta { runtime_va: 0x6000, relative_offset: 0, is_match: false, value: 0x5555_5555_1078 },
    );
    assert_eq!(
        (word.kind, word.static_va, word.target_function),
        (ContextWordKind::CodePtr, Some(HexAddr(0x1078)), None)
    );
    Ok(())
}
