/*
 * XRef — Live Linux procfs inspection and xref-aware memory scanning
 * Copyright (c) 2026 Alexander Panasenko
 * Contact: alex@prod.codes
 * Author: https://prod.codes/about/
 * Project: https://github.com/alex09x/xref
 * SPDX-License-Identifier: MIT OR Apache-2.0
 */

use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::{error::Error, io, time::Duration};

use crate::image::{Image, Segment};
use crate::image_format::{LoadSegment, Metadata};
use crate::live::classify::{
    WordMeta, classify_word, file_offset_to_static_va, resolve_address, static_va_to_file_offset,
};
use crate::live::cli::encode_values_le;
use crate::live::memscan::{CHUNK_BYTES, ReadAt, ScanConfig, scan_memory, scan_memory_cancellable};
use crate::live::procfs::verify_binary_bytes;
use crate::live::procparse::{
    MAX_STAT_BYTES, TargetIdentity, compute_pie_slide, parse_maps, parse_smaps_vmflags, parse_stat_starttime,
};
use crate::live::types::{
    BinaryMatch, ContextWordKind, HexAddr, RegionEntry, ResolveDirection, ScanStatus, StopReason,
};

type TestResult = Result<(), Box<dyn Error>>;

struct MockMem {
    base: u64,
    bytes: Vec<u8>,
    eio_range: Option<(u64, u64)>,
}

impl ReadAt for MockMem {
    fn read_at(&self, buf: &mut [u8], offset: u64) -> io::Result<usize> {
        if let Some((bad_start, bad_end)) = self.eio_range {
            if offset >= bad_start && offset < bad_end {
                return Err(io::Error::from_raw_os_error(5));
            }
            if offset < bad_start {
                let until_bad = usize::try_from(bad_start - offset).unwrap_or(buf.len());
                if until_bad < buf.len() {
                    return self.read_slice(&mut buf[..until_bad], offset);
                }
            }
        }
        self.read_slice(buf, offset)
    }
}

impl MockMem {
    fn read_slice(&self, buf: &mut [u8], offset: u64) -> io::Result<usize> {
        let Some(rel) = offset.checked_sub(self.base).and_then(|d| usize::try_from(d).ok()) else {
            return Err(io::Error::from_raw_os_error(14));
        };
        let Some(avail) = self.bytes.get(rel..) else { return Ok(0) };
        let n = avail.len().min(buf.len());
        buf[..n].copy_from_slice(&avail[..n]);
        Ok(n)
    }
}

pub(super) fn make_region(
    start: u64,
    end: u64,
    perms: &str,
    pathname: Option<&str>,
    scan_status: ScanStatus,
) -> RegionEntry {
    RegionEntry {
        start: HexAddr(start),
        end: HexAddr(end),
        perms: perms.to_owned(),
        offset: HexAddr(0),
        dev: "00:00".to_owned(),
        inode: 0,
        pathname: pathname.map(str::to_owned),
        vm_flags: None,
        is_target_image: false,
        scan_status,
    }
}

pub(super) const fn load_seg(
    va: u64,
    file_offset: u64,
    file_size: u64,
    mem_size: u64,
    exec: bool,
    writable: bool,
) -> LoadSegment {
    LoadSegment { va, file_offset, file_size, mem_size, executable: exec, writable }
}

pub(super) fn synthetic_image() -> Image {
    let mut data = vec![0_u8; 0x3000];
    data[0x1000..0x1020].fill(0x90);
    let long_ascii = b"XREF_STATIC_RODATA_PREVIEW_ABCDEFGHIJKLMNOPQRSTUVWXYZ_0123456789\0";
    data[0x2000..0x2000 + long_ascii.len()].copy_from_slice(long_ascii);
    // 47 ASCII bytes followed by 3-byte UTF-8 '€' (0xE2 0x82 0xAC) crossing byte 48 + NUL:
    let mut utf8_edge = Vec::with_capacity(56);
    utf8_edge.extend_from_slice(&[b'U'; 47]);
    utf8_edge.extend_from_slice("€tail\0".as_bytes());
    data[0x2080..0x2080 + utf8_edge.len()].copy_from_slice(&utf8_edge);

    let load_segments = vec![
        load_seg(0x1000, 0x1000, 0x100, 0x100, true, false),
        load_seg(0x2000, 0x2000, 0x200, 0x200, false, false),
        load_seg(0x3000, 0x2200, 0x100, 0x500, false, true),
    ];
    Image {
        data,
        segments: vec![
            Segment { va: 0x1000, offset: 0x1000, size: 0x100 },
            Segment { va: 0x2000, offset: 0x2000, size: 0x200 },
            Segment { va: 0x3000, offset: 0x2200, size: 0x100 },
        ],
        functions: vec![0x1000..0x1020, 0x1040..0x1060],
        pointers: vec![(0x2100, 0x1000), (0x2108, 0x1040), (0x2110, 0x1000), (0x2118, 0x1040), (0x2120, 0x1000)],
        imports: Vec::new(),
        symbols: vec![(0x1000, "alpha_fn".to_owned()), (0x1040, "beta_fn".to_owned())],
        metadata: Metadata {
            base: 0x1000,
            code_ranges: vec![0x1000..0x1080, 0x1080..0x1100],
            load_segments,
            build_id: Some(vec![0xaa, 0xbb, 0xcc, 0xdd]),
            ..Metadata::default()
        },
    }
}

#[test]
fn live_stat_parses_comm_with_spaces_parentheses_and_enforces_limits() -> TestResult {
    let stat = b"4242 (weird (proc) name\nworker (2)) S 100 4242 100 0 -1 4194304 \
                 12 0 1 0 33 11 0 0 20 0 4 0 987654321 4096000 512 18446744073709551615\n";
    assert_eq!(parse_stat_starttime(stat, 4242)?, 987_654_321);
    assert!(parse_stat_starttime(stat, 9999).is_err());
    assert!(parse_stat_starttime(stat, 0).is_err());
    assert!(parse_stat_starttime(b"123 broken stat", 123).is_err());
    assert!(parse_stat_starttime(b"123 (short) R 1 2 3", 123).is_err());
    let oversized = vec![b' '; MAX_STAT_BYTES + 1];
    assert!(parse_stat_starttime(&oversized, 1).is_err());
    Ok(())
}

#[test]
fn live_maps_smaps_strict_gating_deleted_paths_and_slide_consistency() -> TestResult {
    let maps = b"\
555555555000-555555556000 r-xp 00001000 fe:01 777 /opt/my app/bin (deleted)
555555556000-555555557000 r--p 00002000 fe:01 777 /opt/my app/bin (deleted)
555555557000-555555558000 rw-p 00002200 fe:01 777 /opt/my app/bin (deleted)
555555600000-555555620000 rw-p 00000000 00:00 0   [heap]
7f0000000000-7f0000001000 rw-s 00000000 00:1a 99  /dev/shm/shared_seg
7f0000001000-7f0000002000 rw-p 00000000 00:06 12  /dev/mem
7f0000002000-7f0000003000 rw-p 00000000 00:00 0
7f0000003000-7f0000004000 rw-p 00000000 00:00 0
7f0000004000-7f0000005000 rw-p 00000000 fe:01 888 /usr/lib/libother.so
7ffd00000000-7ffd00002000 r--p 00000000 00:00 0   [vvar]
ffffffffff600000-ffffffffff601000 --xp 00000000 00:00 0 [vsyscall]
";
    let smaps = b"\
555555557000-555555558000 rw-p 00002200 fe:01 777 /opt/my app/bin (deleted)\nVmFlags: rd wr mr mw me ac
555555600000-555555620000 rw-p 00000000 00:00 0   [heap]\nVmFlags: rd wr mr mw me ac
7f0000002000-7f0000003000 rw-p 00000000 00:00 0\nVmFlags: rd wr io mr
7f0000004000-7f0000005000 rw-p 00000000 fe:01 888 /usr/lib/libother.so\nVmFlags: rd wr mr mw
";
    let target = TargetIdentity {
        dev_major_minor: Some((0xfe, 0x01)),
        inode: Some(777),
        pathname: Some("/opt/my app/bin".to_owned()),
    };
    let mut regions = parse_maps(maps, Some(smaps), &target)?;
    assert_eq!(regions[0].pathname.as_deref(), Some("/opt/my app/bin (deleted)"));
    assert!(regions[0].is_target_image && regions[1].is_target_image && regions[2].is_target_image);
    let statuses: Vec<ScanStatus> = regions.iter().map(|r| r.scan_status).collect();
    assert_eq!(
        statuses,
        vec![
            ScanStatus::SkippedNonWritable,
            ScanStatus::SkippedNonWritable,
            ScanStatus::ScannableRwp,
            ScanStatus::ScannableRwp,
            ScanStatus::SkippedShared,
            ScanStatus::SkippedDeviceOrSpecial,
            ScanStatus::SkippedVmflags,
            ScanStatus::SkippedMissingVmflags,
            ScanStatus::SkippedUnclassifiedFile,
            ScanStatus::SkippedDeviceOrSpecial,
            ScanStatus::SkippedDeviceOrSpecial,
        ]
    );
    let no_smaps = parse_maps(maps, None, &target)?;
    assert_eq!(no_smaps[3].scan_status, ScanStatus::SkippedMissingVmflags);
    assert!(parse_smaps_vmflags(b"VmFlags: rd wr\n").is_err());
    assert!(parse_smaps_vmflags(b"1000-2000 rw-p 0 00:00 0\nVmFlags: rd\nVmFlags: wr\n").is_err());
    assert!(parse_maps(b"2000-3000 rw-p 0 00:00 0\n1000-2000 rw-p 0 00:00 0\n", None, &target).is_err());
    assert!(parse_maps(b"1000-2000 rwxz 0 00:00 0\n", None, &target).is_err());

    let img = synthetic_image();
    assert_eq!(compute_pie_slide(&img.metadata.load_segments, &mut regions)?, 0x5555_5555_4000);
    let mut bad_regions = regions;
    bad_regions[2].start = HexAddr(0x5555_5559_0000);
    bad_regions[2].end = HexAddr(0x5555_5559_1000);
    assert!(compute_pie_slide(&img.metadata.load_segments, &mut bad_regions).is_err());

    let lld_segs = [
        load_seg(0x0, 0x0, 0x10_480, 0x10_480, false, false),
        load_seg(0x11_480, 0x10_480, 0x40_380, 0x40_380, true, false),
        load_seg(0x52_800, 0x50_800, 0x3_000, 0x5_000, false, true),
    ];
    let lld_maps = b"5564a7c07000-5564a7c18000 r--p 00000000 fe:01 777 /opt/my app/bin\n\
                     5564a7c18000-5564a7c59000 r-xp 00010000 fe:01 777 /opt/my app/bin\n\
                     5564a7c59000-5564a7c5b000 r--p 00050000 fe:01 777 /opt/my app/bin\n\
                     5564a7c5b000-5564a7c5d000 rw-p 00052000 fe:01 777 /opt/my app/bin\n\
                     7f0000100000-7f0000160000 r--p 00000000 fe:01 777 /opt/my app/bin\n";
    let mut lld_regions = parse_maps(lld_maps, None, &target)?;
    assert_eq!(compute_pie_slide(&lld_segs, &mut lld_regions)?, 0x5564_a7c0_7000);
    assert!(lld_regions[0].is_target_image && !lld_regions[4].is_target_image);
    Ok(())
}

#[test]
fn live_pt_load_static_va_file_offset_and_bss_translation() {
    let img = synthetic_image();
    let segs = &img.metadata.load_segments;
    assert_eq!(static_va_to_file_offset(segs, 0x1010), Some((Some(0x1010), false, true)));
    assert_eq!(file_offset_to_static_va(segs, 0x1010), Some(0x1010));
    assert_eq!(static_va_to_file_offset(segs, 0x3050), Some((Some(0x2250), false, false)));
    assert_eq!(file_offset_to_static_va(segs, 0x2250), Some(0x3050));
    assert_eq!(static_va_to_file_offset(segs, 0x3250), Some((None, true, false)));
    assert_eq!(file_offset_to_static_va(segs, 0x2450), None);

    let slide = 0x5555_5555_0000_i64;
    let mut reg =
        make_region(0x5555_5555_1000, 0x5555_5555_4000, "r-xp", Some("/bin/app"), ScanStatus::SkippedNonWritable);
    reg.offset = HexAddr(0x1000);
    reg.is_target_image = true;
    let regions = vec![reg];

    let fwd = resolve_address(&img, slide, &regions, 0x1008);
    assert_eq!(fwd.direction, ResolveDirection::StaticToRuntime);
    assert_eq!(
        (fwd.runtime_va, fwd.function_start, fwd.function_offset),
        (Some(HexAddr(0x5555_5555_1008)), Some(HexAddr(0x1000)), Some(8))
    );
    assert_eq!(fwd.symbol.as_deref(), Some("alpha_fn"));

    let rev = resolve_address(&img, slide, &regions, 0x5555_5555_1008);
    assert_eq!((rev.direction, rev.static_va), (ResolveDirection::RuntimeToStatic, Some(HexAddr(0x1008))));
    let bss = resolve_address(&img, slide, &regions, 0x3250);
    assert!(bss.in_bss && bss.file_offset.is_none());
}

#[test]
fn live_chunk_split_non_bridging_eio_unreadable_window_and_budgets() -> TestResult {
    let img = synthetic_image();
    let base = 0x7000_0000_u64;
    let total_len = CHUNK_BYTES * 2;
    let region = make_region(base, base + u64::try_from(total_len)?, "rw-p", Some("[heap]"), ScanStatus::ScannableRwp);
    let needle = encode_values_le(&[0x1122_3344_5566_7788, 0x99aa_bbcc_ddee_ff00]);
    let mut bytes = vec![0_u8; total_len];
    let gap_start_off = CHUNK_BYTES + 0x1000;
    let gap_end_off = CHUNK_BYTES + 0x2000;
    let (edge_at, split_at, post_eio) = (0_usize, CHUNK_BYTES - 8, gap_end_off);
    bytes[edge_at..edge_at + 16].copy_from_slice(&needle);
    bytes[split_at..split_at + 16].copy_from_slice(&needle);
    // Half-needle immediately before EIO + half-needle immediately after EIO MUST NOT bridge!
    bytes[gap_start_off - 8..gap_start_off].copy_from_slice(&needle[..8]);
    bytes[gap_end_off - 8..gap_end_off].copy_from_slice(&needle[8..]);
    // Real hit right at gap_end_off so its -0x8 context word falls inside the unreadable EIO page:
    bytes[post_eio..post_eio + 16].copy_from_slice(&needle);

    let reader = MockMem {
        base,
        bytes,
        eio_range: Some((base + u64::try_from(gap_start_off)?, base + u64::try_from(gap_end_off)?)),
    };
    let cfg = ScanConfig {
        align: 8,
        before_words: 1,
        after_words: 1,
        max_hits: 32,
        max_bytes: u64::MAX,
        timeout: Duration::from_secs(5),
    };
    let regs = std::slice::from_ref(&region);
    let out = scan_memory(&reader, &img, 0, regs, &needle, &cfg)?;
    assert_eq!((out.stop_reason, out.unreadable_ranges), (StopReason::Complete, 1));
    let hit_vas: Vec<u64> = out.hits.iter().map(|h| h.runtime_va.0).collect();
    assert_eq!(hit_vas, [base, base + u64::try_from(split_at)?, base + u64::try_from(post_eio)?]);
    assert!(out.hits[0].window_truncated, "hit at region start should mark window_truncated");
    assert!(!out.hits[1].window_truncated);
    assert!(out.hits[2].window_truncated, "hit adjacent to EIO page should mark window_truncated");
    assert_eq!(out.hits[2].context[0].kind, ContextWordKind::Unreadable);
    assert!(out.hits[2].context[0].value.is_none());

    let max_h = scan_memory(&reader, &img, 0, regs, &needle, &ScanConfig { max_hits: 2, ..cfg })?;
    assert_eq!((max_h.stop_reason, max_h.hits.len()), (StopReason::MaxHits, 2));
    assert_eq!(
        scan_memory(&reader, &img, 0, regs, &needle, &ScanConfig { max_bytes: 8192, ..cfg })?.stop_reason,
        StopReason::MaxBytes
    );
    assert_eq!(
        scan_memory(&reader, &img, 0, regs, &needle, &ScanConfig { timeout: Duration::ZERO, ..cfg })?.stop_reason,
        StopReason::Timeout
    );
    Ok(())
}

#[test]
fn live_context_word_classifies_candidates_and_utf8_preview_safely() {
    let img = synthetic_image();
    let slide = 0x5555_0000_0000_i64;
    let regions = vec![
        make_region(0x6000_0000, 0x6001_0000, "rw-p", Some("[heap]"), ScanStatus::ScannableRwp),
        make_region(0x7fff_0000, 0x7fff_8000, "rw-p", Some("[stack]"), ScanStatus::ScannableRwp),
        make_region(0x7000_0000, 0x7000_4000, "rw-p", None, ScanStatus::ScannableRwp),
        make_region(0x7100_0000, 0x7100_4000, "r-xp", Some("/lib/libc.so.6"), ScanStatus::SkippedNonWritable),
        make_region(0x7200_0000, 0x7200_4000, "r--p", Some("/lib/libc.so.6"), ScanStatus::SkippedNonWritable),
    ];
    let mk = |value: u64| {
        classify_word(
            &img,
            slide,
            &regions,
            &WordMeta { runtime_va: 0x6000_0100, relative_offset: 0, is_match: false, value },
        )
    };
    let code = mk(0x5555_0000_1008);
    assert_eq!(code.kind, ContextWordKind::CodePtr);
    assert_eq!(
        (code.target_function, code.function_offset, code.symbol.as_deref()),
        (Some(HexAddr(0x1000)), Some(8), Some("alpha_fn"))
    );
    let relro = mk(0x5555_0000_2100);
    assert_eq!((relro.kind, relro.candidate_targets.len()), (ContextWordKind::RelroPtrCandidate, 4));
    let ro = mk(0x5555_0000_2000);
    assert_eq!(ro.kind, ContextWordKind::StaticDataPtr);
    assert!(ro.static_ascii_preview.as_deref().is_some_and(|s| s.len() <= 48 && s.starts_with("XREF_STATIC_RODATA")));
    let ro_utf8 = mk(0x5555_0000_2080);
    assert_eq!(ro_utf8.kind, ContextWordKind::StaticDataPtr);
    assert!(ro_utf8.static_ascii_preview.as_deref().is_some_and(|s| s.len() <= 48 && s.starts_with("UUUU")));
    let heap = mk(0x6000_3fc0);
    assert_eq!((heap.kind, heap.target_region.as_deref()), (ContextWordKind::HeapPtr, Some("[heap]+0x3fc0")));
    assert_eq!(mk(0x7fff_0100).kind, ContextWordKind::StackPtr);
    assert_eq!(mk(0x7000_0080).kind, ContextWordKind::AnonPtr);
    assert_eq!(mk(0x7100_0200).kind, ContextWordKind::ExecMappingPtr);
    assert_eq!(mk(0x7200_0200).kind, ContextWordKind::MappedPtr);
    assert_eq!(mk(0xdead_beef).kind, ContextWordKind::Scalar);
}

#[test]
fn live_verify_binary_bytes_digest_and_force_modes() -> TestResult {
    let img = synthetic_image();
    let (bm_ok, sha_ok, warns_ok) = verify_binary_bytes(&img, &img.data, false)?;
    assert_eq!((bm_ok, sha_ok.len(), warns_ok.is_empty()), (BinaryMatch::VerifiedSha256, 64, true));
    assert!(verify_binary_bytes(&img, b"different bytes", false).is_err());
    let (bm_forced, _, warns_forced) = verify_binary_bytes(&img, b"different bytes", true)?;
    assert_eq!((bm_forced, warns_forced.len()), (BinaryMatch::ForcedMismatch, 1));
    assert_eq!(
        (BinaryMatch::ProcExeAuto.as_str(), BinaryMatch::VerifiedBuildId.as_str()),
        ("proc_exe_auto", "verified_build_id")
    );
    Ok(())
}

#[test]
fn live_memscan_cancel_during_chunk_read_stops_without_hit_context_reads() {
    struct CancelOnFirstRead<'a> {
        cancel: &'a AtomicBool,
        reads: AtomicUsize,
    }
    impl ReadAt for CancelOnFirstRead<'_> {
        fn read_at(&self, buf: &mut [u8], _offset: u64) -> io::Result<usize> {
            self.reads.fetch_add(1, Ordering::Relaxed);
            self.cancel.store(true, Ordering::Relaxed);
            buf.fill(0);
            Ok(buf.len())
        }
    }

    let img = synthetic_image();
    let region = make_region(0x7000_0000, 0x7000_1000, "rw-p", Some("[heap]"), ScanStatus::ScannableRwp);
    let cancel = AtomicBool::new(false);
    let reader = CancelOnFirstRead { cancel: &cancel, reads: AtomicUsize::new(0) };
    let cfg = ScanConfig {
        align: 8,
        before_words: 0,
        after_words: 0,
        max_hits: 64,
        max_bytes: u64::MAX,
        timeout: Duration::from_secs(5),
    };
    let res = scan_memory_cancellable(&reader, &img, 0, &[region], &[0_u8; 8], &cfg, Some(&cancel));
    assert!(res.is_err(), "cancelled memscan must return Err");
    assert_eq!(reader.reads.load(Ordering::Relaxed), 1, "no hit/context read_at calls may run after cancel");
}
