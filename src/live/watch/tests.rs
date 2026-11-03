/*
 * XRef — Stage L3 unit tests for hardware watchpoint validation, trap IP attribution, and decoding
 * Copyright (c) 2026 Alexander Panasenko
 * Contact: alex@prod.codes
 * Author: https://prod.codes/about/
 * Project: https://github.com/alex09x/xref
 * SPDX-License-Identifier: MIT OR Apache-2.0
 */

use std::collections::BTreeSet;
use std::error::Error;
use std::io;

use iced_x86::{Decoder, DecoderOptions};

use crate::image::Image;
use crate::live::cli::{LiveCommand, LiveSubcommand, WatchAccessMode, WatchLen, parse_watch_len};
use crate::live::memscan::ReadAt;
use crate::live::probe::perf_ring::{
    PERF_RECORD_SAMPLE, PERF_SAMPLE_IP, PERF_SAMPLE_REGS_ABI_64, PERF_SAMPLE_TID, PERF_SAMPLE_TIME,
};
use crate::live::procfs::LiveSession;
use crate::live::types::{BinaryMatch, HexAddr, ProcessMeta, RegionEntry, ScanStatus};
use crate::live::watch::{
    build_watch_results,
    perf::{DecodedWatchRecord, PERF_SAMPLE_REGS_INTR, XREF_WATCH_INTR_REGS_MASK, decode_watch_record},
    perf_stream::{WatchDrainCtx, process_decoded_watch_record},
    types::{WatchRegsSnapshot, WriterConfidence, WrittenValueRecovery},
    validate::{validate_session_for_watch, validate_watch_targets},
    writer::{attribute_watch_trap, recover_store_value},
};

type TestResult = Result<(), Box<dyn Error>>;

struct FakeMem {
    base: u64,
    bytes: Vec<u8>,
}

impl ReadAt for FakeMem {
    fn read_at(&self, buf: &mut [u8], offset: u64) -> io::Result<usize> {
        let Some(rel) = offset.checked_sub(self.base).and_then(|v| usize::try_from(v).ok()) else {
            return Err(io::Error::from_raw_os_error(5));
        };
        let Some(end) = rel.checked_add(buf.len()) else {
            return Err(io::Error::from_raw_os_error(5));
        };
        let Some(slice) = self.bytes.get(rel..end) else {
            return Err(io::Error::from_raw_os_error(5));
        };
        buf.copy_from_slice(slice);
        Ok(buf.len())
    }
}

fn sample_regions() -> Vec<RegionEntry> {
    vec![
        RegionEntry {
            start: HexAddr(0x7f00_0000_0000),
            end: HexAddr(0x7f00_0001_0000),
            perms: "rw-p".to_owned(),
            offset: HexAddr(0),
            dev: "00:00".to_owned(),
            inode: 0,
            pathname: Some("[heap]".to_owned()),
            vm_flags: Some(vec!["rd".to_owned(), "wr".to_owned(), "mr".to_owned()]),
            is_target_image: false,
            scan_status: ScanStatus::ScannableRwp,
        },
        RegionEntry {
            start: HexAddr(0x5555_5555_0000),
            end: HexAddr(0x5555_5556_0000),
            perms: "r--p".to_owned(),
            offset: HexAddr(0),
            dev: "08:01".to_owned(),
            inode: 100,
            pathname: Some("/tmp/app".to_owned()),
            vm_flags: Some(vec!["rd".to_owned()]),
            is_target_image: true,
            scan_status: ScanStatus::SkippedNonWritable,
        },
    ]
}

fn minimal_elf64_image() -> Result<Image, Box<dyn Error>> {
    let mut elf = vec![0_u8; 8192];
    elf[0..4].copy_from_slice(b"\x7fELF");
    elf[4] = 2; // 64-bit
    elf[5] = 1; // little-endian
    elf[6] = 1; // version
    elf[16..18].copy_from_slice(&2_u16.to_le_bytes()); // ET_EXEC
    elf[18..20].copy_from_slice(&0x3e_u16.to_le_bytes()); // EM_X86_64
    elf[20..24].copy_from_slice(&1_u32.to_le_bytes());
    elf[24..32].copy_from_slice(&0x0040_1000_u64.to_le_bytes()); // e_entry
    elf[32..40].copy_from_slice(&64_u64.to_le_bytes()); // e_phoff
    elf[52..54].copy_from_slice(&64_u16.to_le_bytes()); // e_ehsize
    elf[54..56].copy_from_slice(&56_u16.to_le_bytes()); // e_phentsize
    elf[56..58].copy_from_slice(&1_u16.to_le_bytes()); // e_phnum

    // PT_LOAD (PF_R | PF_X) at file offset 0, vaddr 0x0040_0000, size 8192
    let ph = &mut elf[64..120];
    ph[0..4].copy_from_slice(&1_u32.to_le_bytes()); // PT_LOAD
    ph[4..8].copy_from_slice(&5_u32.to_le_bytes()); // PF_R | PF_X
    ph[8..16].copy_from_slice(&0_u64.to_le_bytes()); // p_offset
    ph[16..24].copy_from_slice(&0x0040_0000_u64.to_le_bytes()); // p_vaddr
    ph[24..32].copy_from_slice(&0x0040_0000_u64.to_le_bytes()); // p_paddr
    ph[32..40].copy_from_slice(&8192_u64.to_le_bytes()); // p_filesz
    ph[40..48].copy_from_slice(&8192_u64.to_le_bytes()); // p_memsz
    ph[48..56].copy_from_slice(&4096_u64.to_le_bytes()); // p_align

    // Function at 0x0040_1000:
    // 0x0040_1000: 48 89 37          mov [rdi], rsi
    // 0x0040_1003: c7 07 78 56 34 12 mov dword ptr [rdi], 0x12345678
    // 0x0040_1009: c3                ret
    let code = [0x48_u8, 0x89, 0x37, 0xc7, 0x07, 0x78, 0x56, 0x34, 0x12, 0xc3];
    elf[0x1000..0x1000 + code.len()].copy_from_slice(&code);
    let mut img = Image::parse_for_live(elf)?;
    img.functions.push(0x0040_1000..0x0040_100a);
    Ok(img)
}

#[test]
fn validate_watch_targets_enforces_dr0_dr3_cap_alignment_and_writable_perms() -> TestResult {
    let image = minimal_elf64_image()?;
    let regions = sample_regions();
    let mem = FakeMem { base: 0x7f00_0000_0000, bytes: 0xdead_beef_cafe_babe_u64.to_le_bytes().to_vec() };

    // 1. Valid 8-byte aligned address in rw-p region succeeds and captures initial snapshot.
    let specs = validate_watch_targets(
        &image,
        0,
        &regions,
        &[0x7f00_0000_0000],
        WatchLen::B8,
        WatchAccessMode::Write,
        Some(&mem),
    )?;
    assert_eq!(specs.len(), 1);
    assert_eq!(specs[0].initial_snapshot, Some(HexAddr(0xdead_beef_cafe_babe)));

    // 2. Unaligned 8-byte watch fails.
    let err_align =
        validate_watch_targets(&image, 0, &regions, &[0x7f00_0000_0004], WatchLen::B8, WatchAccessMode::Write, None)
            .err()
            .ok_or("expected unaligned error")?;
    assert!(err_align.contains("unaligned_watch_address"), "{err_align}");

    // 3. Write watch on r--p region fails unless access is rw.
    let err_ro =
        validate_watch_targets(&image, 0, &regions, &[0x5555_5555_0000], WatchLen::B8, WatchAccessMode::Write, None)
            .err()
            .ok_or("expected non_writable_watch_region")?;
    assert!(err_ro.contains("non_writable_watch_region"), "{err_ro}");

    let ok_rw =
        validate_watch_targets(&image, 0, &regions, &[0x5555_5555_0000], WatchLen::B8, WatchAccessMode::Rw, None)?;
    assert_eq!(ok_rw.len(), 1);

    // 4. >4 targets rejected (DR0..DR3 hardware limit).
    let err_cap = validate_watch_targets(
        &image,
        0,
        &regions,
        &[0x7f00_0000_0000, 0x7f00_0000_0008, 0x7f00_0000_0010, 0x7f00_0000_0018, 0x7f00_0000_0020],
        WatchLen::B8,
        WatchAccessMode::Write,
        None,
    )
    .err()
    .ok_or("expected >4 cap rejection")?;
    assert!(err_cap.contains("DR0..DR3"), "{err_cap}");
    Ok(())
}

#[test]
fn recover_store_value_decodes_register_and_immediate_moves() {
    // mov [rdi], rsi (48 89 37); mov dword ptr [rdi], 0x12345678 (c7 07 78 56 34 12)
    let bytes = [0x48_u8, 0x89, 0x37, 0xc7, 0x07, 0x78, 0x56, 0x34, 0x12];
    let mut dec = Decoder::with_ip(64, &bytes, 0x0040_1000, DecoderOptions::NONE);
    let insn_reg = dec.decode();
    let insn_imm = dec.decode();

    let regs = WatchRegsSnapshot {
        rax: HexAddr(0),
        rbx: HexAddr(0),
        rcx: HexAddr(0),
        rdx: HexAddr(0),
        rsi: HexAddr(0x0102_0304_0506_0708),
        rdi: HexAddr(0x7f00_0000_0000),
        rbp: HexAddr(0),
        rsp: HexAddr(0),
        r8: HexAddr(0),
        r9: HexAddr(0),
        r10: HexAddr(0),
        r11: HexAddr(0),
        r12: HexAddr(0),
        r13: HexAddr(0),
        r14: HexAddr(0),
        r15: HexAddr(0),
    };

    assert_eq!(
        recover_store_value(&insn_reg, Some(&regs)),
        WrittenValueRecovery::ProvenRegisterStore {
            register: "rsi",
            width_bytes: 8,
            value: HexAddr(0x0102_0304_0506_0708),
        }
    );
    assert_eq!(
        recover_store_value(&insn_imm, Some(&regs)),
        WrittenValueRecovery::ProvenImmediateStore { width_bytes: 4, value: HexAddr(0x1234_5678) }
    );
}

#[test]
fn decode_and_attribute_watch_sample_recovers_preceding_store_and_snapshots() -> TestResult {
    let image = minimal_elf64_image()?;
    let mut regions = sample_regions();
    regions.push(RegionEntry {
        start: HexAddr(0x0040_0000),
        end: HexAddr(0x0040_2000),
        perms: "r-xp".to_owned(),
        offset: HexAddr(0),
        dev: "08:01".to_owned(),
        inode: 100,
        pathname: Some("/tmp/app".to_owned()),
        vm_flags: Some(vec!["rd".to_owned(), "ex".to_owned()]),
        is_target_image: true,
        scan_status: ScanStatus::SkippedNonWritable,
    });

    let mem_before = FakeMem { base: 0x7f00_0000_0000, bytes: 10_u64.to_le_bytes().to_vec() };
    let specs = validate_watch_targets(
        &image,
        0,
        &regions,
        &[0x7f00_0000_0000],
        WatchLen::B8,
        WatchAccessMode::Write,
        Some(&mem_before),
    )?;

    let sample_type = PERF_SAMPLE_IP | PERF_SAMPLE_TID | PERF_SAMPLE_TIME | PERF_SAMPLE_REGS_INTR;
    let mut payload = Vec::new();
    // trap_ip = 0x0040_1003 (instruction immediately after `mov [rdi], rsi` at 0x0040_1000)
    payload.extend_from_slice(&0x0040_1003_u64.to_le_bytes());
    payload.extend_from_slice(&4242_u32.to_le_bytes()); // tgid
    payload.extend_from_slice(&4243_u32.to_le_bytes()); // tid
    payload.extend_from_slice(&999_000_u64.to_le_bytes()); // timestamp_ns
    payload.extend_from_slice(&PERF_SAMPLE_REGS_ABI_64.to_le_bytes());
    // 16 GPRs in ascending perf bit order: AX, BX, CX, DX, SI, DI, BP, SP, R8..R15
    for idx in 0..16_u64 {
        let val = match idx {
            4 => 777_u64,          // RSI (value stored)
            5 => 0x7f00_0000_0000, // RDI (effective address matching watched slot)
            _ => idx,
        };
        payload.extend_from_slice(&val.to_le_bytes());
    }

    let decoded = decode_watch_record(PERF_RECORD_SAMPLE, 0, &payload, sample_type, XREF_WATCH_INTR_REGS_MASK);
    assert!(matches!(decoded, Ok(DecodedWatchRecord::Sample(_))));

    let mut ctx =
        WatchDrainCtx::new(4242, sample_type, XREF_WATCH_INTR_REGS_MASK, true, &specs, BTreeSet::from([4242, 4243]));
    process_decoded_watch_record(&image, 0, &regions, 0, decoded, &mut ctx, 64);

    let mem_after = FakeMem { base: 0x7f00_0000_0000, bytes: 777_u64.to_le_bytes().to_vec() };
    let results = build_watch_results(&specs, ctx.accumulators, Some(&mem_after));
    assert_eq!(results.len(), 1);
    let r = &results[0];
    assert_eq!(r.accepted_hits, 1);
    assert_eq!(r.initial_snapshot, Some(HexAddr(10)));
    assert_eq!(r.latest_snapshot, Some(HexAddr(777)));
    assert_eq!(r.snapshot_changed, Some(true));
    assert_eq!(r.writer_sites.len(), 1);
    assert_eq!(r.writer_sites[0].trap_static_ip, Some(HexAddr(0x0040_1003)));
    assert_eq!(r.writer_sites[0].candidate_writer_static_ip, Some(HexAddr(0x0040_1000)));
    assert_eq!(r.writer_sites[0].writer_function, Some(HexAddr(0x0040_1000)));
    assert_eq!(r.writer_sites[0].confidence, WriterConfidence::VerifiedLinearPredecessorStore);
    assert_eq!(
        r.samples[0].written_value,
        WrittenValueRecovery::ProvenRegisterStore { register: "rsi", width_bytes: 8, value: HexAddr(777) }
    );
    Ok(())
}

#[test]
fn parse_watch_cli_validates_flags_and_dr0_dr3_cap() {
    assert_eq!(parse_watch_len("1"), Ok(WatchLen::B1));
    assert_eq!(parse_watch_len("2"), Ok(WatchLen::B2));
    assert_eq!(parse_watch_len("4"), Ok(WatchLen::B4));
    assert_eq!(parse_watch_len("8"), Ok(WatchLen::B8));
    let err_len = parse_watch_len("3").err().unwrap_or_default();
    assert!(err_len.contains("invalid --len 3"), "err: {err_len}");

    let make_watch = |pid: u32, duration_ms: u64, addrs: Vec<u64>| LiveCommand {
        subcommand: LiveSubcommand::Watch {
            pid,
            len: WatchLen::B8,
            access: WatchAccessMode::Write,
            regs: false,
            duration_ms,
            max_events: 4096,
            force_bin: false,
            json: false,
            addrs,
        },
    };
    let err_pid = make_watch(0, 1000, vec![0x7f00_0000_0000]).validate().err().unwrap_or_default();
    assert!(err_pid.contains("invalid --pid 0"), "err: {err_pid}");

    let err_cap =
        make_watch(1, 1000, vec![0x1000, 0x1008, 0x1010, 0x1018, 0x1020]).validate().err().unwrap_or_default();
    assert!(err_cap.contains("DR0..DR3"), "err: {err_cap}");

    let err_dur = make_watch(1, 0, vec![0x7f00_0000_0000]).validate().err().unwrap_or_default();
    assert!(err_dur.contains("--duration-ms 0"), "err: {err_dur}");
}

#[test]
fn counterexamples_call_boundary_cmp_read_and_forced_image_are_rejected() -> TestResult {
    let mut image = minimal_elf64_image()?;
    // Overwrite 0x0040_1000..0x0040_1008 with:
    // FDE A (0x0040_1000..0x0040_1003): 48 89 07 (mov [rdi], rax)
    // FDE B (0x0040_1003..0x0040_1007): 48 39 07 (cmp [rdi], rax); c3 (ret)
    image.data[0x1000..0x1007].copy_from_slice(&[0x48, 0x89, 0x07, 0x48, 0x39, 0x07, 0xc3]);
    image.functions = vec![0x0040_1000..0x0040_1003, 0x0040_1003..0x0040_1007];

    let mut regions = sample_regions();
    regions.push(RegionEntry {
        start: HexAddr(0x0040_0000),
        end: HexAddr(0x0040_2000),
        perms: "r-xp".to_owned(),
        offset: HexAddr(0),
        dev: "08:01".to_owned(),
        inode: 100,
        pathname: Some("/tmp/app".to_owned()),
        vm_flags: Some(vec!["rd".to_owned(), "ex".to_owned()]),
        is_target_image: true,
        scan_status: ScanStatus::SkippedNonWritable,
    });
    let specs =
        validate_watch_targets(&image, 0, &regions, &[0x7f00_0000_0000], WatchLen::B8, WatchAccessMode::Rw, None)?;
    let regs = WatchRegsSnapshot {
        rax: HexAddr(0x1111),
        rbx: HexAddr(0),
        rcx: HexAddr(0),
        rdx: HexAddr(0),
        rsi: HexAddr(0),
        rdi: HexAddr(0x7f00_0000_0000),
        rbp: HexAddr(0),
        rsp: HexAddr(0x7f00_0000_0000),
        r8: HexAddr(0),
        r9: HexAddr(0),
        r10: HexAddr(0),
        r11: HexAddr(0),
        r12: HexAddr(0),
        r13: HexAddr(0),
        r14: HexAddr(0),
        r15: HexAddr(0),
    };
    // 1. P1: trap at FDE B entry (0x0040_1003) after CALL stack write must NOT attribute to FDE A.
    let attr_call = attribute_watch_trap(&image, 0, &regions, &specs[0], 0x0040_1003, Some(&regs));
    assert_eq!(attr_call.confidence, WriterConfidence::AmbiguousBranchTarget);
    assert_eq!(attr_call.candidate_writer_static_ip, None);
    assert!(matches!(attr_call.written_value, WrittenValueRecovery::Unknown { .. }));

    // 2. P2: trap at 0x0040_1006 after `cmp [rdi], rax` must classify as Read, NOT Store.
    let attr_cmp = attribute_watch_trap(&image, 0, &regions, &specs[0], 0x0040_1006, Some(&regs));
    assert_eq!(attr_cmp.confidence, WriterConfidence::VerifiedLinearPredecessorRead);
    assert_eq!(attr_cmp.candidate_writer_static_ip, Some(0x0040_1003));
    assert_eq!(attr_cmp.written_value, WrittenValueRecovery::Unknown { reason: "read_only_memory_access_not_a_store" });

    // 3. P2: ForcedMismatch session must be rejected by validate_session_for_watch.
    let bad_session = LiveSession {
        image,
        process: ProcessMeta {
            pid: 99,
            starttime_ticks: 123,
            pid_alive_after: true,
            process_changed: false,
            binary_match: BinaryMatch::ForcedMismatch,
            exe_sha256: None,
            pie_slide: 0,
            warnings: vec!["forced_binary_mismatch".to_owned()],
        },
        regions,
        #[cfg(target_os = "linux")]
        exe_dev_ino: Some((1, 2)),
    };
    let err_force = validate_session_for_watch(&bad_session).err().ok_or("expected ForcedMismatch rejection")?;
    assert!(err_force.contains("verified executable identity required for live watch"), "{err_force}");
    Ok(())
}
