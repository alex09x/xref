/*
 * XRef — Stage L3 Increment 2 unit tests for dependent watch model and rebind transitions
 * Copyright (c) 2026 Alexander Panasenko
 * Contact: alex@prod.codes
 * Author: https://prod.codes/about/
 * Project: https://github.com/alex09x/xref
 * SPDX-License-Identifier: MIT OR Apache-2.0
 */

use std::cell::Cell;
use std::collections::{BTreeMap, BTreeSet};

use crate::image::Image;
use crate::live::cli::{LiveCommand, LiveSubcommand, WatchAccessMode, WatchLen};
use crate::live::memscan::ReadAt;
use crate::live::probe::types::ProbeStopReason;
use crate::live::types::{HexAddr, RegionEntry, ScanStatus};
use crate::live::watch::finalize_watch_observation;
use crate::live::watch::perf::{DecodedWatchRecord, WatchRunConfig, WatchSampleEvent};
use crate::live::watch::perf_stream::{WatchDrainCtx, process_decoded_watch_record};
use crate::live::watch::rebind::{
    DependentBindingState, RebindTransitionKind, RootLivenessStatus, evaluate_dependent_chain, parse_follow_spec,
};
use crate::live::watch::rebind_runtime::{
    WatchSlotSampler, prepare_dependent_watches, reconcile_dependent_watch_entry, sync_live_watch_tids,
};
use crate::live::watch::types::WatchTargetSpec;

struct MapMemReader {
    words: BTreeMap<u64, u64>,
    flip_on_read: Option<(u64, Cell<u64>)>,
}

impl MapMemReader {
    fn new() -> Self {
        Self { words: BTreeMap::new(), flip_on_read: None }
    }

    fn set_u64(&mut self, addr: u64, val: u64) {
        self.words.insert(addr, val);
    }
}

impl ReadAt for MapMemReader {
    fn read_at(&self, buf: &mut [u8], offset: u64) -> std::io::Result<usize> {
        if buf.len() != 8 {
            return Err(std::io::Error::new(std::io::ErrorKind::InvalidInput, "expected 8B read"));
        }
        if let Some((flip_addr, counter)) = &self.flip_on_read
            && *flip_addr == offset
        {
            let next = counter.get().wrapping_add(1);
            counter.set(next);
            buf.copy_from_slice(&next.to_le_bytes());
            return Ok(8);
        }
        let Some(&val) = self.words.get(&offset) else {
            return Err(std::io::Error::new(std::io::ErrorKind::AddrNotAvailable, "unmapped"));
        };
        buf.copy_from_slice(&val.to_le_bytes());
        Ok(8)
    }
}

fn synthetic_image_and_regions() -> Result<(Image, Vec<RegionEntry>), Box<dyn std::error::Error>> {
    let mut elf = vec![0_u8; 8192];
    elf[0..7].copy_from_slice(b"\x7fELF\x02\x01\x01");
    elf[16..24].copy_from_slice(&[2, 0, 0x3e, 0, 1, 0, 0, 0]);
    elf[24..40].copy_from_slice(&[0, 0x10, 0x40, 0, 0, 0, 0, 0, 64, 0, 0, 0, 0, 0, 0, 0]);
    elf[52..58].copy_from_slice(&[64, 0, 56, 0, 1, 0]);
    let ph = &mut elf[64..120];
    ph[0..8].copy_from_slice(&[1, 0, 0, 0, 5, 0, 0, 0]);
    ph[16..32].copy_from_slice(&[0, 0, 0x40, 0, 0, 0, 0, 0, 0, 0, 0x40, 0, 0, 0, 0, 0]);
    ph[32..56].copy_from_slice(&[0, 0x20, 0, 0, 0, 0, 0, 0, 0, 0x20, 0, 0, 0, 0, 0, 0, 0, 0x10, 0, 0, 0, 0, 0, 0]);
    let image = Image::parse_for_live(elf)?;
    let regions = vec![RegionEntry {
        start: HexAddr(0x7000_0000),
        end: HexAddr(0x7001_0000),
        perms: "rw-p".to_owned(),
        offset: HexAddr(0),
        dev: "00:00".to_owned(),
        inode: 0,
        pathname: Some("[heap]".to_owned()),
        vm_flags: Some(vec!["rd".to_owned(), "wr".to_owned(), "mr".to_owned()]),
        is_target_image: false,
        scan_status: ScanStatus::ScannableRwp,
    }];
    Ok((image, regions))
}

#[test]
fn follow_spec_parsing_and_4_slot_hardware_budget_enforcement() -> Result<(), Box<dyn std::error::Error>> {
    let s1 = parse_follow_spec(
        "ptr_slot=0x70000000,offset=16,len_slot=0x70000010,min_len=24",
        WatchLen::B8,
        WatchAccessMode::Write,
    )?;
    assert_eq!(
        (s1.hardware_slots_required(), s1.ptr_slot, s1.offset, s1.len_slot, s1.min_len),
        (2, 0x7000_0000, 16, Some(0x7000_0010), 24)
    );
    let s2 = parse_follow_spec(
        "header_ptr_slot=0x70000000,header_offset=64,ptr_slot=0x70000040,offset=0",
        WatchLen::B8,
        WatchAccessMode::Write,
    )?;
    assert_eq!(s2.hardware_slots_required(), 3);
    let mk_cmd = |addrs: Vec<u64>| LiveCommand {
        subcommand: LiveSubcommand::Watch {
            pid: 123,
            len: WatchLen::B8,
            access: WatchAccessMode::Write,
            regs: false,
            duration_ms: 500,
            max_events: 64,
            max_samples: 32,
            value_range: None,
            json_lines: false,
            force_bin: false,
            json: true,
            follow: vec!["header_ptr_slot=0x70000000,header_offset=64,ptr_slot=0x70000040".to_owned()],
            addrs,
        },
    };
    assert!(mk_cmd(vec![0x7000_0100]).validate().is_ok());
    let err = mk_cmd(vec![0x7000_0100, 0x7000_0108]).validate().err().ok_or("5 hardware slots must fail")?;
    assert!(err.contains("DR0..DR3"), "unexpected error: {err}");
    Ok(())
}

#[test]
fn dependent_chain_transitions_and_torn_read_rejection() -> Result<(), Box<dyn std::error::Error>> {
    let (image, regions) = synthetic_image_and_regions()?;
    let ptr_slot = 0x7000_0040_u64;
    let len_slot = 0x7000_0050_u64;
    let guard_slot = 0x7000_0000_u64;
    let guard_expected = 0x5852_4546_5459_5045_u64;
    let buf1 = 0x7000_1000_u64;
    let buf2 = 0x7000_2000_u64;

    let mut mem = MapMemReader::new();
    mem.set_u64(guard_slot, guard_expected);
    mem.set_u64(ptr_slot, buf1);
    mem.set_u64(len_slot, 16);
    mem.set_u64(buf1, 0xaaaa_0001);
    mem.set_u64(buf2, 0xbbbb_0002);

    let follow_str = format!(
        "ptr_slot={ptr_slot:#x},offset=0,len_slot={len_slot:#x},min_len=8,guard_slot={guard_slot:#x},guard_val={guard_expected:#x}"
    );
    let mut deps = prepare_dependent_watches(
        (&image, 0, &regions),
        (std::slice::from_ref(&follow_str), WatchLen::B8, WatchAccessMode::Write),
        0,
        Some(&mem),
    )?;
    let dep = &mut deps[0];

    // 1. InitialBind: bound to buf1, generation = 1, guard verified liveness
    assert_eq!(dep.state, DependentBindingState::Bound);
    assert_eq!(dep.liveness, RootLivenessStatus::GuardVerifiedWithoutAllocatorProof);
    assert_eq!(dep.generation, 1);
    assert_eq!(dep.active_leaf_spec.as_ref().map(|s| s.runtime_va), Some(buf1));
    assert_eq!(dep.initial_leaf_snapshot, Some(HexAddr(0xaaaa_0001)));

    // 2. InPlaceResize: len grows from 16 -> 32 while ptr_slot stays buf1 -> generation stays 1
    mem.set_u64(len_slot, 32);
    let eval_resize =
        evaluate_dependent_chain(&dep.spec, &regions, Some(&mem), ptr_slot, None, Some(len_slot), Some(guard_slot));
    let changed_sampler = dep.apply_evaluated(eval_resize, false);
    assert!(!changed_sampler, "in-place resize must not re-open leaf sampler");
    assert_eq!(dep.generation, 1);
    assert_eq!(dep.rebind_events.last().map(|e| e.transition), Some(RebindTransitionKind::InPlaceResize));

    // 3. RelocatedBuffer (move): ptr_slot moves to buf2 -> generation increments to 2, sampler rebinds
    mem.set_u64(ptr_slot, buf2);
    let eval_move =
        evaluate_dependent_chain(&dep.spec, &regions, Some(&mem), ptr_slot, None, Some(len_slot), Some(guard_slot));
    let changed_move = dep.apply_evaluated(eval_move, false);
    assert!(changed_move, "relocated buffer must trigger leaf sampler rebind");
    assert_eq!(dep.generation, 2);
    assert_eq!(dep.active_leaf_spec.as_ref().map(|s| s.runtime_va), Some(buf2));
    assert_eq!(dep.rebind_events.last().map(|e| e.transition), Some(RebindTransitionKind::RelocatedBuffer));

    // 4. DisarmedBoundsViolation (clear/shrink): len_slot drops to 0 -> leaf watch disarmed
    mem.set_u64(len_slot, 0);
    let eval_empty =
        evaluate_dependent_chain(&dep.spec, &regions, Some(&mem), ptr_slot, None, Some(len_slot), Some(guard_slot));
    let changed_disarm = dep.apply_evaluated(eval_empty, false);
    assert!(changed_disarm, "disarming must remove active leaf sampler");
    assert_eq!(dep.state, DependentBindingState::DisarmedBoundsViolation);
    assert!(dep.active_leaf_spec.is_none(), "disarmed watch must have no active leaf spec");

    // 5. DisarmedGuardMismatch: owner header overwritten -> disarmed with guard mismatch
    mem.set_u64(len_slot, 16);
    mem.set_u64(guard_slot, 0xdead_beef);
    let eval_guard =
        evaluate_dependent_chain(&dep.spec, &regions, Some(&mem), ptr_slot, None, Some(len_slot), Some(guard_slot));
    let _ = dep.apply_evaluated(eval_guard, false);
    assert_eq!(dep.state, DependentBindingState::DisarmedGuardMismatch);
    assert_eq!(dep.liveness, RootLivenessStatus::InvalidatedByGuardMismatch);

    // 6. DisarmedTornRead: non-atomic /proc/<pid>/mem read where ptr_slot changes on every pass
    mem.set_u64(guard_slot, guard_expected);
    mem.flip_on_read = Some((ptr_slot, Cell::new(0x7000_1000)));
    let eval_torn =
        evaluate_dependent_chain(&dep.spec, &regions, Some(&mem), ptr_slot, None, Some(len_slot), Some(guard_slot));
    assert_eq!(eval_torn.state, DependentBindingState::DisarmedTornRead);
    assert_eq!(eval_torn.liveness, RootLivenessStatus::InvalidatedByTornRead);
    Ok(())
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct MockSlotSampler {
    watch_index: usize,
    tid: u32,
    runtime_va: u64,
    disabled: bool,
}

impl WatchSlotSampler for MockSlotSampler {
    fn watch_index(&self) -> usize {
        self.watch_index
    }
    fn tid(&self) -> u32 {
        self.tid
    }
    fn runtime_va(&self) -> u64 {
        self.runtime_va
    }
    fn disable(&mut self) {
        self.disabled = true;
    }
}

#[test]
fn pending_root_rebind_drops_queued_stale_leaf_samples() -> Result<(), Box<dyn std::error::Error>> {
    let (image, regions) = synthetic_image_and_regions()?;
    let (ptr_slot, buf1) = (0x7000_0040_u64, 0x7000_1000_u64);
    let mut mem = MapMemReader::new();
    mem.set_u64(ptr_slot, buf1);
    mem.set_u64(buf1, 0x1111);

    let follow_str = format!("ptr_slot={ptr_slot:#x},offset=0");
    let deps = prepare_dependent_watches(
        (&image, 0, &regions),
        (std::slice::from_ref(&follow_str), WatchLen::B8, WatchAccessMode::Write),
        0,
        Some(&mem),
    )?;
    let (root_widx, leaf_widx) = (deps[0].ptr_slot_watch_index, deps[0].leaf_watch_index);
    let mut ctx = WatchDrainCtx::with_dependent(4242, 0, 0, false, &[], deps, BTreeSet::from([4242]));

    let sample = DecodedWatchRecord::Sample(WatchSampleEvent {
        ip: Some(0x0040_1010),
        tgid: Some(4242),
        thread_id: Some(4242),
        timestamp_ns: Some(100),
        intr_regs: None,
    });
    process_decoded_watch_record(&image, 0, &regions, root_widx, Ok(sample.clone()), &mut ctx, 64);
    assert!(ctx.pending_rebind_indices.contains(&0) && ctx.dependent[0].root_ptr_slot_hits == 1);

    process_decoded_watch_record(&image, 0, &regions, leaf_widx, Ok(sample), &mut ctx, 64);
    assert_eq!(ctx.dependent[0].leaf_acc.accepted_hits, 0);
    assert!(ctx.coverage_gap_reasons.iter().any(|r| r == "dependent_leaf_sample_dropped_while_root_rebind_pending"));
    Ok(())
}

#[test]
fn two_hop_header_move_rebinds_middle_ptr_slot_and_retry_recovers_failed_attach()
-> Result<(), Box<dyn std::error::Error>> {
    let (image, regions) = synthetic_image_and_regions()?;
    let (hdr_slot, hdr1, hdr2, buf1, buf2) =
        (0x7000_0000_u64, 0x7000_1000_u64, 0x7000_3000_u64, 0x7000_2000_u64, 0x7000_4000_u64);
    let mut mem = MapMemReader::new();
    for (a, v) in [(hdr_slot, hdr1), (hdr1 + 16, buf1), (buf1, 0xaaaa), (hdr2 + 16, buf2), (buf2, 0xbbbb)] {
        mem.set_u64(a, v);
    }
    let follow_str = format!("header_ptr_slot={hdr_slot:#x},header_offset=16,ptr_slot={:#x},offset=0", hdr1 + 16);
    let mut deps = prepare_dependent_watches(
        (&image, 0, &regions),
        (std::slice::from_ref(&follow_str), WatchLen::B8, WatchAccessMode::Write),
        0,
        Some(&mem),
    )?;
    let dep = &mut deps[0];
    let tids = BTreeSet::from([9001_u32]);
    let mut samplers = vec![
        MockSlotSampler { watch_index: dep.ptr_slot_watch_index, tid: 9001, runtime_va: hdr1 + 16, disabled: false },
        MockSlotSampler { watch_index: dep.leaf_watch_index, tid: 9001, runtime_va: buf1, disabled: false },
    ];
    let mut reasons = Vec::new();

    mem.set_u64(hdr_slot, hdr2);
    let leaf_widx = dep.leaf_watch_index;
    let mut fail_leaf = |widx: usize, spec: &WatchTargetSpec, tid: u32| -> Result<MockSlotSampler, &'static str> {
        if widx == leaf_widx {
            Err("dependent_leaf_rebind_perf_enable_failed")
        } else {
            Ok(MockSlotSampler { watch_index: widx, tid, runtime_va: spec.runtime_va, disabled: false })
        }
    };
    reconcile_dependent_watch_entry(dep, &regions, Some(&mem), &mut samplers, &tids, &mut reasons, &mut fail_leaf);
    assert_eq!(
        (dep.ptr_slot_spec.runtime_va, dep.active_leaf_spec.as_ref().map(|s| s.runtime_va), dep.state),
        (hdr2 + 16, Some(buf2), DependentBindingState::RebindAttachRetryPending)
    );
    assert!(reasons.iter().any(|r| r == "dependent_leaf_rebind_perf_enable_failed"));
    assert!(samplers.iter().any(|s| s.watch_index == dep.ptr_slot_watch_index && s.runtime_va == hdr2 + 16));
    assert!(!samplers.iter().any(|s| s.watch_index == dep.leaf_watch_index));

    let mut ok_open = |widx: usize, spec: &WatchTargetSpec, tid: u32| -> Result<MockSlotSampler, &'static str> {
        Ok(MockSlotSampler { watch_index: widx, tid, runtime_va: spec.runtime_va, disabled: false })
    };
    reconcile_dependent_watch_entry(dep, &regions, Some(&mem), &mut samplers, &tids, &mut reasons, &mut ok_open);
    assert_eq!((dep.state, dep.generation), (DependentBindingState::Bound, 2));
    assert!(samplers.iter().any(|s| s.watch_index == dep.leaf_watch_index && s.runtime_va == buf2));
    assert_eq!(dep.clone().into_result(Some(&mem)).ptr_slot_runtime_va, HexAddr(hdr2 + 16));
    Ok(())
}

#[test]
fn exited_worker_tid_is_pruned_before_rebind_and_not_retried() -> Result<(), Box<dyn std::error::Error>> {
    let (image, regions) = synthetic_image_and_regions()?;
    let (ptr_slot, buf1, buf2) = (0x7000_0040_u64, 0x7000_1000_u64, 0x7000_2000_u64);
    let mut mem = MapMemReader::new();
    for (a, v) in [(ptr_slot, buf1), (buf1, 0x1111), (buf2, 0x2222)] {
        mem.set_u64(a, v);
    }
    let follow_str = format!("ptr_slot={ptr_slot:#x},offset=0");
    let deps = prepare_dependent_watches(
        (&image, 0, &regions),
        (std::slice::from_ref(&follow_str), WatchLen::B1, WatchAccessMode::Rw),
        0,
        Some(&mem),
    )?;
    let (ptr_widx, leaf_widx) = (deps[0].ptr_slot_watch_index, deps[0].leaf_watch_index);
    let mut ctx = WatchDrainCtx::with_dependent(4242, 0, 0, false, &[], deps, BTreeSet::from([4242_u32, 4243_u32]));
    let receipt =
        crate::live::watch::types::build_watch_ready_receipt(4242, &ctx.attached_tids, ctx.specs, &ctx.dependent);
    assert_eq!((receipt.access, receipt.len_bytes), ("rw", 1));
    let mut samplers = vec![
        MockSlotSampler { watch_index: ptr_widx, tid: 4242, runtime_va: ptr_slot, disabled: false },
        MockSlotSampler { watch_index: ptr_widx, tid: 4243, runtime_va: ptr_slot, disabled: false },
        MockSlotSampler { watch_index: leaf_widx, tid: 4242, runtime_va: buf1, disabled: false },
        MockSlotSampler { watch_index: leaf_widx, tid: 4243, runtime_va: buf1, disabled: false },
    ];

    let exit_rec = DecodedWatchRecord::Exit { tgid: 4242, thread_id: 4243, timestamp_ns: 50 };
    process_decoded_watch_record(&image, 0, &regions, ptr_widx, Ok(exit_rec), &mut ctx, 64);
    assert!(!ctx.attached_tids.contains(&4243));
    sync_live_watch_tids(&mut samplers, &mut ctx, &BTreeSet::from([4242_u32]));
    assert!(samplers.iter().all(|s| s.tid == 4242));

    mem.set_u64(ptr_slot, buf2);
    let mut dead_tid_attempts = 0_usize;
    let mut open_fn = |widx: usize, spec: &WatchTargetSpec, tid: u32| -> Result<MockSlotSampler, &'static str> {
        if tid == 4243 {
            dead_tid_attempts += 1;
            Err("dependent_leaf_rebind_perf_open_failed")
        } else {
            Ok(MockSlotSampler { watch_index: widx, tid, runtime_va: spec.runtime_va, disabled: false })
        }
    };
    reconcile_dependent_watch_entry(
        &mut ctx.dependent[0],
        &regions,
        Some(&mem),
        &mut samplers,
        &ctx.attached_tids,
        &mut ctx.coverage_gap_reasons,
        &mut open_fn,
    );
    assert_eq!((dead_tid_attempts, ctx.dependent[0].state), (0, DependentBindingState::Bound));
    assert!(samplers.iter().any(|s| s.watch_index == leaf_widx && s.tid == 4242 && s.runtime_va == buf2));

    let cfg = WatchRunConfig {
        duration: std::time::Duration::from_millis(100),
        max_events: 64,
        want_regs: false,
        cancel: None,
        keep: crate::live::watch::samples::SampleKeep::default(),
    };
    let fork_rec =
        DecodedWatchRecord::Fork { tgid: 4242, parent_tgid: 4242, thread_id: 5001, parent_tid: 4242, timestamp_ns: 10 };
    let exit_5001 = DecodedWatchRecord::Exit { tgid: 4242, thread_id: 5001, timestamp_ns: 20 };
    let mut ctx_exit = WatchDrainCtx::new(4242, 0, 0, false, &[], BTreeSet::from([4242_u32]));
    process_decoded_watch_record(&image, 0, &regions, 0, Ok(fork_rec.clone()), &mut ctx_exit, 64);
    process_decoded_watch_record(&image, 0, &regions, 0, Ok(exit_5001), &mut ctx_exit, 64);
    let obs_exit = finalize_watch_observation(&ctx_exit, &cfg, 1, 100, ProbeStopReason::DurationElapsed);
    assert_eq!(obs_exit.thread_coverage.unattached_fork_tids, 1);
    assert!(obs_exit.thread_coverage.partial_coverage && obs_exit.counts_are_lower_bound);

    let mut ctx_proc = WatchDrainCtx::new(4242, 0, 0, false, &[], BTreeSet::from([4242_u32]));
    process_decoded_watch_record(&image, 0, &regions, 0, Ok(fork_rec), &mut ctx_proc, 64);
    sync_live_watch_tids(&mut samplers, &mut ctx_proc, &BTreeSet::from([4242_u32]));
    let obs_proc = finalize_watch_observation(&ctx_proc, &cfg, 1, 100, ProbeStopReason::DurationElapsed);
    assert_eq!(obs_proc.thread_coverage.unattached_fork_tids, 1);
    assert!(obs_proc.thread_coverage.partial_coverage && obs_proc.counts_are_lower_bound);
    Ok(())
}
