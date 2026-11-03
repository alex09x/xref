/*
 * XRef — Stage L3 Increment 2 unit tests for dependent watch model and rebind transitions
 * Copyright (c) 2026 Alexander Panasenko
 * Contact: alex@prod.codes
 * Author: https://prod.codes/about/
 * Project: https://github.com/alex09x/xref
 * SPDX-License-Identifier: MIT OR Apache-2.0
 */

use std::cell::Cell;
use std::collections::BTreeMap;

use crate::image::Image;
use crate::live::cli::{LiveCommand, LiveSubcommand, WatchAccessMode, WatchLen};
use crate::live::memscan::ReadAt;
use crate::live::types::{HexAddr, RegionEntry, ScanStatus};
use crate::live::watch::rebind::{
    DependentBindingState, RebindTransitionKind, RootLivenessStatus, evaluate_dependent_chain, parse_follow_spec,
};
use crate::live::watch::rebind_runtime::prepare_dependent_watches;

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
    elf[0..4].copy_from_slice(b"\x7fELF");
    elf[4] = 2;
    elf[5] = 1;
    elf[6] = 1;
    elf[16..18].copy_from_slice(&2_u16.to_le_bytes());
    elf[18..20].copy_from_slice(&0x3e_u16.to_le_bytes());
    elf[20..24].copy_from_slice(&1_u32.to_le_bytes());
    elf[24..32].copy_from_slice(&0x0040_1000_u64.to_le_bytes());
    elf[32..40].copy_from_slice(&64_u64.to_le_bytes());
    elf[52..54].copy_from_slice(&64_u16.to_le_bytes());
    elf[54..56].copy_from_slice(&56_u16.to_le_bytes());
    elf[56..58].copy_from_slice(&1_u16.to_le_bytes());
    let ph = &mut elf[64..120];
    ph[0..4].copy_from_slice(&1_u32.to_le_bytes());
    ph[4..8].copy_from_slice(&5_u32.to_le_bytes());
    ph[16..24].copy_from_slice(&0x0040_0000_u64.to_le_bytes());
    ph[24..32].copy_from_slice(&0x0040_0000_u64.to_le_bytes());
    ph[32..40].copy_from_slice(&8192_u64.to_le_bytes());
    ph[40..48].copy_from_slice(&8192_u64.to_le_bytes());
    ph[48..56].copy_from_slice(&4096_u64.to_le_bytes());
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
    assert_eq!(s1.hardware_slots_required(), 2);
    assert_eq!(s1.ptr_slot, 0x7000_0000);
    assert_eq!(s1.offset, 16);
    assert_eq!(s1.len_slot, Some(0x7000_0010));
    assert_eq!(s1.min_len, 24);

    let s2 = parse_follow_spec(
        "header_ptr_slot=0x70000000,header_offset=64,ptr_slot=0x70000040,offset=0",
        WatchLen::B8,
        WatchAccessMode::Write,
    )?;
    assert_eq!(s2.hardware_slots_required(), 3);

    // 1 fixed watch (1 slot) + 1 two-hop follow watch (3 slots) = 4 slots -> allowed
    let ok_cmd = LiveCommand {
        subcommand: LiveSubcommand::Watch {
            pid: 123,
            len: WatchLen::B8,
            access: WatchAccessMode::Write,
            regs: false,
            duration_ms: 500,
            max_events: 64,
            force_bin: false,
            json: true,
            follow: vec!["header_ptr_slot=0x70000000,header_offset=64,ptr_slot=0x70000040".to_owned()],
            addrs: vec![0x7000_0100],
        },
    };
    assert!(ok_cmd.validate().is_ok());

    // 2 fixed watches (2 slots) + 1 two-hop follow watch (3 slots) = 5 slots -> rejected (> 4 DR0..DR3)
    let over_cmd = LiveCommand {
        subcommand: LiveSubcommand::Watch {
            pid: 123,
            len: WatchLen::B8,
            access: WatchAccessMode::Write,
            regs: false,
            duration_ms: 500,
            max_events: 64,
            force_bin: false,
            json: true,
            follow: vec!["header_ptr_slot=0x70000000,header_offset=64,ptr_slot=0x70000040".to_owned()],
            addrs: vec![0x7000_0100, 0x7000_0108],
        },
    };
    let err = over_cmd.validate().err().ok_or("5 hardware slots must fail")?;
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
