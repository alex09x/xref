/*
 * XRef — live heap attribution: which call stacks hold the anonymous memory of a process
 * Copyright (c) 2026 Alexander Panasenko
 * Contact: alex@prod.codes
 * Author: https://prod.codes/about/
 * Project: https://github.com/alex09x/xref
 * SPDX-License-Identifier: MIT OR Apache-2.0
 */

//! The ledger of anonymous memory a process maps while it is observed, by the call stack that
//! mapped it. Every memory syscall moves bytes in or out:
//!
//! - `mmap` of anonymous memory maps bytes, unless it only reserves address space (`PROT_NONE`,
//!   the 64 MiB a glibc arena reserves);
//! - `mprotect` making reserved memory writable maps bytes (a glibc arena growing);
//! - `brk` moves the end of `[heap]` (the main glibc arena growing or shrinking);
//! - `mremap` moves bytes and maps or unmaps the difference;
//! - `munmap`, or `mprotect`/`mmap` back to `PROT_NONE`, unmaps them.
//!
//! Allocations below the mmap threshold reach the kernel only as arena growth, in steps that the
//! malloc crossing the boundary triggers, which samples small allocations by their bytes. To keep
//! a long capture bounded, a stack is kept per `sample_bytes` mapped (every mapping at least that
//! large is kept exactly) and stands for the bytes since the last kept one.

use std::collections::BTreeMap;
use std::sync::Arc;

use super::super::types::Sample;

const PROT_WRITE: u64 = 0x2;

/// A mapped range: its bytes, the bytes it stands for, and the stack that mapped it (only for a
/// range that was kept; one sampled out is still tracked, so unmapping it is accounted).
#[derive(Clone, Debug)]
struct Live {
    len: u64,
    weight: u64,
    sample: Option<Arc<Sample>>,
}

/// Live and reserved anonymous memory of one process.
#[derive(Debug)]
pub struct Ledger {
    live: BTreeMap<u64, Live>,
    reserved: BTreeMap<u64, u64>,
    sample_bytes: u64,
    pending: u64,
    brk: Option<u64>,
    /// Bytes mapped and unmapped while observed, all ranges counted.
    pub mapped_total: u64,
    pub unmapped_total: u64,
}

impl Ledger {
    #[must_use]
    pub fn new(sample_bytes: u64, brk: Option<u64>) -> Self {
        Self {
            live: BTreeMap::new(),
            reserved: BTreeMap::new(),
            sample_bytes: sample_bytes.max(1),
            pending: 0,
            brk,
            mapped_total: 0,
            unmapped_total: 0,
        }
    }

    /// The weight a newly mapped range of `len` bytes carries: all of it when it is at least
    /// `sample_bytes`, else a multiple of `sample_bytes` once enough small ranges added up.
    const fn weigh(&mut self, len: u64) -> u64 {
        if len >= self.sample_bytes {
            return len;
        }
        self.pending += len;
        let kept = self.pending - self.pending % self.sample_bytes;
        self.pending -= kept;
        kept
    }

    fn add(&mut self, addr: u64, len: u64, sample: &Arc<Sample>) {
        if len == 0 {
            return;
        }
        self.remove(addr, len);
        self.mapped_total += len;
        let weight = self.weigh(len);
        let sample = (weight > 0).then(|| Arc::clone(sample));
        self.live.insert(addr, Live { len, weight, sample });
    }

    /// Takes `[addr, addr+len)` out of the live ranges; the pieces left keep their share of weight.
    fn remove(&mut self, addr: u64, len: u64) -> Vec<(u64, Live)> {
        let end = addr.saturating_add(len);
        let mut hits: Vec<u64> = self.live.range(addr..end).map(|(start, _)| *start).collect();
        if let Some((start, live)) = self.live.range(..addr).next_back()
            && start + live.len > addr
        {
            hits.push(*start);
        }
        let mut taken = Vec::new();
        for start in hits {
            let Some(live) = self.live.remove(&start) else { continue };
            let (lo, hi) = (start.max(addr), (start + live.len).min(end));
            let share = |piece: u64| {
                u64::try_from(u128::from(live.weight) * u128::from(piece) / u128::from(live.len)).unwrap_or(0)
            };
            if start < lo {
                let piece = lo - start;
                self.live.insert(start, Live { len: piece, weight: share(piece), sample: live.sample.clone() });
            }
            if hi < start + live.len {
                let piece = start + live.len - hi;
                self.live.insert(hi, Live { len: piece, weight: share(piece), sample: live.sample.clone() });
            }
            self.unmapped_total += hi - lo;
            if live.sample.is_none() {
                // Bytes sampled out still wait in `pending`; unmapped, they must not reach a later stack.
                self.pending = self.pending.saturating_sub(hi - lo);
            }
            taken.push((lo, Live { len: hi - lo, weight: share(hi - lo), sample: live.sample }));
        }
        taken
    }

    fn reserved_overlapping(&self, addr: u64, end: u64) -> Vec<(u64, u64)> {
        let mut hits: Vec<(u64, u64)> = self.reserved.range(addr..end).map(|(s, l)| (*s, *l)).collect();
        if let Some((start, l)) = self.reserved.range(..addr).next_back()
            && start + l > addr
        {
            hits.push((*start, *l));
        }
        hits
    }

    fn unreserve(&mut self, addr: u64, len: u64) {
        let end = addr.saturating_add(len);
        for (start, l) in self.reserved_overlapping(addr, end) {
            self.reserved.remove(&start);
            if start < addr {
                self.reserved.insert(start, addr - start);
            }
            if start + l > end {
                self.reserved.insert(end, start + l - end);
            }
        }
    }

    /// `mmap(addr, len, prot, flags)` that returned `addr`.
    pub fn mmap(&mut self, addr: u64, len: u64, prot: u64, anonymous: bool, sample: &Arc<Sample>) {
        self.remove(addr, len);
        self.unreserve(addr, len);
        if !anonymous {
            return;
        }
        if prot & PROT_WRITE == 0 {
            self.reserved.insert(addr, len);
        } else {
            self.add(addr, len, sample);
        }
    }

    pub fn munmap(&mut self, addr: u64, len: u64) {
        self.remove(addr, len);
        self.unreserve(addr, len);
    }

    /// `mprotect(addr, len, prot)`: reserved memory made writable is mapped; writable memory made
    /// inaccessible goes back to reserved.
    pub fn mprotect(&mut self, addr: u64, len: u64, prot: u64, sample: &Arc<Sample>) {
        let end = addr.saturating_add(len);
        if prot & PROT_WRITE != 0 {
            // Memory made writable is new bytes (an arena growing), whether its reservation was
            // seen or predates the capture; ranges already live keep their stack.
            self.unreserve(addr, len);
            let mut at = addr;
            let mut covered: Vec<(u64, u64)> = Vec::new();
            if let Some((start, live)) = self.live.range(..addr).next_back()
                && start + live.len > addr
            {
                covered.push((*start, start + live.len));
            }
            covered.extend(self.live.range(addr..end).map(|(start, live)| (*start, start + live.len)));
            for (lo, hi) in covered {
                if lo > at {
                    self.add(at, lo - at, sample);
                }
                at = at.max(hi);
            }
            if at < end {
                self.add(at, end - at, sample);
            }
        } else if prot == 0 {
            // Memory made inaccessible (an arena shrinking) is reserved again. Read-only or
            // executable memory (RELRO, frozen buffers, JIT code) keeps its bytes.
            self.remove(addr, len);
            self.unreserve(addr, len);
            self.reserved.insert(addr, len);
        }
    }

    /// `brk` that moved the end of `[heap]` to `new_end`.
    pub fn brk(&mut self, new_end: u64, sample: &Arc<Sample>) {
        match self.brk {
            Some(old) if new_end > old => self.add(old, new_end - old, sample),
            Some(old) if new_end < old => {
                self.remove(new_end, old - new_end);
            }
            _ => {}
        }
        self.brk = Some(new_end);
    }

    /// `mremap(old, old_len, new_len)` that returned `new`: the old bytes keep their stack, the
    /// growth gets this call's.
    pub fn mremap(&mut self, old: u64, old_len: u64, new: u64, new_len: u64, sample: &Arc<Sample>) {
        let moved = self.remove(old, old_len);
        self.unmapped_total = self.unmapped_total.saturating_sub(moved.iter().map(|(_, l)| l.len).sum());
        self.unreserve(old, old_len);
        // The destination is replaced (MREMAP_FIXED, or a munmap that was lost).
        self.remove(new, new_len);
        self.unreserve(new, new_len);
        for (at, live) in moved {
            let offset = at - old;
            if offset < new_len {
                let len = live.len.min(new_len - offset);
                let weight =
                    u64::try_from(u128::from(live.weight) * u128::from(len) / u128::from(live.len)).unwrap_or(0);
                self.live.insert(new + offset, Live { len, weight, sample: live.sample });
            }
        }
        if new_len > old_len {
            self.add(new + old_len, new_len - old_len, sample);
        } else {
            self.unmapped_total += old_len - new_len;
        }
    }

    /// One sample per kept live range, its `period` the bytes it stands for.
    #[must_use]
    pub fn snapshot(&self) -> Vec<Sample> {
        self.live
            .values()
            .filter(|live| live.weight > 0)
            .filter_map(|live| {
                let mut sample = (**live.sample.as_ref()?).clone();
                sample.period = live.weight;
                Some(sample)
            })
            .collect()
    }

    /// Bytes the kept ranges stand for.
    #[must_use]
    pub fn live_weight(&self) -> u64 {
        self.live.values().map(|live| live.weight).sum()
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use super::{Ledger, Sample};

    fn stack(ip: u64) -> Arc<Sample> {
        Arc::new(Sample {
            timestamp_ns: 0,
            pid: 1,
            tid: 1,
            cpu_mode: 0,
            ip,
            period: 0,
            registers_mask: 0,
            registers: Vec::new(),
            user_stack: Vec::new(),
            callchain: Vec::new(),
            branches: Vec::new(),
        })
    }

    fn by_ip(ledger: &Ledger) -> Vec<(u64, u64)> {
        let mut sums = std::collections::BTreeMap::new();
        for sample in ledger.snapshot() {
            *sums.entry(sample.ip).or_insert(0) += sample.period;
        }
        sums.into_iter().collect()
    }

    #[test]
    fn large_mappings_count_exactly_and_unmapping_takes_them_back() {
        let mut ledger = Ledger::new(1 << 20, None);
        ledger.mmap(0x10_0000, 8 << 20, 3, true, &stack(0xa));
        ledger.mmap(0x90_0000, 2 << 20, 3, true, &stack(0xb));
        ledger.mmap(0x200_0000, 4 << 20, 1, false, &stack(0xc));
        assert_eq!(by_ip(&ledger), vec![(0xa, 8 << 20), (0xb, 2 << 20)]);
        ledger.munmap(0x10_0000 + (2 << 20), 2 << 20);
        assert_eq!(by_ip(&ledger), vec![(0xa, 6 << 20), (0xb, 2 << 20)]);
        ledger.munmap(0x90_0000, 2 << 20);
        assert_eq!(by_ip(&ledger), vec![(0xa, 6 << 20)]);
    }

    #[test]
    fn arena_growth_inside_a_reservation_is_byte_sampled() {
        let mut ledger = Ledger::new(1 << 20, None);
        ledger.mmap(0x4000_0000, 64 << 20, 0, true, &stack(0x1));
        assert_eq!(ledger.live_weight(), 0, "a PROT_NONE reservation holds no bytes");
        for i in 0..16u64 {
            ledger.mprotect(0x4000_0000 + i * (128 << 10), 128 << 10, 3, &stack(0x100 + i));
        }
        // 16 x 128 KiB = 2 MiB: two kept stacks of 1 MiB each.
        assert_eq!(by_ip(&ledger), vec![(0x107, 1 << 20), (0x10f, 1 << 20)]);
        ledger.mprotect(0x4000_0000 + 15 * (128 << 10), 128 << 10, 0, &stack(0x9));
        assert_eq!(by_ip(&ledger), vec![(0x107, 1 << 20)]);
    }

    #[test]
    fn sampled_out_scratch_buffers_leave_no_phantom_bytes() {
        let mut ledger = Ledger::new(16384, None);
        for _ in 0..10 {
            ledger.mmap(0x5000_0000, 4096, 3, true, &stack(0x1));
            ledger.munmap(0x5000_0000, 4096);
        }
        ledger.mmap(0x6000_0000, 4096, 3, true, &stack(0x2));
        assert_eq!(ledger.live_weight(), 0, "freed scratch buffers must not charge a later mapping");
        // Making the same pages writable twice counts them once.
        ledger.mprotect(0x6000_0000, 4096, 3, &stack(0x3));
        ledger.mprotect(0x6000_0000, 4096, 3, &stack(0x4));
        ledger.mmap(0x7000_0000, 12288, 3, true, &stack(0x5));
        assert_eq!(by_ip(&ledger), vec![(0x5, 16384)]);
    }

    #[test]
    fn read_only_memory_keeps_its_bytes_and_mremap_replaces_its_destination() {
        let mut ledger = Ledger::new(4096, None);
        ledger.mmap(0x1000_0000, 0x4000, 3, true, &stack(0xa));
        ledger.mprotect(0x1000_0000, 0x4000, 1, &stack(0xb));
        assert_eq!(by_ip(&ledger), vec![(0xa, 0x4000)]);
        ledger.mmap(0x2000_0000, 0x2000, 3, true, &stack(0xc));
        ledger.mremap(0x1000_0000, 0x4000, 0x2000_0000, 0x4000, &stack(0xd));
        assert_eq!(by_ip(&ledger), vec![(0xa, 0x4000)], "the old mapping at the destination is gone");
        assert_eq!(ledger.snapshot().iter().map(|s| s.period).sum::<u64>(), 0x4000);
    }

    #[test]
    fn brk_and_mremap_move_bytes_and_keep_the_original_stack() {
        let mut ledger = Ledger::new(4096, Some(0x1000_0000));
        ledger.brk(0x1001_0000, &stack(0x5));
        assert_eq!(by_ip(&ledger), vec![(0x5, 0x10000)]);
        ledger.brk(0x1000_8000, &stack(0x6));
        assert_eq!(by_ip(&ledger), vec![(0x5, 0x8000)]);
        ledger.mmap(0x7000_0000, 0x4000, 3, true, &stack(0x7));
        ledger.mremap(0x7000_0000, 0x4000, 0x7100_0000, 0x6000, &stack(0x8));
        assert_eq!(by_ip(&ledger), vec![(0x5, 0x8000), (0x7, 0x4000), (0x8, 0x2000)]);
    }
}
