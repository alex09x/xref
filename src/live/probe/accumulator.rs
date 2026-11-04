/*
 * XRef — per-probe hit accumulator shared by the tracefs and perf probe streams
 * Copyright (c) 2026 Alexander Panasenko
 * Contact: alex@prod.codes
 * Author: https://prod.codes/about/
 * Project: https://github.com/alex09x/xref
 * SPDX-License-Identifier: MIT OR Apache-2.0
 */

use std::collections::BTreeMap;

use crate::live::probe::types::{FetchedSample, MAX_REGISTER_SAMPLES_PER_PROBE, RegisterSample};

/// Distinct return addresses kept per probe. Unbounded runs keep counting hits, but more distinct
/// sites than this (bad CFI, data in the return slot) stay unattributed instead of growing memory.
pub const MAX_CALLER_SITES: usize = 4096;

#[derive(Default)]
pub struct ProbeAccumulator {
    pub caller_sites_overflowed: bool,
    pub accepted_hits: u64,
    pub first_timestamp_ns: Option<u64>,
    pub last_timestamp_ns: Option<u64>,
    pub caller_counts: BTreeMap<u64, u64>,
    pub reg_samples: Vec<RegisterSample>,
    pub reg_samples_truncated: bool,
    pub fetched_samples: Vec<FetchedSample>,
    pub fetched_samples_truncated: bool,
}

impl ProbeAccumulator {
    pub fn count_caller(&mut self, return_addr: u64) {
        if let Some(count) = self.caller_counts.get_mut(&return_addr) {
            *count = count.saturating_add(1);
        } else if self.caller_counts.len() < MAX_CALLER_SITES {
            self.caller_counts.insert(return_addr, 1);
        } else if !self.caller_sites_overflowed {
            self.caller_sites_overflowed = true;
            eprintln!(
                "xref: warning: more than {MAX_CALLER_SITES} distinct return addresses at one probe; further sites are counted as unattributed"
            );
        }
    }

    pub fn record_timestamp(&mut self, ts: Option<u64>) {
        if let Some(t) = ts {
            self.first_timestamp_ns = Some(self.first_timestamp_ns.map_or(t, |prev| prev.min(t)));
            self.last_timestamp_ns = Some(self.last_timestamp_ns.map_or(t, |prev| prev.max(t)));
        }
    }

    pub fn push_reg_sample(&mut self, sample: RegisterSample) {
        if self.reg_samples.len() < MAX_REGISTER_SAMPLES_PER_PROBE {
            self.reg_samples.push(sample);
        } else {
            self.reg_samples_truncated = true;
        }
    }
}

#[test]
fn caller_sites_are_capped_while_hits_keep_counting_as_unattributed() {
    let mut acc = ProbeAccumulator::default();
    for site in 0..(MAX_CALLER_SITES as u64 + 10) {
        acc.count_caller(site);
    }
    acc.count_caller(0);
    assert_eq!(acc.caller_counts.len(), MAX_CALLER_SITES);
    assert_eq!(acc.caller_counts.get(&0), Some(&2), "known sites keep counting");
    assert!(acc.caller_sites_overflowed);
}
