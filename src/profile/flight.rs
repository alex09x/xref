/*
 * XRef — bounded event-triggered sample window
 * Copyright (c) 2026 Alexander Panasenko
 * Contact: alex@prod.codes
 * Author: https://prod.codes/about/
 * Project: https://github.com/alex09x/xref
 * SPDX-License-Identifier: MIT OR Apache-2.0
 */
use super::types::Sample;
use std::collections::BTreeMap;

pub struct Flight {
    samples: BTreeMap<(u64, u64), (Sample, usize)>,
    bytes: usize,
    max_bytes: usize,
    window_ns: u64,
    latest_ns: u64,
    sequence: u64,
    pub trigger_ns: Option<u64>,
    pub evicted: u64,
    discarded_through_ns: Option<u64>,
    pub coverage_gap: bool,
}

impl Flight {
    pub const fn new(window_ns: u64, max_bytes: usize) -> Self {
        Self {
            samples: BTreeMap::new(),
            bytes: 0,
            max_bytes,
            window_ns,
            latest_ns: 0,
            sequence: 0,
            trigger_ns: None,
            evicted: 0,
            discarded_through_ns: None,
            coverage_gap: false,
        }
    }

    pub fn trigger(&mut self, timestamp_ns: u64) {
        if self.trigger_ns.is_none_or(|previous| timestamp_ns < previous) {
            self.trigger_ns = Some(timestamp_ns);
            let begin = timestamp_ns.saturating_sub(self.window_ns / 2);
            self.coverage_gap |= self.discarded_through_ns.is_some_and(|last| last >= begin);
        }
    }

    pub fn push(&mut self, sample: Sample) {
        let size = std::mem::size_of::<Sample>()
            .saturating_add(sample.user_stack.len())
            .saturating_add(sample.registers.len().saturating_mul(8))
            .saturating_add(sample.callchain.len().saturating_mul(8))
            .saturating_add(sample.branches.len().saturating_mul(24));
        if size > self.max_bytes {
            self.evicted = self.evicted.saturating_add(1);
            self.discarded_through_ns = Some(self.discarded_through_ns.unwrap_or(0).max(sample.timestamp_ns));
            if self.trigger_ns.is_some_and(|trigger| sample.timestamp_ns >= trigger.saturating_sub(self.window_ns / 2))
            {
                self.coverage_gap = true;
            }
            return;
        }
        self.latest_ns = self.latest_ns.max(sample.timestamp_ns);
        let key = (sample.timestamp_ns, self.sequence);
        self.sequence = self.sequence.saturating_add(1);
        self.samples.insert(key, (sample, size));
        self.bytes = self.bytes.saturating_add(size);
        let earliest = self.trigger_ns.map_or_else(
            || self.latest_ns.saturating_sub(self.window_ns.saturating_mul(2)),
            |trigger| trigger.saturating_sub(self.window_ns / 2),
        );
        while self.bytes > self.max_bytes
            || self.samples.first_key_value().is_some_and(|((time, _), _)| *time < earliest)
        {
            let over_capacity = self.bytes > self.max_bytes;
            let Some(((time, _), (_, removed))) = self.samples.pop_first() else { break };
            self.bytes = self.bytes.saturating_sub(removed);
            self.discarded_through_ns = Some(self.discarded_through_ns.unwrap_or(0).max(time));
            if over_capacity {
                self.evicted = self.evicted.saturating_add(1);
                if self.trigger_ns.is_some_and(|trigger| time >= trigger.saturating_sub(self.window_ns / 2)) {
                    self.coverage_gap = true;
                }
            }
        }
    }

    pub fn into_window(self) -> Vec<Sample> {
        let Some(trigger) = self.trigger_ns else { return Vec::new() };
        let begin = trigger.saturating_sub(self.window_ns / 2);
        let end = trigger.saturating_add(self.window_ns - self.window_ns / 2);
        self.samples
            .into_iter()
            .filter_map(|((time, _), (sample, _))| (begin..=end).contains(&time).then_some(sample))
            .collect()
    }
}
