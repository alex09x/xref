/*
 * XRef — Intel PT sideband session
 * Copyright (c) 2026 Alexander Panasenko
 * Contact: alex@prod.codes
 * Author: https://prod.codes/about/
 * Project: https://github.com/alex09x/xref
 * SPDX-License-Identifier: MIT OR Apache-2.0
 */
use super::pt_aux_identity::{Threads, mapping_matches, verified_build_id};
use super::pt_synthesis::{SyntheticBatch, synthesize};
use super::types::Mapping;
use crate::image::Image;

/// A PT span is decoded only after its target identity, thread and mapping
/// have been established. The caller must supply timestamps translated into
/// the same clock domain; raw AUXTRACE reference values are not assumed to be
/// nanoseconds. Memory modifications remain unobservable offline.
pub(super) struct Session<'a> {
    image: &'a Image,
    slide: i64,
    pid: u32,
    target_path: &'a str,
    threads: Threads,
    mapped: bool,
    mapping_ranges: Vec<(u64, u64)>,
}

impl<'a> Session<'a> {
    pub(super) fn new(
        image: &'a Image,
        slide: i64,
        pid: u32,
        target_path: &'a str,
        recorded_id: Option<&[u8]>,
    ) -> Result<Self, &'static str> {
        if !verified_build_id(recorded_id, image.metadata.build_id.as_deref()) {
            return Err("unverified PT target build ID");
        }
        if target_path.is_empty() || target_path.ends_with(" (deleted)") {
            return Err("unverified PT target path");
        }
        Ok(Self {
            image,
            slide,
            pid,
            target_path,
            threads: Threads::new(pid)?,
            mapped: false,
            mapping_ranges: Vec::new(),
        })
    }

    pub(super) fn mapping(&mut self, mapping: &Mapping) -> Result<(), &'static str> {
        self.threads.advance(mapping.timestamp_ns)?;
        if mapping.path != self.target_path || !mapping_matches(mapping, self.image, self.pid, self.slide) {
            self.threads.invalidate();
            self.mapped = false;
            return Err("unverified PT target mapping");
        }
        let end = mapping.start.checked_add(mapping.length).ok_or("mapping range overflow")?;
        if self.mapping_ranges.len() >= 256
            || self.mapping_ranges.iter().any(|&(start, previous_end)| mapping.start < previous_end && end > start)
        {
            self.lost();
            return Err("overlapping or excessive target mappings");
        }
        self.mapping_ranges.push((mapping.start, end));
        self.mapped = true;
        Ok(())
    }

    /// A later mapping over the target can change its bytes or ownership even
    /// when the recorded filename and build ID of the original file match.
    pub(super) fn other_mapping(&mut self, mapping: &Mapping) -> Result<(), &'static str> {
        self.threads.advance(mapping.timestamp_ns)?;
        if mapping.pid != self.pid {
            return Ok(());
        }
        let Some(end) = mapping.start.checked_add(mapping.length) else {
            self.lost();
            return Err("mapping range overflow");
        };
        if mapping.length == 0 {
            self.lost();
            return Err("empty mapping");
        }
        if self.mapping_ranges.iter().any(|&(start, previous_end)| mapping.start < previous_end && end > start) {
            self.lost();
            return Err("target mapping replaced");
        }
        Ok(())
    }

    pub(super) fn fork(&mut self, timestamp: u64, pid: u32, tid: u32) -> Result<(), &'static str> {
        self.threads.advance(timestamp)?;
        self.threads.fork(pid, tid)
    }

    pub(super) fn exit(&mut self, timestamp: u64, pid: u32, tid: u32) -> Result<(), &'static str> {
        self.threads.advance(timestamp)?;
        self.threads.exit(pid, tid);
        Ok(())
    }

    pub(super) fn exec(&mut self, timestamp: u64, pid: u32) -> Result<(), &'static str> {
        self.threads.advance(timestamp)?;
        self.threads.exec(pid);
        if pid == self.pid {
            self.mapped = false;
            self.mapping_ranges.clear();
        }
        Ok(())
    }

    pub(super) fn lost(&mut self) {
        self.mapped = false;
        self.mapping_ranges.clear();
        self.threads.invalidate();
    }

    pub(super) fn decode(
        &mut self,
        timestamp: u64,
        tid: u32,
        trace: &[u8],
        return_compression: bool,
    ) -> Result<SyntheticBatch, &'static str> {
        self.threads.advance(timestamp)?;
        if !self.mapped || !self.threads.accepts(tid) {
            return Err("unverified PT mapping or thread");
        }
        let batch = synthesize(trace, self.image, self.slide, self.pid, tid, return_compression, None)?;
        let covered = |address: u64| self.mapping_ranges.iter().any(|&(start, end)| address >= start && address < end);
        if batch.samples.iter().any(|sample| {
            !covered(sample.ip)
                || sample.callchain.iter().any(|address| address.checked_sub(1).is_none_or(|value| !covered(value)))
        }) {
            return Err("PT instruction or caller outside recorded executable mappings");
        }
        Ok(batch)
    }
}
