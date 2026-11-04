/*
 * XRef — Binary analysis
 * Copyright (c) 2026 Alexander Panasenko
 * Contact: alex@prod.codes
 * Author: https://prod.codes/about/
 * Project: https://github.com/alex09x/xref
 * SPDX-License-Identifier: MIT OR Apache-2.0
 */
use super::aggregate::{Aggregate, Frame};
use super::resolve::MappingIndex;
use super::types::{Header, Sample};
use super::unwind::Unwinder;
use crate::image::Image;
use rayon::prelude::*;
use std::collections::{BTreeMap, BTreeSet};

pub struct FrameBatch<'a, 'image> {
    index: &'a MappingIndex,
    image: &'image Image,
    header: &'a Header,
    unwinders: &'a BTreeMap<(u32, i64), Unwinder<'image>>,
    within: &'a BTreeSet<u64>,
    aggregate: &'a mut Aggregate,
    warnings: &'a mut BTreeSet<String>,
    ignored: &'a mut u64,
    unresolved: &'a mut u64,
    pending: Vec<Sample>,
    bytes: usize,
}

struct Resolved {
    frames: Vec<Frame>,
    period: u64,
    warnings: BTreeSet<String>,
}

impl<'a, 'image> FrameBatch<'a, 'image> {
    #[allow(clippy::too_many_arguments)]
    pub const fn new(
        index: &'a MappingIndex,
        image: &'image Image,
        header: &'a Header,
        unwinders: &'a BTreeMap<(u32, i64), Unwinder<'image>>,
        within: &'a BTreeSet<u64>,
        aggregate: &'a mut Aggregate,
        warnings: &'a mut BTreeSet<String>,
        ignored: &'a mut u64,
        unresolved: &'a mut u64,
    ) -> Self {
        Self {
            index,
            image,
            header,
            unwinders,
            within,
            aggregate,
            warnings,
            ignored,
            unresolved,
            pending: Vec::new(),
            bytes: 0,
        }
    }

    pub fn push(&mut self, sample: Sample) {
        let size = sample
            .user_stack
            .len()
            .saturating_add(sample.registers.len() * 8)
            .saturating_add(sample.callchain.len() * 8)
            .saturating_add(sample.branches.len() * 24)
            .saturating_add(128);
        if !self.pending.is_empty()
            && (self.pending.len() >= 2048 || self.bytes.saturating_add(size) > 16 * 1024 * 1024)
        {
            self.flush();
        }
        self.bytes = self.bytes.saturating_add(size);
        self.pending.push(sample);
    }

    pub fn lost(&mut self, count: u64) {
        self.flush();
        self.aggregate.add_lost(count);
    }
    pub fn finish(mut self) {
        self.flush();
    }

    fn flush(&mut self) {
        let resolve = |sample: &Sample| {
            let mut warnings = BTreeSet::new();
            let frames = super::analyze::sample_frames(
                self.index,
                self.image,
                self.header,
                sample,
                self.unwinders,
                &mut warnings,
            );
            Resolved { frames, period: sample.period, warnings }
        };
        let resolved: Vec<_> = if self.header.callchain == "dwarf" && self.pending.len() >= 512 {
            self.pending.par_iter().map(resolve).collect()
        } else {
            self.pending.iter().map(resolve).collect()
        };
        for item in resolved {
            self.warnings.extend(item.warnings);
            if !self.within.is_empty()
                && !item.frames.iter().any(|frame| {
                    frame.function.module == 1 && frame.function.start.is_some_and(|start| self.within.contains(&start))
                })
            {
                *self.ignored = self.ignored.saturating_add(1);
                continue;
            }
            *self.unresolved = self.unresolved.saturating_add(
                u64::try_from(item.frames.iter().filter(|frame| frame.function.start.is_none()).count())
                    .unwrap_or(u64::MAX),
            );
            self.aggregate.add(&item.frames, item.period);
        }
        self.pending.clear();
        self.bytes = 0;
    }
}
