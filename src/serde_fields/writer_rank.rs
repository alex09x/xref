/*
 * XRef — executable analysis
 * Copyright (c) 2026 Alexander Panasenko
 * Contact: alex@prod.codes
 * Author: https://prod.codes/about/
 * Project: https://github.com/alex09x/xref
 * SPDX-License-Identifier: MIT OR Apache-2.0
 */
use super::{FieldOptions, model::LayoutCandidate, writer_index::Entry};
use std::collections::{BTreeMap, BTreeSet};

pub(super) struct Plan {
    expected: Vec<u64>,
    queried: BTreeSet<u64>,
    required: Vec<BTreeSet<u64>>,
    ranking: BTreeSet<u64>,
    masks: Option<Masks>,
}

struct Masks {
    queried: u128,
    required: Vec<u128>,
    ranking: u128,
}

impl Plan {
    pub fn new(layout: &LayoutCandidate, options: &FieldOptions) -> Self {
        let expected: Vec<_> =
            layout.fields.iter().map(|field| field.offset).collect::<BTreeSet<_>>().into_iter().collect();
        let required: Vec<BTreeSet<_>> = options
            .writes_all_of
            .iter()
            .map(|name| layout.fields.iter().filter(|field| &field.name == name).map(|field| field.offset).collect())
            .collect();
        let mut queried: BTreeSet<_> = layout.offsets.iter().map(|field| field.offset).collect();
        queried.extend(required.iter().flatten().copied());
        let ranking = if required.is_empty() {
            expected.iter().copied().collect()
        } else {
            required.iter().flatten().copied().collect()
        };
        let masks = (expected.len() <= 128).then(|| {
            let mask_for = |offsets: &BTreeSet<u64>| {
                expected.iter().enumerate().fold(0_u128, |mask, (index, offset)| {
                    if offsets.contains(offset) { mask | (1_u128 << index) } else { mask }
                })
            };
            Masks {
                queried: mask_for(&queried),
                required: required.iter().map(mask_for).collect(),
                ranking: mask_for(&ranking),
            }
        });
        Self { expected, queried, required, ranking, masks }
    }

    pub fn score(&self, entry: &Entry, argument: usize, minimum: usize) -> Option<(usize, usize)> {
        self.masks.as_ref().map_or_else(
            || self.score_large(entry, argument, minimum),
            |masks| self.score_mask(entry, argument, minimum, masks),
        )
    }

    fn score_mask(&self, entry: &Entry, argument: usize, minimum: usize, masks: &Masks) -> Option<(usize, usize)> {
        let mut matched = 0_u128;
        let mut written = 0_u128;
        let mut current_block = None;
        let mut current_writes = 0_u128;
        let mut colocated = 0_usize;
        for access in entry.accesses.iter().filter(|access| access.argument == argument) {
            let Some(range) = access.range() else { continue };
            let mut mask = 0_u128;
            for (index, offset) in self.expected.iter().enumerate() {
                if range.contains(offset) {
                    mask |= 1_u128 << index;
                }
            }
            if access.write {
                written |= mask;
                if current_block != Some(access.block) {
                    colocated = colocated.max(current_writes.count_ones() as usize);
                    current_writes = 0;
                    current_block = Some(access.block);
                }
                current_writes |= mask & masks.ranking;
            } else if !masks.required.is_empty() {
                continue;
            }
            matched |= mask;
        }
        if (matched.count_ones() as usize) < minimum
            || written & masks.queried == 0
            || masks.required.iter().any(|mask| written & mask == 0)
        {
            return None;
        }
        colocated = colocated.max(current_writes.count_ones() as usize);
        Some((colocated, matched.count_ones() as usize))
    }

    fn score_large(&self, entry: &Entry, argument: usize, minimum: usize) -> Option<(usize, usize)> {
        let mut matched = BTreeSet::new();
        let mut written = BTreeSet::new();
        let mut blocks = BTreeMap::<usize, BTreeSet<u64>>::new();
        for access in entry.accesses.iter().filter(|access| access.argument == argument) {
            let Some(range) = access.range() else { continue };
            for &offset in &self.expected {
                if range.contains(&offset) {
                    if access.write {
                        written.insert(offset);
                        if self.ranking.contains(&offset) {
                            blocks.entry(access.block).or_default().insert(offset);
                        }
                    } else if !self.required.is_empty() {
                        continue;
                    }
                    matched.insert(offset);
                }
            }
        }
        if matched.len() < minimum
            || written.is_disjoint(&self.queried)
            || self.required.iter().any(|offsets| written.is_disjoint(offsets))
        {
            return None;
        }
        Some((blocks.values().map(BTreeSet::len).max().unwrap_or(0), matched.len()))
    }
}
