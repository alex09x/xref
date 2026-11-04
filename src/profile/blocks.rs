/*
 * XRef — sampled basic-block aggregation
 * Copyright (c) 2026 Alexander Panasenko
 * Contact: alex@prod.codes
 * Author: https://prod.codes/about/
 * Project: https://github.com/alex09x/xref
 * SPDX-License-Identifier: MIT OR Apache-2.0
 */
use super::aggregate::{Aggregate, FunctionKey};
use crate::{api::FunctionFlow, image::Image, scan};
use serde::Serialize;
use std::collections::{BTreeMap, BTreeSet};

#[derive(Debug, Serialize)]
pub struct BlockRow {
    pub function: FunctionKey,
    pub start: u64,
    pub end: u64,
    pub samples: u64,
    pub percent: f64,
    pub cfg_incomplete: bool,
}

fn boundaries(image: &Image, start: u64) -> Option<(Vec<u64>, u64, bool)> {
    let function = image.function_at(start).filter(|function| function.start == start)?;
    let code = image.code(&function)?;
    let mut instructions = Vec::new();
    scan::decode(code, function.start, |instruction| instructions.push(*instruction));
    if instructions.is_empty() {
        return None;
    }
    let flow = FunctionFlow::new(&instructions, image, &function);
    let mut leaders = BTreeSet::from([function.start]);
    for (index, instruction) in instructions.iter().enumerate().skip(1) {
        if flow.predecessors[index].as_slice() != [index - 1] || flow.successors[index - 1].as_slice() != [index] {
            leaders.insert(instruction.ip());
        }
    }
    Some((leaders.into_iter().collect(), function.end, flow.incomplete))
}

pub fn collect(image: &Image, aggregate: &Aggregate) -> Vec<BlockRow> {
    let mut cache = BTreeMap::new();
    let mut counts = BTreeMap::<(FunctionKey, u64, u64, bool), u64>::new();
    for (&(function, ip), &samples) in &aggregate.instructions {
        if function.module != 1 {
            continue;
        }
        let Some(start) = function.start else { continue };
        let Some((leaders, end, incomplete)) = cache.entry(start).or_insert_with(|| boundaries(image, start)).as_ref()
        else {
            continue;
        };
        let position = leaders.partition_point(|leader| *leader <= ip);
        if position == 0 || ip >= *end {
            continue;
        }
        let block_start = leaders[position - 1];
        let block_end = leaders.get(position).copied().unwrap_or(*end);
        let count = counts.entry((function, block_start, block_end, *incomplete)).or_default();
        *count = count.saturating_add(samples);
    }
    let mut rows: Vec<_> = counts
        .into_iter()
        .map(|((function, start, end, cfg_incomplete), samples)| BlockRow {
            function,
            start,
            end,
            samples,
            percent: super::report::percent(samples, aggregate.samples),
            cfg_incomplete,
        })
        .collect();
    rows.sort_by(|a, b| b.samples.cmp(&a.samples).then_with(|| (a.function, a.start).cmp(&(b.function, b.start))));
    rows
}
