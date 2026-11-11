/*
 * XRef — bounded profile sample aggregation
 * Copyright (c) 2026 Alexander Panasenko
 * Contact: alex@prod.codes
 * Author: https://prod.codes/about/
 * Project: https://github.com/alex09x/xref
 * SPDX-License-Identifier: MIT OR Apache-2.0
 */
use serde::Serialize;
use std::collections::HashMap;

#[derive(Clone, Copy, Debug, Hash, PartialEq, Eq, PartialOrd, Ord, Serialize)]
pub struct FunctionKey {
    /// Interned module identity, including explicit unknown/kernel identities.
    pub module: u32,
    /// None means the function could not be resolved in that module.
    pub start: Option<u64>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Frame {
    pub function: FunctionKey,
    /// Instruction address in the module's static address space when known.
    pub instruction: Option<u64>,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize)]
pub struct Counts {
    pub self_samples: u64,
    pub total_samples: u64,
    pub self_period: u64,
    pub total_period: u64,
}

#[derive(Clone, Debug)]
pub struct Limits {
    pub functions: usize,
    pub instructions: usize,
    pub paths: usize,
    pub depth: usize,
    pub path_frames: usize,
}

impl Default for Limits {
    fn default() -> Self {
        Self { functions: 262_144, instructions: 1_048_576, paths: 262_144, depth: 512, path_frames: 2_000_000 }
    }
}

pub struct Aggregate {
    pub samples: u64,
    pub total_period: u64,
    pub lost: u64,
    pub incomplete: bool,
    pub functions: HashMap<FunctionKey, Counts>,
    pub instructions: HashMap<(FunctionKey, u64), u64>,
    /// Frame order is root first, as required by folded-stack consumers.
    pub paths: HashMap<Vec<FunctionKey>, u64>,
    /// The summed `period` of each kept path (bytes for a heap capture).
    pub path_periods: HashMap<Vec<FunctionKey>, u64>,
    limits: Limits,
    path_buffer: Vec<FunctionKey>,
    path_frames: usize,
}

impl Aggregate {
    pub fn new(limits: Limits) -> Self {
        Self {
            samples: 0,
            total_period: 0,
            lost: 0,
            incomplete: false,
            functions: HashMap::new(),
            instructions: HashMap::new(),
            paths: HashMap::new(),
            path_periods: HashMap::new(),
            limits,
            path_buffer: Vec::new(),
            path_frames: 0,
        }
    }

    /// Frames are leaf first. Recursive appearances contribute once to inclusive
    /// sample counts; their full recursive path is retained separately.
    pub fn add(&mut self, frames: &[Frame], period: u64) {
        self.samples = add(self.samples, 1, &mut self.incomplete);
        self.total_period = add(self.total_period, period, &mut self.incomplete);
        if frames.len() > self.limits.depth {
            self.incomplete = true;
        }
        let frames = &frames[..frames.len().min(self.limits.depth)];
        for (index, frame) in frames.iter().enumerate() {
            if !self.functions.contains_key(&frame.function) && self.functions.len() >= self.limits.functions {
                self.incomplete = true;
                continue;
            }
            let count = self.functions.entry(frame.function).or_default();
            if index == 0 {
                count.self_samples = add(count.self_samples, 1, &mut self.incomplete);
                count.self_period = add(count.self_period, period, &mut self.incomplete);
            }
            if !frames[..index].iter().any(|earlier| earlier.function == frame.function) {
                count.total_samples = add(count.total_samples, 1, &mut self.incomplete);
                count.total_period = add(count.total_period, period, &mut self.incomplete);
            }
        }
        if let Some(leaf) = frames.first()
            && let Some(ip) = leaf.instruction
        {
            let key = (leaf.function, ip);
            if self.instructions.contains_key(&key) || self.instructions.len() < self.limits.instructions {
                let count = self.instructions.entry(key).or_default();
                *count = add(*count, 1, &mut self.incomplete);
            } else {
                self.incomplete = true;
            }
        }
        if !frames.is_empty() {
            self.path_buffer.clear();
            self.path_buffer.extend(frames.iter().rev().map(|frame| frame.function));
            if let Some(count) = self.paths.get_mut(self.path_buffer.as_slice()) {
                *count = add(*count, 1, &mut self.incomplete);
                if let Some(bytes) = self.path_periods.get_mut(self.path_buffer.as_slice()) {
                    *bytes = add(*bytes, period, &mut self.incomplete);
                }
            } else if self.paths.len() < self.limits.paths
                && self
                    .path_frames
                    .checked_add(self.path_buffer.len())
                    .is_some_and(|frames| frames <= self.limits.path_frames)
            {
                self.path_frames += self.path_buffer.len();
                self.paths.insert(self.path_buffer.clone(), 1);
                self.path_periods.insert(self.path_buffer.clone(), period);
            } else {
                self.incomplete = true;
            }
        }
    }

    pub fn add_lost(&mut self, count: u64) {
        self.lost = add(self.lost, count, &mut self.incomplete);
        self.incomplete |= count > 0;
    }
}

fn add(a: u64, b: u64, incomplete: &mut bool) -> u64 {
    a.checked_add(b).unwrap_or_else(|| {
        *incomplete = true;
        u64::MAX
    })
}
