/*
 * XRef — bounded sampling profile configuration
 * Copyright (c) 2026 Alexander Panasenko
 * Contact: alex@prod.codes
 * Author: https://prod.codes/about/
 * Project: https://github.com/alex09x/xref
 * SPDX-License-Identifier: MIT OR Apache-2.0
 */
use clap::ValueEnum;
use serde::Serialize;
use std::time::Duration;

pub const MAX_DURATION_MS: u64 = 7 * 24 * 60 * 60 * 1000;
pub const MAX_THREADS: usize = 256;
pub const MAX_SAMPLES: u64 = 50_000_000;
pub const MAX_STACK_BYTES: u32 = 65_528;

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, ValueEnum)]
#[serde(rename_all = "snake_case")]
pub enum Event {
    #[default]
    Cycles,
    Instructions,
    CacheMisses,
    BranchMisses,
}

impl Event {
    #[cfg(any(test, all(target_os = "linux", target_arch = "x86_64")))]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Cycles => "cycles",
            Self::Instructions => "instructions",
            Self::CacheMisses => "cache-misses",
            Self::BranchMisses => "branch-misses",
        }
    }
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, ValueEnum)]
#[serde(rename_all = "snake_case")]
pub enum Callers {
    #[default]
    Dwarf,
    Lbr,
    Fp,
    None,
}

impl Callers {
    #[cfg(any(test, all(target_os = "linux", target_arch = "x86_64")))]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Dwarf => "dwarf",
            Self::Lbr => "lbr",
            Self::Fp => "fp",
            Self::None => "none",
        }
    }
}

#[cfg_attr(not(any(test, all(target_os = "linux", target_arch = "x86_64"))), allow(dead_code))]
#[derive(Clone, Debug)]
pub struct Config {
    pub event: Event,
    pub frequency_hz: Option<u64>,
    pub period: Option<u64>,
    pub duration: Duration,
    pub max_samples: u64,
    pub stack_bytes: u32,
    pub tids: Vec<u32>,
    pub include_kernel: bool,
    pub callers: Callers,
    pub trigger_probe: Option<u64>,
    pub trigger_window: Duration,
    pub max_windows: Option<usize>,
    pub trigger_fetch: Vec<String>,
    pub trigger_filter: Vec<String>,
    /// Accept per-thread triggers when the system-wide trigger is unavailable; such captures can
    /// miss a thread that starts, hits the trigger and exits between two `/proc` polls.
    pub allow_per_thread_trigger: bool,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            event: Event::Cycles,
            frequency_hz: Some(4000),
            period: None,
            duration: Duration::from_secs(10),
            max_samples: 10_000_000,
            stack_bytes: 2048,
            tids: Vec::new(),
            include_kernel: false,
            callers: Callers::Dwarf,
            trigger_probe: None,
            trigger_window: Duration::from_millis(200),
            max_windows: None,
            trigger_fetch: Vec::new(),
            trigger_filter: Vec::new(),
            allow_per_thread_trigger: false,
        }
    }
}

impl Config {
    pub fn validate(&self) -> Result<(), String> {
        if self.duration.is_zero() || self.duration > Duration::from_millis(MAX_DURATION_MS) {
            return Err(format!("profile duration must be in 1..={MAX_DURATION_MS} ms"));
        }
        match (self.frequency_hz, self.period) {
            (Some(1..=100_000), None) | (None, Some(1..)) => {}
            _ => return Err("profile requires exactly one positive --freq (at most 100000) or --period".to_owned()),
        }
        if !(1..=MAX_SAMPLES).contains(&self.max_samples) {
            return Err(format!("profile max samples must be in 1..={MAX_SAMPLES}"));
        }
        if self.stack_bytes == 0 || self.stack_bytes > MAX_STACK_BYTES || !self.stack_bytes.is_multiple_of(8) {
            return Err(format!("profile stack bytes must be an 8-byte multiple in 8..={MAX_STACK_BYTES}"));
        }
        if self.tids.len() > MAX_THREADS || self.tids.contains(&0) {
            return Err(format!("profile TIDs must be non-zero and at most {MAX_THREADS} entries"));
        }
        if self.trigger_probe.is_some() && (self.trigger_window.is_zero() || self.trigger_window > self.duration) {
            return Err("trigger window must be positive and no longer than the profile duration".to_owned());
        }
        if self.max_windows.is_some_and(|count| count == 0 || count > 10_000 || self.trigger_probe.is_none()) {
            return Err("max windows requires a trigger and must be between 1 and 10000".to_owned());
        }
        if self.trigger_probe.is_none() && (!self.trigger_fetch.is_empty() || !self.trigger_filter.is_empty()) {
            return Err("trigger fetches and filters require a trigger probe".to_owned());
        }
        #[cfg(any(target_os = "linux", test))]
        {
            let fetches = crate::live::parse_profile_fetches(&self.trigger_fetch)?;
            let names = fetches.iter().map(|fetch| fetch.name.clone()).collect::<Vec<_>>();
            crate::live::parse_profile_filters(&self.trigger_filter, false, &names)?;
        }
        let unique: std::collections::BTreeSet<_> = self.tids.iter().collect();
        if unique.len() != self.tids.len() {
            return Err("profile TIDs must be distinct".to_owned());
        }
        Ok(())
    }
}

pub fn parse_duration(text: &str) -> Result<Duration, String> {
    let (number, multiplier) = if let Some(value) = text.strip_suffix("ms") {
        (value, 1)
    } else if let Some(value) = text.strip_suffix('s') {
        (value, 1000)
    } else {
        return Err("duration must have ms or s suffix".to_owned());
    };
    let milliseconds =
        number.parse::<u64>().map_err(|_| "invalid duration")?.checked_mul(multiplier).ok_or("duration overflow")?;
    if !(1..=MAX_DURATION_MS).contains(&milliseconds) {
        return Err("duration out of range".to_owned());
    }
    Ok(Duration::from_millis(milliseconds))
}
