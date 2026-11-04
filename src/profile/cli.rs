/*
 * XRef — sampling profile command arguments
 * Copyright (c) 2026 Alexander Panasenko
 * Contact: alex@prod.codes
 * Author: https://prod.codes/about/
 * Project: https://github.com/alex09x/xref
 * SPDX-License-Identifier: MIT OR Apache-2.0
 */
use super::config::{self, Callers, Config, Event};
use clap::{Args, Subcommand, ValueEnum};
use std::{path::PathBuf, time::Duration};

#[derive(Clone, Debug, Args)]
pub struct LiveProfileArgs {
    #[arg(long)]
    pub pid: u32,
    /// Capture duration, e.g. 10s or 200ms.
    #[arg(long, default_value = "10s", value_parser = config::parse_duration)]
    pub duration: Duration,
    /// Requested samples per second per thread; defaults to 4000.
    #[arg(long, conflicts_with = "period")]
    pub freq: Option<u64>,
    /// Hardware events per sample instead of a frequency.
    #[arg(long, conflicts_with = "freq")]
    pub period: Option<u64>,
    #[arg(long, value_enum, default_value_t = Event::Cycles)]
    pub event: Event,
    #[arg(long = "tid")]
    pub tids: Vec<u32>,
    #[arg(long, value_enum, default_value_t = Callers::Dwarf)]
    pub callers: Callers,
    #[arg(long = "within")]
    pub within: Vec<String>,
    #[arg(long, value_parser = crate::cli::parse_number)]
    pub trigger_probe: Option<u64>,
    #[arg(long, value_parser = config::parse_duration, requires = "trigger_probe")]
    pub window: Option<Duration>,
    #[arg(long)]
    pub json: bool,
    #[arg(long)]
    pub folded: Option<PathBuf>,
    #[arg(long)]
    pub out: Option<PathBuf>,
    #[arg(long, default_value_t = 10_000_000)]
    pub max_samples: u64,
    #[arg(long, default_value_t = 2048)]
    pub stack_bytes: u32,
    /// Include kernel-mode samples; requires suitable perf permissions.
    #[arg(long)]
    pub include_kernel: bool,
}

impl LiveProfileArgs {
    pub fn config(&self) -> Config {
        Config {
            event: self.event,
            frequency_hz: self.period.is_none().then_some(self.freq.unwrap_or(4000)),
            period: self.period,
            duration: self.duration,
            max_samples: self.max_samples,
            stack_bytes: self.stack_bytes,
            tids: self.tids.clone(),
            include_kernel: self.include_kernel,
            callers: self.callers,
            trigger_probe: self.trigger_probe,
            trigger_window: self.window.unwrap_or(Duration::from_millis(200)),
        }
    }
}

#[derive(Clone, Copy, Debug, Default, ValueEnum)]
pub enum GroupBy {
    #[default]
    Function,
    Block,
    Line,
    CallerPath,
    Instruction,
}

#[derive(Debug, Subcommand)]
pub enum ProfileCommand {
    /// Summarize an existing .xprof recording.
    Report {
        profile: PathBuf,
        #[arg(long, default_value_t = 30)]
        top: usize,
        #[arg(long, value_enum, default_value_t = GroupBy::Function)]
        by: GroupBy,
        #[arg(long)]
        json: bool,
        #[arg(long)]
        folded: Option<PathBuf>,
    },
    /// Annotate assembly or pseudo-C for one function.
    Annotate {
        profile: PathBuf,
        function: String,
        #[arg(long)]
        c: bool,
        #[arg(long)]
        json: bool,
    },
    /// Compare two recorded profiles normalized by their sample counts.
    Diff {
        before: PathBuf,
        after: PathBuf,
        #[arg(long)]
        other: Option<PathBuf>,
        #[arg(long, default_value_t = 30)]
        top: usize,
        #[arg(long)]
        json: bool,
    },
    /// Convert perf.data or perf-script text to a .xprof recording.
    Import {
        input: PathBuf,
        #[arg(long)]
        out: PathBuf,
        #[arg(long)]
        base: Option<String>,
        #[arg(long)]
        maps: Option<PathBuf>,
        #[arg(long)]
        target_path: Option<PathBuf>,
        #[arg(long)]
        pid: Option<u32>,
    },
}
