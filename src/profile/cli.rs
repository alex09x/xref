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
    /// Capture duration in milliseconds.
    #[arg(long, conflicts_with = "duration")]
    pub duration_ms: Option<u64>,
    /// Requested samples per second per thread; defaults to 4000.
    #[arg(long, visible_alias = "hz", conflicts_with = "period")]
    pub freq: Option<u64>,
    /// Hardware events per sample instead of a frequency.
    #[arg(long, conflicts_with = "freq")]
    pub period: Option<u64>,
    #[arg(long, value_enum, default_value_t = Event::Cycles)]
    pub event: Event,
    #[arg(long = "tid")]
    pub tids: Vec<u32>,
    #[arg(long, visible_alias = "callgraph", value_enum, default_value_t = Callers::Dwarf)]
    pub callers: Callers,
    #[arg(long = "within")]
    pub within: Vec<String>,
    #[arg(long, value_parser = crate::cli::parse_number)]
    pub trigger_probe: Option<u64>,
    #[arg(long, value_parser = config::parse_duration, requires = "trigger_probe")]
    pub window: Option<Duration>,
    #[arg(long, requires = "trigger_probe", conflicts_with = "window")]
    pub window_ms: Option<u64>,
    /// Record up to this many separate post-trigger windows.
    #[arg(long, requires = "trigger_probe")]
    pub max_windows: Option<usize>,
    /// Named tracefs fetch, e.g. op=+40(%sp):u64, for trigger filtering.
    #[arg(long = "trigger-fetch", requires = "trigger_probe")]
    pub trigger_fetch: Vec<String>,
    /// Numeric predicate over a named trigger fetch.
    #[arg(long = "trigger-filter", requires = "trigger_probe")]
    pub trigger_filter: Vec<String>,
    /// Without writable tracefs / system-wide perf access, fall back to per-thread triggers
    /// (may miss a thread that starts, hits the trigger and exits between /proc polls).
    #[arg(long = "allow-per-thread-trigger", requires = "trigger_probe")]
    pub allow_per_thread_trigger: bool,
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
            duration: self.duration_ms.map_or(self.duration, Duration::from_millis),
            max_samples: self.max_samples,
            stack_bytes: self.stack_bytes,
            tids: self.tids.clone(),
            include_kernel: self.include_kernel,
            callers: self.callers,
            trigger_probe: self.trigger_probe,
            trigger_window: self
                .window_ms
                .map(Duration::from_millis)
                .or(self.window)
                .unwrap_or(Duration::from_millis(200)),
            max_windows: self.max_windows.or_else(|| {
                (self.window_ms.is_some() || !self.trigger_fetch.is_empty() || !self.trigger_filter.is_empty())
                    .then_some(1)
            }),
            trigger_fetch: self.trigger_fetch.clone(),
            trigger_filter: self.trigger_filter.clone(),
            allow_per_thread_trigger: self.allow_per_thread_trigger,
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

#[derive(Clone, Copy, Debug, clap::ValueEnum)]
pub enum PercentScale {
    Both,
    Function,
    Profile,
}

#[derive(Clone, Copy, Debug, clap::ValueEnum)]
pub enum DiffGroup {
    Function,
}

fn parse_delta(value: &str) -> Result<f64, String> {
    let value = value.strip_suffix('%').unwrap_or(value).parse::<f64>().map_err(|_| "invalid percentage")?;
    if !value.is_finite() || !(0.0..=100.0).contains(&value) {
        return Err("delta must be a percentage between 0 and 100".into());
    }
    Ok(value)
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
        /// Keep samples whose call chain includes this function or address.
        #[arg(long = "within")]
        within: Vec<String>,
        /// Select one captured trigger window (numbered from one).
        #[arg(long, conflicts_with = "merge_windows")]
        window: Option<usize>,
        /// Report the union of all captured windows.
        #[arg(long)]
        merge_windows: bool,
    },
    /// Annotate assembly or pseudo-C for one function.
    Annotate {
        profile: PathBuf,
        function: String,
        #[arg(long)]
        c: bool,
        #[arg(long)]
        json: bool,
        /// Omit rows with fewer samples than this threshold.
        #[arg(long, default_value_t = 0)]
        min_samples: u64,
        #[arg(long, value_enum, default_value_t = PercentScale::Both)]
        percent: PercentScale,
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
        #[arg(long, value_enum, default_value_t = DiffGroup::Function)]
        by: DiffGroup,
        #[arg(long, default_value = "0", value_parser = parse_delta)]
        min_delta: f64,
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
