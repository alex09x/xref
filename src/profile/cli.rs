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
    /// Target process ID.
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
    /// Hardware event that drives sampling.
    #[arg(long, value_enum, default_value_t = Event::Cycles)]
    pub event: Event,
    /// Sample only this thread ID (repeatable); all threads by default.
    #[arg(long = "tid")]
    pub tids: Vec<u32>,
    /// How call chains are recorded: DWARF stack copies unwound with `.eh_frame`, LBR, frame pointers, or none.
    #[arg(long, visible_alias = "callgraph", value_enum, default_value_t = Callers::Dwarf)]
    pub callers: Callers,
    /// Report only samples whose call chain includes this function or address (repeatable).
    #[arg(long = "within")]
    pub within: Vec<String>,
    /// Code address whose uprobe hits open recording windows; without it the whole duration is recorded.
    #[arg(long, value_parser = crate::cli::parse_number)]
    pub trigger_probe: Option<u64>,
    /// Length of each trigger window, e.g. 200ms (the default).
    #[arg(long, value_parser = config::parse_duration, requires = "trigger_probe")]
    pub window: Option<Duration>,
    /// Length of each trigger window in milliseconds.
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
    /// Print the capture statistics and the report as JSON.
    #[arg(long)]
    pub json: bool,
    /// Also write folded stacks (flame-graph input) to this new file.
    #[arg(long)]
    pub folded: Option<PathBuf>,
    /// Keep the `.xprof` recording at this new path; without it a temporary recording is deleted after the report.
    #[arg(long)]
    pub out: Option<PathBuf>,
    /// Stop recording after this many samples.
    #[arg(long, default_value_t = 10_000_000)]
    pub max_samples: u64,
    /// User stack bytes copied with each sample for DWARF unwinding.
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
        /// The `.xprof` recording.
        profile: PathBuf,
        /// Number of rows to print.
        #[arg(long, default_value_t = 30)]
        top: usize,
        /// What a row aggregates: function, basic block, source line, caller path or instruction.
        #[arg(long, value_enum, default_value_t = GroupBy::Function)]
        by: GroupBy,
        /// Print the report as JSON.
        #[arg(long)]
        json: bool,
        /// Also write folded stacks (flame-graph input) to this file.
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
        /// The `.xprof` recording.
        profile: PathBuf,
        /// Function address or symbol name.
        function: String,
        /// Annotate pseudo-C lines instead of assembly.
        #[arg(long)]
        c: bool,
        /// Print the annotation as JSON.
        #[arg(long)]
        json: bool,
        /// Omit rows with fewer samples than this threshold.
        #[arg(long, default_value_t = 0)]
        min_samples: u64,
        /// Which shares to print: of the function, of the whole profile, or both.
        #[arg(long, value_enum, default_value_t = PercentScale::Both)]
        percent: PercentScale,
    },
    /// Compare two recorded profiles normalized by their sample counts.
    Diff {
        /// The earlier `.xprof` recording.
        before: PathBuf,
        /// The later `.xprof` recording.
        after: PathBuf,
        /// Binary AFTER was recorded from, when it is another build; functions are then paired heuristically.
        #[arg(long)]
        other: Option<PathBuf>,
        /// Number of rows to print.
        #[arg(long, default_value_t = 30)]
        top: usize,
        /// Print the comparison as JSON.
        #[arg(long)]
        json: bool,
        /// What a row aggregates.
        #[arg(long, value_enum, default_value_t = DiffGroup::Function)]
        by: DiffGroup,
        /// Omit rows whose share changed by fewer percentage points than this.
        #[arg(long, default_value = "0", value_parser = parse_delta)]
        min_delta: f64,
    },
    /// Convert perf.data or perf-script text to a .xprof recording.
    Import {
        /// `perf.data` file or `perf script` text.
        input: PathBuf,
        /// Path of the new `.xprof` recording.
        #[arg(long)]
        out: PathBuf,
        /// Runtime address of the lowest image virtual address, when no maps are given.
        #[arg(long)]
        base: Option<String>,
        /// Saved `/proc/PID/maps` of the recorded process.
        #[arg(long)]
        maps: Option<PathBuf>,
        /// Executable path as it appears in the maps or perf MMAP records.
        #[arg(long)]
        target_path: Option<PathBuf>,
        /// Process ID to select from the recording.
        #[arg(long)]
        pid: Option<u32>,
    },
}
