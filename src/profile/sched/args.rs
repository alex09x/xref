/*
 * XRef — `live sched` command arguments
 * Copyright (c) 2026 Alexander Panasenko
 * Contact: alex@prod.codes
 * Author: https://prod.codes/about/
 * Project: https://github.com/alex09x/xref
 * SPDX-License-Identifier: MIT OR Apache-2.0
 */
use super::super::heap::args::{MAX_STACK_BYTES, parse_span};
use clap::Args;
use std::{path::PathBuf, time::Duration};

#[derive(Clone, Debug, Args)]
pub struct SchedArgs {
    /// Target process ID.
    #[arg(long)]
    pub pid: u32,
    /// How long to observe, e.g. 12s or 500ms; also ends at process exit or Ctrl-C.
    #[arg(long, default_value = "10s", value_parser = parse_span)]
    pub duration: Duration,
    /// User stack bytes copied at each switch-out, to unwind the stack the thread blocked in.
    #[arg(long, default_value_t = 8192)]
    pub stack_bytes: u32,
    /// Leave out system calls (they need the `raw_syscalls` tracepoints, readable by root).
    #[arg(long)]
    pub no_syscalls: bool,
    /// Keep the off-CPU recording at this new path (`.xprof`, weights are nanoseconds off CPU), for
    /// `xref profile report` and `xref profile diff`.
    #[arg(long)]
    pub out: Option<PathBuf>,
    /// Rows in each table of the report.
    #[arg(long, default_value_t = 20)]
    pub top: usize,
    /// Print the capture and the report as JSON.
    #[arg(long)]
    pub json: bool,
}

impl SchedArgs {
    pub fn validate(&self) -> Result<(), String> {
        if self.pid == 0 {
            return Err("invalid --pid 0".to_owned());
        }
        if self.stack_bytes == 0 || self.stack_bytes > MAX_STACK_BYTES || !self.stack_bytes.is_multiple_of(8) {
            return Err(format!("--stack-bytes must be a multiple of 8 in 8..={MAX_STACK_BYTES}"));
        }
        if !(1..=10_000).contains(&self.top) {
            return Err("--top must be in 1..=10000".to_owned());
        }
        Ok(())
    }
}
