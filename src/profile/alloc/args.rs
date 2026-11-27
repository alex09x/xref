/*
 * XRef — `live alloc` command arguments
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
pub struct AllocArgs {
    /// Target process ID.
    #[arg(long)]
    pub pid: u32,
    /// How long to observe, e.g. 10s or 500ms; also ends at process exit or Ctrl-C.
    #[arg(long, default_value = "10s", value_parser = parse_span)]
    pub duration: Duration,
    /// User stack bytes copied at each allocation for DWARF unwinding.
    #[arg(long, default_value_t = 4096)]
    pub stack_bytes: u32,
    /// The allocator to trace: a path the process maps that exports `malloc` and `free` (by
    /// default the executable, then other libraries, then libc; the others are listed).
    #[arg(long)]
    pub allocator: Option<String>,
    /// Directory (new) for `alloc.xprof` (bytes allocated by stack) and `live.xprof` (bytes still
    /// allocated at the end), for `xref profile report` and `xref profile diff`.
    #[arg(long)]
    pub out: Option<PathBuf>,
    /// Rows in each table of the report.
    #[arg(long, default_value_t = 20)]
    pub top: usize,
    /// Print the capture and the report as JSON.
    #[arg(long)]
    pub json: bool,
}

impl AllocArgs {
    pub fn validate(&self) -> Result<(), String> {
        if self.pid == 0 {
            return Err("invalid --pid 0".to_owned());
        }
        if self.duration.is_zero() || self.duration > Duration::from_secs(24 * 3600) {
            return Err("--duration must be 1ms..=24h".to_owned());
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
