/*
 * XRef — `live heap` command arguments
 * Copyright (c) 2026 Alexander Panasenko
 * Contact: alex@prod.codes
 * Author: https://prod.codes/about/
 * Project: https://github.com/alex09x/xref
 * SPDX-License-Identifier: MIT OR Apache-2.0
 */
use clap::Args;
use std::{path::PathBuf, time::Duration};

/// Largest user stack copy perf accepts per sample.
pub const MAX_STACK_BYTES: u32 = 65_528;

#[derive(Clone, Debug, Args)]
pub struct HeapArgs {
    /// Target process ID.
    #[arg(long)]
    pub pid: u32,
    /// How long to observe, e.g. 10m or 30s; also ends at process exit or Ctrl-C.
    #[arg(long, default_value = "60s", value_parser = parse_span)]
    pub duration: Duration,
    /// Also write a snapshot every interval (e.g. 30s), to see which stacks grow.
    #[arg(long, value_parser = parse_span, requires = "out")]
    pub interval: Option<Duration>,
    /// Keep one stack per this many mapped bytes (e.g. 4M); every mapping at least this large is kept exactly.
    #[arg(long, default_value = "4M", value_parser = parse_size)]
    pub sample_bytes: u64,
    /// User stack bytes copied with each memory syscall for DWARF unwinding.
    #[arg(long, default_value_t = 8192)]
    pub stack_bytes: u32,
    /// Directory (new) for the `.xprof` snapshots (`heap-0001.xprof`, ...); `xref profile diff` compares two.
    #[arg(long)]
    pub out: Option<PathBuf>,
    /// Rows in the report.
    #[arg(long, default_value_t = 30)]
    pub top: usize,
    /// Also write folded stacks weighted by bytes (flame-graph input) to this new file.
    #[arg(long)]
    pub folded: Option<PathBuf>,
    /// Print the capture statistics and the report as JSON.
    #[arg(long)]
    pub json: bool,
}

impl HeapArgs {
    pub fn validate(&self) -> Result<(), String> {
        if self.pid == 0 {
            return Err("invalid --pid 0".to_owned());
        }
        if self.stack_bytes == 0 || self.stack_bytes > MAX_STACK_BYTES || !self.stack_bytes.is_multiple_of(8) {
            return Err(format!("--stack-bytes must be a multiple of 8 in 8..={MAX_STACK_BYTES}"));
        }
        if self.sample_bytes < 4096 {
            return Err("--sample-bytes must be at least 4096".to_owned());
        }
        if self.top == 0 {
            return Err("--top must be at least 1".to_owned());
        }
        if self.interval.is_some_and(|every| every < Duration::from_secs(1)) {
            return Err("--interval must be at least 1s".to_owned());
        }
        Ok(())
    }
}

/// `500ms`, `30s`, `10m`, `2h`; at most 24 hours.
pub fn parse_span(text: &str) -> Result<Duration, String> {
    let text = text.trim();
    let (number, unit_ms) = if let Some(v) = text.strip_suffix("ms") {
        (v, 1)
    } else if let Some(v) = text.strip_suffix('s') {
        (v, 1000)
    } else if let Some(v) = text.strip_suffix('m') {
        (v, 60_000)
    } else if let Some(v) = text.strip_suffix('h') {
        (v, 3_600_000)
    } else {
        return Err(format!("duration {text:?} needs a unit: ms, s, m or h"));
    };
    let ms = number
        .parse::<u64>()
        .ok()
        .and_then(|n| n.checked_mul(unit_ms))
        .filter(|ms| (1..=86_400_000).contains(ms))
        .ok_or_else(|| format!("duration {text:?} must be 1ms..=24h"))?;
    Ok(Duration::from_millis(ms))
}

/// `4096`, `512K`, `4M`, `1G` (binary units).
pub fn parse_size(text: &str) -> Result<u64, String> {
    let text = text.trim();
    let (digits, shift) = match text.chars().last() {
        Some('k' | 'K') => (&text[..text.len() - 1], 10),
        Some('m' | 'M') => (&text[..text.len() - 1], 20),
        Some('g' | 'G') => (&text[..text.len() - 1], 30),
        _ => (text, 0),
    };
    let value: u64 = digits.parse().map_err(|_| format!("invalid size {text:?} (e.g. 4096, 512K, 4M)"))?;
    value.checked_shl(shift).filter(|v| v >> shift == value).ok_or_else(|| format!("size {text:?} is too large"))
}

#[cfg(test)]
mod tests {
    use super::{parse_size, parse_span};
    use std::time::Duration;

    #[test]
    fn sizes_take_binary_suffixes() {
        assert_eq!(parse_size("4096"), Ok(4096));
        assert_eq!(parse_size("512K"), Ok(512 << 10));
        assert_eq!(parse_size("4M"), Ok(4 << 20));
        assert_eq!(parse_size("1g"), Ok(1 << 30));
        assert!(parse_size("x").is_err());
        assert_eq!(parse_span("30m"), Ok(Duration::from_secs(1800)));
        assert_eq!(parse_span("250ms"), Ok(Duration::from_millis(250)));
        assert!(parse_span("25h").is_err() && parse_span("10").is_err());
    }
}
