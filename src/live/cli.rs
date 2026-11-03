/*
 * XRef — Live Linux procfs inspection and xref-aware memory scanning
 * Copyright (c) 2026 Alexander Panasenko
 * Contact: alex@prod.codes
 * Author: https://prod.codes/about/
 * Project: https://github.com/alex09x/xref
 * SPDX-License-Identifier: MIT OR Apache-2.0
 */

//! Command-line definitions and argument validators for `xref [--bin BIN] live SUBCOMMAND`.

#[cfg(any(target_os = "linux", test))]
use std::fmt::Write as _;

use clap::{Args, Subcommand};

pub const DEFAULT_ALIGN: usize = 8;
pub const DEFAULT_BEFORE_WORDS: usize = 2;
pub const DEFAULT_AFTER_WORDS: usize = 6;
pub const MAX_CONTEXT_WORDS: usize = 16;
pub const MAX_PATTERN_WORDS: usize = 64;
pub const DEFAULT_MAX_HITS: usize = 32;
pub const MAX_HITS_CAP: usize = 1024;
pub const DEFAULT_MAX_BYTES: u64 = 268_435_456;
pub const DEFAULT_TIMEOUT_MS: u64 = 5000;

#[derive(Clone, Debug, Args)]
pub struct LiveCommand {
    #[command(subcommand)]
    pub subcommand: LiveSubcommand,
}

#[derive(Clone, Debug, Subcommand)]
pub enum LiveSubcommand {
    /// Inspect `/proc/<pid>/maps` and `/proc/<pid>/smaps`, binary identity, and PIE slide.
    Maps {
        /// Target process ID (must be non-zero).
        #[arg(long)]
        pid: u32,
        /// Continue even if `--bin` does not match `/proc/<pid>/exe`.
        #[arg(long)]
        force_bin: bool,
        /// Emit structured `schema_version: 1` JSON output.
        #[arg(long)]
        json: bool,
    },
    /// Translate static ELF VAs and live runtime VAs bidirectionally using PIE slide and `PT_LOAD`.
    Resolve {
        /// Target process ID (must be non-zero).
        #[arg(long)]
        pid: u32,
        /// Continue even if `--bin` does not match `/proc/<pid>/exe`.
        #[arg(long)]
        force_bin: bool,
        /// Emit structured `schema_version: 1` JSON output.
        #[arg(long)]
        json: bool,
        /// Static or live runtime addresses (`0x...` hex or decimal).
        #[arg(required = true, value_name = "ADDR", value_parser = crate::cli::parse_number)]
        addrs: Vec<u64>,
    },
    /// Scan eligible private `rw-p` regions for consecutive little-endian `u64` values.
    Memscan {
        /// Target process ID (must be non-zero).
        #[arg(long)]
        pid: u32,
        /// Required byte alignment for matches (`1`, `2`, `4`, or `8`).
        #[arg(long, default_value_t = DEFAULT_ALIGN, value_parser = parse_align)]
        align: usize,
        /// Number of 8-byte words to read before each match (`0..=16`).
        #[arg(long, default_value_t = DEFAULT_BEFORE_WORDS, value_parser = parse_context_words)]
        before_words: usize,
        /// Number of 8-byte words to read after each match (`0..=16`).
        #[arg(long, default_value_t = DEFAULT_AFTER_WORDS, value_parser = parse_context_words)]
        after_words: usize,
        /// Maximum number of hits before stopping (`1..=1024`).
        #[arg(long, default_value_t = DEFAULT_MAX_HITS)]
        max_hits: usize,
        /// Maximum scannable region bytes read before stopping.
        #[arg(long, default_value_t = DEFAULT_MAX_BYTES)]
        max_bytes: u64,
        /// Cooperative inter-chunk elapsed-time budget in milliseconds.
        #[arg(long, default_value_t = DEFAULT_TIMEOUT_MS)]
        timeout_ms: u64,
        /// Continue even if `--bin` does not match `/proc/<pid>/exe`.
        #[arg(long)]
        force_bin: bool,
        /// Emit structured `schema_version: 1` JSON output.
        #[arg(long)]
        json: bool,
        /// Consecutive `u64` values (`0x...` hex or decimal) encoded as little-endian bytes.
        #[arg(required = true, value_name = "VALUES", value_parser = crate::cli::parse_number)]
        values: Vec<u64>,
    },
}

impl LiveCommand {
    #[cfg(all(test, target_os = "linux"))]
    #[must_use]
    pub const fn maps(pid: u32, force_bin: bool, json: bool) -> Self {
        Self { subcommand: LiveSubcommand::Maps { pid, force_bin, json } }
    }

    #[cfg(all(test, target_os = "linux"))]
    #[must_use]
    pub const fn resolve(pid: u32, force_bin: bool, json: bool, addrs: Vec<u64>) -> Self {
        Self { subcommand: LiveSubcommand::Resolve { pid, force_bin, json, addrs } }
    }

    #[must_use]
    pub const fn pid(&self) -> u32 {
        match &self.subcommand {
            LiveSubcommand::Maps { pid, .. }
            | LiveSubcommand::Resolve { pid, .. }
            | LiveSubcommand::Memscan { pid, .. } => *pid,
        }
    }

    pub fn validate(&self) -> Result<(), String> {
        if self.pid() == 0 {
            return Err("invalid --pid 0: process ID must be non-zero".to_owned());
        }
        match &self.subcommand {
            LiveSubcommand::Maps { .. } => Ok(()),
            LiveSubcommand::Resolve { addrs, .. } => {
                if addrs.is_empty() {
                    return Err("resolve requires at least one <ADDR>".to_owned());
                }
                Ok(())
            }
            LiveSubcommand::Memscan { align, before_words, after_words, max_hits, values, .. } => {
                validate_align(*align)?;
                validate_context_words(*before_words, "--before-words")?;
                validate_context_words(*after_words, "--after-words")?;
                if *max_hits == 0 || *max_hits > MAX_HITS_CAP {
                    return Err(format!("--max-hits {max_hits} must be in 1..={MAX_HITS_CAP}"));
                }
                if values.is_empty() || values.len() > MAX_PATTERN_WORDS {
                    return Err(format!("memscan requires 1..={MAX_PATTERN_WORDS} <VALUES> words"));
                }
                Ok(())
            }
        }
    }
}

pub fn parse_align(text: &str) -> Result<usize, String> {
    let align = text.parse::<usize>().map_err(|err| format!("invalid --align {text}: {err}"))?;
    validate_align(align)?;
    Ok(align)
}

pub fn validate_align(align: usize) -> Result<(), String> {
    if matches!(align, 1 | 2 | 4 | 8) {
        Ok(())
    } else {
        Err(format!("invalid --align {align}: allowed values are 1, 2, 4, or 8"))
    }
}

pub fn parse_context_words(text: &str) -> Result<usize, String> {
    let words = text.parse::<usize>().map_err(|err| format!("invalid context word count {text}: {err}"))?;
    validate_context_words(words, "context words")?;
    Ok(words)
}

pub fn validate_context_words(words: usize, flag: &str) -> Result<(), String> {
    if words <= MAX_CONTEXT_WORDS { Ok(()) } else { Err(format!("{flag} {words} exceeds maximum {MAX_CONTEXT_WORDS}")) }
}

#[cfg(any(target_os = "linux", test))]
#[must_use]
pub fn encode_values_le(values: &[u64]) -> Vec<u8> {
    let mut needle = Vec::with_capacity(values.len().saturating_mul(8));
    for &word in values {
        needle.extend_from_slice(&word.to_le_bytes());
    }
    needle
}

#[cfg(any(target_os = "linux", test))]
#[must_use]
pub fn format_bytes_hex(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(2 + bytes.len().saturating_mul(2));
    out.push_str("0x");
    for &byte in bytes {
        let _ = write!(out, "{byte:02x}");
    }
    out
}
