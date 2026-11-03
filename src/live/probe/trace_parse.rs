/*
 * XRef — Stage L2 tracefs uprobe definition builder, streaming line parser, and stats parser
 * Copyright (c) 2026 Alexander Panasenko
 * Contact: alex@prod.codes
 * Author: https://prod.codes/about/
 * Project: https://github.com/alex09x/xref
 * SPDX-License-Identifier: MIT OR Apache-2.0
 */

//! Pure formatting and parsing for Linux `tracefs` `uprobe_events`, `trace_pipe`, and `per_cpu` stats.

use std::fmt::Write as _;
use std::path::Path;

use crate::live::probe::types::LostEvents;

const MAX_TRACE_LINE_BYTES: usize = 4096;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ParsedRegisters {
    pub rdi: u64,
    pub rsi: u64,
    pub rdx: u64,
    pub rcx: u64,
    pub r8: u64,
    pub r9: u64,
    pub rax: u64,
    pub rsp: u64,
    pub rbp: Option<u64>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ParsedTraceEvent {
    pub probe_index: usize,
    pub tid: u32,
    pub tgid: Option<u32>,
    pub timestamp_ns: Option<u64>,
    pub hit_ip: u64,
    pub return_addr: Option<u64>,
    pub regs: Option<ParsedRegisters>,
}

#[must_use]
pub fn format_uprobe_definition(
    group: &str,
    event_name: &str,
    exec_path: &str,
    file_offset: u64,
    ra_fetch: Option<&str>,
    want_regs: bool,
) -> String {
    let mut def = format!("p:{group}/{event_name} {exec_path}:{file_offset:#x}");
    if let Some(ra_expr) = ra_fetch {
        let _ = write!(def, " ra={ra_expr}");
    }
    if want_regs {
        def.push_str(
            " rdi=%di:x64 rsi=%si:x64 rdx=%dx:x64 rcx=%cx:x64 r8=%r8:x64 r9=%r9:x64 rax=%ax:x64 rsp=%sp:x64 rbp=%bp:x64",
        );
    }
    def.push('\n');
    def
}

#[derive(Default)]
pub struct StreamingTraceLineBuffer {
    partial: Vec<u8>,
    discarding_overlong: bool,
}

impl StreamingTraceLineBuffer {
    pub fn push_chunk(&mut self, chunk: &[u8], mut on_line: impl FnMut(&str)) {
        for &byte in chunk {
            if byte == b'\n' {
                if !self.discarding_overlong && !self.partial.is_empty() {
                    emit_non_comment(&self.partial, &mut on_line);
                }
                self.partial.clear();
                self.discarding_overlong = false;
            } else if !self.discarding_overlong {
                if self.partial.len() < MAX_TRACE_LINE_BYTES {
                    self.partial.push(byte);
                } else {
                    self.partial.clear();
                    self.discarding_overlong = true;
                }
            }
        }
    }

    pub fn finish(&mut self, mut on_line: impl FnMut(&str)) {
        if !self.discarding_overlong && !self.partial.is_empty() {
            emit_non_comment(&self.partial, &mut on_line);
        }
        self.partial.clear();
        self.discarding_overlong = false;
    }
}

fn emit_non_comment(raw: &[u8], on_line: &mut impl FnMut(&str)) {
    let line = String::from_utf8_lossy(raw);
    let trimmed = line.trim_end_matches('\r');
    if !trimmed.trim_start().is_empty() && !trimmed.trim_start().starts_with('#') {
        on_line(trimmed);
    }
}

#[must_use]
pub fn parse_uprobe_trace_line(line: &str, event_prefix: &str) -> Option<ParsedTraceEvent> {
    let marker = format!(": {event_prefix}");
    let marker_pos = line.find(&marker)?;
    let header = &line[..marker_pos];
    let after_prefix = &line[marker_pos + marker.len()..];

    let (idx_str, after_event) = after_prefix.split_once(": (")?;
    let probe_index = idx_str.parse::<usize>().ok()?;
    let (ip_str, args_tail) = after_event.split_once(')')?;
    let hit_ip = parse_hex_or_dec_u64(ip_str.trim())?;

    let (thread_id, group_id) = parse_header_tid_tgid(header)?;
    let timestamp_ns = header.split_whitespace().last().and_then(parse_trace_timestamp_ns);

    let mut return_addr = None;
    let mut rdi = None;
    let mut rsi = None;
    let mut rdx = None;
    let mut rcx = None;
    let mut r8 = None;
    let mut r9 = None;
    let mut rax = None;
    let mut rsp = None;
    let mut rbp = None;

    for token in args_tail.split_whitespace() {
        let Some((key, val_str)) = token.split_once('=') else { continue };
        let Some(val) = parse_hex_or_dec_u64(val_str) else { continue };
        match key {
            "ra" => return_addr = Some(val),
            "rdi" => rdi = Some(val),
            "rsi" => rsi = Some(val),
            "rdx" => rdx = Some(val),
            "rcx" => rcx = Some(val),
            "r8" => r8 = Some(val),
            "r9" => r9 = Some(val),
            "rax" => rax = Some(val),
            "rsp" => rsp = Some(val),
            "rbp" => rbp = Some(val),
            _ => {}
        }
    }

    let regs = match (rdi, rsi, rdx, rcx, r8, r9, rax, rsp) {
        (Some(rdi), Some(rsi), Some(rdx), Some(rcx), Some(r8), Some(r9), Some(rax), Some(rsp)) => {
            Some(ParsedRegisters { rdi, rsi, rdx, rcx, r8, r9, rax, rsp, rbp })
        }
        _ => None,
    };

    Some(ParsedTraceEvent { probe_index, tid: thread_id, tgid: group_id, timestamp_ns, hit_ip, return_addr, regs })
}

fn parse_trace_timestamp_ns(token: &str) -> Option<u64> {
    if let Some((sec_str, frac_str)) = token.split_once('.') {
        let secs = sec_str.parse::<u64>().ok()?;
        if frac_str.is_empty() || !frac_str.bytes().all(|b| b.is_ascii_digit()) {
            return None;
        }
        let mut frac_ns = 0_u64;
        for &byte in frac_str.as_bytes().iter().take(9) {
            frac_ns = frac_ns.checked_mul(10)?.checked_add(u64::from(byte - b'0'))?;
        }
        let digits = frac_str.len().min(9);
        for _ in digits..9 {
            frac_ns = frac_ns.checked_mul(10)?;
        }
        secs.checked_mul(1_000_000_000)?.checked_add(frac_ns)
    } else {
        token.parse::<u64>().ok()
    }
}

fn parse_header_tid_tgid(header: &str) -> Option<(u32, Option<u32>)> {
    let cpu_bracket_pos = find_last_cpu_bracket(header)?;
    let left_of_cpu = header[..cpu_bracket_pos].trim_end();

    let (task_field, group_id) = if let Some(stripped_close) = left_of_cpu.strip_suffix(')')
        && let Some((before_paren, inside_paren)) = stripped_close.rsplit_once('(')
        && before_paren.ends_with(char::is_whitespace)
        && inside_paren.bytes().all(|b| b == b' ' || b == b'-' || b.is_ascii_digit())
    {
        let parsed_group = inside_paren.trim().parse::<u32>().ok();
        (before_paren.trim_end(), parsed_group)
    } else {
        (left_of_cpu, None)
    };

    let (_comm, tid_str) = task_field.rsplit_once('-')?;
    let thread_id = tid_str.trim().parse::<u32>().ok()?;
    Some((thread_id, group_id))
}

fn find_last_cpu_bracket(header: &str) -> Option<usize> {
    for (idx, _) in header.rmatch_indices(" [") {
        let rest = &header[idx + 2..];
        if let Some((digits, _after)) = rest.split_once(']')
            && !digits.is_empty()
            && digits.bytes().all(|b| b.is_ascii_digit())
        {
            return Some(idx);
        }
    }
    None
}

fn parse_hex_or_dec_u64(text: &str) -> Option<u64> {
    text.strip_prefix("0x").or_else(|| text.strip_prefix("0X")).map_or_else(
        || text.parse::<u64>().or_else(|_| u64::from_str_radix(text, 16)).ok(),
        |hex| u64::from_str_radix(hex, 16).ok(),
    )
}

#[must_use]
pub fn parse_per_cpu_stats_dir(per_cpu_dir: &Path) -> LostEvents {
    let entries = match std::fs::read_dir(per_cpu_dir) {
        Ok(dir) => dir,
        Err(err) => {
            return LostEvents::Unknown { reason: format!("failed to read {}: {err}", per_cpu_dir.display()) };
        }
    };

    let mut cpu_files = 0_usize;
    let mut overrun = 0_u64;
    let mut commit_overrun = 0_u64;
    let mut dropped_events = 0_u64;

    for entry_res in entries {
        let entry = match entry_res {
            Ok(e) => e,
            Err(err) => return LostEvents::Unknown { reason: format!("per_cpu dir entry error: {err}") },
        };
        let name = entry.file_name();
        let name_str = name.to_string_lossy();
        if !name_str.starts_with("cpu") || !name_str[3..].bytes().all(|b| b.is_ascii_digit()) {
            continue;
        }
        let stats_path = entry.path().join("stats");
        let text = match std::fs::read_to_string(&stats_path) {
            Ok(s) => s,
            Err(err) => {
                return LostEvents::Unknown { reason: format!("failed to read {}: {err}", stats_path.display()) };
            }
        };
        cpu_files += 1;
        for line in text.lines() {
            let trimmed = line.trim();
            if let Some(val) = trimmed.strip_prefix("overrun:") {
                let Some(n) = val.trim().parse::<u64>().ok() else {
                    return LostEvents::Unknown { reason: format!("malformed overrun in {}", stats_path.display()) };
                };
                overrun = overrun.saturating_add(n);
            } else if let Some(val) = trimmed.strip_prefix("commit overrun:") {
                let Some(n) = val.trim().parse::<u64>().ok() else {
                    return LostEvents::Unknown {
                        reason: format!("malformed commit overrun in {}", stats_path.display()),
                    };
                };
                commit_overrun = commit_overrun.saturating_add(n);
            } else if let Some(val) = trimmed.strip_prefix("dropped events:") {
                let Some(n) = val.trim().parse::<u64>().ok() else {
                    return LostEvents::Unknown {
                        reason: format!("malformed dropped events in {}", stats_path.display()),
                    };
                };
                dropped_events = dropped_events.saturating_add(n);
            }
        }
    }

    if cpu_files == 0 {
        return LostEvents::Unknown { reason: format!("no cpu*/stats files found in {}", per_cpu_dir.display()) };
    }
    let total = overrun.saturating_add(commit_overrun).saturating_add(dropped_events);
    LostEvents::Known { overrun, commit_overrun, dropped_events, perf_lost_records: 0, total }
}
