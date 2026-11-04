/*
 * XRef — Bounded perf-script and folded-stack text parsing
 * Copyright (c) 2026 Alexander Panasenko
 * Contact: alex@prod.codes
 * Author: https://prod.codes/about/
 * Project: https://github.com/alex09x/xref
 * SPDX-License-Identifier: MIT OR Apache-2.0
 */

use super::{index::parse_hex, models::FrameKind};

pub const MAX_LINE_BYTES: usize = 65_536;
pub const MAX_STACK_FRAMES: usize = 256;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum InputFormat {
    Addresses,
    Perf,
    Folded,
}

#[derive(Clone, Debug)]
pub struct RawFrame {
    pub token: String,
    pub kind: FrameKind,
    pub dso: Option<String>,
}

#[derive(Clone, Debug)]
pub struct RawSample {
    pub pid: Option<u32>,
    pub tid: Option<u32>,
    pub pid_explicit: bool,
    pub weight: u64,
    pub frames: Vec<RawFrame>,
    pub truncated: bool,
}

#[derive(Clone, Debug)]
pub struct MmapRecord {
    pub pid: u32,
    pub tid: u32,
    pub start: u64,
    pub len: u64,
    pub offset: u64,
    pub executable: bool,
    pub path: String,
    pub build_id: Option<String>,
}

#[derive(Clone, Debug)]
pub enum TraceEvent {
    Sample(RawSample),
    Mmap(MmapRecord),
    Fork { pid: u32, tid: u32, parent_pid: u32, parent_tid: u32 },
    Exec(u32),
    Lost(u64),
    KernelMapping,
    Malformed,
}

pub struct TextParser {
    format: InputFormat,
    frame_kind: FrameKind,
    pending: Option<RawSample>,
    first_chain_row: bool,
}

impl TextParser {
    pub const fn new(format: InputFormat, frame_kind: FrameKind) -> Self {
        Self { format, frame_kind, pending: None, first_chain_row: false }
    }

    pub fn finish(&mut self) -> Option<TraceEvent> {
        self.pending.take().map(TraceEvent::Sample)
    }

    pub const fn has_pending(&self) -> bool {
        self.pending.is_some()
    }

    fn metadata_line(&mut self, text: &str) -> Result<Vec<TraceEvent>, String> {
        if let Some(tail) = text.split("PERF_RECORD_MMAP2").nth(1).or_else(|| text.split("PERF_RECORD_MMAP").nth(1)) {
            let mut events: Vec<_> = self.finish().into_iter().collect();
            let kernel = tail.trim_start().split('/').next().is_some_and(|pid| pid == "-1" || pid == "4294967295");
            events.push(if kernel { TraceEvent::KernelMapping } else { TraceEvent::Mmap(parse_mmap(tail)?) });
            return Ok(events);
        }
        if let Some(tail) = text.split("PERF_RECORD_FORK").nth(1) {
            let pairs: Vec<_> = tail
                .split('(')
                .skip(1)
                .filter_map(|part| part.split_once(')'))
                .filter_map(|(pair, _)| parse_pair(pair, ':'))
                .collect();
            let mut events: Vec<_> = self.finish().into_iter().collect();
            if let [child, parent, ..] = pairs.as_slice() {
                events.push(TraceEvent::Fork {
                    pid: child.0,
                    tid: child.1,
                    parent_pid: parent.0,
                    parent_tid: parent.1,
                });
            } else {
                events.push(TraceEvent::Malformed);
            }
            return Ok(events);
        }
        if let Some(tail) = text.split("PERF_RECORD_COMM").nth(1)
            && tail.contains("exec")
        {
            let mut events: Vec<_> = self.finish().into_iter().collect();
            if let Some(pid) = tail.rsplit(':').next().and_then(|part| parse_pair(part.trim(), '/')).map(|pair| pair.0)
            {
                events.push(TraceEvent::Exec(pid));
            } else {
                return Err("cannot identify PID of an exec record".to_owned());
            }
            return Ok(events);
        }
        if let Some(tail) = text.split("PERF_RECORD_LOST").nth(1) {
            let count = tail
                .rsplit_once("lost ")
                .map(|(_, value)| value.trim())
                .ok_or("unrecognized lost-record count")?
                .parse()
                .map_err(|_| "invalid or overflowing lost-record count")?;
            let mut events: Vec<_> = self.finish().into_iter().collect();
            events.push(TraceEvent::Lost(count));
            return Ok(events);
        }
        Ok(self.finish().into_iter().collect())
    }

    pub fn line(&mut self, line: &str) -> Result<Vec<TraceEvent>, String> {
        if line.len() > MAX_LINE_BYTES {
            return Err("trace line exceeds 64 KiB".to_owned());
        }
        let text = line.trim();
        if text.starts_with('#') {
            return Ok(vec![]);
        }
        if self.format != InputFormat::Perf {
            return self.simple_line(text);
        }
        if text.is_empty() {
            return Ok(self.finish().into_iter().collect());
        }
        if let Some(mut sample) = perf_header(text) {
            let events: Vec<_> = self.finish().into_iter().collect();
            if self.frame_kind != FrameKind::Auto {
                for frame in &mut sample.frames {
                    frame.kind = self.frame_kind;
                }
            }
            self.first_chain_row = true;
            self.pending = Some(sample);
            // The sample is emitted only after its callchain has arrived.
            return Ok(events);
        }
        let address_row = line.starts_with(char::is_whitespace)
            && text.split_whitespace().next().is_some_and(|token| parse_hex(token).is_ok());
        if text.contains("PERF_RECORD_") && !address_row {
            return self.metadata_line(text);
        }
        // `perf script -F ip` emits a blank-separated stack without PID/time headers.
        if text.split_whitespace().count() == 1 && parse_hex(text).is_ok() && self.pending.is_none() {
            self.first_chain_row = false;
            self.pending = Some(RawSample {
                pid: None,
                tid: None,
                pid_explicit: false,
                weight: 1,
                frames: vec![],
                truncated: false,
            });
        }
        if (line.starts_with(char::is_whitespace) || (text.split_whitespace().count() == 1 && parse_hex(text).is_ok()))
            && let Some(sample) = &mut self.pending
        {
            let token = text.split_whitespace().next().unwrap_or("[unknown]");
            let dso = perf_dso(text);
            // perf prints the sampled IP in both the header and first chain row.
            let first_row = std::mem::replace(&mut self.first_chain_row, false);
            if first_row
                && sample.frames.len() == 1
                && (sample.frames[0].token == token
                    || parse_hex(&sample.frames[0].token).ok().zip(parse_hex(token).ok()).is_some_and(|(a, b)| a == b))
            {
                sample.frames[0].dso = dso;
                return Ok(vec![]);
            }
            if sample.frames.len() >= MAX_STACK_FRAMES {
                sample.truncated = true;
            } else {
                let kind = if self.frame_kind != FrameKind::Auto {
                    self.frame_kind
                } else if sample.frames.is_empty() {
                    FrameKind::Instruction
                } else {
                    FrameKind::ReturnAddress
                };
                sample.frames.push(RawFrame { token: token.to_owned(), kind, dso });
            }
            return Ok(vec![]);
        }
        let mut events: Vec<_> = self.finish().into_iter().collect();
        events.push(TraceEvent::Malformed);
        Ok(events)
    }

    fn simple_line(&self, text: &str) -> Result<Vec<TraceEvent>, String> {
        if text.is_empty() {
            return Ok(vec![]);
        }
        let (tokens, weight) = match self.format {
            InputFormat::Folded => {
                let (stack, count) = text.rsplit_once(char::is_whitespace).ok_or("folded stack lacks a count")?;
                let weight: u64 = count.trim().parse().map_err(|_| "invalid folded sample count")?;
                if weight == 0 {
                    return Err("folded sample count must be positive".to_owned());
                }
                let mut tokens: Vec<_> = stack.split(';').map(str::trim).collect();
                tokens.reverse();
                (tokens, weight)
            }
            InputFormat::Addresses => (text.split_whitespace().collect(), 1),
            InputFormat::Perf => unreachable!(),
        };
        if tokens.is_empty() || tokens.iter().any(|token| token.is_empty()) {
            return Err("empty frame in stack".to_owned());
        }
        let truncated = tokens.len() > MAX_STACK_FRAMES;
        let frames = tokens
            .into_iter()
            .take(MAX_STACK_FRAMES)
            .enumerate()
            .map(|(position, token)| RawFrame {
                token: token.to_owned(),
                kind: if token.starts_with("fn_") {
                    FrameKind::Static
                } else if self.frame_kind == FrameKind::Auto {
                    if self.format == InputFormat::Folded && parse_hex(token).is_err() {
                        FrameKind::Symbol
                    } else if position == 0 {
                        FrameKind::Instruction
                    } else {
                        FrameKind::ReturnAddress
                    }
                } else {
                    self.frame_kind
                },
                dso: None,
            })
            .collect();
        Ok(vec![TraceEvent::Sample(RawSample { pid: None, tid: None, pid_explicit: false, weight, frames, truncated })])
    }
}

fn parse_pair(text: &str, separator: char) -> Option<(u32, u32)> {
    let (first, second) = text.trim().split_once(separator)?;
    Some((first.trim().parse().ok()?, second.trim().parse().ok()?))
}

fn perf_header(text: &str) -> Option<RawSample> {
    let tokens: Vec<_> = text.split_whitespace().collect();
    let time = tokens.iter().position(|token| {
        token.ends_with(':')
            && token.contains('.')
            && token.trim_end_matches(':').bytes().all(|b| b.is_ascii_digit() || b == b'.')
    })?;
    let pair = tokens[..time].iter().rev().find_map(|token| parse_pair(token, '/'));
    let number = tokens[..time].iter().rev().find_map(|token| token.parse::<u32>().ok());
    let event = tokens[time + 1..].iter().position(|token| token.ends_with(':')).map(|offset| time + 1 + offset)?;
    let event_name = tokens[event].trim_end_matches(':');
    if event_name.chars().all(|ch| ch.is_ascii_digit() || ch == '/' || ch == '-') {
        return None;
    }
    let token = tokens.get(event + 1).filter(|token| parse_hex(token).is_ok());
    if pair.is_none() && number.is_none() {
        return None;
    }
    let frames = token
        .map(|token| RawFrame { token: (*token).to_owned(), kind: FrameKind::Instruction, dso: None })
        .into_iter()
        .collect();
    Some(RawSample {
        pid: pair.map(|p| p.0).or(number),
        tid: pair.map(|p| p.1).or(number),
        pid_explicit: pair.is_some(),
        weight: 1,
        frames,
        truncated: false,
    })
}

fn perf_dso(line: &str) -> Option<String> {
    let suffix = line.rsplit_once('(')?.1.strip_suffix(')')?.trim();
    (!suffix.is_empty()).then(|| suffix.to_owned())
}

pub fn parse_mmap(tail: &str) -> Result<MmapRecord, String> {
    // Linux tools/perf/util/event.c prints pid/tid: [start(len) @ offset
    // <build-id>]: rwxp path, or dev/inode fields instead of the build ID.
    let (identity, rest) = tail.split_once('[').ok_or("MMAP record lacks mapping range")?;
    let (pid, tid) = parse_pair(identity.trim().trim_end_matches(':').trim(), '/').ok_or("invalid MMAP PID/TID")?;
    let (range, after) = rest.split_once("]:").ok_or("MMAP record lacks range terminator")?;
    let (start, len_rest) = range.split_once('(').ok_or("MMAP record lacks length")?;
    let (len, offset_rest) = len_rest.split_once(')').ok_or("invalid MMAP length")?;
    let offset = offset_rest
        .split_once('@')
        .and_then(|(_, part)| part.split_whitespace().next())
        .ok_or("MMAP record lacks file offset")?;
    let (permissions, path) = after.trim().split_once(char::is_whitespace).ok_or("MMAP record lacks pathname")?;
    let build_id =
        range.split_once('<').and_then(|(_, part)| part.split_once('>')).map(|(id, _)| id.to_ascii_lowercase());
    if build_id.as_ref().is_some_and(|id| id.is_empty() || id.len() > 128 || !id.bytes().all(|b| b.is_ascii_hexdigit()))
    {
        return Err("invalid MMAP build ID".to_owned());
    }
    let (start, len, offset) = (parse_hex(start)?, parse_hex(len)?, parse_hex(offset)?);
    if len == 0 || start.checked_add(len).is_none() {
        return Err("invalid MMAP range".to_owned());
    }
    Ok(MmapRecord {
        pid,
        tid,
        start,
        len,
        offset,
        executable: permissions.contains('x'),
        path: path.trim().to_owned(),
        build_id,
    })
}
