/*
 * XRef Code — Label and goto dependencies in slices
 * Copyright (c) 2026 Alexander Panasenko
 * Contact: alex@prod.codes
 * Author: https://prod.codes/about/
 * Project: https://github.com/alex09x/xref
 * SPDX-License-Identifier: MIT OR Apache-2.0
 */

use crate::slice_parse::{BlockSpan, strip_comment};
use std::collections::HashMap;

const fn quoted_end(bytes: &[u8], start: usize) -> usize {
    let (quote, mut i) = (bytes[start], start + 1);
    while i < bytes.len() {
        if bytes[i] == b'\\' {
            i = if i + 2 <= bytes.len() { i + 2 } else { bytes.len() };
        } else if bytes[i] == quote {
            return i + 1;
        } else {
            i += 1;
        }
    }
    bytes.len()
}

fn executable(text: &str) -> String {
    let bytes = text.as_bytes();
    let mut masked = bytes.to_vec();
    let mut i = 0;
    while i < bytes.len() {
        let end = if matches!(bytes[i], b'"' | b'\'') {
            quoted_end(bytes, i)
        } else if bytes[i] == b'/' && bytes.get(i + 1) == Some(&b'/') {
            bytes[i..].iter().position(|&b| b == b'\n').map_or(bytes.len(), |n| i + n)
        } else if bytes[i] == b'/' && bytes.get(i + 1) == Some(&b'*') {
            bytes[i + 2..].windows(2).position(|w| w == b"*/").map_or(bytes.len(), |n| i + 2 + n + 2)
        } else {
            i += 1;
            continue;
        };
        for byte in &mut masked[i..end] {
            if *byte != b'\n' {
                *byte = b' ';
            }
        }
        i = end;
    }
    String::from_utf8_lossy(&masked).into_owned()
}

fn identifier(text: &str) -> bool {
    let mut chars = text.chars();
    chars.next().is_some_and(|ch| ch.is_ascii_alphabetic() || ch == '_')
        && chars.all(|ch| ch.is_ascii_alphanumeric() || ch == '_')
}

fn label(line: &str) -> Option<String> {
    let code = executable(line);
    let name = code.trim().trim_end_matches(';').trim_end().strip_suffix(':')?.trim();
    (identifier(name) && name != "case").then(|| name.to_owned())
}

fn goto_targets(line: &str) -> Vec<String> {
    let code = executable(line);
    let mut out = Vec::new();
    for (index, _) in code.match_indices("goto") {
        if code[..index].chars().next_back().is_some_and(|c| c.is_alphanumeric() || c == '_') {
            continue;
        }
        let tail = &code[index + 4..];
        if !tail.starts_with(char::is_whitespace) {
            continue;
        }
        let tail = tail.trim_start();
        let end = tail.find(|c: char| !(c.is_ascii_alphanumeric() || c == '_')).unwrap_or(tail.len());
        let name = &tail[..end];
        if identifier(name) && tail[end..].trim_start().starts_with(';') {
            out.push(name.to_owned());
        }
    }
    out
}

pub(super) struct Control {
    code: Vec<String>,
    labels: Vec<Option<String>>,
    destinations: Vec<Vec<usize>>,
    incoming: HashMap<usize, Vec<usize>>,
}

impl Control {
    pub(super) fn new(lines: &[&str]) -> Self {
        let code: Vec<String> = executable(&lines.join("\n")).split('\n').map(str::to_owned).collect();
        let labels: Vec<_> = code.iter().map(|line| label(line)).collect();
        let positions: HashMap<&str, usize> =
            labels.iter().enumerate().filter_map(|(i, label)| label.as_deref().map(|s| (s, i))).collect();
        let destinations: Vec<Vec<usize>> = code
            .iter()
            .map(|line| goto_targets(line).iter().filter_map(|name| positions.get(name.as_str()).copied()).collect())
            .collect();
        let mut incoming: HashMap<usize, Vec<usize>> = HashMap::new();
        for (source, targets) in destinations.iter().enumerate() {
            for &target in targets {
                incoming.entry(target).or_default().push(source);
            }
        }
        Self { code, labels, destinations, incoming }
    }

    pub(super) fn is_label(&self, index: usize) -> bool {
        self.labels[index].is_some()
    }

    fn bypasses(&self, index: usize, last_target: usize) -> bool {
        self.destinations[index].iter().any(|&target| target > last_target)
    }

    pub(super) fn keep_bypasses(&self, lines: &[&str], spans: &[BlockSpan], last_target: usize, keep: &mut [bool]) {
        for (index, flag) in keep.iter_mut().enumerate().take(last_target) {
            if self.bypasses(index, last_target) {
                *flag = true;
            }
        }
        for span in spans.iter().filter(|span| span.close < last_target) {
            let mut starts = vec![span.open];
            starts.extend(&span.elses);
            let ends = span.elses.iter().copied().chain([span.close]);
            for (start, end) in starts.into_iter().zip(ends) {
                if let Some(term) = (start + 1..end).rev().find(|&i| !strip_comment(lines[i]).is_empty())
                    && self.bypasses(term, last_target)
                {
                    keep[span.open] = true;
                    keep[start] = true;
                    keep[term] = true;
                    keep[span.close] = true;
                }
            }
        }
    }

    pub(super) fn propagate(&self, lines: &[&str], sig_idx: usize, selected: &[bool], keep: &mut [bool]) -> bool {
        let mut changed = false;
        let mut mark = |index: usize, keep: &mut [bool]| {
            if !keep[index] {
                keep[index] = true;
                changed = true;
            }
        };
        for index in sig_idx + 1..lines.len() - 1 {
            if keep[index] {
                for &target in &self.destinations[index] {
                    mark(target, keep);
                }
            }
        }
        for index in (sig_idx + 1..lines.len() - 1).rev() {
            if !keep[index] {
                continue;
            }
            if self.is_label(index) {
                if selected[index] {
                    for &source in self.incoming.get(&index).into_iter().flatten() {
                        mark(source, keep);
                    }
                }
                continue;
            }
            for previous in (sig_idx + 1..index).rev() {
                if self.is_label(previous) {
                    mark(previous, keep);
                    for &source in self.incoming.get(&previous).into_iter().flatten() {
                        mark(source, keep);
                    }
                    break;
                }
                let code = strip_comment(lines[previous]);
                if lines[previous].len() - lines[previous].trim_start().len() <= 2
                    && (code.starts_with("return") || code == "unreachable();")
                {
                    break;
                }
            }
        }
        changed
    }

    pub(super) fn terminate_sink(&self, lines: &[&str], keep: &[bool], index: usize, clean: String) -> String {
        let code = executable(&clean);
        if !self.is_label(index) || code.trim_end().ends_with(';') {
            return clean;
        }
        let closes = (index + 1..lines.len())
            .filter(|&i| keep[i])
            .find_map(|i| {
                let code = self.code[i].trim();
                (!code.is_empty()).then_some(code)
            })
            .is_none_or(|code| code.starts_with('}'));
        if !closes {
            return clean;
        }
        let Some(colon) = code.find(':') else {
            return clean;
        };
        format!("{} ;{}", &clean[..=colon], &clean[colon + 1..])
    }
}
