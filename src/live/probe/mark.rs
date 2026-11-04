/*
 * XRef — Stage L2 mark-file tailer and regular-expression matcher
 * Copyright (c) 2026 Alexander Panasenko
 * Contact: alex@prod.codes
 * Author: https://prod.codes/about/
 * Project: https://github.com/alex09x/xref
 * SPDX-License-Identifier: MIT OR Apache-2.0
 */

use std::fs::File;
use std::io::{Read, Seek, SeekFrom};
use std::path::PathBuf;

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CharClass {
    Any,
    Literal(char),
    Set { chars: Vec<char>, ranges: Vec<(char, char)>, negated: bool },
}

impl CharClass {
    #[must_use]
    pub fn matches(&self, c: char) -> bool {
        match self {
            Self::Any => c != '\n' && c != '\r',
            Self::Literal(lit) => *lit == c,
            Self::Set { chars, ranges, negated } => {
                let found = chars.contains(&c) || ranges.iter().any(|(s, e)| c >= *s && c <= *e);
                if *negated { !found } else { found }
            }
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Quantifier {
    ExactOne,
    ZeroOrMore,
    OneOrMore,
    ZeroOrOne,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RegexAtom {
    pub class: CharClass,
    pub quant: Quantifier,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SimpleRegex {
    pub anchored_start: bool,
    pub anchored_end: bool,
    pub atoms: Vec<RegexAtom>,
}

impl SimpleRegex {
    pub fn compile(pattern: &str) -> Result<Self, String> {
        let mut chars = pattern.chars().peekable();
        let anchored_start = if chars.peek() == Some(&'^') {
            chars.next();
            true
        } else {
            false
        };

        let mut atoms = Vec::new();
        let mut anchored_end = false;

        while let Some(c) = chars.next() {
            if c == '$' && chars.peek().is_none() {
                anchored_end = true;
                break;
            }
            let class = match c {
                '.' => CharClass::Any,
                '\\' => {
                    let escaped = chars.next().ok_or("trailing escape in regular expression")?;
                    escape_class(escaped)?
                }
                '|' | '(' | ')' | '{' | '}' => {
                    return Err(format!(
                        "unsupported regular expression syntax '{c}': --mark-regex supports literals, ., [...], \\d \\w \\s, ^, $ and * + ?"
                    ));
                }
                '[' => {
                    let negated = if chars.peek() == Some(&'^') {
                        chars.next();
                        true
                    } else {
                        false
                    };
                    let mut set_chars = Vec::new();
                    let mut ranges = Vec::new();
                    let mut closed = false;
                    while let Some(ch) = chars.next() {
                        if ch == ']' && (!set_chars.is_empty() || !ranges.is_empty()) {
                            closed = true;
                            break;
                        }
                        if chars.peek() == Some(&'-') {
                            chars.next(); // consume '-'
                            if let Some(&end_ch) = chars.peek() {
                                if end_ch == ']' {
                                    set_chars.push(ch);
                                    set_chars.push('-');
                                } else {
                                    chars.next();
                                    ranges.push((ch, end_ch));
                                }
                            } else {
                                set_chars.push(ch);
                                set_chars.push('-');
                            }
                        } else {
                            set_chars.push(ch);
                        }
                    }
                    if !closed {
                        return Err("unclosed character class '[' in regular expression".to_owned());
                    }
                    CharClass::Set { chars: set_chars, ranges, negated }
                }
                _ => CharClass::Literal(c),
            };

            let quant = match chars.peek() {
                Some('*') => {
                    chars.next();
                    Quantifier::ZeroOrMore
                }
                Some('+') => {
                    chars.next();
                    Quantifier::OneOrMore
                }
                Some('?') => {
                    chars.next();
                    Quantifier::ZeroOrOne
                }
                _ => Quantifier::ExactOne,
            };

            atoms.push(RegexAtom { class, quant });
        }

        Ok(Self { anchored_start, anchored_end, atoms })
    }

    #[must_use]
    pub fn is_match(&self, text: &str) -> bool {
        let char_vec: Vec<char> = text.chars().collect();
        if self.anchored_start {
            self.match_at(&char_vec, 0, 0)
        } else {
            (0..=char_vec.len()).any(|start| self.match_at(&char_vec, start, 0))
        }
    }

    fn match_at(&self, chars: &[char], char_idx: usize, atom_idx: usize) -> bool {
        if atom_idx == self.atoms.len() {
            return if self.anchored_end { char_idx == chars.len() } else { true };
        }

        let atom = &self.atoms[atom_idx];
        match atom.quant {
            Quantifier::ExactOne => {
                if char_idx < chars.len() && atom.class.matches(chars[char_idx]) {
                    self.match_at(chars, char_idx.saturating_add(1), atom_idx.saturating_add(1))
                } else {
                    false
                }
            }
            Quantifier::ZeroOrOne => {
                if char_idx < chars.len()
                    && atom.class.matches(chars[char_idx])
                    && self.match_at(chars, char_idx.saturating_add(1), atom_idx.saturating_add(1))
                {
                    return true;
                }
                self.match_at(chars, char_idx, atom_idx.saturating_add(1))
            }
            Quantifier::ZeroOrMore => {
                let mut matched_len = 0;
                while char_idx.saturating_add(matched_len) < chars.len()
                    && atom.class.matches(chars[char_idx.saturating_add(matched_len)])
                {
                    matched_len = matched_len.saturating_add(1);
                }
                for count in (0..=matched_len).rev() {
                    if self.match_at(chars, char_idx.saturating_add(count), atom_idx.saturating_add(1)) {
                        return true;
                    }
                }
                false
            }
            Quantifier::OneOrMore => {
                let mut matched_len = 0;
                while char_idx.saturating_add(matched_len) < chars.len()
                    && atom.class.matches(chars[char_idx.saturating_add(matched_len)])
                {
                    matched_len = matched_len.saturating_add(1);
                }
                if matched_len == 0 {
                    return false;
                }
                for count in (1..=matched_len).rev() {
                    if self.match_at(chars, char_idx.saturating_add(count), atom_idx.saturating_add(1)) {
                        return true;
                    }
                }
                false
            }
        }
    }
}

pub fn validate_regex(pattern: &str) -> Result<(), String> {
    SimpleRegex::compile(pattern).map(|_| ())
}

const MAX_MARK_READ_PER_UPDATE: usize = 1024 * 1024;
const MAX_MARK_LINE: usize = 64 * 1024;

/// A mark file must be a regular file (it may not exist yet); devices and FIFOs never reach EOF.
pub fn validate_mark_file(path: &std::path::Path) -> Result<(), String> {
    match std::fs::metadata(path) {
        Ok(meta) if !meta.is_file() => Err(format!("--mark-file {} is not a regular file", path.display())),
        _ => Ok(()),
    }
}

/// Escaped atom: `\d`, `\w`, `\s` (and their negations) are classes; punctuation is literal.
/// Other escaped letters are rejected so an unsupported class never silently matches a literal.
fn escape_class(escaped: char) -> Result<CharClass, String> {
    let set =
        |c: &[char], r: &[(char, char)], negated| CharClass::Set { chars: c.to_vec(), ranges: r.to_vec(), negated };
    let word: &[(char, char)] = &[('a', 'z'), ('A', 'Z'), ('0', '9')];
    let space: &[char] = &[' ', '\t', '\r', '\n', '\x0b', '\x0c'];
    Ok(match escaped {
        'd' => set(&[], &[('0', '9')], false),
        'D' => set(&[], &[('0', '9')], true),
        'w' => set(&['_'], word, false),
        'W' => set(&['_'], word, true),
        's' => set(space, &[], false),
        'S' => set(space, &[], true),
        c if c.is_ascii_alphanumeric() => {
            return Err(format!("unsupported regular expression escape '\\{c}' in --mark-regex"));
        }
        c => CharClass::Literal(c),
    })
}

pub struct MarkTracker {
    path: PathBuf,
    regex: SimpleRegex,
    file: Option<File>,
    offset: u64,
    partial: Vec<u8>,
    latest_mark: Option<String>,
    skip_partial_line: bool,
}

impl MarkTracker {
    pub fn new(path: PathBuf, pattern: &str) -> Result<Self, String> {
        let regex = SimpleRegex::compile(pattern)?;
        let mut tracker = Self {
            path,
            regex,
            file: None,
            offset: 0,
            partial: Vec::new(),
            latest_mark: None,
            skip_partial_line: false,
        };
        tracker.update();
        Ok(tracker)
    }

    /// Reopen from the start when PATH was rotated (new inode) or truncated in place
    /// (`copytruncate`: shorter than what was read); the previous mark stays until a new one.
    fn follow_rotation(&mut self) {
        use std::os::unix::fs::MetadataExt;
        let (Some(file), Ok(current)) = (&self.file, std::fs::metadata(&self.path)) else { return };
        let Ok(open) = file.metadata() else { return };
        if (open.dev(), open.ino()) != (current.dev(), current.ino()) || current.len() < self.offset {
            self.file = None;
            self.offset = 0;
            self.partial.clear();
            self.skip_partial_line = false;
        }
    }

    pub fn update(&mut self) {
        self.follow_rotation();
        if self.file.is_none()
            && let Ok(mut f) = File::open(&self.path)
        {
            // Start from the file's last megabyte so a large existing log yields its current mark
            // at once; the first (possibly cut) line of that tail is skipped.
            let len = f.metadata().map_or(0, |meta| meta.len());
            let tail = u64::try_from(MAX_MARK_READ_PER_UPDATE).unwrap_or(u64::MAX);
            if self.offset == 0 && len > tail {
                self.offset = len - tail;
                self.skip_partial_line = true;
            }
            let _ = f.seek(SeekFrom::Start(self.offset));
            self.file = Some(f);
        }
        let Some(ref mut file) = self.file else { return };
        let mut buf = [0_u8; 4096];
        // Bound the work per call so a fast writer cannot stall the probe loop; the remainder is
        // read on the next hit or poll. Overlong lines keep only their first MAX_MARK_LINE bytes.
        let mut budget = MAX_MARK_READ_PER_UPDATE;
        while budget > 0 {
            match file.read(&mut buf) {
                Ok(0) | Err(_) => break,
                Ok(n) => {
                    budget = budget.saturating_sub(n);
                    let n_u64 = u64::try_from(n).unwrap_or(0);
                    self.offset = self.offset.saturating_add(n_u64);
                    for &byte in &buf[..n] {
                        if byte == b'\n' && std::mem::take(&mut self.skip_partial_line) {
                            self.partial.clear();
                        } else if byte == b'\n' {
                            if let Ok(line) = std::str::from_utf8(&self.partial) {
                                let trimmed = line.trim_end_matches('\r');
                                if self.regex.is_match(trimmed) {
                                    self.latest_mark = Some(trimmed.to_owned());
                                }
                            }
                            self.partial.clear();
                        } else if self.partial.len() < MAX_MARK_LINE {
                            self.partial.push(byte);
                        }
                    }
                }
            }
        }
    }

    #[must_use]
    pub fn current_mark(&mut self) -> Option<&str> {
        self.update();
        self.latest_mark.as_deref()
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::unreadable_literal)]
#[path = "mark_tests.rs"]
mod tests;
