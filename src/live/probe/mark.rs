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

/// Escaped atom: `\d`, `\w`, `\s` (and their negations) are classes; punctuation is literal.
/// Other escaped letters are rejected so an unsupported class never silently matches a literal.
fn escape_class(escaped: char) -> Result<CharClass, String> {
    let set = |chars: &[char], ranges: &[(char, char)], negated: bool| CharClass::Set {
        chars: chars.to_vec(),
        ranges: ranges.to_vec(),
        negated,
    };
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
}

impl MarkTracker {
    pub fn new(path: PathBuf, pattern: &str) -> Result<Self, String> {
        let regex = SimpleRegex::compile(pattern)?;
        let mut tracker = Self { path, regex, file: None, offset: 0, partial: Vec::new(), latest_mark: None };
        tracker.update();
        Ok(tracker)
    }

    pub fn update(&mut self) {
        if self.file.is_none()
            && let Ok(mut f) = File::open(&self.path)
        {
            let _ = f.seek(SeekFrom::Start(self.offset));
            self.file = Some(f);
        }
        let Some(ref mut file) = self.file else { return };
        let mut buf = [0_u8; 4096];
        loop {
            match file.read(&mut buf) {
                Ok(0) | Err(_) => break,
                Ok(n) => {
                    let n_u64 = u64::try_from(n).unwrap_or(0);
                    self.offset = self.offset.saturating_add(n_u64);
                    for &byte in &buf[..n] {
                        if byte == b'\n' {
                            if let Ok(line) = std::str::from_utf8(&self.partial) {
                                let trimmed = line.trim_end_matches('\r');
                                if self.regex.is_match(trimmed) {
                                    self.latest_mark = Some(trimmed.to_owned());
                                }
                            }
                            self.partial.clear();
                        } else {
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
mod tests {
    use std::io::Write;
    use tempfile::NamedTempFile;

    use super::{MarkTracker, SimpleRegex};

    #[test]
    fn matches_anchored_and_unanchored_patterns() {
        let re = SimpleRegex::compile("MARK.*step").unwrap();
        assert!(re.is_match("some MARK item step now"));
        assert!(!re.is_match("MARK item"));

        let anchored = SimpleRegex::compile("^phase [0-9]+$").unwrap();
        assert!(anchored.is_match("phase 42"));
        assert!(!anchored.is_match("pre phase 42"));
        assert!(!anchored.is_match("phase 42 post"));

        let classes = SimpleRegex::compile("^[a-z]+_[A-Z0-9]+$").unwrap();
        assert!(classes.is_match("abc_123"));
        assert!(classes.is_match("hello_WORLD"));
        assert!(!classes.is_match("123_abc"));
    }

    #[test]
    fn supports_escaped_classes_and_rejects_unsupported_syntax() {
        let re = SimpleRegex::compile(r"height=\d+\s\w+$").unwrap();
        assert!(re.is_match("block height=1234 done"));
        assert!(!re.is_match("block height=dd done"), "\\d must not match a literal d");
        assert!(SimpleRegex::compile(r"a\.b").unwrap().is_match("a.b"));
        assert!(!SimpleRegex::compile(r"a\.b").unwrap().is_match("axb"));
        for bad in [r"a|b", r"(ab)", r"a{2}", r"\p"] {
            assert!(SimpleRegex::compile(bad).is_err(), "{bad} must be rejected");
        }
    }

    #[test]
    fn tails_file_and_updates_latest_mark() {
        let mut tmp = NamedTempFile::new().unwrap();
        let mut tracker = MarkTracker::new(tmp.path().to_path_buf(), "^MARK: .*").unwrap();
        assert_eq!(tracker.current_mark(), None);

        writeln!(tmp, "ignorable line").unwrap();
        tmp.flush().unwrap();
        assert_eq!(tracker.current_mark(), None);

        writeln!(tmp, "MARK: first phase").unwrap();
        tmp.flush().unwrap();
        assert_eq!(tracker.current_mark(), Some("MARK: first phase"));

        writeln!(tmp, "another random line").unwrap();
        tmp.flush().unwrap();
        assert_eq!(tracker.current_mark(), Some("MARK: first phase"));

        writeln!(tmp, "MARK: second phase").unwrap();
        tmp.flush().unwrap();
        assert_eq!(tracker.current_mark(), Some("MARK: second phase"));
    }
}
