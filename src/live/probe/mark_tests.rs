/*
 * XRef — mark-file tailer and regular-expression matcher tests
 * Copyright (c) 2026 Alexander Panasenko
 * Contact: alex@prod.codes
 * Author: https://prod.codes/about/
 * Project: https://github.com/alex09x/xref
 * SPDX-License-Identifier: MIT OR Apache-2.0
 */

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
fn mark_file_must_be_regular_and_long_lines_are_bounded() {
    assert!(super::validate_mark_file(std::path::Path::new("/dev/zero")).is_err());
    assert!(super::validate_mark_file(std::path::Path::new("/nonexistent/yet/app.log")).is_ok());
    let mut tmp = NamedTempFile::new().unwrap();
    writeln!(tmp, "MARK: {}", "x".repeat(200_000)).unwrap();
    tmp.flush().unwrap();
    let mut tracker = MarkTracker::new(tmp.path().to_path_buf(), "^MARK: x").unwrap();
    assert_eq!(tracker.current_mark(), None, "an overlong line is skipped, never matched on its prefix");
    writeln!(tmp, "MARK: x short").unwrap();
    tmp.flush().unwrap();
    assert_eq!(tracker.current_mark(), Some("MARK: x short"));
}

#[test]
fn matcher_is_linear_on_pathological_patterns() {
    let re = SimpleRegex::compile("^a*a*a*a*a*a*a*a*b$").unwrap();
    let text = "a".repeat(60_000);
    let started = std::time::Instant::now();
    assert!(!re.is_match(&text));
    assert!(started.elapsed() < std::time::Duration::from_secs(2), "no exponential backtracking");
    assert!(SimpleRegex::compile("^a+b?c*$").unwrap().is_match("aaac"));
    assert!(!SimpleRegex::compile("^a+$").unwrap().is_match(""));
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
fn hits_get_the_mark_current_at_their_timestamp() {
    let mut tmp = NamedTempFile::new().unwrap();
    writeln!(tmp, "MARK: A").unwrap();
    tmp.flush().unwrap();
    let mut tracker = MarkTracker::new(tmp.path().to_path_buf(), "^MARK: ").unwrap();
    let before_b = super::monotonic_now_ns();
    std::thread::sleep(std::time::Duration::from_millis(2));
    writeln!(tmp, "MARK: B").unwrap();
    tmp.flush().unwrap();
    tracker.poll();
    let after_b = super::monotonic_now_ns();
    // A hit before B was written keeps A even though B is already read; a later hit gets B.
    assert_eq!(tracker.mark_at(before_b), Some("MARK: A"));
    assert_eq!(tracker.mark_at(after_b), Some("MARK: B"));
}

#[test]
fn a_hit_older_than_the_kept_history_gets_no_later_mark() {
    let mut tmp = NamedTempFile::new().unwrap();
    let mut tracker = MarkTracker::new(tmp.path().to_path_buf(), "^MARK: ").unwrap();
    let before_all = super::monotonic_now_ns();
    std::thread::sleep(std::time::Duration::from_millis(1));
    for i in 0..1100 {
        writeln!(tmp, "MARK: {i}").unwrap();
        if i % 50 == 0 {
            tmp.flush().unwrap();
            tracker.poll();
        }
    }
    tmp.flush().unwrap();
    tracker.poll();
    assert_eq!(tracker.mark_at(before_all), None, "evicted marks are not attached to earlier hits");
    assert_eq!(tracker.mark_at(u64::MAX), Some("MARK: 1099"));
}

#[test]
fn follows_rotation_and_copytruncate() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("app.log");
    std::fs::write(&path, "MARK: one\n").unwrap();
    let mut tracker = MarkTracker::new(path.clone(), "^MARK: ").unwrap();
    assert_eq!(tracker.current_mark(), Some("MARK: one"));
    // copytruncate: same inode, shorter content.
    std::fs::write(&path, "MARK: 2\n").unwrap();
    assert_eq!(tracker.current_mark(), Some("MARK: 2"));
    // rotation: a new file replaces PATH.
    std::fs::rename(&path, dir.path().join("app.log.1")).unwrap();
    std::fs::write(&path, "MARK: three\n").unwrap();
    assert_eq!(tracker.current_mark(), Some("MARK: three"));
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
