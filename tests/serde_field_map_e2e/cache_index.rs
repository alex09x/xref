/*
 * XRef — executable analysis
 * Copyright (c) 2026 Alexander Panasenko
 * Contact: alex@prod.codes
 * Author: https://prod.codes/about/
 * Project: https://github.com/alex09x/xref
 * SPDX-License-Identifier: MIT OR Apache-2.0
 */
use super::*;
use std::io::Write as _;

struct CacheDir(PathBuf);
impl Drop for CacheDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

#[test]
fn scan_index_is_reused_for_other_keys_and_recovers_from_corruption() {
    let fixture = Fixture::build("release");
    let binary = fixture.stripped();
    let nonce = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos();
    let cache = CacheDir(std::env::temp_dir().join(format!("xref-field-index-{}-{nonce}", std::process::id())));
    fs::create_dir_all(&cache.0).unwrap();
    let query = |target: &std::path::Path, keys: &str, extra: &[&str]| -> Value {
        let mut command = Command::new(env!("CARGO_BIN_EXE_xref"));
        command
            .arg("-b")
            .arg(target)
            .args(["field", "--keys", keys, "--layout-only", "--json"])
            .args(extra)
            .env("XDG_CACHE_HOME", &cache.0)
            .env("XREF_NO_RESULT_CACHE", "1"); // exercise the index, not the whole-report replay
        serde_json::from_slice(&run(&mut command).stdout).unwrap()
    };
    let cold = query(&binary, "c,m,e", &[]);
    assert_eq!(cold["coverage"]["scan_index_cache_hits"], 0);
    assert!(!cold["candidates"].as_array().unwrap().is_empty(), "{cold}");
    let warm = query(&binary, "c,m,missing", &["--min-keys", "2"]);
    assert_eq!(warm["coverage"]["scan_index_cache_hits"], 1);
    assert!(!warm["candidates"].as_array().unwrap().is_empty(), "{warm}");
    let directory = cache.0.join("xref/field-index-v1");
    let entry = fs::read_dir(directory).unwrap().next().unwrap().unwrap().path();
    fs::write(entry, b"corrupt").unwrap();
    let repaired = query(&binary, "c,m,e", &[]);
    assert_eq!(repaired["coverage"]["scan_index_cache_hits"], 0);
    assert_eq!(repaired["candidates"], cold["candidates"]);
    let changed = cache.0.join("changed-elf");
    fs::copy(&binary, &changed).unwrap();
    fs::OpenOptions::new().append(true).open(&changed).unwrap().write_all(b"changed").unwrap();
    let changed_report = query(&changed, "c,m,e", &[]);
    assert_eq!(changed_report["coverage"]["scan_index_cache_hits"], 0);
    assert_eq!(changed_report["candidates"], cold["candidates"]);
}

#[test]
fn writer_index_preserves_ranked_results_and_filter_across_queries() {
    let fixture = Fixture::build("release");
    let binary = fixture.stripped();
    let nonce = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos();
    let cache = CacheDir(std::env::temp_dir().join(format!("xref-writer-index-{}-{nonce}", std::process::id())));
    fs::create_dir_all(&cache.0).unwrap();
    let query = |fields: &str| -> Value {
        let mut command = Command::new(env!("CARGO_BIN_EXE_xref"));
        command
            .arg("-b")
            .arg(&binary)
            .args(["field", "--keys", "c,m,e", "--write", "--writes-all-of", fields, "--limit", "64", "--json"])
            .env("XDG_CACHE_HOME", &cache.0)
            .env("XREF_NO_RESULT_CACHE", "1"); // exercise the index, not the whole-report replay
        serde_json::from_slice(&run(&mut command).stdout).unwrap()
    };
    let cold = query("m,e");
    assert_eq!(cold["coverage"]["writer_index_cache_hits"], 0);
    assert!(!cold["accessor_candidates"].as_array().unwrap().is_empty(), "{cold}");
    let warm = query("m,e");
    assert_eq!(warm["coverage"]["writer_index_cache_hits"], 1);
    assert_eq!(warm["accessor_candidates"], cold["accessor_candidates"]);
    let other_filter = query("c,m,e");
    assert_eq!(other_filter["coverage"]["writer_index_cache_hits"], 1);
    for row in other_filter["accessor_candidates"].as_array().unwrap() {
        let offsets = row["queried_field_accesses"].as_array().unwrap();
        for name in ["c", "m", "e"] {
            let expected = fixture.offsets[&format!("ShortRecord.{name}")];
            assert!(
                offsets.iter().any(|item| {
                    let start = item["offset"].as_i64().unwrap();
                    let width = item["width_bytes"].as_u64().unwrap();
                    let target = i64::try_from(expected).unwrap();
                    item["access"].as_str().unwrap().contains("write")
                        && start <= target
                        && u64::try_from(target - start).is_ok_and(|delta| delta < width)
                }),
                "{other_filter}"
            );
        }
    }
    for entry in fs::read_dir(cache.0.join("xref/field-index-v1")).unwrap() {
        fs::write(entry.unwrap().path(), b"corrupt").unwrap();
    }
    let recovered = query("m,e");
    assert_eq!(recovered["coverage"]["writer_index_cache_hits"], 0);
    assert_eq!(recovered["accessor_candidates"], cold["accessor_candidates"]);
}

#[test]
fn identical_field_query_replays_the_stored_report_until_the_input_changes() {
    let fixture = Fixture::build("release");
    let nonce = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos();
    let cache = CacheDir(std::env::temp_dir().join(format!("xref-result-cache-{}-{nonce}", std::process::id())));
    fs::create_dir_all(&cache.0).unwrap();
    let binary = cache.0.join("target-elf");
    fs::copy(fixture.stripped(), &binary).unwrap();
    let query = || {
        let mut command = Command::new(env!("CARGO_BIN_EXE_xref"));
        command
            .arg("-b")
            .arg(&binary)
            .args(["field", "--keys", "c,m,e", "--write", "--writes-all-of", "m,e", "--json"])
            .env("XDG_CACHE_HOME", &cache.0);
        run(&mut command)
    };
    let cold = query();
    let warm = query();
    assert_eq!(warm.stdout, cold.stdout, "replayed report must be byte-identical");
    assert!(String::from_utf8_lossy(&warm.stderr).contains("cached result"));

    // Any change to the input invalidates the stored report.
    fs::OpenOptions::new().append(true).open(&binary).unwrap().write_all(b"changed").unwrap();
    let changed = query();
    assert!(!String::from_utf8_lossy(&changed.stderr).contains("cached result"));
}
