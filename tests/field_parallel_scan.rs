/*
 * XRef — executable analysis
 * Copyright (c) 2026 Alexander Panasenko
 * Contact: alex@prod.codes
 * Author: https://prod.codes/about/
 * Project: https://github.com/alex09x/xref
 * SPDX-License-Identifier: MIT OR Apache-2.0
 */
#![cfg(all(target_os = "linux", target_arch = "x86_64"))]
#![allow(clippy::unwrap_used, clippy::expect_used)]
use serde_json::Value;
use std::{path::PathBuf, process::Command};

struct TempDir(PathBuf);
impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn run(command: &mut Command) -> std::process::Output {
    let output = command.output().expect("spawn fixture command");
    assert!(output.status.success(), "{command:?}: {}", String::from_utf8_lossy(&output.stderr));
    output
}

#[test]
fn parallel_cold_index_matches_single_thread_on_compiled_stripped_elf() {
    let nonce = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos();
    let dir = TempDir(std::env::temp_dir().join(format!("xref-parallel-{}-{nonce}", std::process::id())));
    std::fs::create_dir_all(&dir.0).unwrap();
    let generator = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/field_perf/generate.py");
    run(Command::new("python3").arg(generator).arg(&dir.0).args([
        "--functions",
        "160",
        "--padding",
        "8192",
        "--writers",
    ]));
    let binary = dir.0.join("target");
    run(Command::new("cc")
        .args(["-O2", "-g0", "-fno-inline", "-fno-ipa-icf"])
        .arg(dir.0.join("target.c"))
        .arg(dir.0.join("bulk.S"))
        .arg("-o")
        .arg(&binary));
    let stripped = dir.0.join("target-stripped");
    run(Command::new("objcopy").arg("--strip-all").arg(&binary).arg(&stripped));
    let query = |threads: &str, cache: &str| -> Value {
        let mut command = Command::new(env!("CARGO_BIN_EXE_xref"));
        command
            .arg("-b")
            .arg(&stripped)
            .args([
                "field",
                "--keys",
                "c,m,e",
                "--write",
                "--writes-all-of",
                "m,e",
                "--max-instructions",
                "16384",
                "--limit",
                "1",
                "--json",
            ])
            .env("RAYON_NUM_THREADS", threads)
            .env("XDG_CACHE_HOME", dir.0.join(cache))
            .env("XREF_NO_RESULT_CACHE", "1"); // exercise the index, not the whole-report replay
        serde_json::from_slice(&run(&mut command).stdout).unwrap()
    };
    let single = query("1", "one");
    let parallel = query("4", "four");
    assert_eq!(single["status"], "candidates");
    assert_eq!(single["coverage"]["scan_index_cache_hits"], 0);
    assert_eq!(parallel, single, "parallel cold scan must preserve every report field");
    let warm = query("4", "four");
    assert_eq!(warm["coverage"]["scan_index_cache_hits"], 1);
    assert_eq!(warm["coverage"]["writer_index_cache_hits"], 1);
    assert_eq!(warm["candidates"], parallel["candidates"]);
    assert_eq!(warm["accessor_candidates"], parallel["accessor_candidates"]);
}
