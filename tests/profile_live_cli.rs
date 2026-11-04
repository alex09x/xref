/*
 * XRef — live profiler CLI integration tests
 * Copyright (c) 2026 Alexander Panasenko
 * Contact: alex@prod.codes
 * Author: https://prod.codes/about/
 * Project: https://github.com/alex09x/xref
 * SPDX-License-Identifier: MIT OR Apache-2.0
 */
#![cfg(all(target_os = "linux", target_arch = "x86_64"))]
#![allow(clippy::unwrap_used, clippy::expect_used)]
use object::{Object, ObjectSymbol};
use serde_json::Value;
use std::{
    io::{BufRead, BufReader, Write},
    path::PathBuf,
    process::{Child, Command, Stdio},
};

struct Fixture {
    directory: PathBuf,
    child: Child,
}
impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
        let _ = std::fs::remove_dir_all(&self.directory);
    }
}

#[test]
#[ignore = "requires sudo -n and Linux perf hardware event permission"]
#[allow(clippy::too_many_lines)] // The steps intentionally share a single real captured process and recording.
fn live_profile_cli_samples_stripped_rust_without_frame_pointers() -> Result<(), Box<dyn std::error::Error>> {
    let nonce = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH)?.as_nanos();
    let directory = std::env::temp_dir().join(format!("xref-profile-rust-{}-{nonce}", std::process::id()));
    std::fs::create_dir_all(&directory)?;
    let source = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/profile_target.rs");
    let original = directory.join("original");
    let binary = directory.join("stripped");
    let compiled = Command::new("rustc")
        .args(["--edition=2024", "-C", "opt-level=2", "-C", "force-frame-pointers=no", "-C", "debuginfo=2"])
        .arg(source)
        .arg("-o")
        .arg(&original)
        .output()?;
    assert!(compiled.status.success(), "{}", String::from_utf8_lossy(&compiled.stderr));
    let bytes = std::fs::read(&original)?;
    let object = object::File::parse(bytes.as_slice())?;
    let hot = object
        .symbols()
        .find(|symbol| symbol.name().ok() == Some("profile_rust_hot"))
        .ok_or("missing hot symbol")?
        .address();
    assert!(Command::new("objcopy").arg("--strip-all").arg(&original).arg(&binary).status()?.success());
    let child = Command::new(&binary).stdin(Stdio::piped()).stdout(Stdio::piped()).spawn()?;
    let mut fixture = Fixture { directory, child };
    let mut ready = String::new();
    BufReader::new(fixture.child.stdout.take().ok_or("missing fixture stdout")?).read_line(&mut ready)?;
    assert!(ready.starts_with("READY pid="), "{ready}");
    let profile = fixture.directory.join("capture.xprof");
    let result = Command::new("sudo")
        .arg("-n")
        .arg(env!("CARGO_BIN_EXE_xref"))
        .arg("-b")
        .arg(&binary)
        .args([
            "live",
            "profile",
            "--pid",
            &fixture.child.id().to_string(),
            "--duration",
            "1s",
            "--freq",
            "1000",
            "--callers",
            "dwarf",
            "--json",
            "--out",
        ])
        .arg(&profile)
        .output()?;
    assert!(result.status.success(), "{}", String::from_utf8_lossy(&result.stderr));
    let result: Value = serde_json::from_slice(&result.stdout)?;
    assert!(result["capture"]["samples"].as_u64().unwrap_or(0) > 0, "{result}");
    assert!(
        result["report"]["functions"].as_array().unwrap().iter().any(|row| {
            row["function"]["module"] == 1
                && row["function"]["start"] == hot
                && row["counts"]["self_samples"].as_u64().unwrap_or(0) > 0
        }),
        "hot stripped Rust function not found: {result}"
    );
    let offline = Command::new("sudo")
        .arg("-n")
        .arg(env!("CARGO_BIN_EXE_xref"))
        .arg("-b")
        .arg(&binary)
        .args(["profile", "report"])
        .arg(&profile)
        .arg("--json")
        .output()?;
    assert!(offline.status.success(), "{}", String::from_utf8_lossy(&offline.stderr));
    let report: Value = serde_json::from_slice(&offline.stdout)?;
    assert_eq!(report["samples"], result["report"]["samples"]);
    let annotated = Command::new("sudo")
        .arg("-n")
        .arg(env!("CARGO_BIN_EXE_xref"))
        .arg("-b")
        .arg(&binary)
        .args(["profile", "annotate"])
        .arg(&profile)
        .arg(format!("{hot:#x}"))
        .arg("--json")
        .output()?;
    assert!(annotated.status.success(), "{}", String::from_utf8_lossy(&annotated.stderr));
    let rows: Value = serde_json::from_slice(&annotated.stdout)?;
    assert!(
        rows.as_array().ok_or("missing annotation rows")?.iter().any(|row| row["samples"].as_u64().unwrap_or(0) > 0)
    );
    let c_report = Command::new("sudo")
        .arg("-n")
        .arg(env!("CARGO_BIN_EXE_xref"))
        .arg("-b")
        .arg(&binary)
        .args(["profile", "annotate"])
        .arg(&profile)
        .arg(format!("{hot:#x}"))
        .args(["--c", "--json"])
        .output()?;
    assert!(c_report.status.success(), "{}", String::from_utf8_lossy(&c_report.stderr));
    let c_report: Value = serde_json::from_slice(&c_report.stdout)?;
    assert!(
        !c_report["lines"].as_array().ok_or("missing pseudo-C lines")?.is_empty(),
        "pseudo-C output must contain lines"
    );
    assert!(c_report["unmapped_samples"].is_number());
    let instruction_samples: u64 =
        rows.as_array().unwrap().iter().map(|row| row["samples"].as_u64().unwrap_or(0)).sum();
    let line_samples: u64 =
        c_report["lines"].as_array().unwrap().iter().map(|line| line["samples"].as_u64().unwrap_or(0)).sum();
    assert_eq!(line_samples + c_report["unmapped_samples"].as_u64().unwrap(), instruction_samples);
    let diff = Command::new("sudo")
        .arg("-n")
        .arg(env!("CARGO_BIN_EXE_xref"))
        .arg("-b")
        .arg(&binary)
        .args(["profile", "diff"])
        .arg(&profile)
        .arg(&profile)
        .arg("--json")
        .output()?;
    assert!(diff.status.success(), "{}", String::from_utf8_lossy(&diff.stderr));
    let diff: Value = serde_json::from_slice(&diff.stdout)?;
    assert!(
        diff["rows"]
            .as_array()
            .ok_or("missing diff rows")?
            .iter()
            .all(|row| row["delta_percent"].as_f64() == Some(0.0))
    );
    let slide = result["report"]["header"]["pie_slide"].as_i64().ok_or("missing PIE slide")?;
    let runtime_hot = u64::try_from(i128::from(hot) + i128::from(slide))?;
    let script = fixture.directory.join("script.txt");
    std::fs::write(
        &script,
        format!("native {0}/{0} [000] 1.000000: cycles:P:\n\t{runtime_hot:x} unknown (target)\n\n", fixture.child.id()),
    )?;
    let imported = fixture.directory.join("imported.xprof");
    let import = Command::new(env!("CARGO_BIN_EXE_xref"))
        .arg("-b")
        .arg(&binary)
        .args(["profile", "import"])
        .arg(&script)
        .arg("--out")
        .arg(&imported)
        .args(["--base", &format!("{slide:#x}"), "--pid", &fixture.child.id().to_string()])
        .output()?;
    assert!(import.status.success(), "{}", String::from_utf8_lossy(&import.stderr));
    let imported_report = Command::new(env!("CARGO_BIN_EXE_xref"))
        .arg("-b")
        .arg(&binary)
        .args(["profile", "report"])
        .arg(&imported)
        .arg("--json")
        .output()?;
    assert!(imported_report.status.success(), "{}", String::from_utf8_lossy(&imported_report.stderr));
    let imported_report: Value = serde_json::from_slice(&imported_report.stdout)?;
    assert_eq!(imported_report["samples"], 1);
    assert!(imported_report["functions"].as_array().unwrap().iter().any(|row| row["function"]["start"] == hot));
    let maps = fixture.directory.join("maps.txt");
    std::fs::write(&maps, std::fs::read(format!("/proc/{}/maps", fixture.child.id()))?)?;
    let maps_profile = fixture.directory.join("maps-imported.xprof");
    let maps_import = Command::new(env!("CARGO_BIN_EXE_xref"))
        .arg("-b")
        .arg(&binary)
        .args(["profile", "import"])
        .arg(&script)
        .arg("--out")
        .arg(&maps_profile)
        .arg("--maps")
        .arg(&maps)
        .args(["--pid", &fixture.child.id().to_string()])
        .output()?;
    assert!(maps_import.status.success(), "maps import failed: {}", String::from_utf8_lossy(&maps_import.stderr));
    let maps_report = Command::new(env!("CARGO_BIN_EXE_xref"))
        .arg("-b")
        .arg(&binary)
        .args(["profile", "report"])
        .arg(&maps_profile)
        .arg("--json")
        .output()?;
    assert!(maps_report.status.success(), "{}", String::from_utf8_lossy(&maps_report.stderr));
    let maps_report: Value = serde_json::from_slice(&maps_report.stdout)?;
    assert!(maps_report["functions"].as_array().unwrap().iter().any(|row| row["function"]["start"] == hot));
    let rejected_output = fixture.directory.join("rejected.xprof");
    let rejected = Command::new(env!("CARGO_BIN_EXE_xref"))
        .arg("-b")
        .arg(&binary)
        .args(["profile", "import"])
        .arg(&script)
        .arg("--out")
        .arg(&rejected_output)
        .arg("--maps")
        .arg(&maps)
        .args(["--base", &format!("{slide:#x}"), "--pid", &fixture.child.id().to_string()])
        .output()?;
    assert!(!rejected.status.success(), "conflicting map and base accepted");
    assert!(!rejected_output.exists(), "rejected import left an output file");
    let bad_data = fixture.directory.join("truncated.data");
    let bad_output = fixture.directory.join("bad.xprof");
    std::fs::write(&bad_data, b"PERFILE2")?;
    let invalid = Command::new(env!("CARGO_BIN_EXE_xref"))
        .arg("-b")
        .arg(&binary)
        .args(["profile", "import"])
        .arg(&bad_data)
        .arg("--out")
        .arg(&bad_output)
        .args(["--base", &format!("{slide:#x}"), "--pid", &fixture.child.id().to_string()])
        .output()?;
    assert!(!invalid.status.success(), "truncated perf.data unexpectedly succeeded");
    assert!(!bad_output.exists(), "failed import left an output file");
    fixture.child.stdin.as_mut().ok_or("missing stdin")?.write_all(b"\n")?;
    assert!(fixture.child.wait()?.success());
    Ok(())
}

#[test]
#[ignore = "requires perf executable and Linux hardware event permission"]
fn native_perf_data_import_works_without_perf_in_child_path() -> Result<(), Box<dyn std::error::Error>> {
    let perf = std::env::split_paths(&std::env::var_os("PATH").ok_or("missing PATH")?)
        .map(|dir| dir.join("perf"))
        .find(|path| path.is_file())
        .ok_or("perf executable missing")?;
    let nonce = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH)?.as_nanos();
    let directory = std::env::temp_dir().join(format!("xref-native-import-{}-{nonce}", std::process::id()));
    std::fs::create_dir_all(&directory)?;
    let binary = directory.join("target");
    let source = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/profile_target.c");
    assert!(
        Command::new("cc")
            .args(["-O2", "-g", "-fomit-frame-pointer", "-pthread"])
            .arg(source)
            .arg("-o")
            .arg(&binary)
            .status()?
            .success()
    );
    let child = Command::new(&binary).stdin(Stdio::piped()).stdout(Stdio::piped()).spawn()?;
    let mut fixture = Fixture { directory, child };
    let mut ready = String::new();
    BufReader::new(fixture.child.stdout.take().ok_or("missing target stdout")?).read_line(&mut ready)?;
    assert!(ready.starts_with("READY pid="), "{ready}");
    let recording = fixture.directory.join("profile.data");
    let recorded = Command::new(perf)
        .args(["record", "--no-buildid-cache", "-F", "400", "-e", "cycles:u", "--call-graph", "dwarf,2048", "-p"])
        .arg(fixture.child.id().to_string())
        .arg("-o")
        .arg(&recording)
        .args(["--", "sleep", "1"])
        .output()?;
    assert!(recorded.status.success(), "{}", String::from_utf8_lossy(&recorded.stderr));
    let maps = fixture.directory.join("maps.txt");
    std::fs::write(&maps, std::fs::read(format!("/proc/{}/maps", fixture.child.id()))?)?;
    let output = fixture.directory.join("native.xprof");
    let imported = Command::new(env!("CARGO_BIN_EXE_xref"))
        .env("PATH", &fixture.directory)
        .arg("-b")
        .arg(&binary)
        .args(["profile", "import"])
        .arg(&recording)
        .arg("--out")
        .arg(&output)
        .arg("--maps")
        .arg(&maps)
        .args(["--pid", &fixture.child.id().to_string()])
        .output()?;
    assert!(imported.status.success(), "native import failed: {}", String::from_utf8_lossy(&imported.stderr));
    let report = Command::new(env!("CARGO_BIN_EXE_xref"))
        .env("PATH", &fixture.directory)
        .arg("-b")
        .arg(&binary)
        .args(["profile", "report"])
        .arg(&output)
        .arg("--json")
        .output()?;
    assert!(report.status.success(), "{}", String::from_utf8_lossy(&report.stderr));
    let report: Value = serde_json::from_slice(&report.stdout)?;
    assert_eq!(report["header"]["callchain"], "dwarf");
    assert!(report["samples"].as_u64().unwrap_or(0) > 0);
    assert!(report["paths"].as_array().is_some_and(|paths| {
        paths.iter().any(|path| path["frames"].as_array().is_some_and(|frames| frames.len() >= 2))
    }));
    fixture.child.stdin.as_mut().ok_or("missing stdin")?.write_all(b"\n")?;
    assert!(fixture.child.wait()?.success());
    Ok(())
}
