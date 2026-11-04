/*
 * XRef — Binary analysis
 * Copyright (c) 2026 Alexander Panasenko
 * Contact: alex@prod.codes
 * Author: https://prod.codes/about/
 * Project: https://github.com/alex09x/xref
 * SPDX-License-Identifier: MIT OR Apache-2.0
 */
use super::tests_live::{start_fixture, start_fixture_variant};
use super::{capture, config::Callers, config::Config};
use super::{codec::ProfileReader, types::Record};
use std::io::Write;
use std::{collections::BTreeSet, io::Cursor, path::PathBuf, process::Command, time::Duration};

#[test]
#[ignore = "requires Linux perf hardware event permission"]
fn diff_matches_real_different_image_hashes_without_claiming_equivalence() -> Result<(), Box<dyn std::error::Error>> {
    let (mut first, first_binary) = start_fixture()?;
    let (mut second, second_binary) = start_fixture_variant(true, false)?;
    assert_ne!(std::fs::read(&first_binary)?, std::fs::read(&second_binary)?);
    let config = Config {
        duration: Duration::from_millis(300),
        frequency_hz: Some(400),
        max_samples: 10_000,
        callers: Callers::None,
        ..Config::default()
    };
    let mut old_session = crate::live::procfs::open_session(first.child.id(), Some(&first_binary), false)?;
    let mut new_session = crate::live::procfs::open_session(second.child.id(), Some(&second_binary), false)?;
    let (old_bytes, _) = capture::capture(&mut old_session, &config, Vec::new(), None)?;
    let (new_bytes, _) = capture::capture(&mut new_session, &config, Vec::new(), None)?;
    let old = super::analyze::analyze(&mut Cursor::new(old_bytes), &old_session.image, &BTreeSet::new())?;
    let new = super::analyze::analyze(&mut Cursor::new(new_bytes), &new_session.image, &BTreeSet::new())?;
    let mut json = Vec::new();
    super::diff::write(&old_session.image, &new_session.image, &old, &new, true, 128, true, &mut json)?;
    let report: serde_json::Value = serde_json::from_slice(&json)?;
    let symbol = |path: &PathBuf| -> Result<u64, Box<dyn std::error::Error>> {
        let output = Command::new("nm").arg(path).output()?;
        let text = std::str::from_utf8(&output.stdout)?;
        let address = text
            .lines()
            .find_map(|line| {
                let mut fields = line.split_whitespace();
                let address = fields.next()?;
                let _kind = fields.next()?;
                (fields.next()? == "profile_hot").then_some(address)
            })
            .ok_or("missing profile_hot symbol")?;
        Ok(u64::from_str_radix(address, 16)?)
    };
    let (old_hot, new_hot) = (symbol(&first_binary)?, symbol(&second_binary)?);
    assert!(
        report["rows"]
            .as_array()
            .ok_or("missing diff rows")?
            .iter()
            .any(|row| row["pairing"] == "heuristic" && row["before"] == old_hot && row["after"] == new_hot),
        "hot function was not paired: {report}"
    );
    assert!(report["note"].as_str().is_some_and(|note| note.contains("heuristic")));
    first.child.stdin.as_mut().ok_or("missing stdin")?.write_all(b"\n")?;
    second.child.stdin.as_mut().ok_or("missing stdin")?.write_all(b"\n")?;
    assert!(first.child.wait()?.success() && second.child.wait()?.success());
    Ok(())
}

#[test]
#[ignore = "requires perf executable, sudo -n and hardware event permission"]
#[allow(clippy::too_many_lines)] // The recording, oracle and identity checks share one controlled process.
fn imports_perf_data_recorded_from_real_process() -> Result<(), Box<dyn std::error::Error>> {
    let (mut fixture, binary) = start_fixture()?;
    let path = std::env::split_paths(&std::env::var_os("PATH").ok_or("missing PATH")?)
        .map(|dir| dir.join("perf"))
        .find(|path| path.is_file())
        .ok_or("perf executable missing")?;
    let recording = fixture.directory.join("recording.data");
    let status = Command::new("sudo")
        .arg("-n")
        .arg(&path)
        .args(["record", "--no-buildid-cache", "-F", "400", "-e", "cycles:u", "-g", "-p"])
        .arg(fixture.child.id().to_string())
        .arg("-o")
        .arg(&recording)
        .args(["--", "sleep", "1"])
        .output()?;
    assert!(status.status.success(), "{}", String::from_utf8_lossy(&status.stderr));
    let session = crate::live::procfs::open_session(fixture.child.id(), Some(&binary), false)?;
    let base = u64::try_from(i128::from(session.image.metadata.base) + i128::from(session.process.pie_slide))?;
    let imported = fixture.directory.join("imported.xprof");
    let script = Command::new(&path)
        .args(["script", "--show-lost-events", "-F", "comm,pid,tid,time,period,event,ip,sym,dso", "-i"])
        .arg(&recording)
        .output()?;
    assert!(script.status.success(), "perf script: {}", String::from_utf8_lossy(&script.stderr));
    let mut parser = crate::trace_analysis::parse::TextParser::new(
        crate::trace_analysis::parse::InputFormat::Perf,
        crate::trace_analysis::models::FrameKind::Auto,
    );
    let mut expected = 0_u64;
    for line in std::str::from_utf8(&script.stdout)?.lines() {
        for event in parser.line(line)? {
            if matches!(event, crate::trace_analysis::parse::TraceEvent::Sample(sample) if sample.pid == Some(fixture.child.id()) && !sample.frames.is_empty())
            {
                expected += 1;
            }
        }
    }
    if matches!(parser.finish(), Some(crate::trace_analysis::parse::TraceEvent::Sample(sample)) if sample.pid == Some(fixture.child.id()) && !sample.frames.is_empty())
    {
        expected += 1;
    }
    let base_text = format!("{base:#x}");
    let options = super::import_text::Options {
        bin: &binary,
        input: &recording,
        output: &imported,
        base: Some(&base_text),
        maps: None,
        target_path: None,
        pid: Some(fixture.child.id()),
    };
    super::import_text::run(&session.image, &options)?;
    let mut raw = ProfileReader::new(std::fs::File::open(&imported)?)?;
    let mut timestamp_seen = false;
    while let Some(record) = raw.read_record()? {
        if let Record::Sample(sample) = record {
            timestamp_seen |= sample.timestamp_ns > 0;
        }
    }
    assert!(timestamp_seen, "recorded sample timestamps were not preserved");
    let mut file = std::fs::File::open(imported)?;
    let analysis = super::analyze::analyze(&mut file, &session.image, &BTreeSet::new())?;
    if analysis.aggregate.samples == 0 {
        let script = Command::new(&path)
            .args(["script", "--show-lost-events", "-F", "comm,pid,tid,time,period,event,ip,sym,dso", "-i"])
            .arg(&recording)
            .output()?;
        return Err(format!(
            "perf.data import had no samples; script: {}",
            String::from_utf8_lossy(&script.stdout).lines().take(8).collect::<Vec<_>>().join(" | ")
        )
        .into());
    }
    assert_eq!(analysis.aggregate.samples, expected, "import changed sample count");
    assert!(
        analysis.aggregate.functions.keys().any(|key| key.module == 1 && key.start.is_some()),
        "no target functions resolved"
    );
    assert!(analysis.aggregate.incomplete, "caller-supplied base must remain unverified");
    let (mut other, other_binary) = start_fixture_variant(true, false)?;
    let other_image = crate::image::Image::load(&other_binary)?;
    let mismatch_output = fixture.directory.join("mismatch.xprof");
    let mismatch = super::import_text::Options {
        bin: &other_binary,
        input: &recording,
        output: &mismatch_output,
        base: Some(&base_text),
        maps: None,
        target_path: Some(&binary),
        pid: Some(fixture.child.id()),
    };
    let Err(failure) = super::import_text::run(&other_image, &mismatch) else {
        return Err("different build ID was not rejected".into());
    };
    assert!(failure.to_string().contains("binary_mismatch"), "unexpected error: {failure}");
    assert!(!mismatch_output.exists(), "rejected binary mismatch left output");
    other.child.stdin.as_mut().ok_or("missing other stdin")?.write_all(b"\n")?;
    assert!(other.child.wait()?.success());
    fixture.child.stdin.as_mut().ok_or("missing target stdin")?.write_all(b"\n")?;
    assert!(fixture.child.wait()?.success());
    Ok(())
}

#[test]
#[ignore = "requires perf executable, sudo -n and hardware event permission"]
fn imports_perf_dwarf_registers_and_stack_without_external_converter() -> Result<(), Box<dyn std::error::Error>> {
    use object::{Object, ObjectSymbol};
    let (mut fixture, binary) = start_fixture()?;
    let perf = std::env::split_paths(&std::env::var_os("PATH").ok_or("missing PATH")?)
        .map(|dir| dir.join("perf"))
        .find(|path| path.is_file())
        .ok_or("perf executable missing")?;
    let recording = fixture.directory.join("dwarf.data");
    let status = Command::new("sudo")
        .arg("-n")
        .arg(&perf)
        .args([
            "record",
            "--no-buildid-cache",
            "--buildid-all",
            "--buildid-mmap",
            "-F",
            "400",
            "-e",
            "cycles:u",
            "--call-graph",
            "dwarf,2048",
            "-p",
        ])
        .arg(fixture.child.id().to_string())
        .arg("-o")
        .arg(&recording)
        .args(["--", "sleep", "1"])
        .output()?;
    assert!(status.status.success(), "{}", String::from_utf8_lossy(&status.stderr));
    let session = crate::live::procfs::open_session(fixture.child.id(), Some(&binary), false)?;
    let image_bytes = std::fs::read(&binary)?;
    let object = object::File::parse(image_bytes.as_slice())?;
    let symbol = |name: &str| {
        object
            .symbols()
            .find(|symbol| symbol.name().ok() == Some(name))
            .map(|symbol| symbol.address())
            .ok_or("missing fixture symbol")
    };
    let (hot, caller) = (symbol("profile_hot")?, symbol("worker")?);
    let base = u64::try_from(i128::from(session.image.metadata.base) + i128::from(session.process.pie_slide))?;
    let base_text = format!("{base:#x}");
    let imported = fixture.directory.join("dwarf.xprof");
    let options = super::import_text::Options {
        bin: &binary,
        input: &recording,
        output: &imported,
        base: Some(&base_text),
        maps: None,
        target_path: None,
        pid: Some(fixture.child.id()),
    };
    super::import_text::run(&session.image, &options)?;
    let mut reader = ProfileReader::new(std::fs::File::open(&imported)?)?;
    assert_eq!(reader.header.callchain, "dwarf");
    let mut stack_seen = false;
    let mut buildid_mapping = false;
    while let Some(record) = reader.read_record()? {
        match record {
            Record::Sample(sample) => stack_seen |= sample.registers_mask != 0 && !sample.user_stack.is_empty(),
            Record::Mapping(mapping) => buildid_mapping |= mapping.inode == 0 && mapping.sha256.is_some(),
            _ => {}
        }
    }
    assert!(stack_seen, "raw user registers and stack were not preserved");
    assert!(buildid_mapping, "verified build-ID mapping was not preserved");
    let analysis = super::analyze::analyze(&mut std::fs::File::open(&imported)?, &session.image, &BTreeSet::new())?;
    assert!(
        analysis
            .aggregate
            .paths
            .keys()
            .any(|path| path.iter().any(|frame| frame.module == 1 && frame.start == Some(caller))
                && path.last().is_some_and(|frame| frame.module == 1 && frame.start == Some(hot))),
        "native import lost the expected hot -> worker path"
    );
    let oracle = Command::new(&perf)
        .args(["script", "-F", "comm,pid,tid,time,event,ip,sym,dso", "-i"])
        .arg(&recording)
        .output()?;
    assert!(oracle.status.success(), "perf script oracle failed: {}", String::from_utf8_lossy(&oracle.stderr));
    assert!(
        String::from_utf8_lossy(&oracle.stdout)
            .split("\n\n")
            .any(|stack| stack.contains("profile_hot") && stack.contains("worker")),
        "perf script did not show the expected caller path"
    );
    assert!(
        analysis.modules.iter().any(|module| module.kind == "shared_object" && module.symbols_loaded),
        "recorded shared-object build IDs were not used"
    );
    fixture.child.stdin.as_mut().ok_or("missing target stdin")?.write_all(b"\n")?;
    assert!(fixture.child.wait()?.success());
    Ok(())
}
