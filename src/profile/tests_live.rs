/*
 * XRef — privileged sampling integration test
 * Copyright (c) 2026 Alexander Panasenko
 * Contact: alex@prod.codes
 * Author: https://prod.codes/about/
 * Project: https://github.com/alex09x/xref
 * SPDX-License-Identifier: MIT OR Apache-2.0
 */
use super::{
    capture,
    codec::ProfileReader,
    config::{Callers, Config},
    types::Record,
};
use std::{
    collections::BTreeSet,
    io::{BufRead, BufReader, Cursor, Write},
    path::PathBuf,
    process::{Child, Command, Stdio},
    time::Duration,
};

pub(super) struct Fixture {
    pub(super) directory: PathBuf,
    pub(super) child: Child,
    pub(super) reader: BufReader<std::process::ChildStdout>,
}
impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
        let _ = std::fs::remove_dir_all(&self.directory);
    }
}

pub(super) fn start_fixture() -> Result<(Fixture, PathBuf), Box<dyn std::error::Error>> {
    start_fixture_variant(false, false)
}

pub(super) fn start_fixture_variant(
    append_marker: bool,
    frame_pointers: bool,
) -> Result<(Fixture, PathBuf), Box<dyn std::error::Error>> {
    start_fixture_config(append_marker, frame_pointers, 2)
}

pub(super) fn start_fixture_config(
    append_marker: bool,
    frame_pointers: bool,
    workers: usize,
) -> Result<(Fixture, PathBuf), Box<dyn std::error::Error>> {
    let nonce = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH)?.as_nanos();
    let directory = std::env::temp_dir().join(format!("xref-profile-target-{}-{nonce}", std::process::id()));
    std::fs::create_dir_all(&directory)?;
    let binary = directory.join("target");
    let source = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/profile_target.c");
    let optimization = if append_marker { "-O3" } else { "-O2" };
    let mut compiler = Command::new("cc");
    compiler.args([optimization, "-g", "-pthread"]);
    if frame_pointers {
        compiler.args(["-fno-omit-frame-pointer", "-mno-omit-leaf-frame-pointer", "-DPROFILE_FORCE_FRAME"]);
    } else {
        compiler.arg("-fomit-frame-pointer");
    }
    let status = compiler.arg(source).arg("-o").arg(&binary).status()?;
    assert!(status.success());
    if append_marker {
        std::fs::OpenOptions::new().append(true).open(&binary)?.write_all(b"\0")?;
    }
    let mut command = if workers > 2 {
        let mut cmd = Command::new("nice");
        cmd.args(["-n", "19"]).arg(&binary);
        cmd
    } else {
        Command::new(&binary)
    };
    command.arg(workers.to_string());
    if workers > 2 {
        command.arg("metrics");
    }
    let mut child = command.stdin(Stdio::piped()).stdout(Stdio::piped()).spawn()?;
    let reader = BufReader::new(child.stdout.take().ok_or("missing target stdout")?);
    let mut fixture = Fixture { directory, child, reader };
    let mut ready = String::new();
    fixture.reader.read_line(&mut ready)?;
    assert!(ready.starts_with("READY pid="), "{ready}");
    Ok((fixture, binary))
}

#[test]
fn cancelled_profile_does_not_start_module_hashing() {
    let cancel = std::sync::atomic::AtomicBool::new(true);
    assert!(super::module_hash::collect(1, &[], Some(&cancel)).is_err());
}

#[test]
#[ignore = "requires Linux perf hardware event permission"]
fn frame_pointer_sampling_retains_real_caller_paths() -> Result<(), Box<dyn std::error::Error>> {
    let (mut fixture, binary) = start_fixture_variant(false, true)?;
    let mut session = crate::live::procfs::open_session(fixture.child.id(), Some(&binary), false)?;
    let config = Config {
        duration: Duration::from_secs(1),
        frequency_hz: Some(1000),
        max_samples: 10_000,
        callers: Callers::Fp,
        ..Config::default()
    };
    let (bytes, _) = capture::capture(&mut session, &config, Vec::new(), None)?;
    let analysis = super::analyze::analyze(&mut Cursor::new(bytes), &session.image, &BTreeSet::new())?;
    assert!(analysis.aggregate.samples > 0);
    if !analysis
        .aggregate
        .paths
        .keys()
        .any(|path| path.iter().filter(|frame| frame.module == 1 && frame.start.is_some()).count() >= 2)
    {
        let asm = Command::new("objdump").args(["-d", "--disassemble=profile_hot"]).arg(&binary).output()?;
        return Err(format!(
            "no resolved target caller path: {:?}; profile_hot: {}",
            analysis.aggregate.paths,
            String::from_utf8_lossy(&asm.stdout)
        )
        .into());
    }
    fixture.child.stdin.as_mut().ok_or("missing target stdin")?.write_all(b"\n")?;
    assert!(fixture.child.wait()?.success());
    Ok(())
}

#[test]
#[ignore = "requires Linux perf hardware event permission"]
fn lbr_reports_real_branches_or_explicit_unsupported_hardware() -> Result<(), Box<dyn std::error::Error>> {
    let (mut fixture, binary) = start_fixture()?;
    let mut session = crate::live::procfs::open_session(fixture.child.id(), Some(&binary), false)?;
    let config = Config {
        duration: Duration::from_millis(500),
        frequency_hz: Some(400),
        max_samples: 10_000,
        callers: Callers::Lbr,
        ..Config::default()
    };
    match capture::capture(&mut session, &config, Vec::new(), None) {
        Ok((bytes, stats)) => {
            assert!(stats.samples > 0, "{stats:?}");
            let mut reader = ProfileReader::new(Cursor::new(bytes))?;
            let mut branches = false;
            while let Some(record) = reader.read_record()? {
                if let Record::Sample(sample) = record {
                    branches |= !sample.branches.is_empty();
                }
            }
            assert!(branches, "successful LBR capture contained no branch history");
        }
        Err(error)
            if error.contains("perf_open_failed")
                && (error.contains("Invalid argument") || error.contains("not supported")) =>
        {
            eprintln!("hardware rejected LBR call-stack mode explicitly: {error}");
        }
        Err(error) => return Err(error.into()),
    }
    fixture.child.stdin.as_mut().ok_or("missing target stdin")?.write_all(b"\n")?;
    assert!(fixture.child.wait()?.success());
    Ok(())
}

#[test]
#[ignore = "requires Linux perf hardware event permission"]
fn captures_real_multithreaded_cpu_samples_and_explicit_coverage() -> Result<(), Box<dyn std::error::Error>> {
    let (mut fixture, binary) = start_fixture()?;
    let pid = fixture.child.id();
    let mut session = crate::live::procfs::open_session(pid, Some(&binary), false)?;
    let config = Config {
        duration: Duration::from_millis(500),
        frequency_hz: Some(400),
        max_samples: 10_000,
        callers: Callers::None,
        ..Config::default()
    };
    let (bytes, stats) = capture::capture(&mut session, &config, Vec::new(), None)?;
    assert!(stats.samples > 0, "{stats:?}");
    assert!(stats.observer_thread_cpu_ms.is_some(), "observer CPU measurement unavailable");
    assert!(stats.initial_threads >= 3, "{stats:?}");
    assert!(stats.partial_coverage);
    let mut analysis_input = Cursor::new(bytes.clone());
    let report = super::analyze::analyze(&mut analysis_input, &session.image, &BTreeSet::new())?;
    assert_eq!(report.aggregate.samples, stats.samples);
    assert!(
        report.aggregate.functions.keys().any(|key| key.module == 1 && key.start.is_some()),
        "no target samples in report"
    );
    let (lines, _, _) = super::lines::collect(&session.image, &report.aggregate)?;
    assert!(
        lines.iter().any(|line| line.file.ends_with("profile_target.c") && line.samples > 0),
        "missing C source lines"
    );
    let rows = super::report::build(&report, &session.image, 30)?;
    assert!(rows.functions.iter().any(|row| row.function.module == 1 && row.counts.self_samples > 0));
    let mut folded = Vec::new();
    super::report::folded(&report, &session.image, &mut folded)?;
    assert!(!folded.is_empty(), "captured samples should yield folded stacks");
    let mut profile = ProfileReader::new(Cursor::new(bytes))?;
    let mut samples = 0_u64;
    let mut footer = None;
    while let Some(record) = profile.read_record()? {
        match record {
            Record::Sample(sample) => {
                assert_eq!(sample.pid, pid);
                samples += 1;
            }
            Record::End(value) => footer = Some(value),
            _ => {}
        }
    }
    assert_eq!(samples, stats.samples);
    assert_eq!(footer.ok_or("missing footer")?.samples, samples);
    fixture.child.stdin.as_mut().ok_or("missing target stdin")?.write_all(b"\n")?;
    assert!(fixture.child.wait()?.success());
    Ok(())
}

#[test]
#[ignore = "requires Linux perf and uprobe permission"]
fn trigger_window_captures_real_uprobe_and_samples() -> Result<(), Box<dyn std::error::Error>> {
    let (mut fixture, binary) = start_fixture()?;
    let symbols = Command::new("nm").arg(&binary).output()?;
    assert!(symbols.status.success());
    let text = std::str::from_utf8(&symbols.stdout)?;
    let address = text
        .lines()
        .find_map(|line| {
            let mut words = line.split_whitespace();
            let address = words.next()?;
            let _kind = words.next()?;
            (words.next()? == "profile_hot").then_some(address)
        })
        .ok_or("missing fixture symbol")?;
    let address = u64::from_str_radix(address, 16)?;
    let mut session = crate::live::procfs::open_session(fixture.child.id(), Some(&binary), false)?;
    let config = Config {
        duration: Duration::from_secs(2),
        frequency_hz: Some(1000),
        max_samples: 10_000,
        callers: Callers::None,
        trigger_probe: Some(address),
        trigger_window: Duration::from_millis(100),
        ..Config::default()
    };
    let (bytes, _) = capture::capture(&mut session, &config, Vec::new(), None)?;
    let mut reader = ProfileReader::new(Cursor::new(bytes))?;
    let mut samples = Vec::new();
    let mut footer = None;
    while let Some(record) = reader.read_record()? {
        match record {
            Record::Sample(sample) => samples.push(sample.timestamp_ns),
            Record::End(value) => footer = Some(value),
            _ => {}
        }
    }
    let footer = footer.ok_or("missing footer")?;
    let trigger = footer.trigger_timestamp_ns.ok_or("uprobe trigger not observed")?;
    assert!(!samples.is_empty(), "no samples captured around trigger");
    assert!(samples.iter().all(|time| time.abs_diff(trigger) <= 100_000_000), "samples outside trigger window");
    fixture.child.stdin.as_mut().ok_or("missing target stdin")?.write_all(b"\n")?;
    assert!(fixture.child.wait()?.success());
    Ok(())
}

#[path = "tests_live_windows.rs"]
mod windows;

#[test]
#[ignore = "requires Linux perf hardware event permission"]
fn captures_and_unwinds_a_real_optimized_frame_without_frame_pointers() -> Result<(), Box<dyn std::error::Error>> {
    use object::{Object, ObjectSymbol};
    let (mut fixture, binary) = start_fixture()?;
    let bytes = std::fs::read(&binary)?;
    let file = object::File::parse(bytes.as_slice())?;
    let hot =
        file.symbols().find(|symbol| symbol.name().ok() == Some("profile_hot")).ok_or("missing fixture function")?;
    let hot_range = hot.address()..hot.address() + hot.size();
    let pid = fixture.child.id();
    let mut session = crate::live::procfs::open_session(pid, Some(&binary), false)?;
    let config = Config {
        duration: Duration::from_secs(1),
        frequency_hz: Some(1000),
        max_samples: 10_000,
        callers: Callers::Dwarf,
        ..Config::default()
    };
    let (bytes, stats) = capture::capture(&mut session, &config, Vec::new(), None)?;
    assert!(stats.samples > 0, "{stats:?}");
    let unwinder = super::unwind::Unwinder::new(&session.image, session.process.pie_slide)?;
    let analysis_start = std::time::Instant::now();
    let analyzed = super::analyze::analyze(&mut Cursor::new(bytes.clone()), &session.image, &BTreeSet::new())?;
    eprintln!("analyzed {} captured samples in {:?}", analyzed.aggregate.samples, analysis_start.elapsed());
    assert!(analyzed.aggregate.paths.keys().any(|path| path.len() >= 2), "analysis did not retain caller paths");
    let single = rayon::ThreadPoolBuilder::new()
        .num_threads(1)
        .build()?
        .install(|| super::analyze::analyze(&mut Cursor::new(bytes.clone()), &session.image, &BTreeSet::new()))?;
    assert_eq!(analyzed.aggregate.functions, single.aggregate.functions);
    assert_eq!(analyzed.aggregate.instructions, single.aggregate.instructions);
    assert_eq!(analyzed.aggregate.paths, single.aggregate.paths);
    assert_eq!(analyzed.warnings, single.warnings);
    let mut profile = ProfileReader::new(Cursor::new(bytes))?;
    let mut verified = 0;
    while let Some(record) = profile.read_record()? {
        if let Record::Sample(sample) = record
            && crate::live::types::remove_slide(sample.ip, session.process.pie_slide)
                .is_some_and(|ip| hot_range.contains(&ip))
            && unwinder.unwind(&sample, 16).frames.len() >= 2
        {
            verified += 1;
        }
    }
    assert!(verified > 0, "no captured hot sample unwound to a caller: {stats:?}");
    fixture.child.stdin.as_mut().ok_or("missing target stdin")?.write_all(b"\n")?;
    assert!(fixture.child.wait()?.success());
    Ok(())
}
