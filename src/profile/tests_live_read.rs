/*
 * XRef — Binary analysis
 * Copyright (c) 2026 Alexander Panasenko
 * Contact: alex@prod.codes
 * Author: https://prod.codes/about/
 * Project: https://github.com/alex09x/xref
 * SPDX-License-Identifier: MIT OR Apache-2.0
 */
use super::tests_live::start_fixture;
use linux_perf_data::{PerfFileReader, linux_perf_event_reader::SampleFormat};
use std::io::Write;
use std::process::Command;

#[test]
#[ignore = "requires perf, sudo -n and hardware event permission"]
fn imports_real_grouped_read_samples() -> Result<(), Box<dyn std::error::Error>> {
    let (mut fixture, binary) = start_fixture()?;
    let recording = fixture.directory.join("read.data");
    let perf = std::env::split_paths(&std::env::var_os("PATH").ok_or("missing PATH")?)
        .map(|path| path.join("perf"))
        .find(|path| path.is_file())
        .ok_or("perf executable missing")?;
    let result = Command::new("sudo")
        .arg("-n")
        .arg(&perf)
        .args(["record", "--no-buildid-cache", "-F", "400", "-e", "{cycles:u,instructions:u}:S", "-g", "-p"])
        .arg(fixture.child.id().to_string())
        .arg("-o")
        .arg(&recording)
        .args(["--", "sleep", "1"])
        .output()?;
    assert!(result.status.success(), "perf record: {}", String::from_utf8_lossy(&result.stderr));
    let parsed = PerfFileReader::parse_file(std::io::BufReader::new(std::fs::File::open(&recording)?))?;
    assert!(parsed.perf_file.event_attributes().len() > 1, "expected multiple grouped events");
    assert!(
        parsed.perf_file.event_attributes()[0].attr.sample_format.contains(SampleFormat::READ),
        "expected sample READ"
    );
    let oracle = Command::new(&perf).args(["script", "-F", "event", "-i"]).arg(&recording).output()?;
    assert!(oracle.status.success(), "perf script: {}", String::from_utf8_lossy(&oracle.stderr));
    let expected =
        std::str::from_utf8(&oracle.stdout)?.lines().filter(|line| line.trim_start().starts_with("cycles")).count();
    let session = crate::live::procfs::open_session(fixture.child.id(), Some(&binary), false)?;
    let base = u64::try_from(i128::from(session.image.metadata.base) + i128::from(session.process.pie_slide))?;
    let base_text = format!("{base:#x}");
    let imported = fixture.directory.join("read.xprof");
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
    let mut input = std::fs::File::open(imported)?;
    let result = super::analyze::analyze(&mut input, &session.image, &std::collections::BTreeSet::new())?;
    assert!(result.aggregate.samples > 0, "expected imported samples");
    assert_eq!(usize::try_from(result.aggregate.samples)?, expected, "import sample count must agree with perf script");
    assert!(result.aggregate.incomplete, "multi-event import must be marked incomplete");
    fixture.child.stdin.as_mut().ok_or("missing stdin")?.write_all(b"\n")?;
    assert!(fixture.child.wait()?.success());
    Ok(())
}
