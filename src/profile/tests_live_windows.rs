/*
 * XRef — triggered profiler window tests
 * Copyright (c) 2026 Alexander Panasenko
 * Contact: alex@prod.codes
 * Author: https://prod.codes/about/
 * Project: https://github.com/alex09x/xref
 * SPDX-License-Identifier: MIT OR Apache-2.0
 */
use super::*;

#[test]
#[ignore = "requires Linux perf and writable tracefs"]
fn distinct_filtered_windows_attribute_samples_to_the_triggered_function() -> Result<(), Box<dyn std::error::Error>> {
    struct ChildGuard(std::process::Child);
    impl Drop for ChildGuard {
        fn drop(&mut self) {
            let _ = self.0.kill();
            let _ = self.0.wait();
        }
    }
    let directory = tempfile::tempdir()?;
    let source = directory.path().join("target.c");
    let binary = directory.path().join("target");
    std::fs::write(
        &source,
        r#"
#include <stdio.h>
#include <unistd.h>
#include <stdint.h>
__attribute__((noinline)) uint64_t rare(uint64_t op) {
    volatile uint64_t value = op;
    for (unsigned i = 0; i < 20000000; ++i) value = value * 3 + 1;
    return value;
}
int main(void) {
    setbuf(stdout, 0); puts("READY"); usleep(100000);
    for (unsigned i = 0; i < 40; ++i) { usleep(80000); rare(i % 2); }
    return 0;
}
"#,
    )?;
    assert!(Command::new("cc").args(["-O2", "-g"]).arg(&source).arg("-o").arg(&binary).status()?.success());
    let mut child = ChildGuard(Command::new(&binary).stdout(Stdio::piped()).spawn()?);
    let mut ready = String::new();
    BufReader::new(child.0.stdout.take().ok_or("missing target stdout")?).read_line(&mut ready)?;
    assert!(ready.starts_with("READY"));
    let symbols = Command::new("nm").arg(&binary).output()?;
    let text = std::str::from_utf8(&symbols.stdout)?;
    let address = text
        .lines()
        .find_map(|line| {
            let mut words = line.split_whitespace();
            let address = words.next()?;
            words.next()?;
            (words.next()? == "rare").then_some(address)
        })
        .ok_or("missing target symbol")?;
    let address = u64::from_str_radix(address, 16)?;
    let mut session = crate::live::procfs::open_session(child.0.id(), Some(&binary), false)?;
    let config = Config {
        duration: Duration::from_secs(3),
        frequency_hz: Some(1000),
        max_samples: 10_000,
        callers: Callers::None,
        trigger_probe: Some(address),
        trigger_window: Duration::from_millis(40),
        max_windows: Some(2),
        trigger_fetch: vec!["op=%di:u64".into()],
        trigger_filter: vec!["op == 1".into()],
        ..Config::default()
    };
    let (bytes, stats) = capture::capture(&mut session, &config, Vec::new(), None)?;
    assert_eq!(stats.stop_reason, "max_windows");
    let mut reader = ProfileReader::new(Cursor::new(&bytes))?;
    let mut windows = Vec::new();
    while let Some(record) = reader.read_record()? {
        if let Record::Window { trigger_ns, end_ns } = record {
            windows.push((trigger_ns, end_ns));
        }
    }
    assert_eq!(windows.len(), 2);
    assert!(windows[0].1 <= windows[1].0, "expected non-overlapping trigger windows");
    for index in 1..=2 {
        let selected = super::super::analyze::analyze_windows(
            &mut Cursor::new(&bytes),
            &session.image,
            &BTreeSet::from([address]),
            Some(index),
            false,
        )?;
        assert!(selected.aggregate.samples > 0, "window {index} has no samples in the target function");
    }
    Ok(())
}

#[test]
#[ignore = "requires Linux perf and writable tracefs"]
fn system_wide_trigger_observes_a_short_lived_thread() -> Result<(), Box<dyn std::error::Error>> {
    struct ChildGuard(std::process::Child);
    impl Drop for ChildGuard {
        fn drop(&mut self) {
            let _ = self.0.kill();
            let _ = self.0.wait();
        }
    }
    let directory = tempfile::tempdir()?;
    let (source, binary) = (directory.path().join("short.c"), directory.path().join("short"));
    std::fs::write(
        &source,
        r#"
#include <pthread.h>
#include <stdio.h>
#include <unistd.h>
#include <stdint.h>
__attribute__((noinline)) uint64_t rare(uint64_t op) { volatile uint64_t v = op; return v * 3; }
static void *once(void *arg) { (void)arg; rare(1); return 0; }
int main(void) {
    setbuf(stdout, 0); puts("READY"); usleep(400000);
    pthread_t thread; pthread_create(&thread, 0, once, 0); pthread_join(thread, 0);
    usleep(1500000);
    return 0;
}
"#,
    )?;
    assert!(Command::new("cc").args(["-O1", "-pthread"]).arg(&source).arg("-o").arg(&binary).status()?.success());
    let mut child = ChildGuard(Command::new(&binary).stdout(Stdio::piped()).spawn()?);
    let mut ready = String::new();
    BufReader::new(child.0.stdout.take().ok_or("missing target stdout")?).read_line(&mut ready)?;
    assert!(ready.starts_with("READY"));
    let symbols = Command::new("nm").arg(&binary).output()?;
    let address = std::str::from_utf8(&symbols.stdout)?
        .lines()
        .find_map(|line| {
            let mut words = line.split_whitespace();
            let address = words.next()?;
            words.next()?;
            (words.next()? == "rare").then_some(address)
        })
        .ok_or("missing target symbol")?;
    let mut session = crate::live::procfs::open_session(child.0.id(), Some(&binary), false)?;
    let config = Config {
        duration: Duration::from_millis(1200),
        frequency_hz: Some(1000),
        max_samples: 10_000,
        callers: Callers::None,
        trigger_probe: Some(u64::from_str_radix(address, 16)?),
        trigger_window: Duration::from_millis(50),
        max_windows: Some(1),
        ..Config::default()
    };
    let (_, stats) = capture::capture(&mut session, &config, Vec::new(), None)?;
    assert_eq!(stats.stop_reason, "max_windows", "the trigger in a thread born after attach must be observed");
    Ok(())
}

#[test]
#[ignore = "requires Linux perf and uprobe permission"]
fn captures_multiple_trigger_windows_in_one_profile() -> Result<(), Box<dyn std::error::Error>> {
    let (mut fixture, binary) = start_fixture()?;
    let symbols = Command::new("nm").arg(&binary).output()?;
    let text = std::str::from_utf8(&symbols.stdout)?;
    let address = text
        .lines()
        .find_map(|line| {
            let mut words = line.split_whitespace();
            let address = words.next()?;
            words.next()?;
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
        max_windows: Some(2),
        ..Config::default()
    };
    let (bytes, stats) = capture::capture(&mut session, &config, Vec::new(), None)?;
    assert_eq!(stats.stop_reason, "max_windows");
    let mut reader = ProfileReader::new(Cursor::new(&bytes))?;
    assert_eq!(reader.header.schema_version, 3);
    let (mut windows, mut samples) = (Vec::new(), Vec::new());
    while let Some(record) = reader.read_record()? {
        match record {
            Record::Window { trigger_ns, end_ns } => {
                windows.push(super::super::windowing::Window { trigger_ns, end_ns });
            }
            Record::Sample(sample) => samples.push(sample.timestamp_ns),
            _ => {}
        }
    }
    assert_eq!(windows.len(), 2);
    assert!(!samples.is_empty(), "no samples inside the captured windows");
    assert!(samples.iter().all(|time| windows.iter().any(|window| window.contains(*time))));
    let mut input = Cursor::new(bytes);
    let analysis = super::super::analyze::analyze_windows(&mut input, &session.image, &BTreeSet::new(), None, true)?;
    assert_eq!(analysis.aggregate.samples, u64::try_from(samples.len())?);
    for (index, window) in windows.iter().enumerate() {
        let selected = super::super::analyze::analyze_windows(
            &mut input,
            &session.image,
            &BTreeSet::new(),
            Some(index + 1),
            false,
        )?;
        assert_eq!(
            selected.aggregate.samples,
            u64::try_from(samples.iter().filter(|time| window.contains(**time)).count())?
        );
    }
    let within = BTreeSet::from([address]);
    let selected = super::super::analyze::analyze_windows(&mut input, &session.image, &within, Some(1), false)?;
    assert!(selected.aggregate.samples > 0, "selected window did not attribute samples to the trigger function");
    fixture.child.stdin.as_mut().ok_or("missing target stdin")?.write_all(b"\n")?;
    assert!(fixture.child.wait()?.success());
    Ok(())
}

#[test]
#[ignore = "requires Linux perf and writable tracefs"]
fn trigger_filter_suppresses_nonmatching_real_uprobes() -> Result<(), Box<dyn std::error::Error>> {
    let (mut fixture, binary) = start_fixture()?;
    let symbols = Command::new("nm").arg(&binary).output()?;
    let text = std::str::from_utf8(&symbols.stdout)?;
    let address = text
        .lines()
        .find_map(|line| {
            let mut words = line.split_whitespace();
            let address = words.next()?;
            words.next()?;
            (words.next()? == "profile_hot").then_some(address)
        })
        .ok_or("missing fixture symbol")?;
    let address = u64::from_str_radix(address, 16)?;
    let mut session = crate::live::procfs::open_session(fixture.child.id(), Some(&binary), false)?;
    let mut config = Config {
        duration: Duration::from_millis(500),
        frequency_hz: Some(1000),
        max_samples: 10_000,
        callers: Callers::None,
        trigger_probe: Some(address),
        trigger_window: Duration::from_millis(100),
        max_windows: Some(1),
        trigger_fetch: vec!["op=%di:u64".into()],
        trigger_filter: vec!["op == 0".into()],
        ..Config::default()
    };
    let (_, rejected) = capture::capture(&mut session, &config, Vec::new(), None)?;
    assert_eq!(rejected.stop_reason, "trigger_not_observed");
    assert_eq!(rejected.samples, 0);
    config.trigger_filter = vec!["op != 0".into()];
    let (_, accepted) = capture::capture(&mut session, &config, Vec::new(), None)?;
    assert_eq!(accepted.stop_reason, "max_windows");
    assert!(accepted.samples > 0, "matching trigger did not record samples");
    fixture.child.stdin.as_mut().ok_or("missing target stdin")?.write_all(b"\n")?;
    assert!(fixture.child.wait()?.success());
    Ok(())
}
