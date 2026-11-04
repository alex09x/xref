/*
 * XRef — Binary analysis
 * Copyright (c) 2026 Alexander Panasenko
 * Contact: alex@prod.codes
 * Author: https://prod.codes/about/
 * Project: https://github.com/alex09x/xref
 * SPDX-License-Identifier: MIT OR Apache-2.0
 */
use super::tests_live::{Fixture, start_fixture_config};
use super::{capture, config::Callers, config::Config};
use std::io::{BufRead, Write};
use std::time::Duration;

#[test]
#[ignore = "10-second 64-thread hardware sampling measurement"]
#[allow(clippy::cast_precision_loss)] // Throughput is a floating-point measurement; raw counts remain exact.
fn profile_64_workers_at_4khz_reports_cost_and_loss() -> Result<(), Box<dyn std::error::Error>> {
    fn finish(fixture: &mut Fixture) -> Result<u64, Box<dyn std::error::Error>> {
        fixture.child.stdin.as_mut().ok_or("missing target stdin")?.write_all(b"\n")?;
        assert!(fixture.child.wait()?.success());
        let mut line = String::new();
        fixture.reader.read_line(&mut line)?;
        Ok(line.trim().strip_prefix("DONE operations=").ok_or("missing operation count")?.parse()?)
    }
    let (mut baseline, _) = start_fixture_config(false, false, 64)?;
    let baseline_start = std::time::Instant::now();
    std::thread::sleep(Duration::from_secs(10));
    let baseline_ops = finish(&mut baseline)?;
    let baseline_seconds = baseline_start.elapsed().as_secs_f64();
    let (mut fixture, binary) = start_fixture_config(false, false, 64)?;
    let observed_start = std::time::Instant::now();
    let mut session = crate::live::procfs::open_session(fixture.child.id(), Some(&binary), false)?;
    let output = fixture.directory.join("load.xprof");
    let writer = std::io::BufWriter::new(std::fs::File::create(&output)?);
    let config = Config {
        duration: Duration::from_secs(10),
        frequency_hz: Some(4000),
        max_samples: 3_000_000,
        callers: Callers::Dwarf,
        stack_bytes: 512,
        ..Config::default()
    };
    let (writer, stats) = capture::capture(&mut session, &config, writer, None)?;
    drop(writer);
    assert!(stats.initial_threads >= 65, "{stats:?}");
    assert!(stats.samples > 0 && stats.observer_thread_cpu_ms.is_some(), "{stats:?}");
    assert_eq!(stats.stop_reason, "duration", "{stats:?}");
    let observed_ops = finish(&mut fixture)?;
    let observed_seconds = observed_start.elapsed().as_secs_f64();
    assert!(baseline_ops > 0 && observed_ops > 0, "target fixture did not make progress");
    let baseline_rate = baseline_ops as f64 / baseline_seconds;
    let observed_rate = observed_ops as f64 / observed_seconds;
    eprintln!(
        "64-worker 4 kHz capture, 512-byte stacks: {stats:?}; recording bytes={}; baseline ops/s={baseline_rate:.1}; observed ops/s={observed_rate:.1}; relative throughput change={:.2}%",
        std::fs::metadata(&output)?.len(),
        100.0 * (observed_rate / baseline_rate - 1.0)
    );
    Ok(())
}
