/*
 * XRef — `live profile` on macOS: macOS `sample` recorded into an `.xprof`
 * Copyright (c) 2026 Alexander Panasenko
 * Contact: alex@prod.codes
 * Author: https://prod.codes/about/
 * Project: https://github.com/alex09x/xref
 * SPDX-License-Identifier: MIT OR Apache-2.0
 */

//! On macOS, `xref live profile` runs the system's `/usr/bin/sample` on the process (it suspends
//! each thread at the interval and walks its frame pointers, which arm64 macOS keeps), reads the
//! call tree it writes and records it as an `.xprof`: one sample per sampled stack, call chains as
//! return addresses, mappings from its binary image list. The main executable must be the `-b`
//! binary (same `LC_UUID`). `profile report`, `diff` and `--within` then work as on Linux. System
//! libraries live in the dyld shared cache, not in files: their frames are attributed to the
//! library, without function names.

use std::io::Write;
use std::path::Path;

use super::cli::LiveProfileArgs;
use super::sample_text::{SampleReport, Stack};
use super::types::{Header, Mapping, Record, Sample};

/// `(major, minor)` of a macOS `dev_t` (8-bit major, 24-bit minor).
const fn device(dev: u64) -> (u64, u64) {
    ((dev >> 24) & 0xff, dev & 0x00ff_ffff)
}

fn sha256_hex(bytes: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    crate::trace_analysis::index::hex_bytes(&Sha256::digest(bytes))
}

/// Runs `sample` on `pid` and returns its report text.
fn run_sample(pid: u32, seconds: u64, interval_ms: u64, dir: &Path) -> Result<String, String> {
    let file = dir.join("sample.txt");
    let output = std::process::Command::new("/usr/bin/sample")
        .arg(pid.to_string())
        .arg(seconds.to_string())
        .arg(interval_ms.to_string())
        .arg("-mayDie")
        .arg("-file")
        .arg(&file)
        .output()
        .map_err(|error| format!("cannot run /usr/bin/sample: {error}"))?;
    if !output.status.success() {
        let detail = String::from_utf8_lossy(&output.stderr);
        return Err(format!(
            "sample failed for pid {pid}: {} (a process of another user, or a hardened one, needs sudo)",
            detail.trim()
        ));
    }
    std::fs::read_to_string(&file).map_err(|error| format!("{}: {error}", file.display()))
}

/// The recording of a parsed report: the executable's mapping verified against `bin`, the other
/// modules identified by their UUIDs.
pub fn recording(
    report: &SampleReport,
    image: &crate::image::Image,
    bin: &Path,
    pid: u32,
) -> Result<(Header, Vec<Mapping>), String> {
    use std::os::unix::fs::MetadataExt;
    let load = report.load_address.ok_or("the sample report has no load address")?;
    let main =
        report.images.iter().find(|image| image.start == load).ok_or("the main executable is not in the image list")?;
    // The binary is verified only when both sides name the same UUID; without one there is no
    // proof that -b is what the process runs.
    let expected = crate::macho::arm64::uuid(&image.data)
        .ok_or_else(|| format!("binary_unverified: {} has no LC_UUID to compare with the process", bin.display()))?;
    let found = main.uuid.as_deref().ok_or("binary_unverified: the sample report gives no UUID for the executable")?;
    if !expected.eq_ignore_ascii_case(found) {
        return Err(format!(
            "binary_mismatch: the process runs {} (UUID {found}), not {} (UUID {expected})",
            main.name,
            bin.display()
        ));
    }
    let metadata = std::fs::metadata(bin).map_err(|error| format!("{}: {error}", bin.display()))?;
    let (major, minor) = device(metadata.dev());
    let sha = sha256_hex(&image.data);
    let slide = i64::try_from(i128::from(load) - i128::from(image.metadata.base)).map_err(|_| "slide overflow")?;
    let header = Header {
        schema_version: 1,
        image_sha256: sha.clone(),
        process_exe_sha256: Some(sha.clone()),
        binary_match: "verified_uuid".to_owned(),
        pie_slide: slide,
        exe_device_major: major,
        exe_device_minor: minor,
        exe_inode: metadata.ino(),
        pid,
        starttime_ticks: 0,
        event: "macos-sample".to_owned(),
        frequency_hz: report.interval_ms.filter(|ms| *ms > 0).map(|ms| 1000 / ms),
        period: None,
        callchain: "fp".to_owned(),
        started_monotonic_ns: 0,
        trigger_static_va: None,
        trigger_window_ns: None,
    };
    let mut mappings = Vec::new();
    for module in &report.images {
        let is_main = module.start == load;
        mappings.push(Mapping {
            timestamp_ns: 0,
            pid,
            tid: pid,
            start: module.start,
            length: module.end.saturating_sub(module.start).saturating_add(1),
            file_offset: 0,
            device_major: if is_main { u32::try_from(major).unwrap_or(0) } else { 0 },
            device_minor: if is_main { u32::try_from(minor).unwrap_or(0) } else { 0 },
            inode: if is_main { metadata.ino() } else { 0 },
            executable: true,
            // A shared-cache library has no file to verify: its UUID names it, so its frames are
            // attributed to it rather than to an unknown module.
            sha256: if is_main {
                Some(sha.clone())
            } else {
                module.uuid.as_deref().map(|uuid| sha256_hex(uuid.as_bytes()))
            },
            path: if is_main {
                bin.display().to_string()
            } else if module.path.is_empty() {
                module.name.clone()
            } else {
                module.path.clone()
            },
        });
    }
    Ok((header, mappings))
}

/// The sample record of one stack (written once per sample it holds).
fn sample_of(stack: &Stack, pid: u32) -> Option<Record> {
    let (&ip, callers) = stack.ips.split_first()?;
    Some(Record::Sample(Sample {
        timestamp_ns: 1,
        pid,
        tid: stack.thread,
        cpu_mode: 2,
        ip,
        period: 1,
        registers_mask: 0,
        registers: Vec::new(),
        user_stack: Vec::new(),
        callchain: callers.to_vec(),
        branches: Vec::new(),
    }))
}

pub fn run(bin: Option<&Path>, args: &LiveProfileArgs, out: &mut dyn Write) -> Result<(), Box<dyn std::error::Error>> {
    use std::io::{BufReader, BufWriter};
    let bin = bin.ok_or("live profile on macOS needs -b <the binary of the process>")?;
    let pid = args.pid;
    let config = args.config();
    // sample is a timer over whole seconds that records whole call stacks and aggregates them: the
    // options it cannot honour are refused rather than ignored.
    let unsupported = !config.tids.is_empty()
        || config.trigger_probe.is_some()
        || config.include_kernel
        || config.period.is_some()
        || config.event != super::config::Event::Cycles
        || !matches!(config.callers, super::config::Callers::Dwarf | super::config::Callers::Fp)
        || args.max_samples != 10_000_000;
    if unsupported {
        return Err("on macOS, live profile supports --pid, --duration, --freq, --within, --out, --folded and --json (sample is a timer that records whole stacks, aggregated)".into());
    }
    if config.duration.subsec_nanos() != 0 {
        return Err("on macOS, --duration must be whole seconds (sample takes seconds)".into());
    }
    let image = crate::image::Image::load_for_profile(bin)?;
    let within = args
        .within
        .iter()
        .map(|name| crate::graph::resolve(&image, name).map(|range| range.start))
        .collect::<Result<std::collections::BTreeSet<_>, _>>()?;
    let seconds = config.duration.as_secs_f64().ceil().max(1.0);
    #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)] // At most 24 h, checked by the config.
    let seconds = seconds as u64;
    let interval_ms = config.frequency_hz.map_or(1, |hz| (1000 / hz.max(1)).max(1));
    let nonce = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map_or(0, |time| time.as_nanos());
    let dir = std::env::temp_dir().join(format!("xref-sample-{}-{nonce}", std::process::id()));
    {
        // The raw report holds the process's paths and stacks: only its owner may read it.
        use std::os::unix::fs::DirBuilderExt;
        std::fs::DirBuilder::new().mode(0o700).create(&dir)?;
    }
    let text = run_sample(pid, seconds, interval_ms, &dir);
    let _ = std::fs::remove_dir_all(&dir);
    let report = super::sample_text::parse(&text?);
    let (header, mappings) = recording(&report, &image, bin, pid)?;
    let path = args.out.clone().unwrap_or_else(|| std::env::temp_dir().join(format!("xref-profile-{nonce}.xprof")));
    {
        use std::os::unix::fs::OpenOptionsExt;
        let file = std::fs::OpenOptions::new().write(true).create_new(true).mode(0o600).open(&path)?;
        let mut writer = super::codec::ProfileWriter::new(BufWriter::new(file), &header)?;
        for mapping in mappings {
            writer.write_record(&Record::Mapping(mapping))?;
        }
        // Each sampled stack is one record per sample it holds, written as it is expanded.
        let mut written = 0_u64;
        for stack in &report.stacks {
            let Some(record) = sample_of(stack, pid) else { continue };
            for _ in 0..stack.samples {
                writer.write_record(&record)?;
                written += 1;
            }
        }
        writer.finish(1, 0, written == 0, "duration", None, 0)?;
    }
    let analysis = std::fs::File::open(&path)
        .map_err(|error| error.to_string())
        .and_then(|file| super::analyze::analyze(&mut BufReader::new(file), &image, &within));
    if args.out.is_none() {
        let _ = std::fs::remove_file(&path);
    }
    let analysis = analysis?;
    if let Some(folded) = &args.folded {
        let mut file = std::fs::OpenOptions::new().write(true).create_new(true).open(folded)?;
        super::report::folded(&analysis, &image, &mut file)?;
    }
    if args.json {
        let report = super::report::build(&analysis, &image, 30)?;
        serde_json::to_writer_pretty(&mut *out, &serde_json::json!({"sampler": "/usr/bin/sample", "report": report}))?;
        writeln!(out)?;
    } else {
        writeln!(out, "capture: {seconds} s with /usr/bin/sample every {interval_ms} ms")?;
        super::report::write(&analysis, &image, 30, super::cli::GroupBy::Function, false, out)?;
    }
    Ok(())
}
