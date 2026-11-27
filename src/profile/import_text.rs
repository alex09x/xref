/*
 * XRef — Binary analysis
 * Copyright (c) 2026 Alexander Panasenko
 * Contact: alex@prod.codes
 * Author: https://prod.codes/about/
 * Project: https://github.com/alex09x/xref
 * SPDX-License-Identifier: MIT OR Apache-2.0
 */
use super::codec::ProfileWriter;
use super::types::{Header, Record, Sample};
use crate::image::Image;
use crate::trace_analysis::models::FrameKind;
use crate::trace_analysis::parse::{InputFormat, TextParser, TraceEvent};
use sha2::{Digest, Sha256};
use std::fs::{File, OpenOptions};
use std::io::{BufRead, BufReader, Read};
use std::path::Path;

pub(super) struct OutputGuard<'a> {
    pub path: &'a Path,
    pub keep: bool,
}
impl Drop for OutputGuard<'_> {
    fn drop(&mut self) {
        if !self.keep {
            let _ = std::fs::remove_file(self.path);
        }
    }
}
pub struct Options<'a> {
    pub bin: &'a Path,
    pub input: &'a Path,
    pub output: &'a Path,
    pub base: Option<&'a str>,
    pub maps: Option<&'a Path>,
    pub target_path: Option<&'a Path>,
    pub pid: Option<u32>,
    /// Threads to keep; all threads of the process when empty.
    pub tids: &'a [u32],
}

pub fn run(image: &Image, options: &Options<'_>) -> Result<(), Box<dyn std::error::Error>> {
    let mut input = File::open(options.input)?;
    let mut magic = [0_u8; 8];
    if input.read_exact(&mut magic).is_ok() && (&magic == b"PERFILE2" || &magic == b"2ELIFREP") {
        return super::import_native::run(image, options);
    }
    run_text(image, options)
}

#[allow(clippy::too_many_lines)] // Input and output guards must cover this complete streaming lifecycle.
fn run_text(image: &Image, options: &Options<'_>) -> Result<(), Box<dyn std::error::Error>> {
    let Options { bin, input, output, base, maps, target_path, pid, tids } = *options;
    let pid = pid.filter(|pid| *pid != 0).ok_or("profile import requires a nonzero --pid")?;
    // Without --base and --maps the target's place comes from its MMAP2 line
    // (`perf script --show-mmap-events`); what the process ran before it is left out.
    let from_mmaps = base.is_none() && maps.is_none();
    let target = Target::new(bin, target_path);
    let (slide, mappings, provenance) = if from_mmaps {
        target_mapping(image, input, pid, &target)?
    } else {
        super::import_maps::resolve(image, bin, base, maps, target_path, pid)?
    };
    let mut started = !from_mmaps;
    let file = File::open(input)?;
    let mut source = BufReader::new(file);
    if source.get_ref().metadata()?.len() > 2_u64 * 1024 * 1024 * 1024 {
        return Err("perf input exceeds the size limit".into());
    }
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let output_file = options.open(output)?;
    let mut guard = OutputGuard { path: output, keep: false };
    let header = Header {
        schema_version: 1,
        image_sha256: crate::trace_analysis::index::hex_bytes(&Sha256::digest(&image.data)),
        process_exe_sha256: None,
        binary_match: provenance.to_owned(),
        pie_slide: slide,
        exe_device_major: 0,
        exe_device_minor: 0,
        exe_inode: 1,
        pid,
        starttime_ticks: 0,
        event: "perf_script_unknown".to_owned(),
        frequency_hz: None,
        period: None,
        callchain: "imported_perf_script".to_owned(),
        started_monotonic_ns: 0,
        trigger_static_va: None,
        trigger_window_ns: None,
    };
    let mut writer = ProfileWriter::new(std::io::BufWriter::new(output_file), &header)?;
    for mapping in mappings {
        writer.write_record(&Record::Mapping(mapping))?;
    }
    let mut parser = TextParser::new(InputFormat::Perf, FrameKind::Auto);
    let mut dropped = 0_u64;
    let mut samples = 0_u64;
    let mut line = String::new();
    let mut total_bytes = 0_u64;
    let mut pending_time = 0_u64;
    let mut pending_period = 1_u64;
    let mut latest_time = 0_u64;
    loop {
        line.clear();
        let bytes = (&mut source).take(65_537).read_line(&mut line)?;
        if bytes == 0 {
            break;
        }
        if bytes > 65_536 {
            return Err("perf-script line exceeds 64 KiB".into());
        }
        total_bytes = total_bytes.saturating_add(bytes as u64);
        if total_bytes > 2 * 1024 * 1024 * 1024 {
            return Err("perf-script output exceeds 2 GiB".into());
        }
        let time = timestamp(&line);
        latest_time = latest_time.max(time.unwrap_or(0));
        for event in parser.line(&line)? {
            if !started {
                if let TraceEvent::Mmap(map) = &event
                    && map.pid == pid
                    && target.is(map)
                {
                    started = true;
                }
                continue;
            }
            if let TraceEvent::Sample(sample) = &event
                && !tids.is_empty()
                && !sample.tid.is_some_and(|tid| tids.contains(&tid))
            {
                continue;
            }
            event_record(
                event,
                pid,
                pending_time,
                pending_period,
                time.unwrap_or(pending_time),
                &mut writer,
                &mut dropped,
                &mut samples,
            )?;
        }
        if !line.contains("PERF_RECORD_")
            && let Some(time) = time
        {
            pending_time = time;
            pending_period = period(&line).unwrap_or(1);
        }
    }
    if let Some(event) = parser.finish()
        && started
        && !matches!(&event, TraceEvent::Sample(sample) if !tids.is_empty() && !sample.tid.is_some_and(|tid| tids.contains(&tid)))
    {
        event_record(event, pid, pending_time, pending_period, pending_time, &mut writer, &mut dropped, &mut samples)?;
    }
    if samples == 0 {
        return Err("no samples for the selected PID in perf input".into());
    }
    writer.finish(latest_time, dropped, true, "imported_perf_script_unverified_base", None, 0)?;
    guard.keep = true;
    Ok(())
}

/// The executable as the perf-script MMAP2 lines name it: the given `--target-path`, or any path
/// with the file name of `-b`.
struct Target {
    exact: Option<String>,
    name: String,
}

impl Target {
    fn new(bin: &Path, target_path: Option<&Path>) -> Self {
        let name = bin.file_name().map(|name| name.to_string_lossy().into_owned()).unwrap_or_default();
        Self { exact: target_path.map(|path| path.to_string_lossy().into_owned()), name }
    }

    fn is(&self, map: &crate::trace_analysis::parse::MmapRecord) -> bool {
        let path = map.path.trim_end_matches(" (deleted)");
        map.executable
            && self
                .exact
                .as_ref()
                .map_or_else(|| path.rsplit('/').next() == Some(self.name.as_str()), |exact| path == exact)
    }
}

/// The target's slide and executable mappings from the MMAP2 lines of the process in the text,
/// up to its first sample after them.
fn target_mapping(
    image: &Image,
    input: &Path,
    pid: u32,
    target: &Target,
) -> Result<(i64, Vec<super::types::Mapping>, &'static str), Box<dyn std::error::Error>> {
    let mut source = BufReader::new(File::open(input)?);
    let mut parser = TextParser::new(InputFormat::Perf, FrameKind::Auto);
    let (mut slide, mut mappings) = (None, Vec::new());
    let mut line = String::new();
    let mut read = 0_u64;
    'lines: loop {
        line.clear();
        let bytes = (&mut source).take(65_537).read_line(&mut line)?;
        read = read.saturating_add(bytes as u64);
        if bytes == 0 || bytes > 65_536 || read > 2 * 1024 * 1024 * 1024 {
            break;
        }
        for event in parser.line(&line)? {
            match event {
                TraceEvent::Mmap(map) if map.pid == pid && target.is(&map) => {
                    if let (Some(recorded), Some(expected)) = (&map.build_id, &image.metadata.build_id)
                        && !recorded.eq_ignore_ascii_case(&crate::trace_analysis::index::hex_bytes(expected))
                    {
                        return Err(format!("{}: the recorded build ID differs from -b", map.path).into());
                    }
                    let candidate = super::import_native_mmaps::mapping_slide(image, map.start, map.offset)?;
                    if slide.is_some_and(|previous| previous != candidate) {
                        return Err("perf-script target mappings have inconsistent slides".into());
                    }
                    slide = Some(candidate);
                    mappings.push(super::types::Mapping {
                        timestamp_ns: 0,
                        pid,
                        tid: pid,
                        start: map.start,
                        length: map.len,
                        file_offset: map.offset,
                        device_major: 0,
                        device_minor: 0,
                        inode: 1,
                        executable: true,
                        sha256: None,
                        path: "[perf-script MMAP2 target mapping]".to_owned(),
                    });
                }
                TraceEvent::Sample(sample) if slide.is_some() && sample.pid == Some(pid) => break 'lines,
                _ => {}
            }
        }
    }
    let slide = slide.ok_or(
        "no MMAP2 line of the target in the perf-script text: run `perf script --show-mmap-events`, or pass --base or --maps",
    )?;
    Ok((slide, mappings, "caller_supplied_base_unverified"))
}

fn timestamp(line: &str) -> Option<u64> {
    let token = line.split_whitespace().find(|part| {
        part.ends_with(':')
            && part.contains('.')
            && part.trim_end_matches(':').bytes().all(|byte| byte.is_ascii_digit() || byte == b'.')
    })?;
    let (seconds, fraction) = token.trim_end_matches(':').split_once('.')?;
    if fraction.is_empty() || fraction.len() > 9 {
        return None;
    }
    let ns = fraction.parse::<u64>().ok()?.checked_mul(10_u64.pow(u32::try_from(9 - fraction.len()).ok()?))?;
    seconds.parse::<u64>().ok()?.checked_mul(1_000_000_000)?.checked_add(ns)
}

fn period(line: &str) -> Option<u64> {
    let mut words = line.split_whitespace();
    words.find(|word| {
        word.ends_with(':')
            && word.contains('.')
            && word.trim_end_matches(':').bytes().all(|byte| byte.is_ascii_digit() || byte == b'.')
    })?;
    words.next()?.parse::<u64>().ok().filter(|value| *value > 0)
}

#[allow(clippy::too_many_arguments)]
fn event_record<W: std::io::Write>(
    event: TraceEvent,
    pid: u32,
    sample_time: u64,
    sample_period: u64,
    event_time: u64,
    writer: &mut ProfileWriter<W>,
    dropped: &mut u64,
    samples: &mut u64,
) -> Result<(), Box<dyn std::error::Error>> {
    match event {
        TraceEvent::Sample(sample) if sample.pid == Some(pid) && !sample.frames.is_empty() => {
            if sample.truncated {
                *dropped = dropped.saturating_add(1);
            }
            let mut ips = Vec::new();
            let mut in_kernel = false;
            let mut first_kernel = false;
            for frame in sample.frames {
                let kernel = frame.dso.as_deref().is_some_and(|dso| dso.starts_with("[kernel"));
                match crate::trace_analysis::index::parse_hex(&frame.token) {
                    Ok(ip) => {
                        if ips.is_empty() {
                            first_kernel = kernel;
                            in_kernel = kernel;
                        } else if in_kernel != kernel {
                            ips.push(if kernel { u64::MAX - 127 } else { u64::MAX - 511 });
                            in_kernel = kernel;
                        }
                        ips.push(ip);
                    }
                    Err(_) => *dropped = dropped.saturating_add(1),
                }
            }
            if let Some((&ip, rest)) = ips.split_first() {
                if *samples >= 10_000_000 {
                    return Err("perf input exceeds the 10000000 sample limit".into());
                }
                writer.write_record(&Record::Sample(Sample {
                    timestamp_ns: sample_time,
                    pid,
                    tid: sample.tid.unwrap_or(pid),
                    cpu_mode: if first_kernel { 1 } else { 2 },
                    ip,
                    period: sample_period,
                    registers_mask: 0,
                    registers: vec![],
                    user_stack: vec![],
                    callchain: rest.to_vec(),
                    branches: vec![],
                }))?;
                *samples = samples.saturating_add(1);
            } else {
                *dropped = dropped.saturating_add(1);
            }
        }
        TraceEvent::Sample(_)
        | TraceEvent::Malformed
        | TraceEvent::Mmap(_)
        | TraceEvent::Fork { .. }
        | TraceEvent::Exec(_)
        | TraceEvent::KernelMapping => *dropped = dropped.saturating_add(1),
        TraceEvent::Lost(count) => writer.write_record(&Record::Lost { timestamp_ns: event_time, tid: pid, count })?,
    }
    Ok(())
}
