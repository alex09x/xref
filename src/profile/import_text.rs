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
    let Options { bin, input, output, base, maps, target_path, pid } = *options;
    let pid = pid.filter(|pid| *pid != 0).ok_or("profile import requires a nonzero --pid")?;
    let (slide, mappings, provenance) = super::import_maps::resolve(image, bin, base, maps, target_path, pid)?;
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
    if let Some(event) = parser.finish() {
        event_record(event, pid, pending_time, pending_period, pending_time, &mut writer, &mut dropped, &mut samples)?;
    }
    if samples == 0 {
        return Err("no samples for the selected PID in perf input".into());
    }
    writer.finish(latest_time, dropped, true, "imported_perf_script_unverified_base", None, 0)?;
    guard.keep = true;
    Ok(())
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
