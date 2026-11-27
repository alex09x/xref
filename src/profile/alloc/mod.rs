/*
 * XRef — `live alloc`: malloc, calloc, realloc and free of a live process by call site
 * Copyright (c) 2026 Alexander Panasenko
 * Contact: alex@prod.codes
 * Author: https://prod.codes/about/
 * Project: https://github.com/alex09x/xref
 * SPDX-License-Identifier: MIT OR Apache-2.0
 */

//! `xref live alloc --pid P` puts uprobes on the allocator the process calls and reports, by call
//! stack and by function, how many allocations were made, how many bytes, and how many bytes are
//! still allocated at the end. Recordings weighted by bytes (`alloc.xprof`, `live.xprof`) are read
//! by `xref profile report` and compared by `xref profile diff`, like heap snapshots.
#![cfg_attr(not(all(target_os = "linux", target_arch = "x86_64")), allow(dead_code, unused_imports))]

pub mod args;
#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
mod capture;
pub(super) mod render;
#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
mod symbols;

use std::io::Write;
use std::path::Path;

pub use args::AllocArgs;

/// Recording events: bytes allocated, allocations made, bytes still allocated at the end.
pub const BYTES_EVENT: &str = "alloc-bytes";
pub const COUNT_EVENT: &str = "alloc-count";
pub const LIVE_EVENT: &str = "alloc-live-bytes";

#[cfg(not(all(target_os = "linux", target_arch = "x86_64")))]
pub fn run(_bin: Option<&Path>, _args: &AllocArgs, _out: &mut dyn Write) -> Result<(), Box<dyn std::error::Error>> {
    Err("unsupported_platform: live alloc requires Linux x86-64".into())
}

/// Writes one recording: each call chain is one sample weighted by `weight`, its frames a
/// frame-pointer style call chain already unwound.
#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
fn write_recording(
    path: &Path,
    header: &super::types::Header,
    event: &str,
    mappings: &[super::types::Mapping],
    capture: &capture::Capture,
    pid: u32,
    weight: impl Fn(&capture::Chain) -> u64,
) -> Result<(), String> {
    use super::types::{Record, Sample};
    use std::io::BufWriter;
    use std::os::unix::fs::OpenOptionsExt;
    let chains = &capture.chains;
    let mut header = header.clone();
    event.clone_into(&mut header.event);
    let file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)
        .map_err(|error| format!("{}: {error}", path.display()))?;
    let mut writer = super::codec::ProfileWriter::new(BufWriter::new(file), &header).map_err(|e| e.to_string())?;
    for mapping in mappings {
        writer.write_record(&Record::Mapping(mapping.clone())).map_err(|e| e.to_string())?;
    }
    if let Some(marker) = super::names::boot_marker() {
        writer.write_record(&Record::Mapping(marker)).map_err(|e| e.to_string())?;
    }
    let mut samples = 0;
    for chain in chains {
        let (Some(&ip), value) = (chain.ips.first(), weight(chain)) else { continue };
        if value == 0 {
            continue;
        }
        samples += 1;
        writer
            .write_record(&Record::Sample(Sample {
                timestamp_ns: 1,
                pid,
                tid: pid,
                cpu_mode: 2,
                ip,
                period: value,
                registers_mask: 0,
                registers: Vec::new(),
                user_stack: Vec::new(),
                callchain: chain.ips[1..].to_vec(),
                branches: Vec::new(),
            }))
            .map_err(|e| e.to_string())?;
    }
    // Lost or undecoded hits and threads not attached leave the totals partial; the footer says so.
    let stats = &capture.stats;
    let partial = samples == 0 || stats.lost > 0 || stats.undecoded > 0 || stats.unattached_threads > 0;
    writer.finish(1, stats.lost, partial, stats.stop_reason, None, 0).map_err(|e| e.to_string())?;
    Ok(())
}

/// Removes a temporary recordings directory when dropped.
#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
struct Cleanup(Option<std::path::PathBuf>);

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
impl Drop for Cleanup {
    fn drop(&mut self) {
        if let Some(dir) = &self.0 {
            let _ = std::fs::remove_dir_all(dir);
        }
    }
}

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
pub fn run(bin: Option<&Path>, args: &AllocArgs, out: &mut dyn Write) -> Result<(), Box<dyn std::error::Error>> {
    use std::collections::BTreeSet;
    use std::fs::File;
    use std::io::BufReader;

    args.validate()?;
    let mut session = crate::live::procfs::open_session(args.pid, bin, false)?;
    let allocator = symbols::find(&session)?;
    let mut header = super::heap::header_of(&session, BYTES_EVENT)?;
    // Chains are unwound during the capture; the recordings hold them as call chains.
    "fp".clone_into(&mut header.callchain);
    let module_hashes = super::module_hash::collect(session.process.pid, &session.regions, None)?;
    let mappings = session
        .regions
        .iter()
        .map(|region| {
            super::capture::initial_mapping(
                region,
                session.process.pid,
                session.process.exe_sha256.as_deref(),
                &module_hashes,
            )
        })
        .collect::<Result<Vec<_>, _>>()?;
    let interrupted = crate::live::register_interrupt_flag()?;
    let mut unwind_header = header.clone();
    "dwarf".clone_into(&mut unwind_header.callchain);
    let settings =
        capture::Settings { duration: args.duration, stack_bytes: args.stack_bytes, cancel: Some(&interrupted) };
    let capture = capture::observe(&mut session, &allocator, &unwind_header, mappings.clone(), &settings)?;
    let (dir, keep) = if let Some(dir) = &args.out {
        std::fs::create_dir(dir).map_err(|error| format!("--out {}: {error}", dir.display()))?;
        (dir.clone(), true)
    } else {
        let nonce =
            std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map_or(0, |time| time.as_nanos());
        let dir = std::env::temp_dir().join(format!("xref-alloc-{}-{nonce}", std::process::id()));
        std::fs::create_dir(&dir)?;
        (dir, false)
    };
    // The temporary recordings go on success and on error alike.
    let _cleanup = Cleanup(if keep { None } else { Some(dir.clone()) });
    let pid = session.process.pid;
    let recordings =
        [("alloc.xprof", BYTES_EVENT, 0_u8), ("count.xprof", COUNT_EVENT, 1), ("live.xprof", LIVE_EVENT, 2)];
    let mut analyses = Vec::new();
    for (name, event, kind) in recordings {
        let path = dir.join(name);
        write_recording(&path, &header, event, &mappings, &capture, pid, |chain| match kind {
            0 => chain.bytes,
            1 => chain.allocations,
            _ => chain.live_bytes,
        })?;
        analyses.push(super::analyze::analyze(
            &mut BufReader::new(File::open(&path)?),
            &session.image,
            &BTreeSet::new(),
        )?);
    }
    let _ = std::fs::remove_file(dir.join("count.xprof"));
    let [bytes, count, live] = <[_; 3]>::try_from(analyses).map_err(|_| "three recordings")?;
    let context = render::Context { allocator: &allocator, stats: &capture.stats, dir: keep.then_some(dir.as_path()) };
    render::report(&context, &bytes, &count, &live, &session.image, args, out)
}
