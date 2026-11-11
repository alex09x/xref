/*
 * XRef — `live heap`: which call stacks hold the anonymous memory of a live process
 * Copyright (c) 2026 Alexander Panasenko
 * Contact: alex@prod.codes
 * Author: https://prod.codes/about/
 * Project: https://github.com/alex09x/xref
 * SPDX-License-Identifier: MIT OR Apache-2.0
 */

//! `xref live heap --pid P` follows the memory syscalls of every thread (no uprobe on `malloc`,
//! so the process runs at full speed) and reports the call stacks holding the anonymous memory
//! mapped while it was observed, by bytes. Snapshots are `.xprof` recordings whose sample
//! weights are bytes, so `xref profile diff` compares two of them.
#![cfg_attr(not(all(target_os = "linux", target_arch = "x86_64")), allow(dead_code, unused_imports))]

pub mod args;
#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
mod capture;
pub mod ledger;
mod render;

use std::io::Write;
use std::path::Path;

pub use args::HeapArgs;

/// The `event` of a heap snapshot header; its sample weights are bytes.
pub const EVENT: &str = "heap-bytes";

#[cfg(not(all(target_os = "linux", target_arch = "x86_64")))]
pub fn run(_bin: Option<&Path>, _args: &HeapArgs, _out: &mut dyn Write) -> Result<(), Box<dyn std::error::Error>> {
    Err("unsupported_platform: live heap requires Linux x86-64".into())
}

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
pub fn run(bin: Option<&Path>, args: &HeapArgs, out: &mut dyn Write) -> Result<(), Box<dyn std::error::Error>> {
    use std::fs::{File, OpenOptions};
    use std::io::{BufReader, BufWriter};
    use std::os::unix::fs::OpenOptionsExt;

    use super::types::Record;

    args.validate()?;
    let mut session = crate::live::procfs::open_session(args.pid, bin, false)?;
    let header = header_of(&session)?;
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
    let dir = if let Some(dir) = &args.out {
        std::fs::create_dir(dir).map_err(|error| format!("--out {}: {error}", dir.display()))?;
        dir.clone()
    } else {
        {
            let nonce =
                std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map_or(0, |time| time.as_nanos());
            let dir = std::env::temp_dir().join(format!("xref-heap-{}-{nonce}", std::process::id()));
            std::fs::create_dir(&dir)?;
            dir
        }
    };
    let interrupted = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
    for signal in [signal_hook::consts::SIGINT, signal_hook::consts::SIGTERM] {
        signal_hook::flag::register_conditional_shutdown(signal, 1, std::sync::Arc::clone(&interrupted))?;
        signal_hook::flag::register(signal, std::sync::Arc::clone(&interrupted))?;
    }
    let settings = capture::HeapCapture {
        duration: args.duration,
        interval: args.interval,
        sample_bytes: args.sample_bytes,
        stack_bytes: args.stack_bytes,
        cancel: Some(&interrupted),
    };
    let mut written: Vec<(std::path::PathBuf, u64)> = Vec::new();
    let stats = capture::observe(&mut session, &settings, mappings, |ledger, mappings| {
        let path = dir.join(format!("heap-{:04}.xprof", written.len() + 1));
        let file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&path)
            .map_err(|error| format!("{}: {error}", path.display()))?;
        let mut writer =
            super::codec::ProfileWriter::new(BufWriter::new(file), &header).map_err(|error| error.to_string())?;
        for mapping in mappings {
            writer.write_record(&Record::Mapping(mapping.clone())).map_err(|error| error.to_string())?;
        }
        let samples = ledger.snapshot();
        let last = samples.iter().map(|s| s.timestamp_ns).max().unwrap_or(0);
        for sample in samples {
            writer.write_record(&Record::Sample(sample)).map_err(|error| error.to_string())?;
        }
        writer.finish(last, 0, true, "snapshot", None, 0).map_err(|error| error.to_string())?;
        written.push((path, ledger.live_weight()));
        Ok(())
    })?;
    let last = written.last().map(|(path, _)| path.clone()).ok_or("no heap snapshot was written")?;
    let analysis = super::analyze::analyze(
        &mut BufReader::new(File::open(&last)?),
        &session.image,
        &std::collections::BTreeSet::default(),
    )?;
    if let Some(path) = &args.folded {
        let mut file = OpenOptions::new().write(true).create_new(true).mode(0o600).open(path)?;
        render::folded(&analysis, &session.image, &mut file)?;
    }
    render::report(&analysis, &session.image, &stats, &written, args, out)?;
    if args.out.is_none() {
        let _ = std::fs::remove_dir_all(&dir);
    }
    Ok(())
}

/// The `.xprof` header of a heap snapshot: the target identity, bytes as the sample weight.
#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
fn header_of(session: &crate::live::procfs::LiveSession) -> Result<super::types::Header, String> {
    use sha2::{Digest, Sha256};
    let (device, inode) = session.exe_dev_ino.ok_or("binary_mismatch: missing executable device/inode")?;
    Ok(super::types::Header {
        schema_version: 1,
        image_sha256: crate::trace_analysis::index::hex_bytes(&Sha256::digest(&session.image.data)),
        pid: session.process.pid,
        process_exe_sha256: session.process.exe_sha256.clone(),
        binary_match: session.process.binary_match.as_str().to_owned(),
        pie_slide: session.process.pie_slide,
        exe_device_major: ((device >> 8) & 0xfff) | ((device >> 32) & !0xfff),
        exe_device_minor: (device & 0xff) | ((device >> 12) & !0xff),
        exe_inode: inode,
        starttime_ticks: session.process.starttime_ticks,
        event: EVENT.to_owned(),
        frequency_hz: None,
        period: None,
        callchain: "dwarf".to_owned(),
        started_monotonic_ns: 0,
        trigger_static_va: None,
        trigger_window_ns: None,
    })
}
