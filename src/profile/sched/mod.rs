/*
 * XRef — `live sched`: where a live process waits — off-CPU stacks, switches, wakeups, syscalls
 * Copyright (c) 2026 Alexander Panasenko
 * Contact: alex@prod.codes
 * Author: https://prod.codes/about/
 * Project: https://github.com/alex09x/xref
 * SPDX-License-Identifier: MIT OR Apache-2.0
 */

//! `xref live sched --pid P` follows the scheduling of every thread: context switches (voluntary
//! or preempted), wakeups, the time off CPU with the user stack each wait started in, and every
//! system call with its latency. The off-CPU stacks are an `.xprof` recording whose weights are
//! nanoseconds, so `xref profile report` and `xref profile diff` read it like a CPU profile.
#![cfg_attr(not(all(target_os = "linux", target_arch = "x86_64")), allow(dead_code, unused_imports))]

pub mod args;
#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
mod capture;
pub(super) mod render;
pub mod syscalls;

use std::io::Write;
use std::path::Path;

pub use args::SchedArgs;

/// The `event` of an off-CPU recording; its sample weights are nanoseconds off CPU.
pub const EVENT: &str = "off-cpu-ns";

#[cfg(not(all(target_os = "linux", target_arch = "x86_64")))]
pub fn run(_bin: Option<&Path>, _args: &SchedArgs, _out: &mut dyn Write) -> Result<(), Box<dyn std::error::Error>> {
    Err("unsupported_platform: live sched requires Linux x86-64".into())
}

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
pub fn run(bin: Option<&Path>, args: &SchedArgs, out: &mut dyn Write) -> Result<(), Box<dyn std::error::Error>> {
    use std::fs::{File, OpenOptions};
    use std::io::{BufReader, BufWriter};
    use std::os::unix::fs::OpenOptionsExt;

    use super::types::Record;

    args.validate()?;
    let mut session = crate::live::procfs::open_session(args.pid, bin, false)?;
    let header = super::heap::header_of(&session, EVENT)?;
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
    let capture = capture::observe(
        &mut session,
        args.duration,
        args.stack_bytes,
        !args.no_syscalls,
        Some(&interrupted),
        mappings,
    )?;
    let path = args.out.clone().unwrap_or_else(|| {
        let nonce =
            std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map_or(0, |time| time.as_nanos());
        std::env::temp_dir().join(format!("xref-sched-{}-{nonce}.xprof", std::process::id()))
    });
    {
        let file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&path)
            .map_err(|error| format!("{}: {error}", path.display()))?;
        let mut writer = super::codec::ProfileWriter::new(BufWriter::new(file), &header).map_err(|e| e.to_string())?;
        for mapping in &capture.mappings {
            writer.write_record(&Record::Mapping(mapping.clone())).map_err(|e| e.to_string())?;
        }
        let last = capture.off_cpu.iter().map(|sample| sample.timestamp_ns).max().unwrap_or(0);
        for sample in &capture.off_cpu {
            writer.write_record(&Record::Sample(sample.clone())).map_err(|e| e.to_string())?;
        }
        writer
            .finish(last, 0, capture.stats.lost > 0, capture.stats.stop_reason, None, 0)
            .map_err(|e| e.to_string())?;
    }
    let analysis = super::analyze::analyze(
        &mut BufReader::new(File::open(&path)?),
        &session.image,
        &std::collections::BTreeSet::new(),
    );
    if args.out.is_none() {
        let _ = std::fs::remove_file(&path);
    }
    render::report(&capture, &analysis?, &session.image, args, out)
}
