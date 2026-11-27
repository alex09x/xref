/*
 * XRef — live sampling profile command
 * Copyright (c) 2026 Alexander Panasenko
 * Contact: alex@prod.codes
 * Author: https://prod.codes/about/
 * Project: https://github.com/alex09x/xref
 * SPDX-License-Identifier: MIT OR Apache-2.0
 */
use super::cli::LiveProfileArgs;
use std::{io::Write, path::Path};

#[cfg(not(all(target_os = "linux", target_arch = "x86_64")))]
pub fn run(
    _bin: Option<&Path>,
    _args: &LiveProfileArgs,
    _out: &mut dyn Write,
) -> Result<(), Box<dyn std::error::Error>> {
    Err("unsupported_platform: live profile requires Linux x86-64".into())
}

/// Without --pid: the first process matching --comm/--argv-match that opens as a session of the
/// binary (a match running another binary, or exiting first, is skipped), within the duration.
#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
fn wait_for_target(
    bin: Option<&Path>,
    config: &super::config::Config,
) -> Result<(u32, crate::live::procfs::LiveSession), String> {
    use std::os::unix::fs::MetadataExt;
    let started = std::time::Instant::now();
    // When each identity (PID, start time, executable) was last tried: a failure is retried after
    // a pause, since it may be transient (maps read during a mapping change).
    let mut tried: std::collections::BTreeMap<_, std::time::Instant> = std::collections::BTreeMap::new();
    let mut last_error = None;
    loop {
        for (pid, start) in super::follow::matching_processes(&config.follow) {
            let exe = std::fs::metadata(format!("/proc/{pid}/exe")).ok().map(|meta| (meta.dev(), meta.ino()));
            let identity = (pid, start, exe);
            if tried.get(&identity).is_some_and(|at| at.elapsed() < std::time::Duration::from_millis(250)) {
                continue;
            }
            tried.insert(identity, std::time::Instant::now());
            match crate::live::procfs::open_session(pid, bin, false) {
                // The session must be the process that matched: same start time, still running.
                Ok(session)
                    if session.process.pid_alive_after
                        && !session.process.process_changed
                        && session.process.starttime_ticks == start =>
                {
                    return Ok((pid, session));
                }
                Ok(_) => last_error = Some(format!("pid {pid}: exited or changed while it was opened")),
                Err(error) => last_error = Some(format!("pid {pid}: {error}")),
            }
        }
        if started.elapsed() >= config.duration {
            let detail = last_error.map_or_else(String::new, |error| format!("; last candidate: {error}"));
            return Err(format!(
                "no_matching_process: no process matching --comm/--argv-match opened within the duration{detail}"
            ));
        }
        std::thread::sleep(std::time::Duration::from_millis(5));
    }
}

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
pub fn run(bin: Option<&Path>, args: &LiveProfileArgs, out: &mut dyn Write) -> Result<(), Box<dyn std::error::Error>> {
    use std::{
        collections::BTreeSet,
        fs::{File, OpenOptions},
        io::{BufReader, BufWriter},
        os::unix::fs::OpenOptionsExt,
        path::PathBuf,
    };
    struct OutputFile {
        path: PathBuf,
        keep: bool,
    }
    impl Drop for OutputFile {
        fn drop(&mut self) {
            if !self.keep {
                let _ = std::fs::remove_file(&self.path);
            }
        }
    }
    let config = args.config();
    config.validate()?;
    let (pid, mut session) = match args.pid {
        Some(pid) => (pid, crate::live::procfs::open_session(pid, bin, false)?),
        None => wait_for_target(bin, &config)?,
    };
    let within = args
        .within
        .iter()
        .map(|name| crate::graph::resolve(&session.image, name).map(|range| range.start))
        .collect::<Result<BTreeSet<_>, _>>()?;
    let path = args.out.clone().unwrap_or_else(|| {
        let nonce =
            std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map_or(0, |time| time.as_nanos());
        std::env::temp_dir().join(format!("xref-profile-{}-{nonce}.xprof", std::process::id()))
    });
    let file = OpenOptions::new().write(true).create_new(true).mode(0o600).open(&path)?;
    let mut guard = OutputFile { path: path.clone(), keep: false };
    let (writer, stats) = super::capture::capture(&mut session, &config, BufWriter::new(file), None)?;
    drop(writer);
    guard.keep = args.out.is_some();
    let mut input = BufReader::new(File::open(&path)?);
    let analysis = super::analyze::analyze(&mut input, &session.image, &within)?;
    if let Some(path) = &args.folded {
        let mut file = OpenOptions::new().write(true).create_new(true).mode(0o600).open(path)?;
        super::report::folded(&analysis, &session.image, &mut file)?;
    }
    if args.json {
        let report = super::report::build(&analysis, &session.image, 30)?;
        serde_json::to_writer_pretty(&mut *out, &serde_json::json!({"capture": stats, "report": report}))?;
        writeln!(out)?;
    } else {
        let observer = stats.observer_thread_cpu_ms.map_or_else(|| "unavailable".to_owned(), |ms| format!("{ms} ms"));
        writeln!(
            out,
            "capture: {} ms, observer thread CPU: {observer} (excludes target and interrupt-context overhead)",
            stats.elapsed_ms
        )?;
        if config.follow.any() {
            writeln!(
                out,
                "processes: target {pid} and {} followed; {} refused (another executable), {} gone before sampling",
                stats.followed_processes, stats.refused_processes, stats.gone_processes
            )?;
        }
        super::report::write(&analysis, &session.image, 30, super::cli::GroupBy::Function, false, out)?;
    }
    Ok(())
}
