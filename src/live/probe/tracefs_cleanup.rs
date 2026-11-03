/*
 * XRef — Stage L2 tracefs root discovery, error diagnostics, watchdog, and deterministic teardown
 * Copyright (c) 2026 Alexander Panasenko
 * Contact: alex@prod.codes
 * Author: https://prod.codes/about/
 * Project: https://github.com/alex09x/xref
 * SPDX-License-Identifier: MIT OR Apache-2.0
 */

//! Enforces tracefs cleanup ordering (disable -> close FDs -> `rmdir` instance -> append `-:event`)
//! and spawns a parent-pipe supervisor child so `SIGINT`/`SIGTERM`/`abort` cleans up dynamic events.

use std::fs::{File, OpenOptions};
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::Duration;

#[must_use]
pub fn discover_tracefs_root() -> PathBuf {
    let primary = PathBuf::from("/sys/kernel/tracing");
    if primary.join("uprobe_events").exists() || primary.exists() {
        return primary;
    }
    let fallback = PathBuf::from("/sys/kernel/debug/tracing");
    if fallback.exists() {
        return fallback;
    }
    primary
}

#[must_use]
pub fn format_tracefs_io_error(operation: &str, path: &Path, err: &io::Error) -> String {
    let errno_part = err.raw_os_error().map_or_else(String::new, |code| format!("errno {code}: "));
    if err.kind() == io::ErrorKind::PermissionDenied {
        format!(
            "permission_denied: tracefs {operation} on {} failed ({errno_part}{err}); Linux tracefs uprobes require write access to tracefs (typically root DAC permissions; CAP_PERFMON alone does not bypass root-owned tracefs mode bits)",
            path.display()
        )
    } else {
        format!("tracefs {operation} on {} failed ({errno_part}{err})", path.display())
    }
}

pub fn write_tracefs_control(path: &Path, contents: &str, op_label: &str) -> Result<(), String> {
    let mut file =
        OpenOptions::new().write(true).open(path).map_err(|e| format_tracefs_io_error(op_label, path, &e))?;
    file.write_all(contents.as_bytes()).map_err(|e| format_tracefs_io_error(op_label, path, &e))
}

pub fn append_tracefs_line(path: &Path, line: &str, op_label: &str) -> Result<(), String> {
    let mut file =
        OpenOptions::new().append(true).open(path).map_err(|e| format_tracefs_io_error(op_label, path, &e))?;
    file.write_all(line.as_bytes()).map_err(|e| format_tracefs_io_error(op_label, path, &e))
}

pub struct CleanupSupervisor {
    child: Option<Child>,
}

impl CleanupSupervisor {
    pub fn spawn(tracefs_root: &Path, instance_name: &str, full_events: &[String]) -> Option<Self> {
        let exe = std::env::current_exe().ok()?;
        let mut cmd = Command::new(exe);
        cmd.arg("live")
            .arg("tracefs-watchdog")
            .arg("--tracefs-root")
            .arg(tracefs_root)
            .arg("--instance")
            .arg(instance_name);
        for ev in full_events {
            cmd.arg("--event").arg(ev);
        }
        cmd.stdin(Stdio::piped()).stdout(Stdio::null()).stderr(Stdio::null());
        let child = cmd.spawn().ok()?;
        Some(Self { child: Some(child) })
    }

    pub fn disarm_and_wait(&mut self) {
        if let Some(mut child) = self.child.take() {
            drop(child.stdin.take());
            let _ = child.wait();
        }
    }
}

/// Entrypoint for hidden `xref live tracefs-watchdog`: blocks until parent pipe EOF, then cleans up.
pub fn run_watchdog_entrypoint(tracefs_root: &Path, instance_name: &str, full_events: &[String]) {
    let mut sink = [0_u8; 64];
    while matches!(io::stdin().read(&mut sink), Ok(n) if n > 0) {}

    let instance_dir = tracefs_root.join("instances").join(instance_name);
    for attempt in 0..10_u8 {
        let errs = teardown_session_resources(tracefs_root, &instance_dir, full_events, None, None);
        if errs.is_empty() || (!instance_dir.exists() && attempt > 0) {
            break;
        }
        std::thread::sleep(Duration::from_millis(20));
    }
}

/// Strict teardown order:
/// 1. Disable session events and `tracing_on` inside the instance.
/// 2. Close all open instance file descriptors (`trace_pipe`, `free_buffer`) so `rmdir` cannot `EBUSY`.
/// 3. Remove the session `instances/<name>` directory.
/// 4. Append `-:<group>/<event>\n` (`O_WRONLY | O_APPEND`, never `O_TRUNC`) to `uprobe_events`.
pub fn teardown_session_resources(
    tracefs_root: &Path,
    instance_dir: &Path,
    registered_events: &[String],
    trace_pipe_fd: Option<File>,
    free_buffer_fd: Option<File>,
) -> Vec<String> {
    let mut warnings = Vec::new();

    if instance_dir.exists() {
        let tracing_on = instance_dir.join("tracing_on");
        if tracing_on.exists()
            && let Err(e) = write_tracefs_control(&tracing_on, "0\n", "disable tracing_on")
        {
            warnings.push(format!("cleanup_warning: {e}"));
        }
        for full_ev in registered_events {
            if let Some((group, event)) = full_ev.split_once('/') {
                let enable_path = instance_dir.join("events").join(group).join(event).join("enable");
                if enable_path.exists()
                    && let Err(e) = write_tracefs_control(&enable_path, "0\n", "disable event")
                {
                    warnings.push(format!("cleanup_warning: {e}"));
                }
            }
        }
    }

    drop(trace_pipe_fd);
    drop(free_buffer_fd);

    if instance_dir.exists()
        && let Err(err) = std::fs::remove_dir(instance_dir)
        && err.kind() != io::ErrorKind::NotFound
    {
        warnings.push(format!("cleanup_warning: {}", format_tracefs_io_error("rmdir instance", instance_dir, &err)));
    }

    let uprobe_events_path = tracefs_root.join("uprobe_events");
    for full_ev in registered_events.iter().rev() {
        let remove_cmd = format!("-:{full_ev}\n");
        if let Err(err) = append_tracefs_line(&uprobe_events_path, &remove_cmd, "unregister uprobe_events")
            && !err.contains("errno 2:")
        {
            warnings.push(format!("cleanup_warning: {err}"));
        }
    }

    warnings
}
