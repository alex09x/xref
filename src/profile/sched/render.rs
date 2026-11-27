/*
 * XRef — `live sched` report: rates, system call latencies, threads and off-CPU stacks
 * Copyright (c) 2026 Alexander Panasenko
 * Contact: alex@prod.codes
 * Author: https://prod.codes/about/
 * Project: https://github.com/alex09x/xref
 * SPDX-License-Identifier: MIT OR Apache-2.0
 */

use std::io::Write;

use serde::Serialize;

use super::super::analyze::Analysis;

/// `1.25 s`, `812.0 ms`, `20.3 us`, `950 ns`.
#[must_use]
#[allow(clippy::cast_precision_loss)] // One decimal of a duration needs no more than f64 precision.
pub fn duration(ns: u64) -> String {
    if ns >= 1_000_000_000 {
        format!("{:.2} s", ns as f64 / 1e9)
    } else if ns >= 1_000_000 {
        format!("{:.1} ms", ns as f64 / 1e6)
    } else if ns >= 1_000 {
        format!("{:.1} us", ns as f64 / 1e3)
    } else {
        format!("{ns} ns")
    }
}

/// Events per second over `elapsed_ms`.
#[allow(clippy::cast_precision_loss)]
fn rate(count: u64, elapsed_ms: u64) -> f64 {
    if elapsed_ms == 0 { 0.0 } else { count as f64 * 1000.0 / elapsed_ms as f64 }
}

#[derive(Debug, Serialize)]
pub struct SyscallRow {
    pub name: String,
    pub number: u64,
    /// Calls entered while observed.
    pub count: u64,
    pub per_second: f64,
    /// Calls that also returned while observed; the latencies are theirs.
    pub completed: u64,
    pub total_ns: u64,
    pub mean_ns: u64,
    pub p50_ns: u64,
    pub p99_ns: u64,
    pub max_ns: u64,
}

#[derive(Debug, Serialize)]
pub struct StackRow {
    pub off_cpu_ns: u64,
    pub percent: f64,
    /// Root first.
    pub frames: Vec<String>,
}

/// Off-CPU stacks by time: the frames below the program's last frame (the blocking call in libc)
/// fold into one frame, as in a heap snapshot.
pub fn stacks(analysis: &Analysis, image: &crate::image::Image, top: usize) -> Vec<StackRow> {
    super::super::heap::render::stacks(analysis, image, top)
        .into_iter()
        .map(|row| StackRow { off_cpu_ns: row.bytes, percent: row.percent, frames: row.frames })
        .collect()
}

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
#[allow(clippy::too_many_lines)] // One report: totals, then three tables.
pub fn report(
    capture: &super::capture::Capture,
    analysis: &Analysis,
    image: &crate::image::Image,
    args: &super::SchedArgs,
    out: &mut dyn Write,
) -> Result<(), Box<dyn std::error::Error>> {
    let elapsed = capture.stats.elapsed_ms;
    let threads: Vec<_> = capture.threads.values().collect();
    let voluntary: u64 = threads.iter().map(|t| t.voluntary_switches).sum();
    let involuntary: u64 = threads.iter().map(|t| t.involuntary_switches).sum();
    let wakeups: u64 = threads.iter().map(|t| t.wakeups).sum();
    let off_cpu: u64 = threads.iter().map(|t| t.off_cpu_ns).sum();
    let syscall_count: u64 = capture.syscalls.values().map(|calls| calls.entered).sum();
    let mut syscalls: Vec<SyscallRow> = capture
        .syscalls
        .iter()
        .map(|(number, calls)| (number, calls.entered, &calls.latency))
        .map(|(number, entered, histogram)| SyscallRow {
            name: super::syscalls::name(*number),
            number: *number,
            count: entered,
            per_second: rate(entered, elapsed),
            completed: histogram.count,
            total_ns: histogram.total,
            mean_ns: histogram.total / histogram.count.max(1),
            p50_ns: histogram.quantile(0.5),
            p99_ns: histogram.quantile(0.99),
            max_ns: histogram.max,
        })
        .collect();
    syscalls.sort_by(|a, b| b.total_ns.cmp(&a.total_ns).then(b.count.cmp(&a.count)).then(a.number.cmp(&b.number)));
    syscalls.truncate(args.top);
    let stack_rows = stacks(analysis, image, args.top);
    let mut thread_rows: Vec<_> = threads.clone();
    thread_rows.sort_by(|a, b| {
        (b.voluntary_switches + b.involuntary_switches + b.syscalls)
            .cmp(&(a.voluntary_switches + a.involuntary_switches + a.syscalls))
            .then(a.tid.cmp(&b.tid))
    });
    thread_rows.truncate(args.top);
    if args.json {
        serde_json::to_writer_pretty(
            &mut *out,
            &serde_json::json!({
                "capture": capture.stats,
                "context_switches": {"voluntary": voluntary, "involuntary": involuntary,
                    "per_second": rate(voluntary + involuntary, elapsed)},
                "wakeups": {"count": wakeups, "per_second": rate(wakeups, elapsed)},
                "syscalls": {"count": syscall_count, "per_second": rate(syscall_count, elapsed), "by_call": syscalls},
                "off_cpu_ns": off_cpu,
                "threads": thread_rows,
                "off_cpu_stacks": stack_rows,
                "recording": args.out,
                "incomplete": analysis.aggregate.incomplete || capture.stats.lost > 0,
                "warnings": analysis.warnings,
                "caveat": "latency quantiles are within 1/16 of a doubling and cover calls that returned while observed; a wakeup is a thread getting a CPU after leaving it voluntarily (blocking or yielding); a wait that began before its thread was attached counts from the attachment; threads are attached every 25 ms",
            }),
        )?;
        writeln!(out)?;
        return Ok(());
    }
    writeln!(
        out,
        "live sched: {elapsed} ms, {} threads ({} unattached), {} lost and {} undecoded records, stop {}",
        capture.stats.threads,
        capture.stats.unattached_threads,
        capture.stats.lost,
        capture.stats.undecoded,
        capture.stats.stop_reason
    )?;
    writeln!(
        out,
        "context switches: {} ({:.1}/s): {voluntary} voluntary, {involuntary} preempted; wakeups: {wakeups} ({:.1}/s)",
        voluntary + involuntary,
        rate(voluntary + involuntary, elapsed),
        rate(wakeups, elapsed)
    )?;
    if capture.stats.syscalls_traced {
        writeln!(out, "system calls: {syscall_count} ({:.1}/s)", rate(syscall_count, elapsed))?;
    } else {
        writeln!(out, "system calls: not traced (--no-syscalls)")?;
    }
    writeln!(out, "off-CPU: {} summed over threads", duration(off_cpu))?;
    if capture.stats.waits_started_before_attach > 0 {
        writeln!(
            out,
            "note: {} waits began before their thread was attached and count from the attachment",
            capture.stats.waits_started_before_attach
        )?;
    }
    if capture.stats.lost > 0 {
        writeln!(out, "warning: {} records lost; waits and calls across a loss are left out", capture.stats.lost)?;
    }
    if !syscalls.is_empty() {
        writeln!(out, "system calls by total time:")?;
        writeln!(
            out,
            "  {:<18} {:>9} {:>9} {:>9} {:>11} {:>10} {:>10} {:>10} {:>10}",
            "call", "count", "/s", "returned", "total", "mean", "p50", "p99", "max"
        )?;
        for row in &syscalls {
            writeln!(
                out,
                "  {:<18} {:>9} {:>9.1} {:>9} {:>11} {:>10} {:>10} {:>10} {:>10}",
                row.name,
                row.count,
                row.per_second,
                row.completed,
                duration(row.total_ns),
                duration(row.mean_ns),
                duration(row.p50_ns),
                duration(row.p99_ns),
                duration(row.max_ns)
            )?;
        }
    }
    writeln!(out, "threads:")?;
    writeln!(
        out,
        "  {:>8} {:<16} {:>11} {:>10} {:>10} {:>9} {:>9}",
        "tid", "name", "off-CPU", "voluntary", "preempted", "wakeups", "syscalls"
    )?;
    for thread in &thread_rows {
        writeln!(
            out,
            "  {:>8} {:<16} {:>11} {:>10} {:>10} {:>9} {:>9}",
            thread.tid,
            thread.comm,
            duration(thread.off_cpu_ns),
            thread.voluntary_switches,
            thread.involuntary_switches,
            thread.wakeups,
            thread.syscalls
        )?;
    }
    if !stack_rows.is_empty() {
        writeln!(out, "off-CPU stacks by time (root -> leaf):")?;
        for row in &stack_rows {
            writeln!(out, "{:>11} {:>6.2}%  {}", duration(row.off_cpu_ns), row.percent, row.frames.join(" -> "))?;
        }
    }
    if let Some(path) = &args.out {
        writeln!(out, "recording: {} (`xref profile report`, `xref profile diff A B`)", path.display())?;
    }
    if voluntary + involuntary == 0 && syscall_count == 0 {
        writeln!(out, "note: no context switches, wakeups or system calls were observed")?;
    }
    Ok(())
}

/// `profile report` on an off-CPU recording: stacks by the time spent off CPU after them.
pub fn snapshot(
    analysis: &Analysis,
    image: &crate::image::Image,
    top: usize,
    json: bool,
    out: &mut dyn Write,
) -> Result<(), Box<dyn std::error::Error>> {
    let total = analysis.aggregate.total_period;
    let rows = stacks(analysis, image, top);
    let incomplete = analysis.aggregate.incomplete;
    if json {
        serde_json::to_writer_pretty(
            &mut *out,
            &serde_json::json!({"off_cpu_ns": total, "stacks": rows, "incomplete": incomplete,
                "warnings": analysis.warnings}),
        )?;
        writeln!(out)?;
        return Ok(());
    }
    writeln!(out, "off-CPU recording: {} over {} waits", duration(total), analysis.aggregate.samples)?;
    if incomplete {
        writeln!(out, "warning: the recording is incomplete (records were lost or threads were not attached)")?;
    }
    for warning in &analysis.warnings {
        writeln!(out, "warning: {warning}")?;
    }
    writeln!(out, "off-CPU stacks by time (root -> leaf):")?;
    for row in &rows {
        writeln!(out, "{:>11} {:>6.2}%  {}", duration(row.off_cpu_ns), row.percent, row.frames.join(" -> "))?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{duration, rate};

    #[test]
    fn durations_and_rates_read_naturally() {
        assert_eq!(duration(950), "950 ns");
        assert_eq!(duration(20_300), "20.3 us");
        assert_eq!(duration(812_000_000), "812.0 ms");
        assert_eq!(duration(1_250_000_000), "1.25 s");
        assert!((rate(120, 12_000) - 10.0).abs() < 1e-9);
        assert!(rate(5, 0).abs() < 1e-9);
    }
}
