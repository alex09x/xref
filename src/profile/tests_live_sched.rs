/*
 * XRef — privileged test: `live sched` on a process that polls with a timeout
 * Copyright (c) 2026 Alexander Panasenko
 * Contact: alex@prod.codes
 * Author: https://prod.codes/about/
 * Project: https://github.com/alex09x/xref
 * SPDX-License-Identifier: MIT OR Apache-2.0
 */
use std::process::{Command, Stdio};
use std::time::Duration;

const SOURCE: &str = r#"
#include <poll.h>
#include <unistd.h>
#include <fcntl.h>
__attribute__((noinline, noipa)) int wait_tick(int fd) { struct pollfd p = {fd, POLLIN, 0}; return poll(&p, 1, 10); }
__attribute__((noinline, noipa)) long report_tick(int out) { return write(out, "x", 1); }
int main(void) {
    int fds[2];
    if (pipe(fds) != 0) return 1;
    int out = open("/dev/null", O_WRONLY);
    for (;;) { wait_tick(fds[0]); report_tick(out); }
}
"#;

struct Killed(std::process::Child, std::path::PathBuf);

impl Drop for Killed {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
        let _ = std::fs::remove_dir_all(&self.1);
    }
}

#[test]
#[ignore = "requires root (perf kernel events and tracefs)"]
fn a_polling_process_shows_its_wakeups_syscalls_and_blocking_stack() -> Result<(), Box<dyn std::error::Error>> {
    // A fresh private directory (the test runs as root and executes what it builds there).
    let dir = tempfile::tempdir()?.keep();
    let (source, binary) = (dir.join("waiter.c"), dir.join("waiter"));
    std::fs::write(&source, SOURCE)?;
    assert!(Command::new("cc").args(["-O1", "-g"]).arg(&source).arg("-o").arg(&binary).status()?.success());
    let child = Command::new(&binary).stdout(Stdio::null()).spawn()?;
    let guard = Killed(child, dir);
    std::thread::sleep(Duration::from_millis(100));
    let args = super::sched::SchedArgs {
        pid: guard.0.id(),
        duration: Duration::from_millis(1000),
        stack_bytes: 8192,
        no_syscalls: false,
        out: None,
        top: 20,
        json: true,
    };
    let mut output = Vec::new();
    super::sched::run(Some(&binary), &args, &mut output)?;
    let report: serde_json::Value = serde_json::from_slice(&output)?;
    assert_eq!(report["capture"]["lost"], 0, "records were lost: {report}");
    let wakeups = report["wakeups"]["count"].as_u64().ok_or("wakeups")?;
    // poll times out every 10 ms: at most about 100 wakeups in a second; a loaded machine may give
    // fewer, so only their presence is required.
    assert!((5..=110).contains(&wakeups), "wakeups {wakeups}: {report}");
    let calls = report["syscalls"]["by_call"].as_array().ok_or("by_call")?;
    let poll = calls.iter().find(|row| row["name"] == "poll").ok_or("no poll row")?;
    let count = poll["count"].as_u64().unwrap_or(0);
    assert!(count.abs_diff(wakeups) <= 2, "one poll per wakeup: {poll}");
    assert!(poll["p50_ns"].as_u64().unwrap_or(0) >= 9_000_000, "poll waits its 10 ms timeout: {poll}");
    assert!(calls.iter().any(|row| row["name"] == "write"), "{report}");
    let stacks = report["off_cpu_stacks"].as_array().ok_or("stacks")?;
    let top = stacks.first().ok_or("no off-CPU stack")?;
    let frames = top["frames"].as_array().ok_or("frames")?;
    assert!(frames.iter().any(|frame| frame == "target:wait_tick"), "the wait is in wait_tick: {top}");
    assert!(top["percent"].as_f64().unwrap_or(0.0) > 90.0, "{top}");
    drop(guard);
    Ok(())
}
