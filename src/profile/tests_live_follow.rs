/*
 * XRef — privileged test: a profile follows a daemon forked twice without exec
 * Copyright (c) 2026 Alexander Panasenko
 * Contact: alex@prod.codes
 * Author: https://prod.codes/about/
 * Project: https://github.com/alex09x/xref
 * SPDX-License-Identifier: MIT OR Apache-2.0
 */
use super::config::{Callers, Config, Follow};
use std::{
    collections::BTreeSet,
    io::{BufRead, BufReader, Cursor},
    process::{Command, Stdio},
    time::Duration,
};

/// The launcher waits for a line on stdin, then forks; the child calls `setsid`, forks the daemon
/// and exits, so the daemon is a grandchild reparented away from the launcher.
const SOURCE: &str = r#"
#include <stdio.h>
#include <unistd.h>
#include <sys/wait.h>
__attribute__((noinline, noipa)) unsigned long daemon_hot(unsigned long n) {
    unsigned long s = 0; for (unsigned long i = 0; i < n; i++) s += i * i ^ (s >> 3); return s;
}
__attribute__((noinline)) unsigned long launcher_wait(void) { char line[8]; return fgets(line, sizeof line, stdin) != 0; }
int main(void) {
    printf("READY\n"); fflush(stdout);
    if (!launcher_wait()) return 0;
    pid_t child = fork();
    if (child == 0) {
        setsid();
        if (fork() == 0) {
            volatile unsigned long sink = 0, n = 100000;
            for (;;) sink += daemon_hot(n);
        }
        _exit(0);
    }
    waitpid(child, 0, 0);
    for (;;) pause();
}
"#;

/// Kills the launcher and every process of the fixture binary, whatever the test outcome.
struct Cleanup(std::process::Child, std::path::PathBuf);

impl Drop for Cleanup {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
        let _ = Command::new("pkill").arg("-f").arg(self.1.as_os_str()).status();
        let _ = std::fs::remove_dir_all(self.1.parent().unwrap_or(&self.1));
    }
}

#[test]
#[ignore = "requires Linux perf hardware event permission"]
fn follows_a_double_forked_daemon_started_during_the_capture() -> Result<(), Box<dyn std::error::Error>> {
    let nonce = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH)?.as_nanos();
    let dir = std::env::temp_dir().join(format!("xref-profile-follow-{}-{nonce}", std::process::id()));
    std::fs::create_dir_all(&dir)?;
    let source = dir.join("daemon.c");
    let binary = dir.join("daemon");
    std::fs::write(&source, SOURCE)?;
    assert!(Command::new("cc").args(["-O1", "-g"]).arg(&source).arg("-o").arg(&binary).status()?.success());
    let launcher = Command::new(&binary).stdin(Stdio::piped()).stdout(Stdio::piped()).spawn()?;
    let mut cleanup = Cleanup(launcher, binary.clone());
    let launcher = &mut cleanup.0;
    let mut ready = String::new();
    BufReader::new(launcher.stdout.take().ok_or("stdout")?).read_line(&mut ready)?;
    assert_eq!(ready.trim(), "READY");
    let mut session = crate::live::procfs::open_session(launcher.id(), Some(&binary), false)?;
    let config = Config {
        duration: Duration::from_millis(1500),
        frequency_hz: Some(1000),
        callers: Callers::Dwarf,
        follow: Follow { children: true, ..Follow::default() },
        ..Config::default()
    };
    let mut stdin = launcher.stdin.take().ok_or("stdin")?;
    let starter = std::thread::spawn(move || {
        std::thread::sleep(Duration::from_millis(200));
        let _ = std::io::Write::write_all(&mut stdin, b"go\n");
        stdin
    });
    let result = super::capture::capture(&mut session, &config, Vec::new(), None);
    let _stdin = starter.join();
    let (bytes, stats) = result?;
    // The intermediate child may exit before it is sampled; the daemon must be followed.
    assert!(stats.followed_processes >= 1, "the daemon is followed: {stats:?}");
    let analysis = super::analyze::analyze(&mut Cursor::new(bytes), &session.image, &BTreeSet::new())?;
    let hot = crate::graph::resolve(&session.image, "daemon_hot")?.start;
    let hot_samples = analysis
        .aggregate
        .functions
        .iter()
        .find(|(key, _)| key.module == 1 && key.start == Some(hot))
        .map_or(0, |(_, counts)| counts.self_samples);
    assert!(
        hot_samples * 2 > analysis.aggregate.samples,
        "daemon_hot dominates: {hot_samples} of {}",
        analysis.aggregate.samples
    );
    drop(cleanup);
    Ok(())
}
