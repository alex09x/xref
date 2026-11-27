/*
 * XRef — the processes a live profile samples: the target, its forked children, matched processes
 * Copyright (c) 2026 Alexander Panasenko
 * Contact: alex@prod.codes
 * Author: https://prod.codes/about/
 * Project: https://github.com/alex09x/xref
 * SPDX-License-Identifier: MIT OR Apache-2.0
 */

//! A profile samples one binary. `--follow-children` adds every process a sampled process forks
//! (fork without exec, such as a daemon that forks and calls `setsid`), seen from the perf fork
//! record of the parent's thread and, as a fallback, from `/proc`: a process whose parent, process
//! group or session is of the target's family, so a daemon reparented after its parent exited is
//! still found through the session its parent created. `--comm` and
//! `--argv-match` add processes of the same executable file (same device and inode) whose name or
//! command line matches, as they start. A child that execs another program leaves the profile.

use std::collections::BTreeSet;
use std::os::unix::fs::MetadataExt;
use std::path::Path;

pub use super::config::Follow;

/// The fields of `/proc/PID/stat` that relate a process to its family.
#[derive(Debug, PartialEq, Eq)]
pub struct Stat {
    pub comm: String,
    pub ppid: u32,
    pub pgrp: u32,
    pub session: u32,
}

/// Parses `/proc/PID/stat`; the name is in parentheses and may contain any byte.
pub fn parse_stat(text: &str) -> Option<Stat> {
    let open = text.find('(')?;
    let close = text.rfind(')')?;
    let comm = text.get(open + 1..close)?.to_owned();
    let mut rest = text.get(close + 1..)?.split_whitespace();
    let _state = rest.next()?;
    let mut number = || rest.next()?.parse().ok();
    Some(Stat { comm, ppid: number()?, pgrp: number()?, session: number()? })
}

fn stat_of(pid: u32) -> Option<Stat> {
    parse_stat(&std::fs::read_to_string(format!("/proc/{pid}/stat")).ok()?)
}

fn argv_of(pid: u32) -> String {
    std::fs::read(format!("/proc/{pid}/cmdline"))
        .map(|bytes| {
            bytes
                .split(|&byte| byte == 0)
                .filter(|arg| !arg.is_empty())
                .map(String::from_utf8_lossy)
                .collect::<Vec<_>>()
                .join(" ")
        })
        .unwrap_or_default()
}

fn exe_of(pid: u32) -> Option<(u64, u64)> {
    std::fs::metadata(format!("/proc/{pid}/exe")).ok().map(|meta| (meta.dev(), meta.ino()))
}

/// The processes being sampled.
pub struct Targets {
    pub primary: u32,
    /// Processes currently sampled.
    pub pids: BTreeSet<u32>,
    /// Every process ever sampled.
    seen: BTreeSet<u32>,
    /// The target's family for `--follow-children`: every process sampled or reported forked by a
    /// family member, also those gone before they could be sampled. A daemon whose parent exited
    /// is reparented, but keeps that parent as its process group or session (`setsid`).
    family: BTreeSet<u32>,
    /// Processes checked and refused because they run another executable.
    refused: BTreeSet<u32>,
    /// Processes gone before they could be checked.
    gone: BTreeSet<u32>,
    exe: Option<(u64, u64)>,
    pub follow: Follow,
}

impl Targets {
    pub fn new(primary: u32, exe: Option<(u64, u64)>, follow: Follow) -> Self {
        Self {
            primary,
            pids: BTreeSet::from([primary]),
            seen: BTreeSet::from([primary]),
            family: BTreeSet::from([primary]),
            refused: BTreeSet::new(),
            gone: BTreeSet::new(),
            exe,
            follow,
        }
    }

    pub fn contains(&self, pid: u32) -> bool {
        self.pids.contains(&pid)
    }

    /// Followed processes beyond the first target.
    pub fn followed(&self) -> usize {
        self.seen.len().saturating_sub(1)
    }

    /// Candidates refused: another executable, or gone before they were checked.
    pub fn refused(&self) -> usize {
        self.refused.len()
    }

    /// Whether the capture keeps running while no process is sampled (waiting for a match).
    pub const fn waits_for_matches(&self) -> bool {
        self.follow.comm.is_some() || self.follow.argv.is_some()
    }

    /// Accepts `pid` when it runs the same executable file; `true` when newly accepted.
    pub fn accept(&mut self, pid: u32) -> bool {
        if self.seen.contains(&pid) || self.refused.contains(&pid) || self.gone.contains(&pid) {
            return false;
        }
        match exe_of(pid) {
            None => {
                self.gone.insert(pid);
                return false;
            }
            Some(exe) if self.exe != Some(exe) => {
                self.refused.insert(pid);
                return false;
            }
            Some(_) => {}
        }
        self.pids.insert(pid);
        self.seen.insert(pid);
        self.family.insert(pid);
        true
    }

    /// A fork record: `child` is a new process when its parent is of the family and following is
    /// on; it joins the family even when it is gone before it can be sampled.
    pub fn on_fork(&mut self, child: u32, parent: u32) -> bool {
        if !self.follow.children || child == parent || !self.family.contains(&parent) {
            return false;
        }
        self.family.insert(child);
        self.accept(child)
    }

    /// Whether a process found in `/proc` descends from the family.
    fn related(&self, stat: &Stat) -> bool {
        self.follow.children
            && (self.family.contains(&stat.ppid)
                || self.family.contains(&stat.pgrp)
                || self.family.contains(&stat.session))
    }

    pub fn remove(&mut self, pid: u32) {
        self.pids.remove(&pid);
    }

    /// New processes from `/proc`: children of sampled processes, and name or command-line matches.
    pub fn scan(&mut self, proc_root: &Path) -> Vec<u32> {
        if !self.follow.any() {
            return Vec::new();
        }
        let Ok(entries) = std::fs::read_dir(proc_root) else { return Vec::new() };
        let mut found = Vec::new();
        for entry in entries.flatten() {
            let Some(pid) = entry.file_name().to_str().and_then(|name| name.parse::<u32>().ok()) else { continue };
            if pid == 0 || self.seen.contains(&pid) || self.refused.contains(&pid) {
                continue;
            }
            let Some(stat) = stat_of(pid) else { continue };
            let related = self.related(&stat);
            let matched = (self.follow.comm.is_some() || self.follow.argv.is_some()) && {
                let argv = if self.follow.argv.is_some() { argv_of(pid) } else { String::new() };
                self.follow.matches(&stat.comm, &argv)
            };
            if related {
                // Its own children are related through it, even if it runs another program.
                self.family.insert(pid);
            }
            if (related || matched) && self.accept(pid) {
                found.push(pid);
            }
        }
        found
    }
}

/// The first process whose name or command line matches, waiting up to `timeout`.
pub fn wait_for_match(follow: &Follow, timeout: std::time::Duration) -> Result<u32, String> {
    let started = std::time::Instant::now();
    let own = std::process::id();
    loop {
        if let Ok(entries) = std::fs::read_dir("/proc") {
            let mut pids: Vec<u32> =
                entries.flatten().filter_map(|entry| entry.file_name().to_str()?.parse::<u32>().ok()).collect();
            pids.sort_unstable();
            for pid in pids {
                if pid == own {
                    continue;
                }
                let Some(stat) = stat_of(pid) else { continue };
                let argv = if follow.argv.is_some() { argv_of(pid) } else { String::new() };
                // xref's own command line holds the pattern; skip it and its sudo parent.
                if follow.matches(&stat.comm, &argv) && !argv.contains("--argv-match") && !argv.contains("--comm") {
                    return Ok(pid);
                }
            }
        }
        if started.elapsed() >= timeout {
            return Err("no_matching_process: no process matched --comm/--argv-match within the duration".to_owned());
        }
        std::thread::sleep(std::time::Duration::from_millis(5));
    }
}

#[cfg(test)]
mod tests {
    use super::super::config::truncate_comm;
    use super::{Follow, Stat, Targets, parse_stat};

    #[test]
    fn stat_names_may_hold_spaces_and_parentheses() {
        let stat = |comm: &str, ppid, pgrp, session| Stat { comm: comm.to_owned(), ppid, pgrp, session };
        assert_eq!(parse_stat("4242 (tako session) S 17 4242 4243 0"), Some(stat("tako session", 17, 4242, 4243)));
        assert_eq!(parse_stat("7 (a) b)) R 1 7 7 0"), Some(stat("a) b)", 1, 7, 7)));
        assert_eq!(parse_stat("garbage"), None);
    }

    #[test]
    fn a_reparented_daemon_is_related_through_its_session() {
        let mut targets = Targets::new(100, None, Follow { children: true, ..Follow::default() });
        // 101 was forked by the target and exited (no exe): it stays in the family.
        assert!(!targets.on_fork(101, 100));
        let daemon = Stat { comm: "d".to_owned(), ppid: 1, pgrp: 101, session: 101 };
        assert!(targets.related(&daemon), "setsid in 101 made it the daemon's session");
        let stranger = Stat { comm: "d".to_owned(), ppid: 1, pgrp: 500, session: 500 };
        assert!(!targets.related(&stranger));
        assert_eq!(targets.refused(), 0, "a process gone before the check is not refused");
    }

    #[test]
    fn names_match_as_the_kernel_truncates_them() {
        assert_eq!(truncate_comm("tako-session-daemon"), "tako-session-da");
        let follow = Follow { comm: Some("tako-session-daemon".to_owned()), ..Follow::default() };
        assert!(follow.matches("tako-session-da", ""));
        assert!(!follow.matches("tako", ""));
        let argv = Follow { argv: Some("attach --create-only".to_owned()), ..Follow::default() };
        assert!(argv.matches("x", "tako attach --create-only --name a"));
        assert!(!Follow::default().any());
    }

    #[test]
    fn forks_are_followed_only_from_sampled_parents() {
        let mut targets = Targets::new(std::process::id(), super::exe_of(std::process::id()), Follow::default());
        assert!(!targets.on_fork(1, std::process::id()), "following is off");
        targets.follow.children = true;
        // pid 1 runs another executable than the test binary: refused, and remembered.
        assert!(!targets.on_fork(1, std::process::id()));
        assert!(!targets.on_fork(2, 99_999_999), "parent is not sampled");
        assert_eq!(targets.followed(), 0);
    }
}
