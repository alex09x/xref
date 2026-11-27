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
//! still found through the session its parent created. `--comm` and `--argv-match` add processes
//! of the same executable file (same device and inode) whose name or command line matches, as they
//! start. A process is identified by its PID and start time: a sampled process whose start time or
//! executable changes (exit and PID reuse, or exec) leaves the profile, and a refused one is
//! reconsidered when either changes.

use std::collections::{BTreeMap, BTreeSet};
use std::os::unix::fs::MetadataExt;
use std::path::Path;

pub use super::config::Follow;

/// The fields of `/proc/PID/stat` that relate a process to its family and identify it.
#[derive(Debug, PartialEq, Eq)]
pub struct Stat {
    /// The raw name bytes (Linux task names need not be UTF-8).
    pub comm: Vec<u8>,
    pub ppid: u32,
    pub pgrp: u32,
    pub session: u32,
    /// Start time in clock ticks after boot: with the PID, the process identity.
    pub start: u64,
}

/// Parses `/proc/PID/stat`; the name is in parentheses and may contain any byte.
pub fn parse_stat(bytes: &[u8]) -> Option<Stat> {
    let open = bytes.iter().position(|&b| b == b'(')?;
    let close = bytes.iter().rposition(|&b| b == b')')?;
    let comm = bytes.get(open + 1..close)?.to_vec();
    let rest = std::str::from_utf8(bytes.get(close + 1..)?).ok()?;
    let fields: Vec<&str> = rest.split_whitespace().collect();
    // After the state: ppid, pgrp, session, ..., starttime (field 22 of stat, 20th after the name).
    let id = |index: usize| fields.get(index)?.parse::<u32>().ok();
    let start = fields.get(19)?.parse::<u64>().ok()?;
    Some(Stat { comm, ppid: id(1)?, pgrp: id(2)?, session: id(3)?, start })
}

fn stat_of(pid: u32) -> Option<Stat> {
    parse_stat(&std::fs::read(format!("/proc/{pid}/stat")).ok()?)
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
    /// Start time of every sampled process, to notice PID reuse.
    admitted: BTreeMap<u32, u64>,
    /// The target's family for `--follow-children`: every process sampled or reported forked by a
    /// family member, also those gone before they could be sampled. A daemon whose parent exited
    /// is reparented, but keeps that parent as its process group or session (`setsid`).
    family: BTreeSet<u32>,
    /// Refused processes and the start time and executable they were refused with.
    refused: BTreeMap<u32, (u64, Option<(u64, u64)>)>,
    refusals: BTreeSet<(u32, u64)>,
    gone: BTreeSet<u32>,
    followed: usize,
    exe: Option<(u64, u64)>,
    pub follow: Follow,
    /// PIDs listed in `/proc` at the previous scan; only new ones are examined between full scans.
    listed: BTreeSet<u32>,
    last_full_scan: Option<std::time::Instant>,
}

/// How often every process is examined again (for exec and PID reuse); new PIDs are examined at
/// every scan.
const FULL_SCAN_EVERY: std::time::Duration = std::time::Duration::from_millis(250);

impl Targets {
    pub fn new(primary: u32, exe: Option<(u64, u64)>, follow: Follow) -> Self {
        let start = stat_of(primary).map_or(0, |stat| stat.start);
        Self {
            primary,
            pids: BTreeSet::from([primary]),
            admitted: BTreeMap::from([(primary, start)]),
            family: BTreeSet::from([primary]),
            refused: BTreeMap::new(),
            refusals: BTreeSet::new(),
            gone: BTreeSet::new(),
            followed: 0,
            exe,
            follow,
            listed: BTreeSet::new(),
            last_full_scan: None,
        }
    }

    pub fn contains(&self, pid: u32) -> bool {
        self.pids.contains(&pid)
    }

    /// Processes beyond the first target whose sampling was set up.
    pub const fn followed(&self) -> usize {
        self.followed
    }

    /// Records that a newly accepted process is sampled.
    pub const fn confirm(&mut self) {
        self.followed += 1;
    }

    /// Candidates refused because they ran another executable.
    pub fn refused(&self) -> usize {
        self.refusals.len()
    }

    /// Candidates gone before they could be checked or set up.
    pub fn gone(&self) -> usize {
        self.gone.len()
    }

    /// Whether the capture keeps running while no process is sampled (waiting for a match).
    pub const fn waits_for_matches(&self) -> bool {
        self.follow.comm.is_some() || self.follow.argv.is_some()
    }

    /// Whether `pid` was refused and is still the same process running the same executable.
    fn still_refused(&self, pid: u32, start: u64) -> bool {
        self.refused
            .get(&pid)
            .is_some_and(|(refused_start, refused_exe)| *refused_start == start && *refused_exe == exe_of(pid))
    }

    /// Accepts `pid` when it runs the same executable file; `true` when newly accepted.
    pub fn accept(&mut self, pid: u32) -> bool {
        let Some(stat) = stat_of(pid) else {
            self.gone.insert(pid);
            return false;
        };
        if self.admitted.get(&pid) == Some(&stat.start) || self.still_refused(pid, stat.start) {
            return false;
        }
        match exe_of(pid) {
            None => {
                self.gone.insert(pid);
                return false;
            }
            Some(exe) if self.exe != Some(exe) => {
                self.refused.insert(pid, (stat.start, Some(exe)));
                self.refusals.insert((pid, stat.start));
                return false;
            }
            Some(_) => {}
        }
        self.pids.insert(pid);
        self.admitted.insert(pid, stat.start);
        self.family.insert(pid);
        true
    }

    /// Whether a sampled process is still the one admitted: same start time and executable.
    pub fn still_same(&self, pid: u32) -> bool {
        let Some(start) = self.admitted.get(&pid) else { return false };
        stat_of(pid).is_some_and(|stat| stat.start == *start) && exe_of(pid).is_some() && exe_of(pid) == self.exe
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

    /// Stops sampling `pid`; `gone` also counts it as lost before it could be set up.
    pub fn remove(&mut self, pid: u32, gone: bool) {
        self.pids.remove(&pid);
        self.admitted.remove(&pid);
        if gone {
            self.gone.insert(pid);
        }
    }

    /// New processes from `/proc`: children of sampled processes, and name or command-line matches.
    pub fn scan(&mut self, proc_root: &Path) -> Vec<u32> {
        if !self.follow.any() {
            return Vec::new();
        }
        let Ok(entries) = std::fs::read_dir(proc_root) else { return Vec::new() };
        let full = self.last_full_scan.is_none_or(|at| at.elapsed() >= FULL_SCAN_EVERY);
        if full {
            self.last_full_scan = Some(std::time::Instant::now());
        }
        let listed: BTreeSet<u32> = entries
            .flatten()
            .filter_map(|entry| entry.file_name().to_str().and_then(|name| name.parse::<u32>().ok()))
            .collect();
        let previous = std::mem::replace(&mut self.listed, listed.clone());
        let mut found = Vec::new();
        for pid in listed {
            if pid == 0 || self.pids.contains(&pid) || (!full && previous.contains(&pid)) {
                continue;
            }
            let Some(stat) = stat_of(pid) else { continue };
            if self.still_refused(pid, stat.start) {
                continue;
            }
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

/// xref itself and the processes that started it (`sudo`, a shell running the command): their
/// command lines hold the selector, so they are never selected.
fn own_lineage() -> BTreeSet<u32> {
    let mut out = BTreeSet::new();
    let mut pid = std::process::id();
    while pid > 1 && out.insert(pid) {
        let Some(stat) = stat_of(pid) else { break };
        pid = stat.ppid;
    }
    out
}

/// The processes whose name or command line matches, lowest PID first; xref and its lineage are
/// left out.
pub fn matching_processes(follow: &Follow) -> Vec<u32> {
    let lineage = own_lineage();
    let Ok(entries) = std::fs::read_dir("/proc") else { return Vec::new() };
    let mut pids: Vec<u32> =
        entries.flatten().filter_map(|entry| entry.file_name().to_str()?.parse::<u32>().ok()).collect();
    pids.sort_unstable();
    pids.retain(|pid| {
        !lineage.contains(pid)
            && stat_of(*pid).is_some_and(|stat| {
                let argv = if follow.argv.is_some() { argv_of(*pid) } else { String::new() };
                follow.matches(&stat.comm, &argv)
            })
    });
    pids
}

#[cfg(test)]
mod tests {
    use super::super::config::truncate_comm;
    use super::{Follow, Stat, Targets, parse_stat};

    /// Above any PID the kernel hands out (`pid_max` is at most 2^22).
    const ABSENT: u32 = 4_000_000_001;

    #[test]
    fn stat_names_may_hold_spaces_parentheses_and_any_byte() {
        let line = b"4242 (tako session) S 17 4242 4243 0 -1 4194560 1 0 0 0 0 0 0 0 20 0 1 0 98765 0";
        let stat =
            parse_stat(line).unwrap_or_else(|| Stat { comm: Vec::new(), ppid: 0, pgrp: 0, session: 0, start: 0 });
        assert_eq!(
            (stat.comm.as_slice(), stat.ppid, stat.pgrp, stat.session, stat.start),
            (&b"tako session"[..], 17, 4242, 4243, 98765)
        );
        let odd = b"7 (a) \xff) R 1 7 7 0 -1 0 0 0 0 0 0 0 0 0 20 0 1 0 5 0";
        assert_eq!(parse_stat(odd).map(|s| s.comm), Some(b"a) \xff".to_vec()));
        assert_eq!(parse_stat(b"garbage"), None);
    }

    #[test]
    fn names_match_as_the_kernel_truncates_them() {
        assert_eq!(truncate_comm("tako-session-daemon"), b"tako-session-da");
        let follow = Follow { comm: Some("tako-session-daemon".to_owned()), ..Follow::default() };
        assert!(follow.matches(b"tako-session-da", ""));
        assert!(!follow.matches(b"tako", ""));
        // A multibyte character cut at byte 15 still matches its raw bytes.
        let name = "abcdefghijklmn\u{e9}x";
        let cut = &name.as_bytes()[..15];
        assert!(Follow { comm: Some(name.to_owned()), ..Follow::default() }.matches(cut, ""));
        let argv = Follow { argv: Some("attach --create-only".to_owned()), ..Follow::default() };
        assert!(argv.matches(b"x", "tako attach --create-only --name a"));
        assert!(!Follow::default().any());
    }

    #[test]
    fn a_reparented_daemon_is_related_through_its_session() {
        let mut targets = Targets::new(std::process::id(), None, Follow { children: true, ..Follow::default() });
        // ABSENT was forked by the target and exited: it stays in the family, counted as gone.
        assert!(!targets.on_fork(ABSENT, std::process::id()));
        let stat = |ppid, pgrp, session| Stat { comm: b"d".to_vec(), ppid, pgrp, session, start: 1 };
        assert!(targets.related(&stat(1, ABSENT, ABSENT)), "setsid in the exited child made it the daemon's session");
        assert!(!targets.related(&stat(1, 500, 500)));
        assert_eq!((targets.refused(), targets.gone()), (0, 1));
        assert!(!targets.on_fork(ABSENT + 1, ABSENT + 2), "parent is not of the family");
        assert_eq!(targets.followed(), 0);
    }
}
