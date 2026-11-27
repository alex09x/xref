/*
 * XRef — x86-64 Linux system call names and a latency histogram
 * Copyright (c) 2026 Alexander Panasenko
 * Contact: alex@prod.codes
 * Author: https://prod.codes/about/
 * Project: https://github.com/alex09x/xref
 * SPDX-License-Identifier: MIT OR Apache-2.0
 */

/// Names of the system calls a program commonly makes, from the `libc` numbers (a wrong name does
/// not compile); others print as `syscall_N`.
#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
macro_rules! names {
    ($($name:ident),* $(,)?) => {
        &[$((paste_number!($name), stringify!($name))),*]
    };
}

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
macro_rules! paste_number {
    ($name:ident) => {
        syscall_number(concat_idents_sys!($name))
    };
}

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
macro_rules! concat_idents_sys {
    (read) => {
        libc::SYS_read
    };
    (write) => {
        libc::SYS_write
    };
    (open) => {
        libc::SYS_open
    };
    (close) => {
        libc::SYS_close
    };
    (stat) => {
        libc::SYS_stat
    };
    (fstat) => {
        libc::SYS_fstat
    };
    (lstat) => {
        libc::SYS_lstat
    };
    (poll) => {
        libc::SYS_poll
    };
    (lseek) => {
        libc::SYS_lseek
    };
    (mmap) => {
        libc::SYS_mmap
    };
    (mprotect) => {
        libc::SYS_mprotect
    };
    (munmap) => {
        libc::SYS_munmap
    };
    (brk) => {
        libc::SYS_brk
    };
    (rt_sigaction) => {
        libc::SYS_rt_sigaction
    };
    (rt_sigprocmask) => {
        libc::SYS_rt_sigprocmask
    };
    (rt_sigreturn) => {
        libc::SYS_rt_sigreturn
    };
    (ioctl) => {
        libc::SYS_ioctl
    };
    (pread64) => {
        libc::SYS_pread64
    };
    (pwrite64) => {
        libc::SYS_pwrite64
    };
    (readv) => {
        libc::SYS_readv
    };
    (writev) => {
        libc::SYS_writev
    };
    (access) => {
        libc::SYS_access
    };
    (pipe) => {
        libc::SYS_pipe
    };
    (select) => {
        libc::SYS_select
    };
    (sched_yield) => {
        libc::SYS_sched_yield
    };
    (mremap) => {
        libc::SYS_mremap
    };
    (msync) => {
        libc::SYS_msync
    };
    (madvise) => {
        libc::SYS_madvise
    };
    (dup) => {
        libc::SYS_dup
    };
    (dup2) => {
        libc::SYS_dup2
    };
    (pause) => {
        libc::SYS_pause
    };
    (nanosleep) => {
        libc::SYS_nanosleep
    };
    (getpid) => {
        libc::SYS_getpid
    };
    (socket) => {
        libc::SYS_socket
    };
    (connect) => {
        libc::SYS_connect
    };
    (accept) => {
        libc::SYS_accept
    };
    (sendto) => {
        libc::SYS_sendto
    };
    (recvfrom) => {
        libc::SYS_recvfrom
    };
    (sendmsg) => {
        libc::SYS_sendmsg
    };
    (recvmsg) => {
        libc::SYS_recvmsg
    };
    (shutdown) => {
        libc::SYS_shutdown
    };
    (bind) => {
        libc::SYS_bind
    };
    (listen) => {
        libc::SYS_listen
    };
    (getsockname) => {
        libc::SYS_getsockname
    };
    (getpeername) => {
        libc::SYS_getpeername
    };
    (socketpair) => {
        libc::SYS_socketpair
    };
    (setsockopt) => {
        libc::SYS_setsockopt
    };
    (getsockopt) => {
        libc::SYS_getsockopt
    };
    (clone) => {
        libc::SYS_clone
    };
    (fork) => {
        libc::SYS_fork
    };
    (vfork) => {
        libc::SYS_vfork
    };
    (execve) => {
        libc::SYS_execve
    };
    (exit) => {
        libc::SYS_exit
    };
    (wait4) => {
        libc::SYS_wait4
    };
    (kill) => {
        libc::SYS_kill
    };
    (uname) => {
        libc::SYS_uname
    };
    (fcntl) => {
        libc::SYS_fcntl
    };
    (flock) => {
        libc::SYS_flock
    };
    (fsync) => {
        libc::SYS_fsync
    };
    (fdatasync) => {
        libc::SYS_fdatasync
    };
    (ftruncate) => {
        libc::SYS_ftruncate
    };
    (getdents64) => {
        libc::SYS_getdents64
    };
    (getcwd) => {
        libc::SYS_getcwd
    };
    (chdir) => {
        libc::SYS_chdir
    };
    (rename) => {
        libc::SYS_rename
    };
    (mkdir) => {
        libc::SYS_mkdir
    };
    (rmdir) => {
        libc::SYS_rmdir
    };
    (unlink) => {
        libc::SYS_unlink
    };
    (readlink) => {
        libc::SYS_readlink
    };
    (chmod) => {
        libc::SYS_chmod
    };
    (fchmod) => {
        libc::SYS_fchmod
    };
    (umask) => {
        libc::SYS_umask
    };
    (gettimeofday) => {
        libc::SYS_gettimeofday
    };
    (getrlimit) => {
        libc::SYS_getrlimit
    };
    (getrusage) => {
        libc::SYS_getrusage
    };
    (sysinfo) => {
        libc::SYS_sysinfo
    };
    (getuid) => {
        libc::SYS_getuid
    };
    (getgid) => {
        libc::SYS_getgid
    };
    (geteuid) => {
        libc::SYS_geteuid
    };
    (getppid) => {
        libc::SYS_getppid
    };
    (setsid) => {
        libc::SYS_setsid
    };
    (sigaltstack) => {
        libc::SYS_sigaltstack
    };
    (prctl) => {
        libc::SYS_prctl
    };
    (arch_prctl) => {
        libc::SYS_arch_prctl
    };
    (gettid) => {
        libc::SYS_gettid
    };
    (tkill) => {
        libc::SYS_tkill
    };
    (futex) => {
        libc::SYS_futex
    };
    (sched_getaffinity) => {
        libc::SYS_sched_getaffinity
    };
    (epoll_wait) => {
        libc::SYS_epoll_wait
    };
    (set_tid_address) => {
        libc::SYS_set_tid_address
    };
    (clock_gettime) => {
        libc::SYS_clock_gettime
    };
    (clock_nanosleep) => {
        libc::SYS_clock_nanosleep
    };
    (exit_group) => {
        libc::SYS_exit_group
    };
    (epoll_ctl) => {
        libc::SYS_epoll_ctl
    };
    (tgkill) => {
        libc::SYS_tgkill
    };
    (openat) => {
        libc::SYS_openat
    };
    (mkdirat) => {
        libc::SYS_mkdirat
    };
    (newfstatat) => {
        libc::SYS_newfstatat
    };
    (unlinkat) => {
        libc::SYS_unlinkat
    };
    (renameat) => {
        libc::SYS_renameat
    };
    (readlinkat) => {
        libc::SYS_readlinkat
    };
    (faccessat) => {
        libc::SYS_faccessat
    };
    (pselect6) => {
        libc::SYS_pselect6
    };
    (ppoll) => {
        libc::SYS_ppoll
    };
    (set_robust_list) => {
        libc::SYS_set_robust_list
    };
    (splice) => {
        libc::SYS_splice
    };
    (tee) => {
        libc::SYS_tee
    };
    (epoll_pwait) => {
        libc::SYS_epoll_pwait
    };
    (signalfd4) => {
        libc::SYS_signalfd4
    };
    (eventfd2) => {
        libc::SYS_eventfd2
    };
    (epoll_create1) => {
        libc::SYS_epoll_create1
    };
    (dup3) => {
        libc::SYS_dup3
    };
    (pipe2) => {
        libc::SYS_pipe2
    };
    (accept4) => {
        libc::SYS_accept4
    };
    (timerfd_create) => {
        libc::SYS_timerfd_create
    };
    (timerfd_settime) => {
        libc::SYS_timerfd_settime
    };
    (timerfd_gettime) => {
        libc::SYS_timerfd_gettime
    };
    (preadv) => {
        libc::SYS_preadv
    };
    (pwritev) => {
        libc::SYS_pwritev
    };
    (recvmmsg) => {
        libc::SYS_recvmmsg
    };
    (sendmmsg) => {
        libc::SYS_sendmmsg
    };
    (prlimit64) => {
        libc::SYS_prlimit64
    };
    (getrandom) => {
        libc::SYS_getrandom
    };
    (memfd_create) => {
        libc::SYS_memfd_create
    };
    (statx) => {
        libc::SYS_statx
    };
    (rseq) => {
        libc::SYS_rseq
    };
    (io_uring_setup) => {
        libc::SYS_io_uring_setup
    };
    (io_uring_enter) => {
        libc::SYS_io_uring_enter
    };
    (clone3) => {
        libc::SYS_clone3
    };
    (close_range) => {
        libc::SYS_close_range
    };
    (epoll_pwait2) => {
        libc::SYS_epoll_pwait2
    };
    (copy_file_range) => {
        libc::SYS_copy_file_range
    };
    (sendfile) => {
        libc::SYS_sendfile
    };
    (pidfd_open) => {
        libc::SYS_pidfd_open
    };
    (sched_setaffinity) => {
        libc::SYS_sched_setaffinity
    };
}

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
const fn syscall_number(number: libc::c_long) -> u64 {
    number.cast_unsigned()
}

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
static NAMES: &[(u64, &str)] = names![
    read,
    write,
    open,
    close,
    stat,
    fstat,
    lstat,
    poll,
    lseek,
    mmap,
    mprotect,
    munmap,
    brk,
    rt_sigaction,
    rt_sigprocmask,
    rt_sigreturn,
    ioctl,
    pread64,
    pwrite64,
    readv,
    writev,
    access,
    pipe,
    select,
    sched_yield,
    mremap,
    msync,
    madvise,
    dup,
    dup2,
    pause,
    nanosleep,
    getpid,
    socket,
    connect,
    accept,
    sendto,
    recvfrom,
    sendmsg,
    recvmsg,
    shutdown,
    bind,
    listen,
    getsockname,
    getpeername,
    socketpair,
    setsockopt,
    getsockopt,
    clone,
    fork,
    vfork,
    execve,
    exit,
    wait4,
    kill,
    uname,
    fcntl,
    flock,
    fsync,
    fdatasync,
    ftruncate,
    getdents64,
    getcwd,
    chdir,
    rename,
    mkdir,
    rmdir,
    unlink,
    readlink,
    chmod,
    fchmod,
    umask,
    gettimeofday,
    getrlimit,
    getrusage,
    sysinfo,
    getuid,
    getgid,
    geteuid,
    getppid,
    setsid,
    sigaltstack,
    prctl,
    arch_prctl,
    gettid,
    tkill,
    futex,
    sched_getaffinity,
    epoll_wait,
    set_tid_address,
    clock_gettime,
    clock_nanosleep,
    exit_group,
    epoll_ctl,
    tgkill,
    openat,
    mkdirat,
    newfstatat,
    unlinkat,
    renameat,
    readlinkat,
    faccessat,
    pselect6,
    ppoll,
    set_robust_list,
    splice,
    tee,
    epoll_pwait,
    signalfd4,
    eventfd2,
    epoll_create1,
    dup3,
    pipe2,
    accept4,
    timerfd_create,
    timerfd_settime,
    timerfd_gettime,
    preadv,
    pwritev,
    recvmmsg,
    sendmmsg,
    prlimit64,
    getrandom,
    memfd_create,
    statx,
    rseq,
    io_uring_setup,
    io_uring_enter,
    clone3,
    close_range,
    epoll_pwait2,
    copy_file_range,
    sendfile,
    pidfd_open,
    sched_setaffinity,
];

/// The name of system call `number` (`syscall_N` when it is not in the table).
pub fn name(number: u64) -> String {
    #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
    if let Some((_, name)) = NAMES.iter().find(|(value, _)| *value == number) {
        return (*name).to_owned();
    }
    format!("syscall_{number}")
}

/// Latencies in log-linear buckets: 16 per power of two, so a quantile is within 1/16 of a doubling.
#[derive(Clone, Debug, Default)]
pub struct Histogram {
    buckets: std::collections::BTreeMap<u32, u64>,
    pub count: u64,
    pub total: u64,
    pub max: u64,
}

const SUB_BITS: u32 = 4;

impl Histogram {
    fn bucket(value: u64) -> u32 {
        if value < (1 << SUB_BITS) {
            return u32::try_from(value).unwrap_or(0);
        }
        let exponent = value.ilog2();
        let sub = u32::try_from((value >> (exponent - SUB_BITS)) & ((1 << SUB_BITS) - 1)).unwrap_or(0);
        ((exponent - SUB_BITS + 1) << SUB_BITS) + sub
    }

    /// The upper bound of a bucket's values.
    fn upper(bucket: u32) -> u64 {
        if bucket < (1 << SUB_BITS) {
            return u64::from(bucket);
        }
        let exponent = (bucket >> SUB_BITS) + SUB_BITS - 1;
        let sub = u64::from(bucket & ((1 << SUB_BITS) - 1));
        (((1 << SUB_BITS) + sub + 1) << (exponent - SUB_BITS)) - 1
    }

    pub fn record(&mut self, value: u64) {
        *self.buckets.entry(Self::bucket(value)).or_insert(0) += 1;
        self.count += 1;
        self.total = self.total.saturating_add(value);
        self.max = self.max.max(value);
    }

    /// The value at quantile `q` (0..=1), rounded up to its bucket's bound and capped at the max.
    pub fn quantile(&self, q: f64) -> u64 {
        if self.count == 0 {
            return 0;
        }
        #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss, clippy::cast_precision_loss)]
        let rank = ((self.count as f64) * q).ceil().max(1.0) as u64;
        let mut seen = 0;
        for (bucket, count) in &self.buckets {
            seen += count;
            if seen >= rank {
                return Self::upper(*bucket).min(self.max);
            }
        }
        self.max
    }
}

#[cfg(test)]
mod tests {
    use super::{Histogram, name};

    #[test]
    fn names_come_from_libc_numbers() {
        #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
        {
            assert_eq!(name(0), "read");
            assert_eq!(name(7), "poll");
            assert_eq!(name(202), "futex");
        }
        assert_eq!(name(100_000), "syscall_100000");
    }

    #[test]
    fn quantiles_are_within_a_sixteenth_of_a_doubling() {
        let mut histogram = Histogram::default();
        for value in 1..=1000_u64 {
            histogram.record(value * 1000);
        }
        let p50 = histogram.quantile(0.5);
        let p99 = histogram.quantile(0.99);
        assert!((500_000..=500_000 + 500_000 / 16 + 1).contains(&p50), "{p50}");
        assert!((990_000..=1_000_000).contains(&p99), "{p99}");
        assert_eq!(histogram.quantile(1.0), 1_000_000);
        assert_eq!((histogram.count, histogram.max), (1000, 1_000_000));
        let mut small = Histogram::default();
        small.record(3);
        assert_eq!(small.quantile(0.99), 3);
    }
}
