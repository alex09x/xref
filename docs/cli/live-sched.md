# xref live sched

See where a running process waits rather than where it computes: the time
each thread spends off CPU together with the user stack it blocked in,
voluntary and preempted context switches, wakeups, and every system call with
its count and latency (p50, p99, max). The off-CPU stacks are saved as an
`.xprof` recording whose weights are nanoseconds, so
[`profile report`](profile-report.md) and [`profile diff`](profile-diff.md)
read it like a CPU profile.

## Usage

<!-- xref:usage live sched -->
```text
xref live sched [OPTIONS] --pid <PID>
```
<!-- /xref -->

## Arguments and options

<!-- xref:options live sched -->
**Options**

| Option | Description | Default |
| --- | --- | --- |
| `--pid <PID>` | Target process ID. |  |
| `--duration <DURATION>` | How long to observe, e.g. 12s or 500ms; also ends at process exit or Ctrl-C. | `10s` |
| `--stack-bytes <STACK_BYTES>` | User stack bytes copied at each switch-out, to unwind the stack the thread blocked in. | `8192` |
| `--no-syscalls` | Leave out system calls (they need the `raw_syscalls` tracepoints, readable by root). |  |
| `--out <OUT>` | Keep the off-CPU recording at this new path (`.xprof`, weights are nanoseconds off CPU), for `xref profile report` and `xref profile diff`. |  |
| `--top <TOP>` | Rows in each table of the report. | `20` |
| `--json` | Print the capture and the report as JSON. |  |
<!-- /xref -->

## Examples

```sh
# Does an idle daemon ever wake up? Twelve seconds of its scheduling and system calls:
sudo xref -b daemon live sched --pid 1234 --duration 12s
# Where a request's latency goes, kept for a before/after comparison:
sudo xref -b daemon live sched --pid 1234 --duration 5s --out before.xprof
sudo xref -b daemon profile diff before.xprof after.xprof
```

A process that waits in `poll` with a 10 ms timeout and writes one byte each
time gives:

```text
live sched: 2000 ms, 1 threads (0 unattached), 0 lost and 0 undecoded records, stop duration
context switches: 197 (98.5/s): 195 voluntary, 2 preempted; wakeups: 194 (97.0/s)
system calls: 390 (195.0/s)
off-CPU: 1.97 s summed over threads
note: 1 waits began before their thread was attached and count from the attachment
system calls by total time:
  call                   count        /s  returned       total       mean        p50        p99        max
  poll                     195      97.5       194      1.96 s    10.1 ms    10.5 ms    11.0 ms    12.8 ms
  write                    195      97.5       195    299.9 us     1.5 us     1.4 us     3.2 us     5.6 us
off-CPU stacks by time (root -> leaf):
     1.97 s 100.00%  target:_start -> … -> target:main -> target:wait_tick -> libc.so.6:poll
```

## Reading the output

- **Context switches** are voluntary (the thread blocked: a system call that
  waits, a futex, a page fault on I/O, or it yielded) or preempted (the
  scheduler took the CPU from a runnable thread). A **wakeup** is a thread
  getting a CPU again after leaving it voluntarily, so an idle process that
  never wakes shows 0 of both.
- **System calls**: `count` is the calls entered while observed, `returned`
  those that also returned. Latencies are of the returned calls, from entry
  to exit, waiting included, so `poll` with a timeout shows the timeout.
  Quantiles are kept in buckets within 1/16 of a doubling of each other.
- A wait already in progress when a thread is attached counts from the
  attachment (the `note:` line says how many). A lost record breaks its
  thread's stream: no wait or call is paired across it.
- **Off-CPU stacks** add up the time each thread spent off CPU after leaving
  it in that stack; the frames below the program's last one are named by
  library file and function (`libc.so.6:poll`): the call the thread waited in.
- Threads that start during the capture are attached when xref sees them
  (every 25 ms), so their first records can be missed.

## Limits

- Needs root or `CAP_PERFMON` with tracefs access: the switch events count in
  the kernel, and system calls come from the `raw_syscalls` tracepoints
  (`--no-syscalls` leaves them out).
- Who woke a thread is not reported; that needs system-wide scheduler
  tracepoints.
- Every system call of every thread is recorded, so a process making millions
  of calls a second slows down while it is observed.
