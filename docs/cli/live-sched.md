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
live sched: 2046 ms, 1 threads (0 unattached), 0 lost and 0 undecoded records, stop duration
context switches: 194 (94.8/s): 194 voluntary, 0 preempted; wakeups: 193 (94.3/s)
system calls: 387 (189.1/s)
off-CPU: 2.01 s summed over threads
system calls by total time:
  call                   count        /s       total       mean        p50        p99        max
  poll                     193      94.3      1.96 s    10.2 ms    10.5 ms    12.7 ms    12.7 ms
  write                    194      94.8    546.4 us     2.8 us     2.8 us     6.1 us     6.3 us
off-CPU stacks by time (root -> leaf):
     2.01 s 100.00%  target:_start -> … -> target:main -> target:wait_tick -> [libc.so.6]
```

## Reading the output

- **Context switches** are voluntary (the thread blocked: a system call that
  waits, a futex, a page fault on I/O) or preempted (the scheduler took the
  CPU from a runnable thread). A **wakeup** is a thread getting a CPU again
  after it blocked, so an idle process that never wakes shows 0 of both.
- **System calls** are timed from entry to exit, waiting included, so `poll`
  with a timeout shows the timeout. Latency quantiles are kept in buckets
  within 1/16 of a doubling of each other.
- **Off-CPU stacks** add up the time each thread spent off CPU after leaving
  it in that stack; frames below the program's last one (the blocking call in
  libc) are folded into one frame.
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
