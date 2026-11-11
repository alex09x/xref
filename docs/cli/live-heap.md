# xref live heap

Find which call stacks hold the anonymous memory of a running process. xref
follows the memory syscalls of every thread (`mmap`, `munmap`, `mremap`,
`brk`, `mprotect`) through kernel tracepoints, copies the user stack at each
one that maps memory, unwinds it from `.eh_frame` like
[`live profile`](live-profile.md), and reports the stacks by the bytes they
still hold. There is no uprobe on `malloc`, so the process keeps its speed
even with millions of allocations per second.

## Usage

<!-- xref:usage live heap -->
```text
xref live heap [OPTIONS] --pid <PID>
```
<!-- /xref -->

## Arguments and options

<!-- xref:options live heap -->
**Options**

| Option | Description | Default |
| --- | --- | --- |
| `--pid <PID>` | Target process ID. |  |
| `--duration <DURATION>` | How long to observe, e.g. 10m or 30s; also ends at process exit or Ctrl-C. | `60s` |
| `--interval <INTERVAL>` | Also write a snapshot every interval (e.g. 30s), to see which stacks grow. |  |
| `--sample-bytes <SAMPLE_BYTES>` | Keep one stack per this many mapped bytes (e.g. 4M); every mapping at least this large is kept exactly. | `4M` |
| `--stack-bytes <STACK_BYTES>` | User stack bytes copied with each memory syscall for DWARF unwinding. | `8192` |
| `--out <OUT>` | Directory (new) for the `.xprof` snapshots (`heap-0001.xprof`, ...); `xref profile diff` compares two. |  |
| `--top <TOP>` | Rows in the report. | `30` |
| `--folded <FOLDED>` | Also write folded stacks weighted by bytes (flame-graph input) to this new file. |  |
| `--json` | Print the capture statistics and the report as JSON. |  |
<!-- /xref -->

## Examples

```sh
# Start the program, then attach at once: memory mapped before xref attaches is not attributed.
./server & sudo xref live heap --pid $! --duration 10m --out heap-run1
# Snapshots every 30 seconds show which stacks keep growing.
sudo xref live heap --pid 1234 --duration 30m --interval 30s --out heap-run2
# Compare two runs (before and after a change) stack by stack.
xref -b server profile diff heap-run1/heap-0001.xprof heap-run2/heap-0060.xprof
```

On a small C program that allocates 256 MiB in `big()` and 200,000 objects
of 1000 bytes in `small_many()`, then frees a second 64 MiB block (library paths shortened):

```text
live heap: 448.0 MiB mapped while observed (2953 memory syscalls, 38 lost, 1 threads, 4920 ms, stop process_exited)
stacks by live bytes (root -> leaf):
  256.0 MiB  57.14%  target:_start -> libc.so.6:fn_2a200 -> libc.so.6:fn_2a150 -> target:main -> target:phase -> target:big -> libc.so.6:fn_ad750 -> ...
  192.0 MiB  42.86%  target:_start -> libc.so.6:fn_2a200 -> libc.so.6:fn_2a150 -> target:main -> target:phase -> target:small_many -> libc.so.6:fn_ad750 -> ...
```

## Reading the output

- The first line is the bytes the reported stacks hold, the number of memory
  syscalls seen and lost, the threads followed and why the capture stopped.
- `stacks by live bytes` lists whole call stacks, root first; the frames at the
  leaf end are the allocator (`malloc` and the syscall wrapper). The frame
  before the allocator is the code that asked for the memory.
- `functions by live bytes` adds up every stack a function is on.
- With `--interval`, `snapshots:` shows the total at each snapshot. Each one is
  an `.xprof` recording in `--out`, whose sample weights are bytes, so
  [`profile diff`](profile-diff.md) compares two of them.

## How bytes are attributed

- An allocation at or above glibc's mmap threshold (128 KiB by default, raised
  up to 32 MiB after large frees) is its own `mmap`, so it is attributed exactly
  to the stack that allocated it, and its `free` (`munmap`) takes it back.
- Smaller allocations reach the kernel only when an arena grows: `brk` for the
  main arena, `mprotect` inside the 64 MiB reservation of another arena. The
  `malloc` that crosses the boundary carries the stack, which samples small
  allocations by their bytes.
- To keep long captures bounded, one stack is kept per `--sample-bytes` of
  mapped memory and stands for those bytes; every mapping at least that large
  is kept exactly.

## Limits

- Only memory mapped while xref observes is attributed. Attach when the
  process starts: a process at steady state makes no memory syscalls, and
  what it mapped earlier is not shown.
- Freed small objects stay in their arena and are not returned to the kernel,
  so the small-allocation part is a high-water mark, not live objects.
  Arena memory a later `malloc` reuses is attributed to the stack that first
  grew it.
- Needs root (or `CAP_PERFMON` with tracefs access) for the `syscalls`
  tracepoints. Function names need a symbol table; for a stripped Rust binary
  build with `strip = false`.
- A burst of syscalls can overflow a ring: the first line counts lost events.
- Allocators other than glibc (jemalloc, mimalloc) map memory in their own
  chunk sizes; the attribution still follows their syscalls.
