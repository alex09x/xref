# xref live alloc

Count a running process's allocations by call site: uprobes on the
allocator's `malloc`, `calloc`, `realloc` and `free` report, for every call
stack and every function, how many allocations it made, how many bytes, and
how many bytes are still allocated at the end. The stacks are unwound from
`.eh_frame` while the capture runs, so a long capture of a busy allocator
stays small. Recordings weighted by bytes are read by
[`profile report`](profile-report.md) and compared by
[`profile diff`](profile-diff.md).

[`live heap`](live-heap.md) needs no uprobes and keeps the process at full
speed, but it sees only memory the allocator maps from the kernel.
`live alloc` sees every call, so it answers questions like "does this
allocate per row?" or "does the idle daemon allocate at all?".

## Usage

<!-- xref:usage live alloc -->
```text
xref live alloc [OPTIONS] --pid <PID>
```
<!-- /xref -->

## Arguments and options

<!-- xref:options live alloc -->
**Options**

| Option | Description | Default |
| --- | --- | --- |
| `--pid <PID>` | Target process ID. |  |
| `--duration <DURATION>` | How long to observe, e.g. 10s or 500ms; also ends at process exit or Ctrl-C. | `10s` |
| `--stack-bytes <STACK_BYTES>` | User stack bytes copied at each allocation for DWARF unwinding. | `4096` |
| `--out <OUT>` | Directory (new) for `alloc.xprof` (bytes allocated by stack) and `live.xprof` (bytes still allocated at the end), for `xref profile report` and `xref profile diff`. |  |
| `--top <TOP>` | Rows in each table of the report. | `20` |
| `--json` | Print the capture and the report as JSON. |  |
<!-- /xref -->

## Examples

```sh
# Who allocates, and what stays allocated, over ten seconds:
sudo xref -b daemon live alloc --pid 1234 --duration 10s
# Before and after a change: compare bytes allocated by function.
sudo xref -b daemon live alloc --pid 1234 --duration 10s --out before
sudo xref -b daemon live alloc --pid 1234 --duration 10s --out after
xref -b daemon profile diff before/alloc.xprof after/alloc.xprof
```

A program that, every millisecond, allocates and frees ten 64-byte rows,
keeps one 16-byte block and grows a buffer with `realloc`:

```text
live alloc: 2061 ms, allocator /usr/lib/x86_64-linux-gnu/libc.so.6 (1 threads, 0 lost and 0 undecoded records, stop duration)
allocations: 21694 (10526.0/s), 213.1 MiB; frees: 18074 (+1 of blocks from before), reallocs: 1807
live at the end: 36.2 KiB in 1808 blocks allocated while observed
functions by allocations (callees included):
     allocs       bytes        live  function
      18080     1.1 MiB         0 B  target:alloc_row
       1807   212.0 MiB     8.0 KiB  target:grow_buffer
       1807    28.2 KiB    28.2 KiB  target:keep_style
```

## Reading the output

- `allocs` and `bytes` count the blocks allocated while xref observed, by
  `malloc`, `calloc` and `realloc`. A `realloc` that moves a block counts as
  one allocation of the new size. `live` is what those blocks still hold at
  the end.
- Only the outermost allocator call of a thread counts, so glibc's `realloc`,
  which calls `malloc` and `free` inside, is not counted twice.
- A `free` of a block allocated before xref attached is counted separately
  (`of blocks from before`): its size is unknown.
- The allocator is the first mapped file that exports `malloc` and `free`,
  searched in this order: the executable, other libraries (an interposed
  jemalloc or mimalloc), then the C library.

## Limits

- Needs root (uprobes). Every allocator call stops the thread twice (entry
  and return) and copies `--stack-bytes` of stack, so a program that
  allocates millions of times a second slows down while it is observed.
- An allocator without exported symbols, such as Rust's `jemallocator`
  linked statically, cannot be traced; Rust's default system allocator can.
- Libraries loaded during the capture are not unwound.
