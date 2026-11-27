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
live alloc: 2069 ms, allocator /usr/lib/x86_64-linux-gnu/libc.so.6 (1 threads, 0 unattached, 0 lost and 0 undecoded records, stop duration)
allocations: 21467 (10375.5/s), 211.1 MiB; frees: 17890 (0 of blocks from before), reallocs: 1788
live at the end: 29.0 KiB in 1790 blocks allocated while observed
functions by allocations (callees included):
     allocs       bytes        live  function
      17890     1.1 MiB         0 B  target:alloc_row
       1789    28.0 KiB    28.0 KiB  target:keep_style
       1788   210.0 MiB     1.0 KiB  target:grow_buffer
```

## Reading the output

- `allocs` and `bytes` count the blocks allocated while xref observed, by
  `malloc`, `calloc` and `realloc`. A `realloc` that moves a block counts as
  one allocation of the new size. `live` is what those blocks still hold at
  the end.
- Only the outermost allocator call of a thread counts, so glibc's `realloc`,
  which calls `malloc` and `free` inside, is not counted twice.
- `frees` counts `free` calls; those of blocks allocated before xref attached
  (`of blocks from before`) are part of it, with an unknown size. A block
  moved by `realloc` is not a `free`.
- The function table lists functions of the program and of its libraries,
  the allocator's own file left out, by the allocations under them.
- `profile report` prints `alloc.xprof` as bytes allocated and `live.xprof` as
  bytes still allocated; `profile diff` compares two recordings of the same
  kind.
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
