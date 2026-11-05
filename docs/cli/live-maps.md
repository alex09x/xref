# xref live maps

Show the memory map of a running Linux process and check it against the
binary passed with `-b`: the executable must be the one that is running
(compared by SHA-256), and xref computes the PIE slide that links runtime
addresses to static ones. Every other `live` command starts with the same
check. Linux x86-64 only.

## Usage

<!-- xref:usage live maps -->
```text
xref live maps [OPTIONS] --pid <PID>
```
<!-- /xref -->

## Arguments and options

<!-- xref:options live maps -->
**Options**

| Option | Description | Default |
| --- | --- | --- |
| `--pid <PID>` | Target process ID (must be non-zero). |  |
| `--force-bin` | Continue even if `--bin` does not match `/proc/<pid>/exe`. |  |
| `--json` | Emit structured `schema_version: 1` JSON output. |  |
<!-- /xref -->

## Examples

The target is ripgrep 14.1.1 (`rg`, the official stripped release) running as
`yes "haystack line with a needle in it" | rg --line-buffered needle > /dev/null`:
a public binary kept busy by an endless input stream. PIDs and runtime
addresses belong to that run; ASLR changes them on every start.

### Map of a running ripgrep

<!-- xref:run max=20 -->
```console
$ xref -b rg live maps --pid 4060909
```

```text output
pid 4060909  starttime 1480802351  match verified_sha256  pie_slide +0x77d9cd600000  alive true  changed false
0x55559418f000..0x555594190000  ---p  off 0x00000000  skipped_non_writable        -       [heap]
0x555594190000..0x555594191000  rw-p  off 0x00000000  scannable_rwp               -       [heap]
0x77d9cd200000..0x77d9cd600000  rw-p  off 0x00000000  scannable_rwp               -       [anon]
0x77d9cd600000..0x77d9cdb86000  r-xp  off 0x00000000  skipped_non_writable        target  /home/alex09x/xref-docs/rg
0x77d9cdd85000..0x77d9cde4b000  rw-p  off 0x00585000  scannable_rwp               target  /home/alex09x/xref-docs/rg
0x77d9cde4b000..0x77d9cde97000  rw-p  off 0x00000000  scannable_rwp               -       [anon]
0x77d9cdf7b000..0x77d9cdf7c000  ---p  off 0x00000000  skipped_non_writable        -       [anon]
0x77d9cdf7c000..0x77d9cdf7e000  rw-p  off 0x00000000  scannable_rwp               -       [anon]
0x77d9cdf7e000..0x77d9cdf80000  rw-p  off 0x00000000  scannable_rwp               -       [anon]
0x7fff26295000..0x7fff262b6000  rw-p  off 0x00000000  scannable_rwp               -       [stack]
0x7fff263f5000..0x7fff263f9000  r--p  off 0x00000000  skipped_device_or_special   -       [vvar]
0x7fff263f9000..0x7fff263fb000  r-xp  off 0x00000000  skipped_device_or_special   -       [vdso]
0x7fffffffe000..0x7ffffffff000  --xp  off 0x00000000  skipped_non_writable        -       [uprobes]
0xffffffffff600000..0xffffffffff601000  --xp  off 0x00000000  skipped_device_or_special   -       [vsyscall]
14 regions (7 scannable_rwp)
```
<!-- /xref -->

## Reading the output

- The header: PID, its kernel start time (so a recycled PID is detected),
  `match verified_sha256` (the running executable is the file given with
  `-b`), the PIE slide, and whether the process is alive and unchanged.
- One line per mapping: range, permissions, file offset, its class for
  [`memscan`](live-memscan.md) (`scannable_rwp` is private writable memory,
  `skipped_*` everything else), `target` for mappings of the binary, and the
  path or kind (`[heap]`, `[stack]`, `[anon]`).

## Limits

- Reads `/proc/<pid>/maps` and `smaps`: same user as the target, or root.
- A binary that does not match the running executable is refused unless
  `--force-bin` is given.

## Provenance

<!-- xref:provenance -->
Recorded with a development build of xref after 0.4.0 on Linux x86-64, on `rg` = ripgrep 14.1.1 (official stripped release). Live examples ran against one ripgrep process filtering an endless input stream; commands shown with `sudo` ran as root. Output is unchanged; long outputs are cut where marked.
<!-- /xref -->
