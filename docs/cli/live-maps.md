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
$ xref -b rg live maps --pid 247604
```

```text output
pid 247604  starttime 1515335484  match verified_sha256  pie_slide +0x786736c00000  alive true  changed false
0x55556ab94000..0x55556ab95000  ---p  off 0x00000000  skipped_non_writable        -       [heap]
0x55556ab95000..0x55556ab96000  rw-p  off 0x00000000  scannable_rwp               -       [heap]
0x786736800000..0x786736c00000  rw-p  off 0x00000000  scannable_rwp               -       [anon]
0x786736c00000..0x786737186000  r-xp  off 0x00000000  skipped_non_writable        target  /srv/xref-docs/rg
0x786737385000..0x78673744b000  rw-p  off 0x00585000  scannable_rwp               target  /srv/xref-docs/rg
0x78673744b000..0x786737497000  rw-p  off 0x00000000  scannable_rwp               -       [anon]
0x786737676000..0x786737677000  ---p  off 0x00000000  skipped_non_writable        -       [anon]
0x786737677000..0x786737679000  rw-p  off 0x00000000  scannable_rwp               -       [anon]
0x786737679000..0x78673767b000  rw-p  off 0x00000000  scannable_rwp               -       [anon]
0x7ffe1fda8000..0x7ffe1fdc9000  rw-p  off 0x00000000  scannable_rwp               -       [stack]
0x7ffe1fdd2000..0x7ffe1fdd6000  r--p  off 0x00000000  skipped_device_or_special   -       [vvar]
0x7ffe1fdd6000..0x7ffe1fdd8000  r-xp  off 0x00000000  skipped_device_or_special   -       [vdso]
0xffffffffff600000..0xffffffffff601000  --xp  off 0x00000000  skipped_device_or_special   -       [vsyscall]
13 regions (7 scannable_rwp)
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
Recorded with xref 0.5.0 (the remapped release build of commit b00d4a14, made by scripts/package-release.sh before the tag) on Linux x86-64, on `rg` = ripgrep 14.1.1 (official stripped release). Live examples ran against one ripgrep process filtering an endless input stream; commands shown with `sudo` ran as root. Output is unchanged except that whitespace at the end of each line and empty lines at the end of the output are removed; long outputs are cut where marked.
<!-- /xref -->
