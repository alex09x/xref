# xref live memscan

Search a running process for a known value: xref scans its private writable
memory (`rw-p`: heap, anonymous mappings, writable data) for consecutive
little-endian `u64` values and prints the words around each hit. Use it to
locate a structure you know a field of, then resolve the pointers next to it
with [`resolve`](live-resolve.md).

## Usage

<!-- xref:usage live memscan -->
```text
xref live memscan [OPTIONS] --pid <PID> <VALUES>...
```
<!-- /xref -->

## Arguments and options

<!-- xref:options live memscan -->
**Arguments**

| Option | Description | Default |
| --- | --- | --- |
| `<VALUES>...` | Consecutive `u64` values (`0x...` hex or decimal) encoded as little-endian bytes. |  |

**Options**

| Option | Description | Default |
| --- | --- | --- |
| `--pid <PID>` | Target process ID (must be non-zero). |  |
| `--align <ALIGN>` | Required byte alignment for matches (`1`, `2`, `4`, or `8`). | `8` |
| `--before-words <BEFORE_WORDS>` | Number of 8-byte words to read before each match (`0..=16`). | `2` |
| `--after-words <AFTER_WORDS>` | Number of 8-byte words to read after each match (`0..=16`). | `6` |
| `--max-hits <MAX_HITS>` | Maximum number of hits before stopping (`1..=1024`). | `32` |
| `--max-bytes <MAX_BYTES>` | Maximum scannable region bytes read before stopping. | `268435456` |
| `--timeout-ms <TIMEOUT_MS>` | Cooperative inter-chunk elapsed-time budget in milliseconds. | `5000` |
| `--force-bin` | Continue even if `--bin` does not match `/proc/<pid>/exe`. |  |
| `--json` | Emit structured `schema_version: 1` JSON output. |  |
<!-- /xref -->

## Examples

The target is ripgrep 14.1.1 (`rg`) filtering an endless input stream, as on
[`live maps`](live-maps.md). PIDs and runtime addresses belong to that run.

### A text in the input buffer

The eight bytes `haystack` read as a little-endian `u64` are
`0x6b63617473796168`:

<!-- xref:run max=24 -->
```console
$ sudo xref -b rg live memscan --pid 247604 0x6b63617473796168 --max-hits 2
```

```text output
pid 247604  starttime 1515335484  match verified_sha256  pie_slide +0x786736c00000  alive true  changed false
needle 0x686179737461636b  align 8  elapsed 0ms  regions 2/8  bytes 0x81000  unreadable 0  stop max_hits  hits 2
hit 0x78673685f000  [anon@0x786736800000]+0x5f000
   -0x10  0x000078673685eff0  0x0000000000000000  scalar
    -0x8  0x000078673685eff8  0x0000000000000000  scalar
     0x0* 0x000078673685f000  0x6b63617473796168  scalar
    +0x8  0x000078673685f008  0x697720656e696c20  scalar
   +0x10  0x000078673685f010  0x65656e2061206874  scalar
   +0x18  0x000078673685f018  0x69206e6920656c64  scalar
   +0x20  0x000078673685f020  0x6174737961680a74  scalar
   +0x28  0x000078673685f028  0x20656e696c206b63  scalar
   +0x30  0x000078673685f030  0x6e20612068746977  scalar
hit 0x78673685f088  [anon@0x786736800000]+0x5f088
   -0x10  0x000078673685f078  0x6c6465656e206120  scalar
    -0x8  0x000078673685f080  0x0a7469206e692065  scalar
     0x0* 0x000078673685f088  0x6b63617473796168  scalar
    +0x8  0x000078673685f090  0x697720656e696c20  scalar
   +0x10  0x000078673685f098  0x65656e2061206874  scalar
   +0x18  0x000078673685f0a0  0x69206e6920656c64  scalar
   +0x20  0x000078673685f0a8  0x6174737961680a74  scalar
   +0x28  0x000078673685f0b0  0x20656e696c206b63  scalar
   +0x30  0x000078673685f0b8  0x6e20612068746977  scalar
```
<!-- /xref -->

## Reading the output

- The second line is the scan summary: the needle as stored in memory, the
  alignment, how many regions and bytes were read, and why the scan stopped
  (`max_hits`, `max_bytes`, the time budget, or the end of memory).
- Each `hit` gives the runtime address and the region it is in; the rows under
  it are the words before and after (`*` marks the hit), each with its address,
  value and a classification: `scalar`, or a pointer into the binary, heap or
  stack.

## Limits

- Reading another process's memory needs ptrace access: same user with Yama
  `ptrace_scope` 0, the target's permission, or root. This recording used
  `sudo`.
- The scan is a snapshot; memory can change while it runs.

## Provenance

<!-- xref:provenance -->
Recorded with xref 0.5.0 (the remapped release build of commit b00d4a14, made by scripts/package-release.sh before the tag) on Linux x86-64, on `rg` = ripgrep 14.1.1 (official stripped release). Live examples ran against one ripgrep process filtering an endless input stream; commands shown with `sudo` ran as root. Output is unchanged except that whitespace at the end of each line and empty lines at the end of the output are removed; long outputs are cut where marked.
<!-- /xref -->
