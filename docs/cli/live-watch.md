# xref live watch

Catch the instruction that writes a field: xref sets x86 hardware data
watchpoints (`DR0`–`DR3`, up to four addresses of 1–8 bytes) on a running
process and attributes every store to its instruction, function and static
address. `--follow` re-arms the watch when a pointer-backed buffer moves (for
example after a `Vec` grows).

## Usage

<!-- xref:usage live watch -->
```text
xref live watch [OPTIONS] --pid <PID> [ADDR]...
```
<!-- /xref -->

## Arguments and options

<!-- xref:options live watch -->
**Arguments**

| Option | Description | Default |
| --- | --- | --- |
| `[ADDR]...` | Target static or runtime data addresses (`0x...` hex or decimal, sharing `1..=4` total `DR0`–`DR3` slots). |  |

**Options**

| Option | Description | Default |
| --- | --- | --- |
| `--pid <PID>` | Target process ID (must be non-zero). |  |
| `--len <LEN>` | Hardware watchpoint length in bytes (`1`, `2`, `4`, or `8`). | `8` |
| `--access <ACCESS>` | Hardware breakpoint access mode (`write` or `rw`). Values: `write` (Hardware write watchpoint (`HW_BREAKPOINT_W`)); `rw` (Hardware read-or-write watchpoint (`HW_BREAKPOINT_RW`)). | `write` |
| `--regs` | Include raw 16-GPR `PERF_SAMPLE_REGS_INTR` snapshot in per-hit samples. |  |
| `--duration-ms <DURATION_MS>` | Observation window duration in milliseconds (`0..=60000`); `0` runs until --max-events, target exit, or SIGINT/SIGTERM, which still print the full report. | `1000` |
| `--heartbeat-ms <MS>` | Periodic stderr heartbeat with the running hit count, in milliseconds (`1..=60000`). |  |
| `--arm-at <CODE_VA>` | Attach the watchpoints only after this code address (static or runtime) first runs. |  |
| `--max-events <MAX_EVENTS>` | Maximum accepted watch events before stopping (`1..=65536`; default 4096, unlimited with `--duration-ms 0`). |  |
| `--max-samples <MAX_SAMPLES>` | Per-hit samples kept per watch (`1..=65536`); every accepted hit still counts toward its writer site, which also reports the least and greatest written value. | `32` |
| `--value-range <LO> <HI>` | Keep a sample only when its recovered written value is in `[LO, HI)`; a hit whose value could not be recovered is kept with its trap registers. |  |
| `--json-lines` | Print every hit passing --value-range as one JSON line when it happens (also past --max-samples); the last line is the full report. |  |
| `--force-bin` | Continue even if `--bin` does not match `/proc/<pid>/exe`. |  |
| `--json` | Emit structured `schema_version: 1` JSON output. |  |
| `--follow <SPEC>` | Follow a pointer-backed dependent watch (`ptr_slot=<ADDR>[,offset=<OFF>][,len_slot=<ADDR>,min_len=<BYTES>][,guard_slot=<ADDR>,guard_val=<U64>][,header_ptr_slot=<ADDR>,header_offset=<OFF>]`). |  |
<!-- /xref -->

## Examples

```sh
# Who writes the 8 bytes at this runtime address during the next second?
sudo xref -b app live watch --pid 1234 0x7f3a1c02a048 --duration-ms 1000
# Follow a field of a growable buffer: re-arm when the pointer in ptr_slot changes.
sudo xref -b app live watch --pid 1234 --follow ptr_slot=0x7f3a1c02a010,offset=0x8
# A field written millions of times, where one rare writer stores a large value:
sudo xref -b app live watch --pid 1234 0x7f3a1c02a048 --duration-ms 10000 \
  --max-events 65536 --value-range 0x100000000 0xffffffffffffffff --max-samples 256 --json-lines
# Watch for a whole run, arming after the function that creates the object has run;
# every hit is a JSON line as it happens, Ctrl-C prints the full report:
sudo xref -b app live watch --pid 1234 0x7f3a1c02a048 --duration-ms 0 --arm-at 0x401230 \
  --heartbeat-ms 10000 --json-lines > watch.jsonl
```

### Rare writes in a busy field

Every accepted hit counts toward its writer site, and each site reports the
least and greatest value it wrote (`values 0x1..=0x40` in the table,
`written_min`/`written_max` in JSON) when xref could recover the stored value
from the instruction and its registers. That alone often points at the writer
that stores the unusual value.

Per-hit samples are kept for the first `--max-samples` hits (32 by default).
`--value-range LO HI` keeps only samples whose recovered value is in
`[LO, HI)`; a hit whose value could not be recovered is kept with its trap
registers. The watch line counts the hits left out (`value_filtered N`,
`samples_value_filtered` in JSON). `--json-lines` prints every hit that passes
`--value-range` as one JSON line (`{"watch": "0x...", "sample": {...}}`) as it
happens, also past `--max-samples` (bounded by `--max-events`), and the last
line is the full report (`{"report": {...}}`) with the first `--max-samples`.

### Whole-run sessions

`--duration-ms 0` keeps the watch on until `--max-events` (unlimited unless
given), the target exits, or xref gets SIGINT or SIGTERM; each of these still
prints the full report, and a second signal ends xref at once. With
`--json-lines` every hit is written and flushed as it happens, so a session
that is killed keeps every earlier hit. `--heartbeat-ms N` writes
`xref: heartbeat hits H  alive true  armed true  last_hit_age 812ms` to stderr
every N ms.

`--arm-at CODE_VA` holds the watchpoints back until that instruction first
runs in any thread (a uprobe counter per thread), for example the end of the
function that allocates the watched object. The watched addresses and
`--follow` chains are resolved and read only then, so the address may be in
memory mapped by the code before it. The report's `arm` object says
whether and after how many milliseconds the watch was armed. A write in the
few milliseconds between that execution and the attach is not seen.

A recorded session, including a watch that follows a moved buffer, is in the
[Live Analysis walkthrough](../live-walkthrough.md). It is not recorded on
ripgrep here: ripgrep's input buffer is filled by the kernel's `read`, and
hardware watchpoints only report stores made by the process's own code.

## Limits

- Needs privileged perf access (root, or capabilities and
  `kernel.perf_event_paranoid` settings that allow it).
- At most four watched addresses (the CPU has four debug registers).
- Writes made by the kernel (system calls such as `read`) are not reported.
