# xref path

Shortest call chains from function FROM to function TO over direct calls, tail jumps and pointer slots.

Finds shortest call chains between two functions and prints indented caller/callee trees annotated with panic source locations.

## Usage

<!-- xref:usage path -->
```text
xref path [OPTIONS] <FROM> <TO>
```
<!-- /xref -->

## Arguments and options

<!-- xref:options path -->
**Arguments**

| Option | Description | Default |
| --- | --- | --- |
| `<FROM>` | Function where chains start (address or symbol name). |  |
| `<TO>` | Function where chains end (address or symbol name). |  |

**Options**

| Option | Description | Default |
| --- | --- | --- |
| `--depth <DEPTH>` | Maximum call-chain depth (hops). | `8` |
| `--with-observed <WITH_OBSERVED>` | Explicit observed-edge store tied to this binary; sample counts are not call counts. |  |
<!-- /xref -->

## Examples

All examples were recorded on public binaries; see [Provenance](#provenance).

### Path 0xc7fc0 0x160bb0

Shortest call chains from 0xc7fc0 to 0x160bb0 with exact call-site addresses.

<!-- xref:run max=40 -->
```console
$ xref -b xref.stripped path 0xc7fc0 0x160bb0
```

```text output
0xc7fc0 -> 0x160bb0  (via 0xcf3cc)
0xc7fc0 -> 0xc7d60 -> 0x160bb0  (via 0xc8157, 0xc7fba)
0xc7fc0 -> 0xb43a0 -> 0x160bb0  (via 0xcea2e, 0xbafa7)
0xc7fc0 -> 0xc7d60 -> 0x124d50 -> 0x160bb0  (via 0xc8157, 0xc7e18, 0x124e0c)
0xc7fc0 -> 0x123950 -> 0x124d50 -> 0x160bb0  (via 0xcd2ae, 0x123b30, 0x124e0c)
0xc7fc0 -> 0xb43a0 -> 0xd5120 -> 0x160bb0  (via 0xcea2e, 0xb51e7, 0xd52b4)
0xc7fc0 -> 0xb43a0 -> 0xb3f00 -> 0x160bb0  (via 0xcea2e, 0xb7d23, 0xb41f6)
0xc7fc0 -> 0xb43a0 -> 0xc7d60 -> 0x160bb0  (via 0xcea2e, 0xba676, 0xc7fba)
8 paths
```

```stderr
xref: load 1.9ms, total 5.0ms
```
<!-- /xref -->

## Reading the output

- One line per call chain from FROM to TO, shortest first, with the call sites that make each hop (`via …`). The last line counts the paths.
- With `0 paths`, the next lines say how many functions are reachable from FROM within
  `--depth` - 1 hops and how many indirect calls in them have no static target (`call [rax+0x20]`
  through a dyn-trait vtable, a closure or a function pointer), nearest first with their hop. Any
  of them can lead to TO, so `0 paths` then means "no chain xref can see", not "unreachable".
- After that, the other side: how many functions reach TO within `--depth` hops, and which of
  them can be entered indirectly at all, because their address is taken (held in a pointer slot
  or vtable record that code reads as data or that is never named directly, or loaded by code with
  `lea`). Slots that code only calls through are already followed as edges and are not listed.
  With no such entry, no chain of that depth exists; otherwise each entry names the slot or the
  code that takes its address, and `xref callers ENTRY` shows who.

## Limits

- Chains use direct calls, tail jumps and pointer slots xref can see, including a register
  loaded from a slot and called later (`mov r12, [slot]` ... `call r12`, with no write to the
  register in between, in code order). Calls through run-time pointers can hide a path; the
  `0 paths` report lists them.
- `--depth` bounds the chain length.

## Provenance

<!-- xref:provenance -->
Recorded with a development build of xref after 0.5.0 (path: unfollowed indirect calls) on Linux x86-64, on `xref.stripped` = a stripped xref build (the binary of the home-page examples). Output is unchanged except that whitespace at the end of each line and empty lines at the end of the output are removed; long outputs are cut where marked.
<!-- /xref -->
