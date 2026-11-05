# xref calls

Calls and tail jumps of the function containing an address, in code order.

Inspects incoming call sites, outgoing direct/PLT calls, and register/stack argument values reaching every call to a target function.

## Usage

<!-- xref:usage calls -->
```text
xref calls <ADDR>
```
<!-- /xref -->

## Arguments and options

<!-- xref:options calls -->
**Arguments**

| Option | Description | Default |
| --- | --- | --- |
| `<ADDR>` | An address inside the function. |  |
<!-- /xref -->

## Examples

All examples were recorded on public binaries; see [Provenance](#provenance).

### Calls 0xa2270

All outgoing direct and PLT calls inside 0xa2270..0xa2566.

<!-- xref:run max=40 -->
```console
$ xref -b xref.stripped calls 0xa2270
```

```text output
function 0xa2270..0xa2566
0xa2406  call 0x126900
0xa2464  call 0x126900
0xa24a0  call 0x126470
0xa24ba  call memcpy via 0x1de5d8
0xa24f1  call 0x1267f0
0xa2500  call 0x126470
0xa2516  call memcpy via 0x1de5d8
0xa2554  call 0x15fe80
0xa2561  call 0x1267c5
9 calls
```

```stderr
xref: load 592.3µs, total 849.7µs
```
<!-- /xref -->

### Calls

<!-- xref:run max=40 -->
```console
$ xref -b xref.stripped calls 0xc7d60
```

```text output
function 0xc7d60..0xc7fbf
0xc7e0b  call 0x160550
0xc7e18  call 0x124d50
0xc7f66  call 0xa5e20
0xc7fba  call 0x160bb0
4 calls
```

```stderr
xref: load 519.7µs, total 738.0µs
```
<!-- /xref -->

### Calls

<!-- xref:run max=40 -->
```console
$ xref -b xref.stripped calls 0x9a8a0
```

```text output
function 0x9a8a0..0x9a97a
0x9a908  call 0xfb8e0
0x9a954  call 0x15ff61
0x9a966  call 0x15ff61
0x9a975  call 0x15ff61
4 calls
```

```stderr
xref: load 580.2µs, total 794.3µs
```
<!-- /xref -->

### Calls

<!-- xref:run max=40 -->
```console
$ xref -b xref.stripped calls 0xfbff0
```

```text output
function 0xfbff0..0xfc159
0xfc12a  call 0x15ff61
0xfc13f  call 0x15ff61
0xfc154  call 0x15ff61
3 calls
```

```stderr
xref: load 429.8µs, total 634.1µs
```
<!-- /xref -->

## Reading the output

- The first line is the function range; then every call and tail jump in code order: instruction address and target.
- Imports are named (`memcpy via 0x1de5d8`: through that GOT slot). `jmp` lines are tail calls.

## Limits

- Indirect calls are listed with their operand only; their targets are not resolved.

## Provenance

<!-- xref:provenance -->
Recorded with a development build of xref after 0.4.0 on Linux x86-64, on `xref.stripped` = a stripped xref build (the binary of the home-page examples). Output is unchanged; long outputs are cut where marked.
<!-- /xref -->
