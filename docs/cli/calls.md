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
xref: load 616.2µs, total 941.6µs
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
xref: load 577.2µs, total 889.0µs
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
xref: load 492.8µs, total 800.2µs
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
xref: load 576.2µs, total 844.6µs
```
<!-- /xref -->

## Reading the output

- The first line is the function range; then every call and tail jump in code order: instruction address and target.
- Imports are named (`memcpy via 0x1de5d8`: through that GOT slot). `jmp` lines are tail calls.
- An indirect call through constant records (a trait object's vtable chosen by branch) ends with its possible targets: `-> {0x1150 (when eax == 0xa), 0x11a0} via 5 records +0x18`. [`table`](table.md) dumps the records.

## Limits

- An indirect call is resolved only through constant records whose address is set in the same function (see [`table`](table.md)); a call through a register loaded any other way is listed with its operand only.

## Provenance

<!-- xref:provenance -->
Recorded with xref 0.5.0 (the remapped release build of commit b00d4a14, made by scripts/package-release.sh before the tag) on Linux x86-64, on `xref.stripped` = a stripped xref build (the binary of the home-page examples). Output is unchanged except that whitespace at the end of each line and empty lines at the end of the output are removed; long outputs are cut where marked.
<!-- /xref -->
