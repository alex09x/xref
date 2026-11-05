# xref callers

Direct calls and jumps to an address, and code taking its address or loading a slot holding it.

Inspects incoming call sites, outgoing direct/PLT calls, and register/stack argument values reaching every call to a target function.

## Usage

<!-- xref:usage callers -->
```text
xref callers [OPTIONS] <ADDR>
```
<!-- /xref -->

## Arguments and options

<!-- xref:options callers -->
**Arguments**

| Option | Description | Default |
| --- | --- | --- |
| `<ADDR>` | Address whose callers and references to list. |  |

**Options**

| Option | Description | Default |
| --- | --- | --- |
| `--with-observed <WITH_OBSERVED>` | Explicit observed-edge store tied to this binary; sample counts are not call counts. |  |
<!-- /xref -->

## Examples

All examples were recorded on public binaries; see [Provenance](#provenance).

### Callers 0xc7d60

All 6 call sites invoking 0xc7d60 across the stripped binary.

<!-- xref:run max=40 -->
```console
$ xref -b xref.stripped callers 0xc7d60
```

```text output
branches
0xb3955  in 0xb38a0  call 0xc7d60
0xba676  in 0xb43a0  call 0xc7d60
0xbae1a  in 0xb43a0  call 0xc7d60
0xc8157  in 0xc7fc0  call 0xc7d60
0xc9928  in 0xc7fc0  call 0xc7d60
0xd58e2  in 0xd57c0  call 0xc7d60
6 hits
address taken
0 hits
```

```stderr
xref: load 649.7µs, total 2.9ms
```
<!-- /xref -->

### Callers

<!-- xref:run max=40 -->
```console
$ xref -b xref.stripped callers 0x9a8a0
```

```text output
branches
0xb9b64  in 0xb43a0  call 0x9a8a0
1 hits
address taken
0 hits
```

```stderr
xref: load 546.6µs, total 2.6ms
```
<!-- /xref -->

### Callers

<!-- xref:run max=40 -->
```console
$ xref -b xref.stripped callers 0xfbff0
```

```text output
branches
0xb6ef4  in 0xb43a0  call 0xfbff0
0xb6f8e  in 0xb43a0  call 0xfbff0
2 hits
address taken
0 hits
```

```stderr
xref: load 630.2µs, total 2.9ms
```
<!-- /xref -->

### Callers

<!-- xref:run max=40 -->
```console
$ xref -b xref.stripped callers 0xa2270
```

```text output
branches
0x909e6  in 0x8ff70  call 0xa2270
0xbf061  in 0xbeed0  call 0xa2270
0xc063a  in 0xbff20  call 0xa2270
0xc0723  in 0xbff20  call 0xa2270
0xe84f2  in 0xd7740  call 0xa2270
0xe85b1  in 0xd7740  call 0xa2270
0xe91c6  in 0xd7740  call 0xa2270
0xecca0  in 0xd7740  call 0xa2270
8 hits
address taken
0 hits
```

```stderr
xref: load 534.0µs, total 2.8ms
```
<!-- /xref -->

## Reading the output

- `branches`: direct `call`/`jmp` instructions to the address, each with the containing function.
- `address taken`: code that loads the address itself (`lea`), for example to pass a callback.
- `pointer slots`: data slots holding the address (vtables, function tables) and the code that loads those slots.
- Each section ends with its hit count.

## Limits

- A call through a pointer computed at run time is found only when the pointer comes from a slot or `lea` xref can see; dynamically built pointers are not.
- For callers across builds use [`match`](match.md); for whole chains use [`path`](path.md) and [`tree`](tree.md).

## Provenance

<!-- xref:provenance -->
Recorded with a development build of xref after 0.4.0 on Linux x86-64, on `xref.stripped` = a stripped xref build (the binary of the home-page examples). Output is unchanged; long outputs are cut where marked.
<!-- /xref -->
