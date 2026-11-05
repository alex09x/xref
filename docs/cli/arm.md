# xref arm

Jump-table indices whose arm holds each address (closest preceding arm of every table, best first).

Resolves relative jump tables into variant arm ranges, string literals per arm, reverse instruction-to-arm ownership, and constant error returns.

## Usage

<!-- xref:usage arm -->
```text
xref arm <ADDRS>...
```
<!-- /xref -->

## Arguments and options

<!-- xref:options arm -->
**Arguments**

| Option | Description | Default |
| --- | --- | --- |
| `<ADDRS>...` | Code addresses to place in jump-table arms. |  |
<!-- /xref -->

## Examples

All examples were recorded on public binaries; see [Provenance](#provenance).

### Arm 0xcf3db

Reverse lookup: which jump-table dispatch and variant index owns instruction 0xcf3db.

<!-- xref:run max=40 -->
```console
$ xref -b xref.stripped arm 0xcf3db
```

```text output
0xcf3db  in 0xc7fc0  variant 2 (0x2)  table 0xc06c (dispatch 0xcdc32)  arm 0xce1f1 +0x11ea
0xcf3db  in 0xc7fc0  variant 7 (0x7)  table 0xc058 (dispatch 0xcdcb8)  arm 0xce1dd +0x11fe
0xcf3db  in 0xc7fc0  variant 12 (0xc)  table 0xc044 (dispatch 0xcdd50)  arm 0xce1c9 +0x1212
0xcf3db  in 0xc7fc0  variant 17 (0x11)  table 0xc030 (dispatch 0xc807a)  arm 0xce1b5 +0x1226
0xcf3db  in 0xc7fc0  variant 0 (0x0), 3 (0x3)  table 0xc080 (dispatch 0xcbee4)  arm 0xcc060 +0x337b
```

```stderr
xref: load 471.6µs, total 801.6µs
```
<!-- /xref -->

## Reading the output

- One line per jump table whose arm contains the address: the address, its function, the enum variant indices that dispatch to that arm, the table address, the dispatching instruction and the arm start with the distance from it (`+0x11ea`).
- Tables are listed best match first: the arm that starts closest before the address.

## Limits

- The arm is the nearest preceding table target; an address deep inside shared code can belong to several arms, and all of them are listed.

## Provenance

<!-- xref:provenance -->
Recorded with a development build of xref after 0.4.0 on Linux x86-64, on `xref.stripped` = a stripped xref build (the binary of the home-page examples). Output is unchanged; long outputs are cut where marked.
<!-- /xref -->
