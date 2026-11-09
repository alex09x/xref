# xref args

Constant and symbolic arguments at every call site of a function (rdi..r9 and stack0..N).

Inspects incoming call sites, outgoing direct/PLT calls, and register/stack argument values reaching every call to a target function.

## Usage

<!-- xref:usage args -->
```text
xref args [OPTIONS] <ADDR>
```
<!-- /xref -->

## Arguments and options

<!-- xref:options args -->
**Arguments**

| Option | Description | Default |
| --- | --- | --- |
| `<ADDR>` | Function address or symbol name. |  |

**Options**

| Option | Description | Default |
| --- | --- | --- |
| `--max <MAX>` | Maximum number of stack argument slots to inspect. | `4` |
| `--filter <FILTER>` | Filter predicate to preflight against call-site arguments (e.g. "rdx == 0"). |  |
<!-- /xref -->

## Examples

All examples were recorded on public binaries; see [Provenance](#provenance).

### Args 0xa2270

Constant, register, and stack-slot argument provenance across all 8 call sites of 0xa2270.

<!-- xref:run max=40 -->
```console
$ xref -b xref.stripped args 0xa2270
```

```text output
0x909e6  in 0x8ff70..0x91c10  rdi=&rsp[0x128] (dynamic)  rsi=u64 [rsp+0x18]  rdx=mem (dynamic)  r9=mem (dynamic)  stack0=mem (dynamic)  stack1=rax (dynamic)  stack2=mem (dynamic)  stack3=mem (dynamic)
0xbf061  in 0xbeed0..0xbf10d  rdi=&rsp[0x68] (dynamic)  rsi=0x14eb7  rdx=r8  r8=mem (dynamic)  stack0=mem (dynamic)  stack1=&rsp[0x48] (dynamic)  stack2=0x161260  stack3=rcx (dynamic)
0xc063a  in 0xbff20..0xc128e  rdi=&rsp[0x10] (dynamic)  rdx=mem (dynamic)  r8=0  stack2=&rsp[0x68] (dynamic)  stack3=0x162bb0
0xc0723  in 0xbff20..0xc128e  rdi=&rsp[0x10] (dynamic)  rcx=0x2fc52  stack2=mem (dynamic)  stack3=mem (dynamic)
0xe84f2  in 0xd7740..0xf13ff  rdi=&rsp[0x1b0] (dynamic)  rsi=u64 [rsp+0x8]  rdx=u64 [rax+0x8]  stack0=0  stack1=rcx (dynamic)  stack2=mem (dynamic)  stack3=8
0xe85b1  in 0xd7740..0xf13ff  rdi=&rsp[0xf0] (dynamic)  rsi=u64 [rsp+0x8]  stack0=0  stack1=rcx (dynamic)  stack2=mem (dynamic)  stack3=8
0xe91c6  in 0xd7740..0xf13ff  rdi=&rsp[0x90] (dynamic)  rsi=u64 [rsp+0x8]  rdx=mem (dynamic)  stack0=0  stack1=mem (dynamic)  stack2=8  stack3=mem (dynamic)
0xecca0  in 0xd7740..0xf13ff  rdi=&rsp[0xf0] (dynamic)  rsi=u64 [rsp+0x8]  rdx=mem (dynamic)  rcx=rcx (dynamic)  r8=r8 (dynamic)  r9=mem (dynamic)  stack0=0  stack1=8  stack2=0  stack3=mem (dynamic)
8 call sites
```

```stderr
xref: load 1.9ms, total 14.2ms
```
<!-- /xref -->

### Args

<!-- xref:run max=40 -->
```console
$ xref -b xref.stripped args 0xc7d60
```

```text output
0xb3955  in 0xb38a0..0xb3efe  rdi=&rsp[0x48] (dynamic)  rsi=u64 [r9+0x48]  rdx=u64 [r9+0x50]  stack0=rax (dynamic)
0xba676  in 0xb43a0..0xbb5da  rdi=rbx  rsi=u64 [r12+0x48]  rdx=u64 [r12+0x50]  stack0=mem (dynamic)  stack2=rdi (dynamic)  stack3=mem (dynamic)
0xbae1a  in 0xb43a0..0xbb5da  rdi=r14  rsi=u64 [r12+0x48]  rdx=u64 [r12+0x50]  stack0=mem (dynamic)  stack2=8  stack3=rbp (dynamic)
0xc8157  in 0xc7fc0..0xd0a9d  rdi=&rsp[0x10] (dynamic)  rsi=u64 [rbp+0x48]  rdx=u64 [rbp+0x50]  stack0=mem (dynamic)
0xc9928  in 0xc7fc0..0xd0a9d  rdi=r15  rsi=u64 [rax+0x48]  rdx=u64 [rax+0x50]  stack0=rax (dynamic)  stack1=mem (dynamic)  stack2=rax (dynamic)  stack3=rax (dynamic)
0xd58e2  in 0xd57c0..0xd6301  rdi=&rsp[0x70] (dynamic)  rsi=u64 [r14+0x48]  rdx=u64 [r14+0x50]  stack1=mem (dynamic)  stack2=rax (dynamic)  stack3=rdx (dynamic)
6 call sites
```

```stderr
xref: load 895.4µs, total 3.1ms
```
<!-- /xref -->

### Args

<!-- xref:run max=40 -->
```console
$ xref -b xref.stripped args 0x9a8a0
```

```text output
0xb9b64  in 0xb43a0..0xbb5da  rdi=&rsp[0x1c0] (dynamic)  rsi=r13  rdx=u64 [rsp+0x30]  stack2=rdi (dynamic)  stack3=mem (dynamic)
1 call sites
```

```stderr
xref: load 698.4µs, total 2.7ms
```
<!-- /xref -->

### Args

<!-- xref:run max=40 -->
```console
$ xref -b xref.stripped args 0xfbff0
```

```text output
0xb6ef4  in 0xb43a0..0xbb5da  rdi=&rsp[0xf0] (dynamic)  rdx=rdx (dynamic)  rcx=u64 [rsp+0x38]  stack2=mem (dynamic)  stack3=rax (dynamic)
0xb6f8e  in 0xb43a0..0xbb5da  rdi=&rsp[0x60] (dynamic)  stack2=mem (dynamic)  stack3=rax (dynamic)
2 call sites
```

```stderr
xref: load 632.1µs, total 2.8ms
```
<!-- /xref -->

## Reading the output

- One line per call site of the function: the call instruction, the caller's range, then each argument register (`rdi`…`r9`) and stack argument (`stack0`…) with what xref could resolve.
- A constant is printed as its value (`rsi=0x14eb7`); `&rsp[0x68]` is the address of a caller stack slot; `u64 [rsp+0x18]` is a value loaded from memory; `r8` means the argument is copied from another register.
- `(dynamic)` marks a value computed at run time that xref could not reduce further; `mem` is a load it could not name.
- The last line counts the call sites.

## Limits

- Only direct calls and tail jumps are found; indirect calls through pointers are not listed.
- Stack arguments are decoded from the slots the caller writes before the call; for callees that take six or fewer register arguments the `stack*` entries can be unrelated values.

## Provenance

<!-- xref:provenance -->
Recorded with xref 0.5.0 (the remapped release build of commit b00d4a14, made by scripts/package-release.sh before the tag) on Linux x86-64, on `xref.stripped` = a stripped xref build (the binary of the home-page examples). Output is unchanged except that whitespace at the end of each line and empty lines at the end of the output are removed; long outputs are cut where marked.
<!-- /xref -->
