# xref asm

Annotated disassembly of the function containing an address.

## Usage

<!-- xref:usage asm -->
```text
xref asm [OPTIONS] <ADDR>
```
<!-- /xref -->

## Arguments and options

<!-- xref:options asm -->
**Arguments**

| Option | Description | Default |
| --- | --- | --- |
| `<ADDR>` | An address inside the function. |  |

**Options**

| Option | Description | Default |
| --- | --- | --- |
| `--from <FROM>` | First address to print. |  |
| `--to <TO>` | End address (exclusive). |  |
<!-- /xref -->

## Examples

All examples were recorded on public binaries; see [Provenance](#provenance).

### Full ASM

<!-- xref:run max=40 -->
```console
$ xref -b xref.stripped asm 0xc7d60
```

```asm output
function 0xc7d60..0xc7fbf
0xc7d60  push rbp
0xc7d61  push r15
0xc7d63  push r14
0xc7d65  push r13
0xc7d67  push r12
0xc7d69  push rbx
0xc7d6a  sub rsp, 0xa8
0xc7d71  mov [rsp+0x20], rdi
0xc7d76  mov qword ptr [rsp], 0
0xc7d7e  mov qword ptr [rsp+8], 8
0xc7d87  mov qword ptr [rsp+0x10], 0
0xc7d90  test rdx, rdx
0xc7d93  je 0xc7f7a
0xc7d99  mov r14, rsi
0xc7d9c  lea rax, [rdx+rdx*2]
0xc7da0  lea r15, [rsi+rax*8]
0xc7da4  mov eax, 8
0xc7da9  mov [rsp+0x18], rax
0xc7dae  xor r13d, r13d
0xc7db1  lea r12, [rsp+0x40]
0xc7db6  jmp short 0xc7ded
0xc7db8  xor ebx, ebx
0xc7dba  cmp r13, [rsp]
0xc7dbe  je 0xc7f63
0xc7dc4  mov rax, [rsp+0x18]
0xc7dc9  mov [rax+r13*8], rbx
0xc7dcd  inc r13
0xc7dd0  mov [rsp+0x10], r13
0xc7dd5  nop [rax+rax]
0xc7de0  add r14, 0x18
0xc7de4  cmp r14, r15
0xc7de7  je 0xc7f7a
0xc7ded  mov rbx, [r14+8]
0xc7df1  mov rbp, [r14+0x10]
0xc7df5  mov r8d, 7
0xc7dfb  mov rdi, r12
0xc7dfe  mov rsi, rbx
0xc7e01  mov rdx, rbp
0xc7e04  lea rcx, [0x150e7]                               ; "goto L_while (->"
```
*Output cut here: lines 1–40 of 159 shown.*

```stderr
xref: load 420.0µs, total 1.0ms
```
<!-- /xref -->

### Full ASM

<!-- xref:run max=40 -->
```console
$ xref -b xref.stripped asm 0x9a8a0
```

```asm output
function 0x9a8a0..0x9a97a
0x9a8a0  push r15
0x9a8a2  push r14
0x9a8a4  push rbx
0x9a8a5  sub rsp, 0x40
0x9a8a9  test rsi, rsi
0x9a8ac  je short 0x9a91a
0x9a8ae  mov rax, [rdi+8]
0x9a8b2  cmp rsi, rax
0x9a8b5  jae 0x9a947
0x9a8bb  mov rax, [rdi]
0x9a8be  cmp qword ptr [rax+rsi*8], 1
0x9a8c3  jne short 0x9a91a
0x9a8c5  mov rax, [rdi+0x10]
0x9a8c9  mov r14, [rdi+0x18]
0x9a8cd  mov rdi, [rax]
0x9a8d0  lea rax, [rdi+2]
0x9a8d4  cmp rsi, rax
0x9a8d7  jne short 0x9a91e
0x9a8d9  inc rdi
0x9a8dc  mov rbx, [r14+0x10]
0x9a8e0  cmp rdi, rbx
0x9a8e3  jae 0x9a96b
0x9a8e9  mov r15, rsi
0x9a8ec  lea rdi, [rdi+rdi*2]
0x9a8f0  shl rdi, 5
0x9a8f4  add rdi, [r14+8]
0x9a8f8  mov [rsp+8], rdx
0x9a8fd  mov qword ptr [rsp], 1
0x9a905  mov rsi, rsp
0x9a908  call 0xfb8e0                                     ; 0xfb8e0
0x9a90d  mov ecx, eax
0x9a90f  mov al, 1
0x9a911  test cl, cl
0x9a913  mov rsi, r15
0x9a916  je short 0x9a922
0x9a918  jmp short 0x9a93d
0x9a91a  xor eax, eax
0x9a91c  jmp short 0x9a93d
0x9a91e  mov rbx, [r14+0x10]
```
*Output cut here: lines 1–40 of 64 shown.*

```stderr
xref: load 457.0µs, total 1.0ms
```
<!-- /xref -->

### Full ASM

<!-- xref:run max=40 -->
```console
$ xref -b xref.stripped asm 0xfbff0
```

```asm output
function 0xfbff0..0xfc159
0xfbff0  push r15
0xfbff2  push r14
0xfbff4  push r12
0xfbff6  push rbx
0xfbff7  push rax
0xfbff8  mov r9, [rdi]
0xfbffb  mov r10, [rdi+8]
0xfbfff  cmp r9, r10
0xfc002  je 0xfc10f
0xfc008  mov r11, [rdi+0x10]
0xfc00c  mov rbx, [rdi+0x18]
0xfc010  mov rax, [r11]
0xfc013  mov r14, [rax+8]
0xfc017  mov rsi, [rax+0x10]
0xfc01b  jmp short 0xfc039
0xfc01d  inc rcx
0xfc020  cmp rcx, r8
0xfc023  jb 0xfc10a
0xfc029  nop [rax]
0xfc030  cmp r9, r10
0xfc033  je 0xfc108
0xfc039  mov rdx, [r9]
0xfc03c  add r9, 0x20
0xfc040  test rsi, rsi
0xfc043  je short 0xfc030
0xfc045  cmp rsi, 1
0xfc049  jne short 0xfc050
0xfc04b  xor ecx, ecx
0xfc04d  jmp short 0xfc086
0xfc04f  nop
0xfc050  mov rax, rsi
0xfc053  xor ecx, ecx
0xfc055  nop [rax+rax]
0xfc060  mov r8, rcx
0xfc063  mov r15, rax
0xfc066  shr r15, 1
0xfc069  add rcx, r15
0xfc06c  lea r12, [rcx+rcx*2]
0xfc070  shl r12, 5
```
*Output cut here: lines 1–40 of 104 shown.*

```stderr
xref: load 463.5µs, total 1.1ms
```
<!-- /xref -->

### Full ASM

<!-- xref:run max=40 -->
```console
$ xref -b xref.stripped asm 0xa2270
```

```asm output
function 0xa2270..0xa2566
0xa2270  push r15
0xa2272  push r14
0xa2274  push r12
0xa2276  push rbx
0xa2277  sub rsp, 0x18
0xa227b  mov rax, rsi
0xa227e  mov rsi, [rsi+0x28]
0xa2282  test rsi, rsi
0xa2285  je 0xa24d9
0xa228b  mov rcx, [rax+0x20]
0xa228f  shl rsi, 3
0xa2293  lea r8, [rsi+rsi*2]
0xa2297  lea rsi, [rdx+0x40]
0xa229b  mov r10, r8
0xa229e  mov r9, rcx
0xa22a1  jmp short 0xa22ba
0xa22a3  nop [rax+rax]
0xa22b0  add r9, 0x18
0xa22b4  add r10, 0xffffffffffffffe8
0xa22b8  je short 0xa22f7
0xa22ba  mov rbx, [r9]
0xa22bd  mov r11, rdx
0xa22c0  sub r11, rbx
0xa22c3  jb short 0xa22b0
0xa22c5  mov r14, rsi
0xa22c8  sub r14, rbx
0xa22cb  cmp r14, [r9+0x10]
0xa22cf  ja short 0xa22b0
0xa22d1  mov r9, [r9+8]
0xa22d5  lea rsi, [r9+r11]
0xa22d9  cmp rsi, 0xffffffffffffffbf
0xa22dd  ja short 0xa22f7
0xa22df  add r9, r11
0xa22e2  add r9, 0x40
0xa22e6  cmp r9, [rax+0x10]
0xa22ea  ja short 0xa22f7
0xa22ec  add rsi, [rax+8]
0xa22f0  mov edx, 0x40
0xa22f5  jmp short 0xa2351
```
*Output cut here: lines 1–40 of 206 shown.*

```stderr
xref: load 404.2µs, total 958.9µs
```
<!-- /xref -->

## Reading the output

- The first line is the function range from `.eh_frame`.
- Each line is one instruction: address, Intel-syntax text, and after `;` the resolved target or referenced data (string previews, pointer slots, call targets).
- `--from` / `--to` print a part of the function; the annotations stay the same.

## Limits

- Annotation is static: values loaded at run time and indirect targets are not resolved.

## Provenance

<!-- xref:provenance -->
Recorded with a development build of xref after 0.4.0 on Linux x86-64, on `xref.stripped` = a stripped xref build (the binary of the home-page examples). Output is unchanged except that whitespace at the end of each line and empty lines at the end of the output are removed; long outputs are cut where marked.
<!-- /xref -->
