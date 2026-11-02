// Synthetic x86-64 ELF input for static field-origin tests; never executed.
// SPDX-License-Identifier: MIT OR Apache-2.0
core::arch::global_asm!(r#"
.pushsection .rodata
field_marker:
    .asciz "XREF_FIELD_ORIGIN_NEEDLE"
.popsection
.text
.global field_entry
.type field_entry,@function
field_entry:
.cfi_startproc
    push r12
.cfi_def_cfa_offset 16
.cfi_offset r12,-16
    mov r12,rdi
    lea rax,[rip+field_marker]
    mov rax,[rdi+24]
    lea rsi,[rdi+24]
    mov rdx,rax
    call field_sink
    mov rdi,r12
    pop r12
.cfi_def_cfa_offset 8
    ret
.cfi_endproc
.size field_entry,.-field_entry
.type field_sink,@function
field_sink:
.cfi_startproc
    cmp qword ptr [rdi+24],0
    add qword ptr [rsi],1
    mov qword ptr [rdi+32],rdx
    xor eax,eax
    ret
.cfi_endproc
.size field_sink,.-field_sink
"#);
extern "C" { fn field_entry(ptr: *mut u64) -> u64; }
fn main() {
    let mut data = [0u64; 8];
    unsafe { std::hint::black_box(field_entry(data.as_mut_ptr())); }
}
