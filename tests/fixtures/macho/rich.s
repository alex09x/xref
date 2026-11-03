// Synthetic static-analysis input; never executed.
// SPDX-License-Identifier: MIT OR Apache-2.0
.section __TEXT,__cstring,cstring_literals
.globl _macho_marker
_macho_marker: .asciz "XREF_MACHO_SEED"
.section __DATA,__data
.p2align 3
.globl _macho_callback
_macho_callback:
.quad _macho_hidden
.quad _macho_helper
.text
.p2align 4
.globl _macho_entry
_macho_entry:
.cfi_startproc
pushq %rbp
.cfi_def_cfa_offset 16
.cfi_offset %rbp,-16
movq %rsp,%rbp
.cfi_def_cfa_register %rbp
.cfi_escape 0x0f,0x02,0x76,0x10
leaq _macho_marker(%rip),%rdi
callq _macho_helper
callq _macho_export_return
callq _macho_hidden
callq _macho_pair
xorl %eax,%eax
popq %rbp
.cfi_def_cfa %rsp,8
retq
.cfi_endproc
.p2align 4
.globl _macho_helper
_macho_helper:
.cfi_startproc
.cfi_escape 0x0f,0x02,0x77,0x08
movl $7,%eax
retq
.cfi_endproc
.p2align 4
.globl _macho_export_return
_macho_export_return:
.cfi_startproc
.cfi_escape 0x0f,0x02,0x77,0x08
movl $99,%eax
retq
.cfi_endproc
.p2align 4
_macho_hidden:
.cfi_startproc
.cfi_escape 0x0f,0x02,0x77,0x08
movl $55,%eax
retq
.cfi_endproc
.p2align 4
.globl _macho_pair
_macho_pair:
.cfi_startproc
.cfi_escape 0x0f,0x02,0x77,0x08
movl $9,%edx
movl $8,%eax
retq
.cfi_endproc
.p2align 4
.globl _macho_import
_macho_import:
.cfi_startproc
pushq %rbp
.cfi_def_cfa_offset 16
.cfi_offset %rbp,-16
movq %rsp,%rbp
.cfi_def_cfa_register %rbp
.cfi_escape 0x0f,0x02,0x76,0x10
leaq _macho_marker(%rip),%rdi
callq _puts
popq %rbp
.cfi_def_cfa %rsp,8
retq
.cfi_endproc
.p2align 4
.globl _macho_abort
_macho_abort:
.cfi_startproc
pushq %rbp
.cfi_def_cfa_offset 16
.cfi_offset %rbp,-16
movq %rsp,%rbp
.cfi_def_cfa_register %rbp
.cfi_escape 0x0f,0x02,0x76,0x10
callq _abort
ud2
.cfi_endproc
