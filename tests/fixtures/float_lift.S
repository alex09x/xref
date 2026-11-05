/* XRef scalar-double decompiler fixture. Assembly is compiled into an ELF; functions are never executed. */
.section .rodata
.p2align 4
.Lpoint015:
    .double 0.015
.Lscale1000:
    .double 1000.0
.Lperiod:
    .double 31557600.0
.Lnegative_half:
    .double -0.5
.Ltwo:
    .double 2.0
.Lten:
    .double 10.0
.Lpositive_infinity:
    .quad 0x7ff0000000000000
.Lu64_magic:
    .quad 0x4530000043300000
.p2align 4
.Lu64_bias:
    .quad 0x4330000000000000, 0x4530000000000000
.Lu64_near_magic:
    .quad 0x4530000043300001

.text
.globl float_formula
.type float_formula,@function
float_formula:
.cfi_startproc
    movsd %xmm0, %xmm2
    addsd .Lpoint015(%rip), %xmm2
    subsd .Lpoint015(%rip), %xmm2
    mulsd .Lnegative_half(%rip), %xmm2
    divsd .Lscale1000(%rip), %xmm2
    sqrtsd %xmm1, %xmm3
    maxsd .Lpoint015(%rip), %xmm3
    minsd .Lten(%rip), %xmm3
    ucomisd %xmm3, %xmm2
    ja .Lordered_greater
    movsd .Lperiod(%rip), %xmm4
.Lordered_greater:
    movsd .Lpositive_infinity(%rip), %xmm5
    ret
.cfi_endproc
.size float_formula, .-float_formula

.globl convert_signed_double
.type convert_signed_double,@function
convert_signed_double:
.cfi_startproc
    cvtsi2sd %rdi, %xmm0
    cvttsd2si %xmm0, %rax
    ret
.cfi_endproc
.size convert_signed_double, .-convert_signed_double

.globl convert_integer_rodata
.type convert_integer_rodata,@function
convert_integer_rodata:
.cfi_startproc
    cvtsi2sdq .Lscale1000(%rip), %xmm0
    ret
.cfi_endproc
.size convert_integer_rodata, .-convert_integer_rodata

.globl convert_u64_double
.type convert_u64_double,@function
convert_u64_double:
.cfi_startproc
    movq %rdi, %xmm0
    punpckldq .Lu64_magic(%rip), %xmm0
    subpd .Lu64_bias(%rip), %xmm0
    movapd %xmm0, %xmm1
    unpckhpd %xmm0, %xmm0
.globl convert_u64_double_add_site
convert_u64_double_add_site:
    addsd %xmm1, %xmm0
    ret
.cfi_endproc
.size convert_u64_double, .-convert_u64_double

.globl near_miss_u64_double
.type near_miss_u64_double,@function
near_miss_u64_double:
.cfi_startproc
    movq %rdi, %xmm0
    punpckldq .Lu64_near_magic(%rip), %xmm0
    subpd .Lu64_bias(%rip), %xmm0
    movapd %xmm0, %xmm1
    unpckhpd %xmm0, %xmm0
    addsd %xmm1, %xmm0
    ret
.cfi_endproc
.size near_miss_u64_double, .-near_miss_u64_double

.globl u64_partial_after_store
.type u64_partial_after_store,@function
u64_partial_after_store:
.cfi_startproc
    movsd (%rdi), %xmm2
    unpcklps .Lu64_magic(%rip), %xmm2
    subpd .Lu64_bias(%rip), %xmm2
    movapd %xmm2, %xmm1
    unpckhpd %xmm2, %xmm1
    addsd %xmm2, %xmm1
    movq $0, (%rdi)
    addsd %xmm2, %xmm1
    movsd %xmm1, (%rsi)
    ret
.cfi_endproc
.size u64_partial_after_store, .-u64_partial_after_store

.globl float_copy_chain
.type float_copy_chain,@function
float_copy_chain:
.cfi_startproc
    movsd %xmm0, %xmm2
    movapd %xmm2, %xmm0
    mulsd %xmm2, %xmm0
    movsd %xmm1, %xmm3
    divsd %xmm2, %xmm3
    divsd %xmm3, %xmm0
    ret
.cfi_endproc
.size float_copy_chain, .-float_copy_chain

.section .note.GNU-stack,"",@progbits
