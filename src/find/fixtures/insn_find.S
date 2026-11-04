.text
.globl insn_div, insn_div_site
.type insn_div,@function
insn_div:
.cfi_startproc
insn_div_site:
    divsd %xmm1, %xmm0
    ret
.cfi_endproc
.size insn_div, .-insn_div

.globl insn_sqrt, insn_sqrt_site
.type insn_sqrt,@function
insn_sqrt:
.cfi_startproc
insn_sqrt_site:
    sqrtsd %xmm1, %xmm0
    ret
.cfi_endproc
.size insn_sqrt, .-insn_sqrt

.globl insn_convert, insn_convert_site
.type insn_convert,@function
insn_convert:
.cfi_startproc
insn_convert_site:
    cvtsi2sd %rdi, %xmm0
    ret
.cfi_endproc
.size insn_convert, .-insn_convert

.globl insn_integer
.type insn_integer,@function
insn_integer:
.cfi_startproc
    pxor %xmm0, %xmm0
    paddd %xmm1, %xmm0
    ret
.cfi_endproc
.size insn_integer, .-insn_integer

.globl insn_many, insn_many_site_0
.type insn_many,@function
insn_many:
.cfi_startproc
insn_many_site_0:
    divsd %xmm1, %xmm0
    divsd %xmm1, %xmm0
    divsd %xmm1, %xmm0
    divsd %xmm1, %xmm0
    divsd %xmm1, %xmm0
    divsd %xmm1, %xmm0
    divsd %xmm1, %xmm0
    divsd %xmm1, %xmm0
    divsd %xmm1, %xmm0
    divsd %xmm1, %xmm0
    ret
.cfi_endproc
.size insn_many, .-insn_many

.globl insn_avx_arithmetic, insn_avx_site
.type insn_avx_arithmetic,@function
insn_avx_arithmetic:
.cfi_startproc
insn_avx_site:
    vaddsd %xmm1, %xmm0, %xmm0
    vfmadd231ps %ymm2, %ymm1, %ymm0
    ret
.cfi_endproc
.size insn_avx_arithmetic, .-insn_avx_arithmetic

.globl insn_avx_integer
.type insn_avx_integer,@function
insn_avx_integer:
.cfi_startproc
    vpaddd %ymm1, %ymm0, %ymm0
    ret
.cfi_endproc
.size insn_avx_integer, .-insn_avx_integer
