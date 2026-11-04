/* Neutral x86-64 CFI fixture. */
.text
.globl profile_leaf
.type profile_leaf,@function
profile_leaf:
.cfi_startproc
    nop
    ret
.cfi_endproc
.size profile_leaf, .-profile_leaf

.globl profile_parent
.type profile_parent,@function
profile_parent:
.cfi_startproc
    nop
    ret
.cfi_endproc
.size profile_parent, .-profile_parent
.section .note.GNU-stack,"",@progbits
