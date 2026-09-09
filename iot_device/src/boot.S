    .section .text.vectors
    .align 11
    .global vector_table
vector_table:
    .align 7
    b .
    .align 7
    b .
    .align 7
    b .
    .align 7
    b .
    .align 7
    b sync_handler_asm
    .align 7
    b .
    .align 7
    b .
    .align 7
    b .
    .align 7
    b .
    .align 7
    b .
    .align 7
    b .
    .align 7
    b .
    .align 7
    b .
    .align 7
    b .
    .align 7
    b .
    .align 7
    b .

sync_handler_asm:
    bl sync_exception_handler

    .section .text._start
    .global _start
_start:
    ldr x0, =__bss_start
    ldr x1, =__bss_end
1:
    cmp x0, x1
    b.ge 2f
    str xzr, [x0], #8
    b 1b
2:
    ldr x0, =__stack_top
    mov sp, x0

    mrs x0, CurrentEL
    lsr x0, x0, #2
    cmp x0, #3
    b.eq drop_from_el3
    cmp x0, #2
    b.eq drop_from_el2
    b start_el1

drop_from_el3:
    mov x0, #0x5b1
    msr scr_el3, x0
    mov x0, #0x3c9
    msr spsr_el3, x0
    adr x0, drop_from_el2
    msr elr_el3, x0
    eret

drop_from_el2:
    mov x0, #(1 << 31)
    msr hcr_el2, x0
    mov x0, #0x3c5
    msr spsr_el2, x0
    adr x0, start_el1
    msr elr_el2, x0
    eret

start_el1:
    bl _start_main
3:
    wfe
    b 3b