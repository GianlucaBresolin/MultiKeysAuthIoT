OUTPUT_ARCH(aarch64)
ENTRY(_start)

MEMORY
{
    RAM : ORIGIN = 0x40000000, LENGTH = 128M
}

SECTIONS
{
    . = ORIGIN(RAM);

    .dma (NOLOAD) : ALIGN(4096) {
        __dma_start = .;
        . += 0x400000;
        __dma_end = .;
    } > RAM

    .text : {
        *(.text._start)
        *(.text .text.*)
    } > RAM

    .rodata : {
        *(.rodata .rodata.*)
    } > RAM

    .data : {
        *(.data .data.*)
    } > RAM

    .bss (NOLOAD) : ALIGN(8) {
        __bss_start = .;
        *(.bss .bss.*)
        *(COMMON)
        __bss_end = .;
    } > RAM

    . = ALIGN(16);
    . += 0x80000; /* 512 KiB di stack */
    __stack_top = .;

    /DISCARD/ : {
        *(.comment)
        *(.gnu*)
        *(.note*)
        *(.eh_frame*)
    }
}