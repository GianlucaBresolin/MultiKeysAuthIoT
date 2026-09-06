OUTPUT_ARCH(aarch64)
ENTRY(_start)

MEMORY
{
    RAM : ORIGIN = 0x40080000, LENGTH = 128M
}

SECTIONS
{
    . = ORIGIN(RAM);

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