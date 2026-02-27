ENTRY(_start)

SECTIONS
{
    /* Put the raw kernel in conventional RAM, away from low firmware regions. */
    . = 0x20000000;

    .text : ALIGN(4K) {
        __text_start = .;
        KEEP(*(.text.boot))
        *(.text*)
        __text_end = .;
    }

    .rodata : ALIGN(4K) {
        __rodata_start = .;
        *(.rodata*)
        __rodata_end = .;
    }

    .data : ALIGN(4K) {
        __data_start = .;
        *(.data*)
        __data_end = .;
    }

    .bss (NOLOAD) : ALIGN(4K) {
        __bss_start = .;
        *(.bss*)
        *(COMMON)
        __bss_end = .;
    }

    .stack (NOLOAD) : ALIGN(16) {
        __stack_bottom = .;
        . = . + 0x10000; /* 64 KiB */
        __stack_top = .;
    }

    /DISCARD/ : { *(.comment*) *(.note*) }
}
