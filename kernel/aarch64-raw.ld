ENTRY(kstart)

SECTIONS
{
    /* QEMU virt DRAM starts @0x4000_0000; leave 512KB guard for firmware data */
    . = 0x40080000;

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

    /DISCARD/ : { *(.comment*) *(.note*) }
}
