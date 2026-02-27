ENTRY(oneos_app_main)

SECTIONS
{
  /* QEMU virt RAM starts at 0x4000_0000; keep apps above the kernel (0x4008_0000). */
  . = 0x41000000;

  .text : ALIGN(0x1000) {
    *(.text .text.*)
  }

  .rodata : ALIGN(0x1000) {
    *(.rodata .rodata.*)
  }

  .data : ALIGN(0x1000) {
    *(.data .data.*)
  }

  .bss : ALIGN(0x1000) {
    *(.bss .bss.*)
    *(COMMON)
  }
}

