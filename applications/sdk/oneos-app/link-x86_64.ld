ENTRY(oneos_app_main)

SECTIONS
{
  /* Keep apps above the kernel (0x2000_0000) but within 1GiB RAM (default mem=1024). */
  . = 0x30000000;

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

