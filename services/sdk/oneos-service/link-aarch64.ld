OUTPUT_ARCH(aarch64)
ENTRY(oneos_service_main)

SECTIONS
{
  . = 0x42000000;

  .text : {
    *(.text .text.*)
  }

  .rodata : {
    *(.rodata .rodata.*)
  }

  .data : {
    *(.data .data.*)
  }

  .bss : {
    *(.bss .bss.*)
    *(COMMON)
  }

  /DISCARD/ : {
    *(.eh_frame*)
    *(.comment)
  }
}

