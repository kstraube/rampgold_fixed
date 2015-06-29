SECTIONS
{
  . = 0xf0000000;
  .text : { *(.text) }
  .data : { *(.data) }
  .bss : { *(.bss) }
}

ENTRY(_start);
