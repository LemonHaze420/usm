SECTIONS
{
  . = 0x00100000;

  .text 0x00100000 : {
    *(.text)
  }

  .vutext 0x006D5040 : {
    *(.vutext)
  }

  .data 0x00727C00 : {
    *(.data)
  }

  .load_pad1 0x00777B58 : {
    *(LOAD_PAD1*)
  }

  .rodata 0x00777B80 : {
    *(.rodata)
    *(.rodata*)
  }

  .load_pad2 0x0080527C : {
    *(LOAD_PAD2*)
  }

  .sbss 0x00805280 (NOLOAD) : {
    *(.sbss)
  }

  .load_pad3 0x0080540F : {
    *(LOAD_PAD3*)
  }

  .bss 0x00805480 (NOLOAD) : {
    *(.bss)
    *(COMMON)
  }  

  .override 0x0087CC20 : {
    *(.override)
  }
  
  .abs_data 0x0083CD20 : {
    LONG(0x10000);         /* _stack_size */
    PROVIDE(_stack_size = . - 4);
  
    LONG(0xFFFFFFFF);      /* _stack */
    PROVIDE(_stack = . - 4);
  
    LONG(0xFFFFFFFF);      /* _heap_size */
    PROVIDE(_heap_size = . - 4);
  
    LONG(0x00727C00);      /* _etext */
    PROVIDE(_etext = . - 4);
  
    LONG(0x84D250);        /* _gp */
    PROVIDE(_gp = . - 4);
  
    LONG(0x83CD20);        /* end */
    PROVIDE(end = . - 4);
  
    LONG(0x845258);        /* __bss_start */
    PROVIDE(__bss_start = . - 4);
  
    LONG(0x845258);        /* _edata */
    PROVIDE(_edata = . - 4);
  
    LONG(0x87CCA0);        /* _end */
    PROVIDE(_end = . - 4);
  
    LONG(0xFFFFFFFF);      /* _stack */
    PROVIDE(_stack = . - 4);
  
    LONG(0x845258);        /* _fbss */
    PROVIDE(_fbss = . - 4);
  
    LONG(0xFFFFFFFF);      /* _heap_size again */
    PROVIDE(_heap_size = . - 4);
  
    LONG(0x00);            /* o_c */
    PROVIDE(o_c = . - 4);
  
    LONG(0x04);            /* o_fx_int */
    PROVIDE(o_fx_int = . - 4);
  
    LONG(0x08);            /* o_cu */
    PROVIDE(o_cu = . - 4);
  
    LONG(0x0C);            /* o_cd */
    PROVIDE(o_cd = . - 4);
  
    LONG(0x10);            /* o_sadd */
    PROVIDE(o_sadd = . - 4);
  
    LONG(0x14);            /* o_left */
    PROVIDE(o_left = . - 4);
  
    LONG(0x18);            /* o_right */
    PROVIDE(o_right = . - 4);
  }
  
}
