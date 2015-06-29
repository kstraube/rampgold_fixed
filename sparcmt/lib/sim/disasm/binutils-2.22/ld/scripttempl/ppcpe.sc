# A PE linker script for PowerPC.
# Loosely based on Steve Chamberlain's pe.sc.
# All new mistakes should be credited to Kim Knuttila (krk@cygnus.com)
#
# These are substituted in as variables in order to get '}' in a shell
# conditional expansion.
INIT='.init : { *(.init) }'
FINI='.fini : { *(.fini) }'
cat <<EOF
OUTPUT_FORMAT(${OUTPUT_FORMAT})
${LIB_SEARCH_DIRS}

/* Much of this layout was determined by delving into .exe files for
   the box generated by other compilers/linkers/etc. This means that
   if a particular feature did not happen to appear in one of the 
   subject files, then it may not be yet supported.
*/

/* It's "mainCRTStartup", not "_mainCRTStartup", and it's located in
   one of the two .lib files (libc.lib and kernel32.lib) that currently
   must be present on the link line. This means that you must use 
   "-u mainCRTStartup" to make sure it gets included in the link.
*/

${RELOCATING+ENTRY (mainCRTStartup)}

SECTIONS
{

  /* text - the usual meaning */
  .text ${RELOCATING+ __image_base__ + __section_alignment__ } : 
	{
	    ${RELOCATING+ *(.init);}
	    *(.text)
	    ${RELOCATING+ *(.text.*)}
	    *(.gcc_except_table)
	    ${CONSTRUCTING+ ___CTOR_LIST__ = .; __CTOR_LIST__ = . ; 
		        LONG (-1); *(.ctors); *(.ctor); LONG (0); }
            ${CONSTRUCTING+ ___DTOR_LIST__ = .; __DTOR_LIST__ = . ; 
			LONG (-1); *(.dtors); *(.dtor);  LONG (0); }
	    ${RELOCATING+ *(.fini);}
	    ${RELOCATING+ etext  =  .};
	}

  /* rdata - Read Only Runtime Data
     CTR sections: All of the CRT (read only C runtime data) sections 
	appear at the start of the .rdata (read only runtime data) 
	section, in the following order. Don't know if it matters or not.
	Not all sections are always present either.
     .rdata: compiler generated read only data
     .xdata: compiler generated exception handling table. (Most docs
	seem to suggest that this section is now deprecated infavor
	of the ydata section)
     .edata: The exported names table.
  */
  .rdata BLOCK(__section_alignment__) :
	{
	    *(.CRT\$XCA);
	    *(.CRT\$XCC);
	    *(.CRT\$XCZ);
	    *(.CRT\$XIA);
	    *(.CRT\$XIC);
	    *(.CRT\$XIZ);
	    *(.CRT\$XLA);
	    *(.CRT\$XLZ);
	    *(.CRT\$XPA);
	    *(.CRT\$XPX);
	    *(.CRT\$XPZ);
	    *(.CRT\$XTA);
	    *(.CRT\$XTZ);
	    *(.rdata);
	    *(.xdata);
	}

  .edata BLOCK(__section_alignment__) :
	{
    	    *(.edata);
	}

  /* data - initialized data
     .ydata: exception handling information.
     .data: the usual meaning.
     .data2: more of the same.
     .bss: For some reason, bss appears to be included in the data
	section, as opposed to being given a section of it's own.
     COMMON:
  */
  .data BLOCK(__section_alignment__) : 
	{
	    __data_start__ = . ; 
	    *(.ydata);
	    *(.data);
	    *(.data2);
	    __bss_start__ = . ;
	    *(.bss) ;
	    *(COMMON);
	    __bss_end__ = . ;
	    ${RELOCATING+ end =  .};
 	    __data_end__ = . ; 
	}

  /* The exception handling table. A sequence of 5 word entries. Section
     address and extent are placed in the DataDirectory.
  */
  .pdata BLOCK(__section_alignment__) :
	{ 					
	    *(.pdata)
 	    ;
	}

  /* The idata section is chock full of magic bits. 
	1. Boundaries around various idata parts are used to initialize
	   some of the fields of the DataDirectory. In particular, the
	   magic for 2, 4 and 5 are known to be used. Some compilers
	   appear to generate magic section symbols for this purpose.
	   Where we can, we catch such symbols and use our own. This of
	   course is something less than a perfect strategy.
	2. The table of contents is placed immediately after idata4.
	   The ".private.toc" sections are generated by the ppc bfd. The
	   .toc variable is generated by gas, and resolved here. It is
	   used to initialized function descriptors (and anyone else who
	   needs the address of the module's toc). The only thing 
	   interesting about it at all? Most ppc instructions using it
	   have a 16bit displacement field. The convention for addressing
	   is to initialize the .toc value to 32K past the start of the
	   actual toc, and subtract 32K from all references, thus using
	   the entire 64K range. Naturally, the reloc code must agree
	   on this number or you get pretty stupid results.
  */
  .idata BLOCK(__section_alignment__) :
	{ 					
	    __idata2_magic__ = .;
	    *(.idata\$2);
	    __idata3_magic__ = .;
	    *(.idata\$3);
	    __idata4_magic__ = .;
	    *(.idata\$4);
	    . = ALIGN(4);
	    .toc = . + 32768;
	    *(.private.toc);
	    __idata5_magic__ = .;
	    *(.idata\$5);
	    __idata6_magic__ = .;
	    *(.idata\$6);
	    __idata7_magic__ = .;
	    *(.idata\$7);
	    ;
	}

  /* reldata -- data that requires relocation
  */
  .reldata BLOCK(__section_alignment__) :
	{ 					
	    *(.reldata)
 	    ;
	}


  /* Resources */
  .rsrc BLOCK(__section_alignment__) :
	{ 					
	    *(.rsrc\$01)
	    *(.rsrc\$02)
	    ;
	}

  .stab BLOCK(__section_alignment__)  ${RELOCATING+(NOLOAD)} : 
  {
    [ .stab ]
  }

  .stabstr BLOCK(__section_alignment__) ${RELOCATING+(NOLOAD)} :
  {
    [ .stabstr ]
  }

  /* The .reloc section is currently generated by the dlltool from Steve 
     Chamberlain in a second pass of linking. Section address and extent
     are placed in the DataDirectory.
  */
  .reloc BLOCK(__section_alignment__) :
	{ 					
	    *(.reloc)
	    ;
	}

  /* We don't do anything useful with codeview debugger support or the
     directive section (yet). Hopefully, we junk them correctly. 
  */
  /DISCARD/ BLOCK(__section_alignment__) : 
	{
    	    *(.debug\$S)
    	    *(.debug\$T)
    	    *(.debug\$F)
    	    *(.drectve)
    	    ;
   	}
}
EOF
