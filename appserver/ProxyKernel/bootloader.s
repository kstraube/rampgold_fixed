#include "bootloader.h"

	.section ".text"
	.align 4

	.global _start
_start:

		mov	0x000000E0,%psr; nop; nop; nop
		mov	0,%wim; nop; nop; nop

		call	set_up_mmu
		nop

		call	romvec_init
		nop

		set	0xf0004000,%g1
		set	romvec, %o0
		call	%g1
		nop

	.section ".data"
	.align 1024

	.global __mmu_context_table
__mmu_context_table:
	.skip CTX_TABLE_ENTRIES*4

	.global __l1_page_table
__l1_page_table:
	.skip L1_PAGE_TABLE_ENTRIES*4
