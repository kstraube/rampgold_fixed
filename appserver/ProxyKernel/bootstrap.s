	.section	".text"
	.align 4

#include "kernel.h"
#include <specialregs.h>

    .global bootstrap
bootstrap:

	mov	NUM_CORES_REG,%g1
	cmp	%g1,MAX_PROCS
	tg	0x7f

	! compute NWINDOWS
	mov	-1,%wim
	mov	0x000000C0,%psr	! icc=0, EC=EF=0, PIL=0, S=PS=1, ET=0, CWP=0
	nop
	mov	0,%g2
	mov	%wim,%g1

wimloop:
	srl	%g1,1,%g1
	tst	%g1
	bne,a	wimloop
	inc	%g2

	set	spill_patchme,%g1
	ld	[%g1],%g3
	or	%g2,%g3,%g3
	st	%g3,[%g1]
	flush	%g1

	set	fill_patchme,%g1
	ld	[%g1],%g3
	or	%g2,%g3,%g3
	st	%g3,[%g1]
	flush	%g1

	set	nwindows,%g1
	inc	%g2
	st	%g2,[%g1]

	! WIM = 1<<1
	mov	2,%g3
	mov	%g3,%wim
	nop

	! initialize TBR
	sethi	%hi(trap_table),%g1	! tbr[11:0] must be 0
	mov	%g1,%tbr

	! dummy FP for backtraces
	mov	0,%fp

	! initialize kernel stack pointer
	set	bootstacktop-64,%sp
	mov	CORE_ID_REG,%o0
	mov	%o0,%asr13
	sll	%o0,KSTKSHIFT,%l1
	sub	%sp,%l1,%sp
	set	kernel_stack_pointers,%l1
	sll	%o0,2,%l2
	st	%sp,[%l1+%l2]

	! tare perfctrs
	tst	%o0
	bne	1f
	 nop
	call	print_stats
	 mov	1,%o0

	call	kernel_boot
	 nop

1:

#ifdef KERNEL_USE_MMU
	call	set_up_mmu
	 nop
#endif
	! branch to kernel or user?
	set	kernel_entryp, %l1
	ld	[%l1],%o0
	tst	%o0
	be	set_up_stack
	nop
	save
	jmp	%i0
	rett	%i0+4

set_up_stack:
	mov	CORE_ID_REG,%o0

	! leave room for register spill just below args
	set	USER_VIRTUAL_START+USER_SIZE-ARGS_SIZE-64,%sp
	set	USER_STACK_SIZE_THREAD,%l2
	umul	%o0,%l2,%l3
	sub	%sp,%l3,%sp

	! if core != 0, wait for active message
	tst	%o0
	bne	notcore0

	! if core == 0, jump to user code
	set	user_entryp, %l1
	ld	[%l1],%o0
	save
	jmp	%i0
	rett	%i0+4
	
notcore0:
	! now we can safely enable traps
	mov	%psr,%l1
	wr	%l1,0x20,%psr
	

	set	active_message_mailbox,%l0
	mov	CORE_ID_REG,%l1
	sll	%l1,5,%l1
	add	%l1,%l0,%l0

forever:
	!mov	0,AM_SLEEP_REG
	!ba,a	forever

	ld	[%l0+28],%l1
	tst	%l1
	be	forever
	nop

	ld	[%l0+4],%o1
	ld	[%l0+8],%o2
	ld	[%l0+12],%o0
	st	%g0,[%l0+28]

	mov	%psr,%l6 
	wr	%l6,0x20,%psr
	nop; nop; nop

	save
	jmp	%i2
	rett	%i2+4

.global nwindows
nwindows:
	.word	0


.global user_entryp
user_entryp:
	.word illegal_inst_trap			! location of entry point, set by appserver

.global illegal_inst_trap
illegal_inst_trap:
	unimp
	unimp

! if someone overrides this symbol with a nonzero value,
! we'll jump here rather than user code
.weak kernel_entryp
kernel_entryp:
	.word 0
