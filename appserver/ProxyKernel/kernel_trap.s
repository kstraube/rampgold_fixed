#include "kernel.h"
#include <specialregs.h>

	.section	".text"!,#alloc,#execinstr,#progbits
	.align	4

	.global handle_trap
handle_trap:

	! compute stack pointer.  if we came from userland, sp = ksp[id]
	set	kernel_stack_pointers,%l6
	mov	CORE_ID_REG,%l7
	sll	%l7,2,%l7
	ld	[%l6+%l7],%l6
	add	%l6,-224,%l6

	mov	%psr,%l7

	btst	0x40,%l7
	bne,a	1f
	 add	%fp,-224,%l6	! trap came from supervisor; sp = fp-64

1:	mov	%l7,%l0		! %l0 = psr. we can't just use mov %psr,%l0,
	mov	%wim,%l3	! because we changed the condition codes
	mov	%tbr,%l4

	! save state from before trap: psr, pc, npc, wim, tbr
	std	%l0,[%l6+192]
	std	%l2,[%l6+200]
	st	%l4,[%l6+208]

#ifdef KERNEL_USE_MMU
	set	MMU_FAULT_STATUS_REG,%l4
	lda	[%l4] ASI_MMU_REGS,%l4
	st	%l4,[%l6+212]
	set	MMU_FAULT_ADDRESS_REG,%l4
	lda	[%l4] ASI_MMU_REGS,%l4
	st	%l4,[%l6+216]
#else
	st	%g0,[%l6+212]
	st	%g0,[%l6+216]
#endif
	set	0x1000,%l4
	btst	%l4,%l0
	be	1f
	 st	%g0,[%l6+220]
	st	%fsr,[%l6+220]
	
1:	! is CWP valid?
	and	%l0,0x1f,%l4	! %l4 = cwp
	mov	1,%l7
	sll	%l7,%l4,%l4	! %l4 = 1 << cwp
	btst	%l3,%l4		! (%wim & %l4) == 0?
	be	2f

	! CWP not valid; spill a window
	sethi	%hi(spill),%l7
	jmpl	%lo(spill)+%l7,%l7
	nop

	! now we have a valid register window.
	! save the whole user context to a trap_state_t (except for FP)

2:	std	%g0,[%l6+64]
	std	%g2,[%l6+72]
	std	%g4,[%l6+80]
	std	%g6,[%l6+88]

	mov	%l6,%g2

	restore
	std	%o0,[%g2+96]
	std	%o2,[%g2+104]
	std	%o4,[%g2+112]
	std	%o6,[%g2+120]
	std	%l0,[%g2+128]
	std	%l2,[%g2+136]
	std	%l4,[%g2+144]
	std	%l6,[%g2+152]
	std	%i0,[%g2+160]
	std	%i2,[%g2+168]
	std	%i4,[%g2+176]
	std	%i6,[%g2+184]
	save

	! valid window and stack pointer; can enable traps
	mov	%l6,%sp
	wr	%l0,0x20,%psr		! enable traps

	add	%sp,64,%o0		! pointer to trap_state_t
	mov	%g1,%o1			! syscall type, if it's a syscall
	mov	%i0,%o2			! syscall args, if it's a syscall
	mov	%i1,%o3
	mov	%i2,%o4
	call	%l5
	 mov	%i3,%o5

	! now we're back. disable traps
	! since wrpsr/rdpsr is interruptible, all interrupt handlers
	! must restore the psr to its interrupt-time value
	mov	%psr,%l6
	wr	%l6,0x20,%psr

	! is (CWP+1) % NWINDOWS valid?
	and	%l6,0x1f,%l5
	set	nwindows,%l6
	ld	[%l6],%l6
	add	%l5,1,%l5
	cmp	%l5,%l6
	be,a	3f
	 mov	0,%l5

3:	mov	1,%l7
	sll	%l7,%l5,%l5		! %l5 = 1 << ((CWP+1)%NWINDOWS)
	mov	%wim,%l7
	btst	%l5,%l7			! (%wim & %l5) == 0?
	be	4f
	 nop

	sethi	%hi(fill),%l7		! gotta fill a window
	jmpl	%lo(fill)+%l7,%l7
	 save	%l7,0,%l7
	restore

	! restore user context
4:	mov	%sp,%g2
	restore
	ldd	[%g2+96],%o0
	ldd	[%g2+104],%o2
	ldd	[%g2+112],%o4
	ldd	[%g2+120],%o6
	ldd	[%g2+128],%l0
	ldd	[%g2+136],%l2
	ldd	[%g2+144],%l4
	ldd	[%g2+152],%l6
	ldd	[%g2+160],%i0
	ldd	[%g2+168],%i2
	ldd	[%g2+176],%i4
	ldd	[%g2+184],%i6
	save

	ld	[%sp+68],%g1
	ldd	[%sp+72],%g2
	ldd	[%sp+80],%g4
	ldd	[%sp+88],%g6

	ld	[%sp+192],%l0
	mov	%l0,%psr
	ld	[%sp+196],%l1
	ld	[%sp+200],%l2

	jmp	%l1
	rett	%l2

	.global handle_perfctr
handle_perfctr:
	andn    %i0,7,%i1
	lda     [%i1] 2,%i0
	add     %i1,4,%i1
	lda     [%i1] 2,%i1
	jmp     %l2
	 rett   %l2+4


! handle_message(srcid,funcptr,dataptr)
! disabled for now
    .global handle_active_message
handle_active_message:

	set	unhandled_trap,%l5
	set	handle_trap,%l6
	jmp	%l6
	nop

	.global handle_reset
handle_reset:
	jmp	%g0
	nop

.section	".data"

.align 4
.global kernel_stack_pointers
kernel_stack_pointers:
	.skip   4*MAX_PROCS
