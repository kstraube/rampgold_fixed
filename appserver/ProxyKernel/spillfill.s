! after handling a window trap, spill/fill will return to window_rett+8,
! so these two nops are necessary!
	.global	window_rett
window_rett:
	nop
	nop
	jmp	%l1
	rett	%l2

! preconditions:
! WIM & (1<<CWP) != 0
! link address in %l7
! postconditions:
! CWP same, but is now valid
! %l0, %l1, %l2, %l5, %l6 have not changed 
.global spill
spill:
	mov	%g1,%l4
	mov	%wim,%l3
	mov	%g0,%wim
	and	%l3,1,%g1

	! this will be patched at runtime; 0 is really NWINDOWS-1
.global spill_patchme
spill_patchme:
	sll	%g1,0,%g1

	srl	%l3,1,%l3
	or	%g1,%l3,%g1

	save
	mov	%g1,%wim
	std	%l0,[%sp+ 0]
	std	%l2,[%sp+ 8]
	std	%l4,[%sp+16]
	std	%l6,[%sp+24]
	std	%i0,[%sp+32]
	std	%i2,[%sp+40]
	std	%i4,[%sp+48]
	std	%i6,[%sp+56]
	restore

	jmp	%l7+8
	mov	%l4,%g1

! preconditions:
! WIM & (1<<((CWP+2)%NWINDOWS)) != 0
! link address in %l7
! postconditions:
! CWP same, but (CWP+2)%NWINDOWS now valid
! %l0, %l1, %l2, %l5, %l6 have not changed
.global fill 
fill:
	mov	%g1,%l4
	mov	%wim,%l3
	mov	%g0,%wim

	! this will be patched at runtime; 0 is really NWINDOWS-1
.global fill_patchme
fill_patchme:
	srl	%l3,0,%g1

	and	%g1,1,%g1
	sll	%l3,1,%l3
	or	%g1,%l3,%g1

	restore
	restore
	ldd	[%sp+ 0],%l0
	ldd	[%sp+ 8],%l2
	ldd	[%sp+16],%l4
	ldd	[%sp+24],%l6
	ldd	[%sp+32],%i0
	ldd	[%sp+40],%i2
	ldd	[%sp+48],%i4
	ldd	[%sp+56],%i6
	save
	save
	mov	%g1,%wim
	nop

	jmp	%l7+8
	mov	%l4,%g1
