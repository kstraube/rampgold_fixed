#ifndef _PK_TRAP_H
#define _PK_TRAP_H

#define TRAP_TABLE_ENTRY(label) sethi %hi(handle_trap),%l6; sethi %hi(label),%l5; jmp %lo(handle_trap)+%l6; or %lo(label),%l5,%l5
#define JMP(target) sethi %hi(target),%l4; jmp %lo(target)+%l4; mov %psr,%l0; nop
#define ENTER_ERROR_MODE unimp; unimp; unimp; unimp

#define HANDLE_WINDOW_OVERFLOW sethi %hi(spill),%l6; sethi %hi(window_rett),%l7; jmp %lo(spill)+%l6; or %l7,%lo(window_rett),%l7
#define HANDLE_WINDOW_UNDERFLOW sethi %hi(fill),%l6; sethi %hi(window_rett),%l7; jmp %lo(fill)+%l6; or %l7,%lo(window_rett),%l7

#define UNHANDLED_TRAP TRAP_TABLE_ENTRY(unhandled_trap)

#endif
