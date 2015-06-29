#ifndef _FPU_H
#define _FPU_H

#include <host.h>

void emulate_fpu(trap_state_t* state, uint32 fsr);
void fp_exception(trap_state_t* state);

#endif
