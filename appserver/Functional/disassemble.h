#ifndef _DISASSEMBLE_H
#define _DISASSEMBLE_H

#include <Common/host.h>

char* disassemble(uint32_t insn, uint32_t PC, char buf[32]);

#endif
