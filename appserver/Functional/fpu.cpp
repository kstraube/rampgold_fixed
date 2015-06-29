/* Author: Andrew S. Waterman
 *         Parallel Computing Laboratory
 *         Electrical Engineering and Computer Sciences
 *         University of California, Berkeley
 *
 * Copyright (c) 2008, The Regents of the University of California.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *     * Redistributions of source code must retain the above copyright
 *       notice, this list of conditions and the following disclaimer.
 *     * Redistributions in binary form must reproduce the above copyright
 *       notice, this list of conditions and the following disclaimer in the
 *       documentation and/or other materials provided with the distribution.
 *     * Neither the name of the University of California, Berkeley nor the
 *       names of its contributors may be used to endorse or promote products
 *       derived from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE REGENTS ''AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
 * IN NO EVENT SHALL THE REGENTS BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
 * THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */


#include "fpu.h"
#include "traps.h"
#include <cstring>
#include "opcodes.h"
#include <Common/util.h>
#include "config.h"
#include "targetconfig.h"

fpu_t::fpu_t()
{
  debug_assert(sizeof(sparcfpu.FSR) == 4);
  sparcfpu_init(&sparcfpu);
}

void fpu_t::setFSR(uint32_t newFSR)
{
  sparcfpu_setFSR(&sparcfpu,*(fsr_t*)&newFSR);
}

uint32_t fpu_t::getFSR()
{
  return *(uint32_t*)&sparcfpu.FSR;
}

void fpu_t::FPop1(uint32_t insn)
{
  fp_insn_t fpi = *(fp_insn_t*)&insn;
  #ifndef HAVE_FPU_DIV_SQRT
    switch(fpi.opf)
    {
      case opFSQRTs:
      case opFSQRTd:
      case opFSQRTq:
      case opFDIVs:
      case opFDIVd:
      case opFDIVq:
      case opFiTOq:
      case opFqTOi:
      case opFsTOq:
      case opFqTOs:
      case opFdTOq:
      case opFqTOd:
      case opFADDq:
      case opFSUBq:
      case opFMULq:
      case opFdMULq:
      case opFCMPq:
      case opFCMPEq:
        sparcfpu.FSR.ftt = fp_trap_unimplemented_FPop;
        return;
    }
    switch(fpi.opf)
    {
      case opFADDd:
      case opFMULd:
      case opFSUBd:
      case opFADDs:
      case opFMULs:
      case opFSUBs:
        if(sparcfpu.FSR.rd != 0)
        {
          sparcfpu.FSR.ftt = fp_trap_unimplemented_FPop;
          return;
        }
    }
  #endif
  sparcfpu_fpop1(&sparcfpu,fpi);
}

void fpu_t::FPop2(uint32_t insn)
{
  sparcfpu_fpop2(&sparcfpu,*(fp_insn_t*)&insn);
}

uint32_t fpu_t::reg(uint32_t r)
{
  debug_assert(r < 32);
  return sparcfpu.freg[r];
}

void fpu_t::wrreg(uint32_t r, uint32_t val)
{
  debug_assert(r < 32);
  sparcfpu.freg[r] = val;
}

void fpu_t::clear_ftt()
{
  sparcfpu.FSR.ftt = 0;
}

uint32_t fpu_t::get_ftt()
{
  return sparcfpu.FSR.ftt;
}

void fpu_t::set_ftt(uint32_t trp)
{
  sparcfpu.FSR.ftt = trp;
}

