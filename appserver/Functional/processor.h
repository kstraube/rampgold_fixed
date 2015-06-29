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


#ifndef _PROCESSOR_H
#define _PROCESSOR_H

#include "traps.h"
#include <Common/host.h>
#include <Common/util.h>
#include "targetconfig.h"
#include "config.h"
#include "decode.h"
#include "memory.h"

// psr_t represents the processor state register (in an unpacked form)
struct psr_t
{
  uint8_t impl_ver;   // 31:28 = impl; 27:24 = ver
  uint8_t icc;        // 23:20 = integer condition codes
  uint8_t reserved;   // 19:14 = reserved
  uint8_t EC;         // 13 = coprocessor enabled
  uint8_t EF;         // 12 = floating point enabled
  uint8_t PIL;        // 11:8 = processor interrupt level
  uint8_t S;          // 7 = supervisor mode
  uint8_t PS;         // 6 = previous value of supervisor mode
  uint8_t ET;         // 5 = traps enabled
  uint8_t CWP;        // 4:0 = current window pointer  

  // align to 16-byte boundary
  uint16_t pad2;
  uint32_t pad4;

  // set the PSR, except for hard-wired fields
  void set(uint32_t packed_psr)
  {
    icc = (packed_psr >> 20)& 0xF;
    PIL = (packed_psr >> 8) & 0xF;
    S   = (packed_psr >> 7) & 1;
    PS  = (packed_psr >> 6) & 1;
    ET  = (packed_psr >> 5) & 1;
    CWP =  packed_psr       & 0x1F;

    #ifdef HAVE_COPROCESSOR
    EC = (packed_psr >> 13) & 1;
    #endif
    #ifdef HAVE_FPU
    EF = (packed_psr >> 12) & 1;
    #endif
  }

  uint32_t get()
  {
    return impl_ver << 24 |
           icc      << 20 |
           reserved << 14 |
           EC       << 13 |
           EF       << 12 |
           PIL      <<  8 |
           S        <<  7 |
           PS       <<  6 |
           ET       <<  5 |
           CWP;
  }
};

struct active_message_t
{
  spinlock_t lock;
  uint32_t valid;
  uint32_t srcid;
  uint32_t destid;
  uint32_t PC;
  uint32_t arg0;
  uint32_t arg1;
  uint32_t arg2;

  active_message_t() { lock = SPINLOCK_INIT; valid = 0; }
};

struct insn_return_t
{
  uint32_t PC;
  uint32_t nPC;
};

struct memory_t;
struct cache_t;
struct fpu_t;
struct processor_t;
typedef insn_return_t (processor_t::*insn_func_t)(insn_return_t,uint32_t);
typedef insn_return_t (*fast_insn_func_t)(processor_t*,insn_return_t,uint32_t);

struct decoded_insn_t
{
  fast_insn_func_t func;
  uint32_t tag;
  uint32_t insn;
};

struct processor_t
{
  uint32_t id;
  uint32_t timer_period;
  bool ipi_pending;
  uint64_t nretired;
  uint64_t ncti;
  uint64_t nld;
  uint64_t nst;
  uint64_t namo;
  uint64_t ndiv;
  uint64_t nmul;
  uint64_t nshift;
  uint64_t ntrap;
  uint64_t nldhit;
  uint64_t nsthit;
  uint64_t nicmiss;
  uint64_t nfpop;

  psr_t PSR;
  uint32_t CSR;
  uint32_t WIM;
  uint32_t TBR;
  vaddr PC;
  vaddr nPC;
  int stall;
  uint32_t IRL;
  active_message_t mailbox;

  #ifdef CACHE_SIM
    memory_t* dcache;
    memory_t* icache;
  #endif

  uint32_t creg[32];
  uint32_t ASR[32];
  uint32_t regfile[NWINDOWS*16+8];
  fpu_t* fpu;

  bool bicc_LUT[16][16];
  uint32_t* regaddr[32];
  uint32_t dummy_register_g0;

  const static int FUNCTIONAL_ICACHE_SIZE = 256;
  decoded_insn_t functional_icache[FUNCTIONAL_ICACHE_SIZE];

  static fast_insn_func_t insn_funcs[256];

  sim_t* sim;
  mmu_t* mmu;

  processor_t();
  ~processor_t();

  void execute();
  insn_return_t execute_insn(insn_return_t);
  void execute_trap(trap_t trap);
  void init(sim_t* s, uint32_t id, mmu_t* mmu);
  void setCWP(uint32_t cwp);
  void flush_icache();


  // write the windowed register file
  void wrreg(uint32_t regnum, uint32_t value)
  { 
    debug_assert(regnum < 32);
    *regaddr[regnum] = value;
  }
 
  // read the windowed register file
  uint32_t reg(uint32_t regnum)
  {
    debug_assert(regnum < 32);
    return *regaddr[regnum];
  } 
 
  // evaluate the right-hand (or address) operand of a type-3 instruction
  uint32_t rhs(uint32_t insn)
  {
    uint32_t r = RS2VAL;
    uint32_t imm = SIMM13;
    if(HAS_IMMEDIATE)
      r = imm;
    return r;
  }

  insn_return_t insn_func_undefined(uint32_t insn);

  #include "insns.prototypes.gh"
};

#endif
