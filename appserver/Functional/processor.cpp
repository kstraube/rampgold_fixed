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


#include <queue>
#include "fpu.h"
#include "cache.h"
#include "processor.h"
#include "decode.h"
#include "opcodes.h"
#include "condcodes.h"
#include "sim.h"
#include "disassemble.h"
#include <cstring>
#include <Common/util.h>

processor_t::processor_t()
{
  fpu = new fpu_t;
}

processor_t::~processor_t()
{
  delete fpu;
}

void processor_t::init(sim_t* s, uint32_t _id, mmu_t* _mmu)
{
  sim = s;
  id = _id;
  timer_period = 0;
  ipi_pending = false;
  nretired = 0;
  ncti = 0;
  nfpop = 0;
  nld = 0;
  nst = 0;
  namo = 0;
  ntrap = 0;
  nshift = 0;
  nmul = 0;
  ndiv = 0;
  nldhit = 0;
  nsthit = 0;
  nicmiss = 0;
  nfpop = 0;
  IRL = 0;
  PC = 0;
  nPC = 1;
  mmu = _mmu;

  stall = 0;

  CSR = 0;
  TBR = 0;
  memset(&PSR,0,sizeof(PSR));
  memset(regfile,0,sizeof(regfile));
  memset(creg,0,sizeof(creg));
  memset(ASR,0,sizeof(ASR));

  ASR[13] = sim->memsize >> 20; // asr13 == memsize in MB
  ASR[14] = sim->nprocs;   // asr14 == number of cores
  ASR[15] = id;            // asr15 == my core id

  #ifdef CACHE_SIM
    dcache = icache = new magic_memory_t;
    icache = new cache_t(this,"I$",1,32768,64,2,new deterministic_memory_t(11));
    //memory_t* privl2 = new cache_t(this,"L2D",8,262144,64,8,new deterministic_memory_t(32));
    //dcache = new cache_t(this,"L1D",1,32768,64,2,privl2);
  #endif

  setCWP(0);
  WIM = 0;
  PSR.impl_ver = 0xf2; // useful for (attempting to) boot Linux
  PSR.S = 1;
  PSR.ET = 0;
  Y = 0;

  // Initialize the table of pointers to instruction functions.
  // By default, all opcodes are undefined.
  for(uint32_t i = 0; i < sizeof(insn_funcs)/sizeof(insn_funcs[0]); i++)
    insn_funcs[i] = &processor_t::insn_func_undefined;

  // Load in the table of opcode pointers
  #include "insns.ptrtable.gh"

  flush_icache();
}

// Execute a few instructions
void processor_t::execute()
{
  // if the cache model told us to stall, do so
  if(stall)
  {
    if(stall > 0)
      stall--;
    // else, we're in error mode
    return;
  }

  // check for IPI
  if(IRL < 14 && ipi_pending)
    IRL = 14;

  // check for timer interrupt
  if(IRL < 10 && timer_period && (sim->cycle & (timer_period-1)) == 0)
    IRL = 10;

  // check for active message receipt
  if(IRL < 8 && mailbox.valid)
    IRL = 8;

  // might take an interrupt
  if(PSR.ET && (IRL == 15 || IRL > PSR.PIL))
  {
    execute_trap(trap_t(0x10 + IRL));
    IRL = 0;
    return;
  }

  // try to execute INSNS_PER_CYCLE instructions.
  // end early if one traps.

  insn_return_t fetchPC = {PC,nPC};
  int insns_this_cycle;
  try
  {
    for(insns_this_cycle = 0; insns_this_cycle < INSNS_PER_CYCLE; insns_this_cycle++)
      fetchPC = execute_insn(fetchPC);
    PC = fetchPC.PC;
    nPC = fetchPC.nPC;
  }
  catch(trap_t trp)
  {
    PC = fetchPC.PC;
    nPC = fetchPC.nPC;

    switch(trp)
    {
      case trap_replay: break;
      case trap_nofault: PC = nPC; nPC++; break;
      default: execute_trap(trp); break;
    }
  }
  nretired += insns_this_cycle;
}

void processor_t::execute_trap(trap_t trap)
{
  debug_assert(trap > 0 && trap < 256);
  ntrap++;

  const char* trap_name = get_trap_name(trap);

  if(!sim->silent)
    debug_notice(4,"procs[%3d].execute_trap(%s)",id,trap_name);

  if(PSR.ET == 0)
  {
    warn("Cycle %lld: %s caused core %d to enter error mode!",sim->cycle,trap_name,id);
    stall = -1;

    sim->lock();
    for(unsigned int i = 0; i < sim->nprocs; i++)
      if(sim->procs[i].stall != -1)
        return;
    sim->unlock();
    error("All cores have entered error mode; aborting!");
  }

  PSR.ET = 0;
  PSR.PS = PSR.S;
  PSR.S = 1;
  setCWP(PSR.CWP > 0 ? PSR.CWP-1 : NWINDOWS-1); // no overflow test!
  wrreg(17, 4*PC);
  wrreg(18, 4*nPC);

  // active message receipt
  if(trap == 0x18)
  {
    debug_assert(mailbox.valid);
    
    spinlock_lock(&mailbox.lock);
    active_message_t am = mailbox;
    mailbox.valid = 0;
    spinlock_unlock(&mailbox.lock);

    wrreg(16,am.srcid);
    wrreg(19,am.PC);
    wrreg(20,am.arg0);
    wrreg(21,am.arg1);
  }

  // ipi receipt
  if(trap == 0x1E)
    ipi_pending = false;

  TBR = (TBR & ~0xFFF) | ((uint32_t)trap) << 4;
  PC = TBR/4;
  nPC = PC+1;
}

#pragma weak insn_retired_callback
extern "C"
void insn_retired_callback(int id, uint32_t insn, uint32_t pc, uint32_t npc, uint32_t mem_addr)
{
}

inline insn_return_t processor_t::execute_insn(insn_return_t fetchPC)
{
  int idx = fetchPC.PC & (FUNCTIONAL_ICACHE_SIZE-1);
  if(functional_icache[idx].tag != fetchPC.PC)
  {
    #ifdef CACHE_SIM
      // this is a bit sketchy but improves performance dramatically:
      // only check for target icache misses on functional icache misses
      int latency = icache->read(this,4*fetchPC.PC);
      stall += latency-1;
      nicmiss += (latency > 1);
    #endif

    uint32_t insn = mmu->load_instruction_word_fast(4*fetchPC.PC,PSR.S);
    functional_icache[idx].func = insn_funcs[opcode(insn)];
    functional_icache[idx].tag = fetchPC.PC;
    functional_icache[idx].insn = insn;
  }

  fast_insn_func_t insn_func = functional_icache[idx].func;
  uint32_t insn = functional_icache[idx].insn;

  #if DEBUG_LEVEL >= 4
    char buf[32];
    if(!sim->silent)
    {
      fprintf(stdout,"procs[%3d].execute_insn(0x%08x, ",id,4*fetchPC.PC);
      disassemble(insn,4*fetchPC.PC,buf);
      fprintf(stdout,"%s)\n",buf);
    }
    insn_return_t old_pc = fetchPC;
    uint32_t effective_address = EFFECTIVE_ADDRESS;
  #endif

  insn_return_t ret = insn_func(this,fetchPC,insn);
  regfile[0] = 0;

  #if DEBUG_LEVEL >= 4
    insn_retired_callback(id,insn,4*old_pc.PC,4*old_pc.nPC,effective_address);
  #endif

  return ret;
}

void processor_t::setCWP(uint32_t cwp)
{
  PSR.CWP = cwp;

  for(int r = 0; r < 8; r++)
    regaddr[r] = &regfile[r];

  int offset = 16*cwp;
  for(int r = 8; r < 24; r++)
    regaddr[r] = &regfile[r+offset];

  if(cwp == NWINDOWS-1)
    offset = -16;
  for(int r = 24; r < 32; r++)
    regaddr[r] = &regfile[r+offset];
}

// flush the functional instruction cache
void processor_t::flush_icache()
{
  for(int i = 0; i < FUNCTIONAL_ICACHE_SIZE; i++)
    functional_icache[i].tag = -1;
}

// the instruction-function for undefined opcodes
insn_return_t processor_t::insn_func_undefined(uint32_t insn)
{
  throw trap_illegal_instruction;
}

fast_insn_func_t processor_t::insn_funcs[256];

#include "insns.def"
