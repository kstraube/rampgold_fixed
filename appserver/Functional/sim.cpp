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


#include "processor.h"
#include "iobus.h"
#include "sim.h"
#include <Common/util.h>
#include <string.h>

void* sim_threadfunc(void* arg)
{
  int hostproc = ((thread_data*)arg)->hostproc;
  sim_t* sim = ((thread_data*)arg)->sim;
  while(true)
  {
    sim->barrier.wait(hostproc);
    sim->tick(hostproc);
  }
  return NULL;
}

sim_t::sim_t()
 : memif(this), barrier(HOSTPROCS)
{
  cycle = 0;
  trace = 0;
  trace_start = 0;

  nprocs = 0;
  mem = NULL;
  memsize = 0;
  procs = NULL;
  iobus = new iobus_functional_t(this);

  entry_point = 0xF0000000;
  magicmemaddr = 0xFFFFFFFC;
  silent = 0;
  interactive = 1;
  lck = SPINLOCK_INIT;
  memset(&lck_holder,0xFF,sizeof(lck_holder));
  lck_depth = 0;

  threads = new thread_data[HOSTPROCS];
  for(int i = 1; i < HOSTPROCS; i++)
  {
    threads[i].sim = this;
    threads[i].hostproc = i;
    pthread_create(&threads[i].context,NULL,&sim_threadfunc,&threads[i]);
  }
}

sim_t::~sim_t()
{
  delete [] procs;
  delete [] threads;
  delete [] mem;
}

void sim_t::set_memsize(uint64_t size)
{
  try
  {
    // dword alignment to avoid terrible performance
    mem = (uint8_t*)new uint64_t[size/((unsigned int)8)];
    memsize = size;
  }
  catch(...)
  {
    error("Could not allocate physical memory (%llu bytes)!",size);
  }
}

int sim_t::set_num_cores(int num)
{
  if(!mem)
    throw std::logic_error("You must call sim_t::set_memsize() before sim_t::set_num_cores()!");

  nprocs = num;
  procs = new processor_t[num];
  for(int i = 0; i < num; i++)
    procs[i].init(this,i,new mmu_t(this,&procs[i],mem,memsize));
  return num;
}

int sim_t::get_tohost()
{
  try
  {
    return procs[0].mmu->load_word(magicmemaddr,0x1E);
  }
  catch(trap_t trp)
  {
    //error("Reading the tohost register would have faulted!");
  }
}

void sim_t::set_fromhost(int val)
{
  try
  {
    procs[0].mmu->store_word(magicmemaddr+28,val,0x1E);
  }
  catch(trap_t trp)
  {
    //error("Writing the fromhost register would have faulted!");
  }
}

void sim_t::run_for_a_while()
{
  for(int i = 0; i < 32; i++)
  {
    #if HOSTPROCS > 1
      barrier.wait(0);
    #endif
    tick(0);
  }
}

int sim_t::run_to_tohost(int orig_tohost)
{
  if(!procs)
    throw std::logic_error("You must call sim_t::set_num_cores() before sim_t::run_to_tohost()!");

  do 
  {
    run_for_a_while();
  }
  while(orig_tohost == get_tohost());

  return get_tohost();
}

void sim_t::tick(int hostproc)
{
  #ifdef INTERACTIVE
    if(interactive)
      interactive_prompt(this);
  #endif

  if(hostproc == 0 && !silent)
    debug_notice(4,"cycle %lld",cycle);

  for(int i = nprocs*hostproc/HOSTPROCS; i < nprocs && i < nprocs*(hostproc+1)/HOSTPROCS; i++)
  {
    for(int j = 0; j < CYCLES_PER_BARRIER; j++)
      procs[i].execute();
  }

  if(hostproc == 0)
    cycle += INSNS_PER_CYCLE;
}

void sim_t::lock()
{
  if(pthread_equal(pthread_self(),lck_holder))
    lck_depth++;
  else
  {
    spinlock_lock(&lck);
    lck_holder = pthread_self();
    lck_depth = 1;
  }
}

void sim_t::unlock()
{
  if(!pthread_equal(pthread_self(),lck_holder))
    error("I tried to release a lock that isn't mine!");
  else
  {
    lck_depth--;
    if(lck_depth == 0)
    {
      memset(&lck_holder,0xFF,sizeof(lck_holder));
      spinlock_unlock(&lck);
    }
  }
}
