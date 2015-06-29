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


#ifndef _SIM_H
#define _SIM_H

#include <Common/host.h>
#include <Common/barrier.h>
#include <Common/htif.h>
#include <Common/properties.h>
#include "config.h"
#include "memif_sparcfs.h"
#include "memory.h"

extern "C" {
  #include <pthread.h>
}

struct processor_t;
struct iobus_t;
struct pte_t;
struct sim_t;
struct memory_t;

struct thread_data
{
  pthread_t context;
  sim_t* sim;
  int hostproc;
};

class sim_t : public htif_sparc_t
{
public:
  sim_t();
  ~sim_t();

  // host-target interface
  memif_t& lmem() { return memif; }
  void set_memsize(uint64_t size);
  int set_num_cores(int n);
  void set_reset(int val) {}
  void set_run(int val) {}
  int get_magicmemaddr() { return magicmemaddr; }
  void set_magicmemaddr(int addr) { magicmemaddr = addr; }
  long long get_cycle() { return cycle; }
  int get_tohost();
  void set_fromhost(int val);
  int run_to_tohost(int orig_tohost);
  void run_for_a_while();

  void tick(int hostproc = 0);

  friend class memif_sparcfs_t;
  friend class processor_t;
  friend class mmu_t;
  friend void* sim_threadfunc(void* arg);
  friend void interactive_prompt(sim_t* s);

public:
  memif_sparcfs_t memif;
  uint64_t cycle;
  processor_t* procs;
  iobus_t* iobus;
  int nprocs;
  uint8_t* mem;
  uint64_t memsize;
  vaddr entry_point;
  vaddr magicmemaddr;
  barrier_t barrier;
  thread_data* threads;
  spinlock_t lck;
  pthread_t lck_holder;
  int lck_depth;
  int silent;
  int interactive;
  int trace_start;
  int trace;
  
  void lock();
  void unlock();
};

typedef sim_t htif_sparcfs_t;

#endif
