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

#ifndef _CACHE_H
#define _CACHE_H

#include <vector>
#include <utility>
#include "memory.h"

struct processor_t;

class memory_t
{
public:
  virtual int read(processor_t* p,paddr addr) = 0;
  virtual int write(processor_t* p, paddr addr) = 0;
  virtual void tick() = 0;
  virtual ~memory_t() {};
};

class magic_memory_t : public memory_t
{
public:
  magic_memory_t() {}
  int read(processor_t* p, paddr addr) { return 1; }
  int write(processor_t* p, paddr addr) { return 1; }
  void tick() {}
};

class deterministic_memory_t : public memory_t
{
public:
  deterministic_memory_t(int latency) { this->latency = latency; }
  int read(processor_t* p, paddr addr) { return latency; }
  int write(processor_t* p, paddr addr) { return latency; }
  void tick() {}
private:
  int latency;
};

class dram_t : public memory_t
{
public:
  dram_t(uint32_t latency, uint64_t capacity, uint32_t nbanks, uint32_t rowsize);
  ~dram_t();
  int read(processor_t* p,paddr addr);
  int write(processor_t* p, paddr addr);
  void tick();

private:
  uint32_t latency;
  uint64_t capacity;
  uint32_t nbanks;
  uint32_t rowsize;

  int rows_per_bank;
  int* bank_row_open;
  int* bank_busy;
  std::vector<std::pair<int,int> > q;

  uint64_t row_hit;
  uint64_t row_closed;
  uint64_t row_conflict;
};

const int TAG_BITS = 30;

struct line_t
{
  unsigned tag : TAG_BITS;
  unsigned valid : 1;
  unsigned dirty : 1;
};

class simple_cache_t : public memory_t
{
public:
  simple_cache_t(int nprocs, uint32_t is_private, uint32_t offset_bits, uint32_t tag_mask, uint32_t target_index_mask, uint32_t tag_ram_index_mask, uint32_t bank_mux, uint32_t bank_shift, uint32_t misspenalty, memory_t* next_level);
  int lfsr();
  int read(processor_t* p, paddr addr);
  int write(processor_t* p, paddr addr);
  void tick() {}

  static const int L1D_MAX_TAGS = 16384;
  static const int L1D_MAX_ASSOC = 16;
  static const int L1D_MIN_OFFSET_BITS = 4; // change at your own risk!!
  static const int L1D_MAX_OFFSET_BITS = 7;

  static const int L1I_MAX_TAGS = 16384;
  static const int L1I_MAX_ASSOC = 16;
  static const int L1I_MIN_OFFSET_BITS = 4; // change at your own risk!!
  static const int L1I_MAX_OFFSET_BITS = 7;

  static const int L2_MAX_TAGS = 65536;
  static const int L2_MAX_ASSOC = 64;
  static const int L2_MIN_OFFSET_BITS = 4; // change at your own risk!!
  static const int L2_MAX_OFFSET_BITS = 7;
  static const int L2_MAX_NUM_BANKS = 4;

  static const int MAX_PARTITIONS = 8;
  static const int MAX_CORES = 64;

  void hella_asserts()
  {
    static_assert(L1D_MAX_ASSOC <= L2_MAX_ASSOC);
    static_assert(L1D_MAX_TAGS/L1D_MAX_ASSOC <= L2_MAX_TAGS/L2_MAX_ASSOC);
    static_assert(L1D_MIN_OFFSET_BITS == L2_MIN_OFFSET_BITS);
    static_assert(L1D_MAX_OFFSET_BITS == L2_MAX_OFFSET_BITS);

    static_assert(L1I_MAX_ASSOC <= L2_MAX_ASSOC);
    static_assert(L1I_MAX_TAGS/L1I_MAX_ASSOC <= L2_MAX_TAGS/L2_MAX_ASSOC);
    static_assert(L1I_MIN_OFFSET_BITS == L2_MIN_OFFSET_BITS);
    static_assert(L1I_MAX_OFFSET_BITS == L2_MAX_OFFSET_BITS);
  }

private:
  int INDEX_MSB;
  uint16_t lfsr_state;
  uint32_t tags[L2_MAX_ASSOC][L2_MAX_TAGS/L2_MAX_ASSOC];

  uint32_t is_private;
  uint32_t misspenalty;
  uint32_t offset_bits;
  uint32_t tag_mask;
  uint32_t target_index_mask;
  uint32_t tag_ram_index_mask;
  uint32_t bank_mux;
  uint32_t bank_shift;
  memory_t* next_level;
};

class cache_t : public memory_t
{
public:
  cache_t(processor_t* proc, const char* name, uint32_t latency, uint32_t capacity, uint32_t linesize, uint32_t assoc, memory_t* next_level);
  ~cache_t();

  int read(processor_t* p,paddr addr);
  int write(processor_t* p, paddr addr);
  void tick() {}

private:
  bool access(processor_t* p, paddr addr, bool write);

  int get_replacement(int pos);
  void update_replacement(int pos, int way);

  static const int MAX_LINES = 1048576;
  line_t lines[MAX_LINES];
  int repl[MAX_LINES];
  memory_t* next_level;
  char* name;
  processor_t* proc;

  uint32_t latency;
  uint32_t linesize;
  uint32_t capacity;
  uint32_t nlines;
  uint32_t nsets;
  uint32_t assoc;
  uint32_t tagbits;
  uint32_t indexbits;
  uint32_t offsetbits;
  uint32_t assocbits;

  uint64_t read_hits;
  uint64_t read_misses;
  uint64_t write_hits;
  uint64_t write_misses;

  int timestamp;
};

#endif
