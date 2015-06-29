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

#include <Common/util.h>
#include <cstring>
#include "cache.h"
#include "processor.h"
#include "sim.h"

cache_t::cache_t(processor_t* proc, const char* name, uint32_t latency, uint32_t capacity, uint32_t linesize, uint32_t assoc, memory_t* next_level)
{
  if(linesize == 0 || (linesize & (linesize-1)))
    error("Line size must be a power of 2!");
  if(assoc == 0 || (assoc & (assoc-1)))
    error("Associativity must be a power of 2!");
  if(capacity == 0 || (capacity & (capacity-1)) || capacity < linesize*assoc)
    error("Capacity must be a power of 2 and at least the size of one set!");

  memset(lines,0,sizeof(lines));
  memset(repl,0,sizeof(repl));

  this->proc = proc;
  this->latency = latency;
  this->name = strdup(name);
  this->next_level = next_level;

  this->linesize = linesize;
  this->assoc = assoc;
  this->capacity = capacity;
  this->nlines = capacity/linesize;
  this->nsets = this->nlines/assoc;

  for(offsetbits = 0; linesize >>= 1; offsetbits++);
  for(assocbits = 0; assoc >>= 1; assocbits++);
  indexbits = 0;
  for(int temp = this->nsets; temp >>= 1; indexbits++);

  tagbits = 8*sizeof(paddr) - offsetbits - indexbits;

  timestamp = 0;
}

cache_t::~cache_t()
{
  free(this->name);
}

void cache_t::update_replacement(int set, int way)
{
  repl[(set<<assocbits)+way] = ++timestamp;
}

int cache_t::get_replacement(int set)
{
  int oldest = 0;
  for(unsigned int i = 1; i < assoc; i++)
  {
    if(repl[(set<<assocbits)+i] < repl[(set<<assocbits)+oldest])
      oldest = i;
  }
  return oldest;
}

bool cache_t::access(processor_t* p, paddr addr, bool write)
{
  paddr set = (addr >> offsetbits) & (nsets-1);
  paddr pos = set << assocbits;

  bool have_invalid = false;
  int invalid = 0;
  bool found = false;
  int way = 0;

  for(unsigned int i = 0; i < assoc; i++)
  {
    if((addr >> offsetbits) == lines[pos+i].tag && lines[pos+i].valid)
    {
      found = true;
      way = i;
    }

    if(!lines[pos+i].valid)
    {
      have_invalid = true;
      invalid = i;
    }
  }

  if(!found)
  {
    int victim;

    if(have_invalid)
      victim = invalid;
    else
    {
      victim = get_replacement(set);

      if(lines[pos+victim].dirty)
        next_level->write(p, lines[pos+victim].tag << offsetbits);
    }

    lines[pos+victim].tag = addr >> offsetbits;
    lines[pos+victim].valid = 1;
    lines[pos+victim].dirty = 0;

    way = victim;
  }

  lines[pos+way].dirty |= write;
  update_replacement(set,way);  

  return found;
}

int cache_t::read(processor_t* p, paddr addr)
{
  if(access(p,addr,false))
  {
    read_hits++;
    return latency;
  }
  else
  {
    read_misses++;
    return latency+next_level->read(p, addr);
  }
}

int cache_t::write(processor_t* p, paddr addr)
{
  if(access(p,addr,true))
  {
    write_hits++;
    return latency;
  }
  else
  {
    write_misses++;
    return latency+next_level->write(p,addr);
  }
}

dram_t::dram_t(uint32_t latency, uint64_t capacity, uint32_t nbanks, uint32_t rowsize)
{
  this->latency = latency;
  this->capacity = capacity;
  this->nbanks = nbanks;
  this->rowsize = rowsize;
  this->rows_per_bank = capacity/(rowsize*nbanks);

  this->bank_row_open = new int[nbanks];
  this->bank_busy = new int[nbanks];
  for(unsigned int i = 0; i < nbanks; i++)
  {
    this->bank_row_open[i] = -1;
    this->bank_busy[i] = 0;
  }
}

dram_t::~dram_t()
{
  printf("DRAM:\n");
  printf("  Row hits:     %lld\n",row_hit);
  printf("  Row closed:   %lld\n",row_closed);
  printf("  Row conflict: %lld\n",row_conflict);

  delete [] bank_row_open;
  delete [] bank_busy;
}

int dram_t::read(processor_t* p, paddr addr)
{
  debug_assert(addr < capacity);

  int row = addr/rowsize;
  int bank = row % nbanks;
  row = row/nbanks;

  q.push_back(std::pair<int,int>(bank,row));

  return latency; // this is dumb, but fkit
}

int dram_t::write(processor_t* p, paddr addr)
{
  return read(p,addr);
}

void dram_t::tick()
{
  if(q.empty())
    return;

  int tcl = 10;
  int trcd = 5;
  int trp = 5;

  // this is a CAM in HW :-)
  for(size_t i = 0; i < q.size(); i++)
  {
    if(bank_row_open[q[i].first] == q[i].second && bank_busy[q[i].first] == 0)
    {
      bank_busy[q[i].first] = tcl;

      row_hit++;
      q.erase(q.begin()+i);
      return;
    }
  }

  for(size_t i = 0; i < q.size(); i++)
  {
    if(bank_row_open[q[i].first] == -1)
    {
      debug_assert(bank_busy[q[i].first] == 0);
      bank_busy[q[i].first] = trcd+tcl;
      bank_row_open[q[i].first] = q[i].second;

      row_closed++;
      q.erase(q.begin()+i);
      return;
    }
  }

  for(size_t i = 0; i < q.size(); i++)
  {
    if(bank_busy[q[i].first] == 0)
    {
      debug_assert(bank_row_open[q[i].first] != q[i].second);
      bank_row_open[q[i].first] = q[i].second;
      bank_busy[q[i].first] = trp+trcd+tcl;

      row_conflict++;
      q.erase(q.begin()+i);
      return;
    }
  }

  for(unsigned int i = 0; i < nbanks; i++)
    if(bank_busy[i] > 0)
      bank_busy[i]--;
}

simple_cache_t::simple_cache_t(int nprocs, uint32_t is_private, uint32_t offset_bits, uint32_t tag_mask, uint32_t target_index_mask, uint32_t tag_ram_index_mask, uint32_t bank_mux, uint32_t bank_shift, uint32_t misspenalty, memory_t* next_level)
{
  this->is_private = is_private;
  this->offset_bits = offset_bits;
  this->tag_mask = tag_mask;
  this->target_index_mask = target_index_mask;
  this->tag_ram_index_mask = tag_ram_index_mask;
  this->bank_mux = bank_mux;
  this->bank_shift = bank_shift;
  this->misspenalty = misspenalty;
  this->lfsr_state = 0x1;
  this->next_level = next_level;

  for(int i = 0; i < L2_MAX_ASSOC; i++)
    for(int j = 0; j < L2_MAX_TAGS/L2_MAX_ASSOC; j++)
      tags[i][j] = 0;

  int temp = L2_MAX_TAGS/L2_MAX_ASSOC;
  INDEX_MSB = 0;
  while(temp >>= 1) INDEX_MSB++;
}

int simple_cache_t::lfsr()
{
  int ret = lfsr_state & (L2_MAX_ASSOC-1);
  lfsr_state = (lfsr_state>>1) | ((((lfsr_state>>0)^(lfsr_state>>2)^(lfsr_state>>3)^(lfsr_state>>5))&1)<<15);
  return ret;
}

int simple_cache_t::read(processor_t* p, paddr addr)
{
  int index = 0;
  if(is_private&1)
    for(int i = 0; i < INDEX_MSB+1; i++)
      index |= ((p->id >> i) & 1) << (INDEX_MSB-i);

  paddr addr_sans_offset = addr>>(offset_bits+L2_MIN_OFFSET_BITS);
  index |= addr_sans_offset & tag_ram_index_mask;
  int target_index = addr_sans_offset & target_index_mask;

  for(int i = 0; i < L2_MAX_ASSOC; i++)
  {
    if(tags[i][index] == (addr & tag_mask))
    {
      //printf("hit  addr = %8x index = %4x bank = %2x tag = %8x wanttag = %8x\n",addr,index,i,tags[i][index],addr&tag_mask);
      //printf("hit\n");
      //printf("cache access %x - hit in bank %d\n",addr&tag_mask,i);
      return 1;
    }
  }

  //printf("miss\n");
  //printf("cache access %x - miss - replace into bank %d\n",addr&tag_mask,bank);

  int bank = ((bank_mux & lfsr()) | (~bank_mux & (target_index>>bank_shift))) & (L2_MAX_ASSOC-1);
  //printf("miss addr = %8x index = %4x bank = %2x tag = %8x wanttag = %8x\n",addr,index,bank,tags[bank][index],addr&tag_mask);

  tags[bank][index] = addr & tag_mask;
  return next_level->read(p,addr);
}

int simple_cache_t::write(processor_t* p, paddr addr)
{
  return read(p,addr);
}
