/* Author: Andrew Waterman
 *     Parallel Computing Laboratory
 *     Electrical Engineering and Computer Sciences
 *     University of California, Berkeley
 *
 * Copyright (c) 2008, The Regents of the University of California.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *   * Redistributions of source code must retain the above copyright
 *     notice, this list of conditions and the following disclaimer.
 *   * Redistributions in binary form must reproduce the above copyright
 *     notice, this list of conditions and the following disclaimer in the
 *     documentation and/or other materials provided with the distribution.
 *   * Neither the name of the University of California, Berkeley nor the
 *     names of its contributors may be used to endorse or promote products
 *     derived from this software without specific prior written permission.
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

#include "memif_sparcfs.h"
#include "memory.h"
#include "sim.h"
#include "processor.h"
#include <Common/host.h>

memif_sparcfs_t::memif_sparcfs_t(sim_t* _sim)
{
  sim = _sim;
}

uint32_t memif_sparcfs_t::read_chunk_align()
{
  return 4;
}

uint32_t memif_sparcfs_t::read_chunk_min_size()
{
  return 4;
}

uint32_t memif_sparcfs_t::read_chunk_max_size()
{
  return 4;
}

uint32_t memif_sparcfs_t::write_chunk_align()
{
  return 4;
}

uint32_t memif_sparcfs_t::write_chunk_min_size()
{
  return 4;
}

uint32_t memif_sparcfs_t::write_chunk_max_size()
{
  return 4;
}

memif_t::error memif_sparcfs_t::read_chunk(uint32_t addr, uint32_t len, uint8_t* bytes, uint8_t asi)
{
  uint32_t word;
  memif_t::error res = read_uint32(addr,&word,asi);
  bytes[0] = word >> 24; bytes[1] = word >> 16;
  bytes[2] = word >> 8;  bytes[3] = word;
  return res;
}

memif_t::error memif_sparcfs_t::write_chunk(uint32_t addr, uint32_t len, const uint8_t* bytes, uint8_t asi)
{
  uint32_t word = (bytes[0] << 24) | (bytes[1] << 16) | (bytes[2] << 8) | bytes[3];
  return write_uint32(addr,word,asi);
}

memif_t::error
memif_sparcfs_t::read_uint32(uint32_t addr, uint32_t* word, uint8_t asi)
{
  if(!sim->procs)
    return memif_t::Invalid;

  try
  {
    *word = sim->procs[0].mmu->load_word((vaddr)addr,asi);
    return memif_t::OK;
  }
  catch(trap_t trp)
  {
    return memif_t::Invalid;
  }
}

memif_t::error
memif_sparcfs_t::write_uint32(uint32_t addr, uint32_t word, uint8_t asi)
{
  if(!sim->procs)
    return memif_t::Invalid;

  try
  {
    sim->procs[0].mmu->store_word((vaddr)addr,word,asi);
    return memif_t::OK;
  }
  catch(trap_t trp)
  {
    return memif_t::Invalid;
  }
}
