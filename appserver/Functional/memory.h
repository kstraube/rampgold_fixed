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


#ifndef _MEMORY_H
#define _MEMORY_H

#include <endian.h>
#include <stdint.h>
#include <Common/host.h>
#include "targetconfig.h"
#include "traps.h"
#include "srmmu.h"

typedef uint64_t paddr;
typedef uint32_t vaddr;

struct sim_t;
struct processor_t;

struct pdc_entry
{
  paddr ppn;
  vaddr vpn;
  uint32_t ctx;
  uint8_t access[16];
};

#define PDC_SIZE 256

struct mmu_t
{
  sim_t* sim;
  processor_t* proc;
  uint8_t* mem;
  uint64_t memsize;

  uint32_t control_reg;
  uint32_t context_table_ptr;
  uint32_t context_reg;
  uint32_t fault_status_reg;
  uint32_t fault_address_reg;
  
  mmu_t(sim_t* _sim, processor_t* _proc, uint8_t* _mem, uint64_t memsize);

  void flush_pdc();
  void update_pdc(vaddr addr, uint32_t pte, uint32_t level);

  void set_control_register(uint32_t val);
  void set_fault_status_reg(uint32_t pte, uint8_t level, vaddr addr, uint8_t access_type, bool is_supervisor);
  void set_fault_address_reg(uint32_t addr);
  bool check_privilege(uint32_t pte, bool is_fetch, bool is_write, bool is_supervisor);
  void probe(vaddr addr, uint32_t& pte, paddr& pte_addr, uint32_t& level);

  paddr translate(vaddr addr, uint8_t asi, bool is_fetch, bool is_write, bool is_supervisor)
  {
    #ifndef HAVE_MMU
      if(addr >= memsize)
        throw is_fetch ? trap_instruction_access_exception : trap_data_access_exception;
      return addr;
    #endif

    #if PDC_SIZE > 0
      uint8_t pdc_asi = asi + (is_write ? 2 : 0);

      vaddr vpn = addr >> 12;
      int pos = vpn & (PDC_SIZE-1);

      if(vpn == pdc[pos].vpn && pdc[pos].access[pdc_asi] && pdc[pos].ctx == context_reg)
        return pdc[pos].ppn | (addr & 0xFFF);
    #endif

    return translate_probe(addr,asi,is_fetch,is_write,is_supervisor);
  }

  paddr translate_probe(vaddr addr, uint8_t asi, bool is_fetch, bool is_write, bool is_supervisor);

  void store_byte(vaddr addr, uint8_t val, uint8_t asi);
  void store_halfword(vaddr addr, uint16_t val, uint8_t asi);
  void store_word(vaddr addr, uint32_t val, uint8_t asi);
  void store_dword(vaddr addr, uint64_t val, uint8_t asi);

  uint8_t load_byte(vaddr addr, uint8_t asi);
  uint16_t load_halfword(vaddr addr, uint8_t asi);
  uint32_t load_word(vaddr addr, uint8_t asi);
  uint64_t load_dword(vaddr addr, uint8_t asi);

  // the _fast functions can only be used with
  // ASIs 0x8-0xB.  consider yourself warned!

  void store_byte_fast(vaddr addr, uint8_t val, bool is_supervisor)
  {
    paddr pa = translate(addr,0xA+is_supervisor,false,true,is_supervisor);
    *(uint8_t*)(mem+pa) = (val);
  }

  void store_halfword_fast(vaddr addr, uint16_t val, bool is_supervisor)
  {
    paddr pa = translate(addr,0xA+is_supervisor,false,true,is_supervisor);
    *(uint16_t*)(mem+pa) = htobe16(val);
  }

  void store_word_fast(vaddr addr, uint32_t val, bool is_supervisor)
  {
    paddr pa = translate(addr,0xA+is_supervisor,false,true,is_supervisor);
    *(uint32_t*)(mem+pa) = htobe32(val);
  }

  void store_dword_fast(vaddr addr, uint64_t val, bool is_supervisor)
  {
    paddr pa = translate(addr,0xA+is_supervisor,false,true,is_supervisor);
    *(uint64_t*)(mem+pa) = htobe64(val);
  }

  uint8_t load_byte_fast(vaddr addr, bool is_supervisor)
  {
    paddr pa = translate(addr,0xA+is_supervisor,false,false,is_supervisor);
    return *(uint8_t*)(mem+pa);
  }

  uint16_t load_halfword_fast(vaddr addr, bool is_supervisor)
  {
    paddr pa = translate(addr,0xA+is_supervisor,false,false,is_supervisor);
    return be16toh(*(uint16_t*)(mem+pa));
  }

  uint32_t load_word_fast(vaddr addr, bool is_supervisor)
  {
    paddr pa = translate(addr,0xA+is_supervisor,false,false,is_supervisor);
    return be32toh(*(uint32_t*)(mem+pa));
  }

  uint32_t load_instruction_word_fast(vaddr addr, bool is_supervisor)
  {
    paddr pa = translate(addr,0x8+is_supervisor,true,false,is_supervisor);
    return be32toh(*(uint32_t*)(mem+pa));
  }

  uint64_t load_dword_fast(vaddr addr, bool is_supervisor)
  {
    paddr pa = translate(addr,0xA+is_supervisor,false,false,is_supervisor);
    return be64toh(*(uint64_t*)(mem+pa));
  }

  void store_asi3(vaddr addr, uint32_t val);
  uint32_t load_asi3(vaddr addr);
  void store_asi4(vaddr addr, uint32_t val);
  uint32_t load_asi4(vaddr addr);

  static const int offset_mask[4];
  static const int NCONTEXTS = 8;
  pdc_entry pdc[PDC_SIZE];
  uint32_t pdc_lfsr;
};

#endif
