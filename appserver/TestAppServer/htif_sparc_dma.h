/* Author: Yunsup Lee
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

#ifndef __HTIF_SPARC_DMA_H
#define __HTIF_SPARC_DMA_H

#include <Common/htif.h>
#include <Common/properties.h>
#include "memif_sparc_dma.h"

class htif_sparc_dma_t : public htif_sparc_t
{
public:
  htif_sparc_dma_t();
  ~htif_sparc_dma_t();
  memif_t& lmem();
  int set_num_cores(int val);
  void set_memsize(uint64_t memsize);
  void set_reset(int val);
  void set_run(int val);
  int get_tohost();
  void set_fromhost(int val);
  long long get_cycle();
  int run_to_tohost(int origToHost);
  int get_magicmemaddr();
  void set_magicmemaddr(int addr);

protected:
  memif_sparc_dma_t* memif;
  
  virtual void run_for_a_while() = 0;

  int reset;
  int running;
  int magicmemaddr;
};

class htif_sparchw_dma_t : public htif_sparc_dma_t
{
public:
  htif_sparchw_dma_t(const properties_t& props);
  
protected:
  void run_for_a_while();
};

class htif_sparcvs_dma_t : public htif_sparc_dma_t
{
public:
  htif_sparcvs_dma_t(const properties_t& props);
  
protected:
  void run_for_a_while();
};

#endif // __htif_sparchw_dma_H
