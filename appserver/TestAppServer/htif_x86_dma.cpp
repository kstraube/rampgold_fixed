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

#include "htif_x86_dma.h"
#include <Common/host.h>
#include <Common/util.h>
#include <time.h>
#include <stdlib.h>


static void mac_to_string(long long hwaddr, char hwaddr_str[6])
{
  for(int i = 0; i < 6; i++)
    hwaddr_str[i] = (hwaddr >> (8*(5-i))) & 0xFF;
}

htif_x86_dma_t::htif_x86_dma_t(const properties_t& properties)
{
  char hwaddr_str[6];
  mac_to_string(properties.get_int("htif_x86_dma.hwaddr"),hwaddr_str);
  std::string eth_if = properties.get_string("htif_x86_dma.eth_if");

  memif = new memif_x86_dma_t(this,hwaddr_str,eth_if.c_str());

  reset = 0;
  running = 0;
}

void htif_x86_dma_t::set_memsize(uint64_t size)
{
}

htif_x86_dma_t::~htif_x86_dma_t()
{
  delete memif;
}

memif_t& htif_x86_dma_t::lmem()
{
  return *memif;
}

int htif_x86_dma_t::set_num_cores(int val)
{
  return 1;
}

int htif_x86_dma_t::get_tohost()
{
  int32_t reg;
  lmem().read_int32(magicmemaddr+0, &reg);
  return (int)reg;
}

void htif_x86_dma_t::set_fromhost(int val)
{
  lmem().write_int32(magicmemaddr+28, (int32_t)val);
}

int htif_x86_dma_t::get_magicmemaddr()
{
  return magicmemaddr;
}

long long htif_x86_dma_t::get_cycle()
{
  return 0;
}

int htif_x86_dma_t::run_to_tohost(int origToHost)
{
  int ret = origToHost;

  while (1)
  {
    ret = get_tohost();

    if (ret != origToHost)
      break;
    
    run_for_a_while();  
  }

  return ret;
}

void htif_x86_dma_t::set_magicmemaddr(int addr)
{
  magicmemaddr = addr;
}

void htif_x86_dma_t::run_for_a_while()
{
  usleep(500);
}
