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


#include <string>
#include <termios.h>
#include <stdio.h>
#include "fpu.h"
#include "processor.h"
#include <Common/util.h>
#include "sim.h"
using namespace std;

string prompt()
{
  struct termios termios;
  tcgetattr(1,&termios);

  putchar(':');

  string s;
  while(1)
  {
    char ch = getchar();

    if(ch == 0x7F)
    {
      if(s.length())
      {
        s.resize(s.length()-1);
        putchar(0x08);
        putchar(' ');
        putchar(0x08);
      }
      continue;
    }

    if(!(termios.c_lflag & ECHO))
      putchar(ch);

    if(ch == '\n')
      break;

    s += ch;
  }

  return s;
}

// This is a very primitive debug interface.
// TODO make it not suck
void interactive_prompt(sim_t* s)
{
  const uint32_t INVALID = uint32_t(-1);
  static int rabbit = 0;
  static uint32_t untilproc = INVALID;
  static uint32_t untilpc = INVALID;
  static uint32_t untilmemaddr = INVALID;
  static uint32_t untilmemval = INVALID;
  static uint32_t untilmemasi = INVALID;
  static uint32_t untilreg = INVALID;
  static uint32_t untilregval = INVALID;

  if(rabbit != 0)
  {
    try
    {
      if(untilproc != INVALID && untilpc != INVALID && s->procs[untilproc].PC*4 == untilpc)
      {
        s->silent = rabbit = 0;
        untilproc = -1;
        untilpc = -1;
      }
      else if(untilproc != INVALID && untilmemaddr != INVALID && s->procs[untilproc].mmu->load_word(untilmemaddr,untilmemasi) == untilmemval)
      {
        s->silent = rabbit = 0;
        untilproc = -1;
        untilmemaddr = -1;
      }
      else if(untilproc != INVALID && untilreg != INVALID && s->procs[untilproc].reg(untilreg) == untilregval)
      {
        s->silent = rabbit = 0;
        untilproc = -1;
        untilreg = -1;
      }
    }
    catch(trap_t trp) {}

    if(s->silent > 0)
      s->silent--;
    if(rabbit > 0)
      rabbit--;
    return;
  }

  do
  {
    string str = prompt();
    uint32_t temp,proc,addr,val,asi;

    if(str.length() == 0)
      return;
    else if(str == "q")
      exit(0);
    else if(str == "r")
    {
      rabbit = -1;
      return;
    }
    else if(str == "rs")
    {
      s->silent = rabbit = -1;
      return;
    }
    else if(sscanf(str.c_str(),"r %d",&temp) == 1 && temp > 0 || sscanf(str.c_str(),"r %d",&temp) == 1 && temp > 0)
    {
      rabbit = temp-1;
      return;
    }
    else if(sscanf(str.c_str(),"rs %d",&temp) == 1 && temp > 0)
    {
      s->silent = rabbit = temp-1;
      return;
    }
    else if(sscanf(str.c_str(),"until pc %d %x",&proc,&addr) == 2 && proc < s->nprocs)
    {
      s->silent = rabbit = -1;
      untilproc = proc;
      untilpc = addr;
      return;
    }
    else if(sscanf(str.c_str(),"until mem %x %x",&addr,&val) == 2)
    {
      s->silent = rabbit = -1;
      untilproc = 0;
      untilmemaddr = addr;
      untilmemval = val;
      untilmemasi = 0x0B;
      return;
    }
    else if(sscanf(str.c_str(),"until asi %d %x %x %x",&proc,&asi,&addr,&val) == 4 && proc < s->nprocs && asi <= 0xFF)
    {
      s->silent = rabbit = -1;
      untilproc = proc;
      untilmemaddr = addr;
      untilmemval = val;
      untilmemasi = asi;
      return;
    }
    else if(sscanf(str.c_str(),"until reg %d %d %x",&proc,&addr,&val) == 3 && proc < s->nprocs)
    {
      s->silent = rabbit = -1;
      untilproc = proc;
      untilreg = addr;
      untilregval = val;
      return;
    }
    else if(sscanf(str.c_str(),"reg %d %d",&proc,&addr) == 2 && proc < s->nprocs && addr < 32)
    {
      uint32_t r = s->procs[proc].reg(addr);
      printf("%02x %02x %02x %02x\n",(r>>24)&0xFF,(r>>16)&0xFF,(r>>8)&0xFF,r&0xFF);
    }
  #if defined(HAVE_FPU)
    else if(sscanf(str.c_str(),"fregs %d %d",&proc,&addr) == 2 && proc < s->nprocs && addr < 32)
    {
      uint32_t r = s->procs[proc].fpu->reg(addr);
      printf("%f\n",*(float*)&r);
    }
    else if(sscanf(str.c_str(),"fregd %d %d",&proc,&addr) == 2 && proc < s->nprocs && addr < 32 && !(addr & 1))
    {
      uint32_t r = s->procs[proc].fpu->reg(addr);
      uint64_t q = (((uint64_t)r)<<32) | s->procs[proc].fpu->reg(addr+1);
      printf("%08x %016llx\n",r,q);
      printf("%f\n",*(double*)&q);
    }
  #endif
    else if(sscanf(str.c_str(),"wim %d",&proc) == 1 && proc < s->nprocs)
    {
      uint32_t r = s->procs[proc].WIM;
      printf("%02x %02x %02x %02x\n",(r>>24)&0xFF,(r>>16)&0xFF,(r>>8)&0xFF,r&0xFF);
    }
    else if(sscanf(str.c_str(),"int %d %x",&proc,&temp) == 2 && proc < s->nprocs)
    {
      s->procs[proc].IRL = temp;
    }
    else if(sscanf(str.c_str(),"psr %d",&proc) == 1 && proc < s->nprocs)
    {
      uint32_t r = s->procs[proc].PSR.get();
      printf("%02x %02x %02x %02x\n",(r>>24)&0xFF,(r>>16)&0xFF,(r>>8)&0xFF,r&0xFF);
    }
    else if(sscanf(str.c_str(),"pc %d",&proc) == 1 && proc < s->nprocs)
    {
      uint32_t r = s->procs[proc].PC*4;
      printf("%02x %02x %02x %02x\n",(r>>24)&0xFF,(r>>16)&0xFF,(r>>8)&0xFF,r&0xFF);
    }
    else if(sscanf(str.c_str(),"npc %d",&proc) == 1 && proc < s->nprocs)
    {
      uint32_t r = s->procs[proc].nPC*4;
      printf("%02x %02x %02x %02x\n",(r>>24)&0xFF,(r>>16)&0xFF,(r>>8)&0xFF,r&0xFF);
    }
    else if(sscanf(str.c_str(),"str %x",&addr) == 1)
    {
      while(1)
      {
        uint8_t b = s->procs[0].mmu->load_byte(addr++,0x0B);
        if(b == 0)
          break;
        printf("%c",b);
      }
      printf("\n");
    }
    else if(sscanf(str.c_str(),"mem %x",&addr) == 1)
    {
      int align = addr % 4 == 0 ? 4 : (addr % 2 == 0 ? 2 : 1);
      for(int i = 0; i < align; i++)
      {
        try
        {
          uint8_t b = s->procs[0].mmu->load_byte(addr+i,0x0B);
          printf("%02x ",b);
        }
        catch(trap_t trp) {}
      }
      printf("\n");
    }
    else if(sscanf(str.c_str(),"asi %d %x %x",&proc,&asi,&addr) == 3 && proc < s->nprocs && asi <= 0xFF && addr % 4 == 0)
    {
      try
      {
        uint32_t w = s->procs[proc].mmu->load_word(addr,asi);
        for(int i = 3; i >= 0; i--)
          printf("%02x ",(w >> (8*i))&0xFF);
        printf("\n");
      }
      catch(trap_t trp) {}
    }
  }
  while(true);
}
