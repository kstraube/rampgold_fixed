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


#ifndef _DECODE_H
#define _DECODE_H

#include <string.h>
#include <stdint.h>

#define RD                ((insn >> 25) & 0x1F)
#define RS1               ((insn >> 14) & 0x1F)
#define COND              ((insn >> 25) & 0xF)
#define ASI               ((insn >>  5) & 0xFF)
#define OP2               ((insn >> 22) & 0x7)
#define OP3               ((insn >> 19) & 0x3F)
#define RS2               ((insn      ) & 0x1F)
#define DISP30            ((insn      ) & 0x3FFFFFFF)
#define IMM22             ((insn      ) & 0x007FFFFF)
#define ANNUL             ((insn      ) & 0x20000000)
#define HAS_IMMEDIATE     ((insn      ) & 0x2000)
#define SIMM13            ((int32_t)(insn << 19) >> 19)
#define DISP22            ((int32_t)(insn << 10) >> 10)
#define OP                ((insn >> 30))
#define RS1VAL            (reg(RS1))
#define RS2VAL            (reg(RS2))
#define RDVAL             (reg(RD))
#define RHSVAL            (rhs(insn))
#define EFFECTIVE_ADDRESS (RS1VAL + RHSVAL)
#define Y                 (ASR[0])

#define DEFINE_INSN(opcode) insn_return_t processor_t::insn_func_##opcode(insn_return_t fetchPC, uint32_t insn) {
#define END_CTI(opcode) return fetchPC; }
#define END_INSN(opcode) fetchPC.PC = fetchPC.nPC; fetchPC.nPC++; END_CTI(opcode)

#define SETICC(n,z,v,c) do { PSR.icc = !!(n)<<3 | !!(z)<<2 | !!(v)<<1 | !!(c); } while(0)
#define SETICC_ADD(left,right,val) SETICC((val) >> 31, (val) == 0, (((left) & (right) & ~(val)) | (~(left) & ~(right) & (val))) >> 31, (((left) & (right)) | (~(val) & ((left) | (right)))) >> 31)
#define SETICC_SUB(left,right,val) SETICC((val) >> 31, (val) == 0, (((left) & ~(right) & ~(val)) | (~(left) & (right) & (val))) >> 31, ((~(left) & (right)) | ((val) & (~(left) | (right)))) >> 31)
#define SETICC_LOGIC(val) SETICC((val) >> 31, (val) == 0, 0, 0)

#define BYTEMASK(addr,size) ((1<<(size))-1 << (addr)%8)
#ifdef DEBUG_MODE
  #include <assert.h>
  #include <stdio.h>
  #include <stdlib.h>
  #include <Common/util.h>
  #define trace(name,bm,addr,rs1,rs2,rs3,rd) do { if(sim->trace) trace2(sim->trace_start,sim->trace,name,bm,addr,rs1,rs2,rs3,rd); } while(0)
  inline void trace2(int trace_start, int trace_size, const char* name, uint8_t bytemask, uint32_t addr, uint32_t rs1, uint32_t rs2, uint32_t rs3, uint32_t rd)
  {
    static FILE* _tracefile = NULL;

    static int pos = 0;
    if(pos < trace_start)
    {
      pos++;
      return;
    }
    if(pos == trace_start+trace_size)
    {
      if(_tracefile)
      {
        fclose(_tracefile);
        exit(0);
      }
      _tracefile = NULL;
      return;
    }
    pos++;

    assert(_tracefile || (_tracefile = fopen("trace.out","w")));

    //fprintf(_tracefile,"%-8s %08x %02x %02x %02x %02x\n",name,addr,rs1,rs2,rs3,rd);
    char type;
    if(strcmp(name,"ld") == 0)
      type = 0;
    else if(strcmp(name,"st") == 0)
      type = 1;
    else if(strcmp(name,"swap") == 0)
      type = 2;
    else if(strcmp(name,"alu") == 0)
      type = 3;
    else
      error("unknown trace type %s!",name);

    addr &= ~0x7;

    fwrite(&type,1,1,_tracefile);
    fwrite(&bytemask,1,1,_tracefile);
    fwrite(&addr,sizeof(addr),1,_tracefile);
    fwrite(&rs1,1,1,_tracefile);
    fwrite(&rs2,1,1,_tracefile);
    fwrite(&rs3,1,1,_tracefile);
    fwrite(&rd, 1,1,_tracefile);
  }
#else
  #define trace(name,bm,addr,rs1,rs2,rs3,rd) do { } while(0)
#endif

#define pregnum(cwp,r) ((cwp) == NWINDOWS ? 16*NWINDOWS+8+(r) : ((r) < 8 ? (r) : (8+((r)-8+16*(cwp))%(16*NWINDOWS))))
#define trace_alu() trace("alu",0,0,pregnum(PSR.CWP,RS1),pregnum(PSR.CWP,HAS_IMMEDIATE?0:RS2),0,pregnum(PSR.CWP,RD))

#endif
