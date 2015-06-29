/* Author: Andrew S. Waterman
 *         Parallel Computing Laboratory
 *         Electrical Engineering and Computer Sciences
 *         University of California, Berkeley
 *
 * C  opyright (c) 2008, The Regents of the University of California.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *     * Redistributions of source code must retain the above c  opyright
 *       notice, this list of conditions and the following disclaimer.
 *     * Redistributions in binary form must reproduce the above c  opyright
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


#ifndef _OPCODES_H
#define _OPCODES_H

#include "decode.h"

static inline int opcode(uint32_t insn)
{
  return OP << 6 | (OP == 0 ? OP2+(ANNUL>>26) : OP == 1 ? 0 : OP3);
}


// These are the opcodes we understand, as computed from the above function
enum opcodes
{
  opUNIMP    =0x00,
  opBicc     =0x02,
  opSETHI    =0x04,
  opFBfcc    =0x06,
  opCBccc    =0x07,
  opBicca    =0x0A,
  opSETHIa   =0x0C,
  opFBfcca   =0x0E,
  opCBccca   =0x0F,
  opCALL     =0x40,
  opADD      =0x80,
  opAND      =0x81,
  opOR       =0x82,
  opXOR      =0x83,
  opSUB      =0x84,
  opANDN     =0x85,
  opORN      =0x86,
  opXNOR     =0x87,
  opADDX     =0x88,
  opUMUL     =0x8A,
  opSMUL     =0x8B,
  opSUBX     =0x8C,
  opUDIV     =0x8E,
  opSDIV     =0x8F,
  opADDcc    =0x90,
  opANDcc    =0x91,
  opORcc     =0x92,
  opXORcc    =0x93,
  opSUBcc    =0x94,
  opANDNcc   =0x95,
  opORNcc    =0x96,
  opXNORcc   =0x97,
  opADDXcc   =0x98,
  opUMULcc   =0x9A,
  opSMULcc   =0x9B,
  opSUBXcc   =0x9C,
  opUDIVcc   =0x9E,
  opSDIVcc   =0x9F,
  opTADDcc   =0xA0,
  opTSUBcc   =0xA1,
  opTADDccTV =0xA2,
  opTSUBccTV =0xA3,
  opMULScc   =0xA4,
  opSLL      =0xA5,
  opSRL      =0xA6,
  opSRA      =0xA7,
  opRDASR    =0xA8,
  opRDPSR    =0xA9,
  opRDWIM    =0xAA,
  opRDTBR    =0xAB,
  opWRASR    =0xB0,
  opWRPSR    =0xB1,
  opWRWIM    =0xB2,
  opWRTBR    =0xB3,
  opFPop1    =0xB4,
  opFPop2    =0xB5,
  opCPop1    =0xB6,
  opCPop2    =0xB7,
  opJMPL     =0xB8,
  opRETT     =0xB9,
  opTicc     =0xBA,
  opFLUSH    =0xBB,
  opSAVE     =0xBC,
  opRESTORE  =0xBD,
  opSENDAM   =0xBE,
  opLD       =0xC0,
  opLDUB     =0xC1,
  opLDUH     =0xC2,
  opLDD      =0xC3,
  opST       =0xC4,
  opSTB      =0xC5,
  opSTH      =0xC6,
  opSTD      =0xC7,
  opLDSB     =0xC9,
  opLDSH     =0xCA,
  opLDSTUB   =0xCD,
  opSWAP     =0xCF,
  opLDA      =0xD0,
  opLDUBA    =0xD1,
  opLDUHA    =0xD2,
  opLDDA     =0xD3,
  opSTA      =0xD4,
  opSTBA     =0xD5,
  opSTHA     =0xD6,
  opSTDA     =0xD7,
  opLDSBA    =0xD9,
  opLDSHA    =0xDA,
  opLDSTUBA  =0xDD,
  opSWAPA    =0xDF,
  opLDF      =0xE0,
  opLDFSR    =0xE1,
  opLDDF     =0xE3,
  opSTF      =0xE4,
  opSTFSR    =0xE5,
  opSTDFQ    =0xE6,
  opSTDF     =0xE7,
  opLDC      =0xF0,
  opLDCSR    =0xF1,
  opLDDC     =0xF3,
  opSTC      =0xF4,
  opSTCSR    =0xF5,
  opSTDCQ    =0xF6,
  opSTDC     =0xF7
};

#endif
