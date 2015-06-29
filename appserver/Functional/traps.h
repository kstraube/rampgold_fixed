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


#ifndef _TRAPS_H
#define _TRAPS_H

// these are the named traps that might occur
// (and might be thrown/caught by the simulator)
typedef enum
{
  trap_instruction_access_MMU_miss=0x3c,
  trap_instruction_access_exception=0x01,
  trap_privileged_instruction=0x03,
  trap_illegal_instruction=0x02,
  trap_fp_disabled=0x04,
  trap_cp_disabled=0x24,
  trap_watchpoint_detected=0x0B,
  trap_window_overflow=0x05,
  trap_window_underflow=0x06,
  trap_mem_address_not_aligned=0x07,
  trap_fp_exception=0x08,
  trap_cp_exception=0x28,
  trap_data_access_MMU_miss=0x2C,
  trap_data_access_exception=0x09,
  trap_tag_overflow=0x0A,
  trap_division_by_zero=0x2A,
  trap_interrupt_level_15=0x1F,
  trap_interrupt_level_14=0x1E,
  trap_interrupt_level_13=0x1D,
  trap_interrupt_level_12=0x1C,
  trap_interrupt_level_11=0x1B,
  trap_interrupt_level_10=0x1A,
  trap_interrupt_level_9=0x19,
  trap_interrupt_level_8=0x18,
  trap_interrupt_level_7=0x17,
  trap_interrupt_level_6=0x16,
  trap_interrupt_level_5=0x15,
  trap_interrupt_level_4=0x14,
  trap_interrupt_level_3=0x13,
  trap_interrupt_level_2=0x12,
  trap_interrupt_level_1=0x11,
  trap_RTFM=0xff,
  trap_replay=0x100,
  trap_nofault=0x101,
  NUM_TRAPS
} trap_t;

#ifdef __cplusplus
extern "C"
#endif
const char* get_trap_name(int trap);

// useful macros for instruction definitions
#define TRAP_IF(condition,trp) do { if(condition) throw trp; } while(0)
#define FP_TRAP_IF(condition,trp) do { if(condition) { fpu->set_ftt(trp); throw trap_fp_exception; } } while(0)

#endif
