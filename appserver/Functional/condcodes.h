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


#ifndef _CONDCODES_H
#define _CONDCODES_H

// These are the possible conditions on which the processor
// may branch or trap (using the Bicc and Ticc instructions)

enum iconds
{
  iccN,iccE,iccLE,iccL,iccLEU,iccCS,iccNEG,iccVS,
  iccA,iccNE,iccG,iccGE,iccGU,iccCC,iccPOS,iccVC 
};

// This lookup table determines if a branch is taken or not.
// The outer dimension is the branch condition (see iconds, above),
// and the inner dimension is the current value of the integer
// condition codes in the PSR

static const bool check_icc[16][16] = {
  {0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0},
  {0,0,0,0,1,1,1,1,0,0,0,0,1,1,1,1},
  {0,0,1,1,1,1,1,1,1,1,0,0,1,1,1,1},
  {0,0,1,1,0,0,1,1,1,1,0,0,1,1,0,0},
  {0,1,0,1,1,1,1,1,0,1,0,1,1,1,1,1},
  {0,1,0,1,0,1,0,1,0,1,0,1,0,1,0,1},
  {0,0,0,0,0,0,0,0,1,1,1,1,1,1,1,1},
  {0,0,1,1,0,0,1,1,0,0,1,1,0,0,1,1},
  {1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1},
  {1,1,1,1,0,0,0,0,1,1,1,1,0,0,0,0},
  {1,1,0,0,0,0,0,0,0,0,1,1,0,0,0,0},
  {1,1,0,0,1,1,0,0,0,0,1,1,0,0,1,1},
  {1,0,1,0,0,0,0,0,1,0,1,0,0,0,0,0},
  {1,0,1,0,1,0,1,0,1,0,1,0,1,0,1,0},
  {1,1,1,1,1,1,1,1,0,0,0,0,0,0,0,0},
  {1,1,0,0,1,1,0,0,1,1,0,0,1,1,0,0}
};

#endif
