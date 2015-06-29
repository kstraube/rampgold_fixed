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


#ifndef _UTIL_H
#define _UTIL_H

#ifdef __cplusplus
  extern "C" {
#endif

#include <stdio.h>
#include <stdlib.h>

double microtime();
int parse_args(int argc, char** argv, const char* opts, ...);
char* itoa(int value, char* buffer, int radix);
int readfile(const char* fn, char** bytes, int* size);
char* readfile_posix(int fd, int* size);
void writefile_posix(int fd, char* buf, int size);

#define MIN(a,b) ((a) < (b) ? (a) : (b))
#define MAX(a,b) ((a) < (b) ? (b) : (a))

#define likely(x)   __builtin_expect(!!(x),1)
#define unlikely(x) __builtin_expect(!!(x),0)

#define debug_assert(cond) \
  do { \
    if(DEBUG_LEVEL > 0 && !(cond)) { \
      fprintf(stdout,"%s[%d]: assertion (%s) failed\n",__FILE__,__LINE__,#cond); \
      abort(); \
    } \
  } while(0)

#define debug_notice(debuglevel,str,args...) \
  do { \
    if(DEBUG_LEVEL >= (debuglevel)) \
      warn(str,##args); \
  } while(0)

#define warn(str,args...) \
  do { \
    fprintf(stdout,"%s[%d]: ",__FILE__,__LINE__); \
    fprintf(stdout,str"\n",##args); \
  } while(0)

#define error(str,args...) \
  do { \
    warn(str,##args); \
    abort(); \
  } while(0)

#define static_assert(x) switch (x) case 0: case (x):

static inline unsigned int roundup_pow2(unsigned int v)
{
  v--;
  v |= v >> 1;
  v |= v >> 2;
  v |= v >> 4;
  v |= v >> 8;
  v |= v >> 16;
  v++;
 
  return v;
}

static inline int ispow2(unsigned int x)
{
  return x && (x&(x-1)) == 0;
}
 
static inline unsigned int log2i(unsigned int x)
{
  unsigned int r = 0;
  while(x >>= 1)
    r++;
  return r;
}
 
static inline unsigned int bit_reverse(unsigned int foo, unsigned int width)
{
  unsigned int bar = 0, i;
  for(i = 0; i < width-1; i++)
  {
    bar |= foo & 1;
    foo >>= 1;
    bar <<= 1;
  }
  return bar | (foo & 1);
}

double ramp_frecip(double b);
double ramp_frecip_sqrt(double b);
double ramp_fdiv(double x, double y);
double ramp_fsqrt(double x);
double ramp_fcbrt(double x);

#ifdef DEBUG_MODE
  #define DEBUG_LEVEL 4
#else
  #define DEBUG_LEVEL 0
#endif

#ifdef __cplusplus
  }
#endif

#endif
