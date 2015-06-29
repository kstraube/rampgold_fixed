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


#ifndef _COMMON_HOST_H
#define _COMMON_HOST_H

#ifndef MAX_PROCS
#define MAX_PROCS 64
#endif

#ifndef __ASSEMBLER__

#include <stdint.h>
#include <endian.h>
#include <byteswap.h>

// for older glibcs
#ifndef be32toh
# if BYTE_ORDER == LITTLE_ENDIAN
#  define be16toh(x) __bswap_16(x)
#  define be32toh(x) __bswap_32(x)
#  define be64toh(x) __bswap_64(x)
#  define le16toh(x) (x)
#  define le32toh(x) (x)
#  define le64toh(x) (x)
# elif BYTE_ORDER == BIG_ENDIAN
#  define be16toh(x) (x)
#  define be32toh(x) (x)
#  define be64toh(x) (x)
#  define le16toh(x) __bswap_16(x)
#  define le32toh(x) __bswap_32(x)
#  define le64toh(x) __bswap_64(x)
# endif
# define htobe16(x) be16toh(x)
# define htobe32(x) be32toh(x)
# define htobe64(x) be64toh(x)
# define htole16(x) le16toh(x)
# define htole32(x) le32toh(x)
# define htole64(x) le64toh(x)
#endif

#if defined(__x86_64__) || defined(__i386__)

  typedef uint32_t spinlock_t;
  #define SPINLOCK_INIT 0

  static inline uint32_t atomic_swap(uint32_t* addr, uint32_t val)
  {
    __asm__ __volatile__ ("xchg %0, (%2)" : "=r"(val) : "0"(val),"r"(addr) : "memory");
    return val;
  }

  static inline int spinlock_trylock(spinlock_t* ptr)
  {
    return atomic_swap(ptr,1);
  }

  static inline void spinlock_lock(spinlock_t* lock)
  {
    while(spinlock_trylock(lock))
      while(*(volatile int*)lock);
  }

  #define HAS_FETCH_ADD  
  static inline int fetch_add(int* ptr, int value)
  {
    __asm__ __volatile__ ("lock xadd %0, (%2)" : "=a"(value) : "0"(value),"b"(ptr) : "memory");
    return value;
  }

  static inline void spinlock_unlock(spinlock_t* ptr)
  {
    *ptr = 0;
  }

#elif defined(__sun) || defined(__sparc)

  #include "specialregs.h"

  #define store_alternate(addr,asi,data) __asm__ __volatile__ ("sta %0,[%1] %2" : : "r"(data),"r"(addr),"i"(asi))
  #define store_iobus(device,addr,data) store_alternate((device)<<16,2,(data))
  #define load_alternate(addr,asi,data) __asm__ __volatile__ ("lda [%1] %2,%0" : "=r"(data) : "r"(addr),"i"(asi))
  #define load_iobus(device,addr,data) load_alternate((device)<<16,2,(data))

  #include "specialregs.h"

  #define STR(arg) #arg
  #define XSTR(arg) STR(arg)

  static inline int core_id()
  {
    int reg;
    __asm__ __volatile__ ("mov %" XSTR(CORE_ID_REG) ",%0" : "=r"(reg));
    return reg;
  }

  static inline uint32_t atomic_swap(uint32_t* addr, uint32_t val)
  {
    __asm__ __volatile__ ("swap [%2],%0" : "=r"(val) : "0"(val),"r"(addr) : "memory");
    return val;
  }

  typedef int spinlock_t;
  #define SPINLOCK_INIT 0

  static inline int spinlock_trylock(spinlock_t* lock)
  {
    int reg;
    __asm__ __volatile__ ("ldstub [%1],%0" : "=r"(reg) : "r"(lock) : "memory");
    return reg;
  }

  static inline int spinlock_is_locked(spinlock_t* lock)
  {
    int reg;
    __asm__ __volatile__ ("ldub [%1],%0" : "=r"(reg) : "r"(lock) : "memory");
    return reg;
  }

  static inline void __delay(unsigned int n)
  {
    __asm__ __volatile__ ("tst %0; 1: bne 1b; deccc %0" : "=r"(n) : "0"(n) : "cc");
  }

  static inline void spinlock_lock(spinlock_t* lock)
  {
    while(spinlock_trylock(lock))
      while(spinlock_is_locked(lock));
  }

  static inline void spinlock_unlock(spinlock_t* lock)
  {
    *(volatile int*)lock = SPINLOCK_INIT;
  }

  static inline int num_cores()
  {
    int reg;
    __asm__ __volatile__ ("mov %" XSTR(NUM_CORES_REG) ",%0" : "=r"(reg));
    return reg;
  }

  static inline int memsize_MB()
  {
    int reg;
    __asm__ __volatile__ ("mov %" XSTR(MEMSIZE_MB_REG) ",%0" : "=r"(reg));
    return reg;
  }

  static inline void am_sleep()
  {
    __asm__ __volatile__ ("ta 1");
    //__asm__ __volatile__ ("mov 0," XSTR(AM_SLEEP_REG));
    //while(1);
  }
  
#else

  #error Host machine is unknown!

#endif

#endif

#endif
