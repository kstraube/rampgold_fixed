#ifndef _BARRIER_H
#define _BARRIER_H

#include <stdlib.h>
#include <string.h>
#include "host.h"
#ifdef __cplusplus
  #include <stdexcept>
#endif

// #define CENTRALIZED

#define LOG2_BARRIER_MAX_PROCS 16
#define BARRIER_MAX_PROCS (1 << LOG2_BARRIER_MAX_PROCS)
#define CL_SIZE 16 // * sizeof(int)

struct barrier_t;

#ifdef CENTRALIZED
  static int centralized_barrier_init(struct barrier_t* b, int np);
  static void centralized_barrier_wait(struct barrier_t* b, int pid);

  #define barrier_init centralized_barrier_init
  #define barrier_wait centralized_barrier_wait
#else
  static int dissemination_barrier_init(struct barrier_t* b, int np);
  static void dissemination_barrier_wait(struct barrier_t* b, int pid);

  #define barrier_init dissemination_barrier_init
  #define barrier_wait dissemination_barrier_wait
#endif

typedef struct
{
  volatile char myflags[2][LOG2_BARRIER_MAX_PROCS];
  int parity;
  int sense;
  int pad[6];

} dissem_flags_t;

struct barrier_t
{
  int nprocs;

  // used by centralized barrier
  volatile int* local_sense;
  volatile int count;
  spinlock_t lck;
  volatile int sense;

  // used by dissemination barrier
  dissem_flags_t* allnodes;
  int logp;

#ifdef __cplusplus

  barrier_t(int np)
  {
    if(barrier_init(this,np))
      throw std::logic_error("too many processors for barrier!");
  }

  void wait(int pid)
  {
    barrier_wait(this,pid);
  }

#endif
};

int dissemination_barrier_init(struct barrier_t* b, int np)
{
  if(np > BARRIER_MAX_PROCS)
    return -1;
  if(posix_memalign((void**)&b->allnodes,CL_SIZE*sizeof(int),np*sizeof(dissem_flags_t)))
     return -1;
  memset(b->allnodes,0,np*sizeof(dissem_flags_t));
  b->nprocs = np;

  b->logp = (np & (np-1)) != 0;
  while(np >>= 1)
    b->logp++;

  int i;
  for(i = 0; i < b->nprocs; i++)
  {
    b->allnodes[i].parity = 0;
    b->allnodes[i].sense = 1;
  }

  return 0;
}

void dissemination_barrier_wait(struct barrier_t* b, int pid)
{
  dissem_flags_t* localflags = &b->allnodes[pid];
  int i;
  for(i = 0; i < b->logp; i++)
  {
    dissem_flags_t* partnerflags = &b->allnodes[(pid+(1<<i))%b->nprocs];
    partnerflags->myflags[localflags->parity][i] = localflags->sense;
    while(localflags->myflags[localflags->parity][i] != localflags->sense);
  }
  if(localflags->parity)
    localflags->sense = 1-localflags->sense;
  localflags->parity = 1-localflags->parity;
}

#ifdef CENTRALIZED

int centralized_barrier_init(struct barrier_t* b, int np)
{
  b->count = b->nprocs = np;
  b->local_sense = (volatile int*)calloc(CL_SIZE*np*sizeof(int));
  memset(b->local_sense,0,CL_SIZE*np*sizeof(int));
  b->sense = SPINLOCK_INIT;
  b->lck = 0;
  return 0;
}

void centralized_barrier_wait(struct barrier_t* b, int pid)
{
  if(b->nprocs == 1) return;

  int ls = b->local_sense[CL_SIZE*pid] = 1-b->local_sense[CL_SIZE*pid];

#ifdef HAS_FETCH_ADD
  if(fetch_add((int*)&b->count,-1) == 1)
  {
    b->count = b->nprocs;
    b->sense = ls;
  }
  else
  {
    while(b->sense != ls);
  }
#else
  spinlock_lock(&b->lck);
  if(b->count == 1)
  {
    b->count = b->nprocs;
    b->sense = ls;
    spinlock_unlock(&b->lck);
  }
  else
  {
    b->count--;
    spinlock_unlock(&b->lck);
    while(b->sense != ls);
  }
#endif
}

#endif

#endif
