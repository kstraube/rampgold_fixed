#include "hart.h"
#include <host.h>
#include <pthread.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/time.h>

#ifdef NUMA
  #include "affinity.numa.c"
#endif

int _hart_max_harts = 1, _hart_current_harts = 1;
int* _hart_in_use;
pthread_t* _hart_pthreads;
hart_lock_t _hart_lock = HART_LOCK_INIT;

void _hart_init()
{
  static volatile int initialized = 0;
  if(initialized == 0)
  {
    hart_lock_lock(&_hart_lock);
    if(initialized == 0)
    {
      #ifdef NUMA
        Affinity_Init();
      #endif

      initialized = 1;
      _hart_max_harts = sysconf(_SC_NPROCESSORS_CONF);
      _hart_in_use = (int*)calloc(_hart_max_harts,sizeof(int));
      _hart_pthreads = (pthread_t*)calloc(_hart_max_harts,sizeof(pthread_t));
      _hart_in_use[0] = 1;
      _hart_pthreads[0] = pthread_self();
    }
    hart_lock_unlock(&_hart_lock);
  }
}

void hart_lock_init(hart_lock_t* lock)
{
  *(spinlock_t*)lock = 0;
}

void hart_lock_unlock(hart_lock_t* lock)
{
  spinlock_unlock((spinlock_t*)lock);
}

int hart_lock_trylock(hart_lock_t* lock)
{
  return spinlock_trylock((spinlock_t*)lock);
}

int hart_rand(int prev)
{
  return (prev >> 1) ^ (-(prev & 1) & 0xd0000001);
}

void hart_lock_lock(hart_lock_t* l)
{
  spinlock_lock((spinlock_t*)l);
}

#define hart_assert(expr) do { if(!(expr)) { char* _s = "hart_assert: "; int _foo = write(2,_s,strlen(_s)); _foo = write(2,#expr,strlen(#expr)); _foo = write(2,"\n",1); _exit(-1); } } while(0)

void* hart_entry_wrapper(void* arg)
{
  #ifdef NUMA
    Affinity_Bind_Thread(hart_self());
    Affinity_Bind_Memory(hart_self());
  #endif

  hart_entry();
  hart_yield();
  return NULL;
}

int hart_request(size_t k)
{
  int i,j,ret;

  _hart_init();

  hart_lock_lock(&_hart_lock);

  if(k < 0 || _hart_current_harts+k > _hart_max_harts)
  {
    hart_lock_unlock(&_hart_lock);
    return -1;
  }

  _hart_current_harts += k;

  for(i = 0, j = 0; i < _hart_max_harts && j < k; i++)
  {
    if(!_hart_in_use[i])
    {
      _hart_in_use[i] = 1;
      ret = pthread_create(&_hart_pthreads[i],NULL,hart_entry_wrapper,NULL);
      hart_assert(ret == 0);
      j++;
    }
  }

  hart_assert(j == k);

  hart_lock_unlock(&_hart_lock);
  return 0;
}

int hart_self()
{
  int i, id = 0;
  hart_lock_lock(&_hart_lock);
  pthread_t me = pthread_self();
  for(i = 0; i < _hart_max_harts; i++)
    if(_hart_in_use[i] && pthread_equal(me,_hart_pthreads[i]))
      id = i;
  hart_lock_unlock(&_hart_lock);
  return (int)id;
}

void hart_yield()
{
  _hart_init();

  hart_lock_lock(&_hart_lock);
  _hart_current_harts--;
  _hart_in_use[hart_self()] = 0;
  hart_lock_unlock(&_hart_lock);

  pthread_exit(NULL);
}

size_t hart_max_harts()
{
  _hart_init();
  return _hart_max_harts;
}

int hart_barrier_init(hart_barrier_t* b, size_t np)
{
    if(np > hart_max_harts())
        return -1;
    b->allnodes = (hart_dissem_flags_t*)malloc(np*sizeof(hart_dissem_flags_t));
    memset(b->allnodes,0,np*sizeof(hart_dissem_flags_t));
    b->nprocs = np;

    b->logp = (np & (np-1)) != 0;
    while(np >>= 1)
        b->logp++;

    int i,k;
    for(i = 0; i < b->nprocs; i++)
    {
        b->allnodes[i].parity = 0;
        b->allnodes[i].sense = 1;

        for(k = 0; k < b->logp; k++)
        {
            int j = (i+(1<<k)) % b->nprocs;
            b->allnodes[i].partnerflags[0][k] = &b->allnodes[j].myflags[0][k];
            b->allnodes[i].partnerflags[1][k] = &b->allnodes[j].myflags[1][k];
        }
    }

    return 0;
}

void hart_barrier_wait(hart_barrier_t* b, size_t pid)
{
    hart_dissem_flags_t* localflags = &b->allnodes[pid];
    int i;
    for(i = 0; i < b->logp; i++)
    {
        *localflags->partnerflags[localflags->parity][i] = localflags->sense;
        while(localflags->myflags[localflags->parity][i] != localflags->sense);
    }
    if(localflags->parity)
        localflags->sense = 1-localflags->sense;
    localflags->parity = 1-localflags->parity;
}
