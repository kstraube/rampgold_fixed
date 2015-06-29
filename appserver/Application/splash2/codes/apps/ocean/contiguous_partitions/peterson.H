#ifndef _PETERSON_H
#define _PETERSON_H

typedef struct
{
  volatile int* flag;
  volatile int* last;
  int n;
} peterson_lock_t;

static inline void peterson_lock_init(peterson_lock_t* lock, int n)
{
  lock->flag = (int*)calloc(n,sizeof(int));
  lock->last = (int*)calloc(n,sizeof(int));
  lock->n = n;
}

static inline void peterson_lock_lock(peterson_lock_t* lock)
{
  int i = hart_self(), j, k;
  for(j = 1; j < lock->n; j++)
  {
    lock->flag[i] = j;
    lock->last[j] = i;
    for(k = 0; k < lock->n; k++)
      while(k != i && lock->flag[k] >= lock->flag[i] && lock->last[j] == i)
        ;
  }
}

static inline void peterson_lock_unlock(peterson_lock_t* lock)
{
  lock->flag[hart_self()] = 0;
}

#endif
