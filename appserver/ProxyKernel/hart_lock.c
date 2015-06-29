#include "hart.h"

int hart_self()
{
  return core_id();
}

void hart_lock_init(hart_lock_t* lock)
{
  int i;
  lock->lock = 0;
  for(i = 0; i < MAX_PROCS; i++)
  {
    lock->qnode[i].next = 0;
    lock->qnode[i].locked = 0;
  }
}

#define qnode_swap(addr,val) ((hart_lock_qnode_t*)atomic_swap((int*)(addr),(int)(val)))

void hart_lock_lock(hart_lock_t* lock)
{
  hart_lock_qnode_t* qnode = &lock->qnode[hart_self()];
  qnode->next = 0;
  hart_lock_qnode_t* predecessor = qnode_swap(&lock->lock,qnode);
  if(predecessor)
  {
    qnode->locked = 1;
    predecessor->next = qnode;
    while(qnode->locked);
  }
}

int hart_lock_trylock(hart_lock_t* lock)
{
  hart_lock_lock(lock);
}

void hart_lock_unlock(hart_lock_t* lock)
{
  hart_lock_qnode_t* qnode = &lock->qnode[hart_self()];
  if(qnode->next == 0)
  {
    hart_lock_qnode_t* old_tail = qnode_swap(&lock->lock,0);
    if(old_tail == qnode)
      return;

    hart_lock_qnode_t* usurper = qnode_swap(&lock->lock,old_tail);
    while(qnode->next == 0);
    if(usurper)
      usurper->next = qnode->next;
    else
      qnode->next->locked = 0;
  }
  else
    qnode->next->locked = 0;
}
