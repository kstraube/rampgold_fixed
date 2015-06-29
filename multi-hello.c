#include <hart.h>
#include <stdio.h>

hart_barrier_t barrier;

void do_work(int thread_id)
{
  printf("Hello from thread %d!\n",thread_id);

  hart_barrier_wait(&barrier, thread_id);
}

void hart_entry() // this is where the requested harts enter the program
{
  do_work(hart_self()); // do this thread's share of the work
}

int main()
{
  hart_barrier_init(&barrier,hart_max_harts()); // initialize a barrier

  hart_request(hart_max_harts()-1); // request the other N-1 threads

  do_work(0); // do thread 0's part of the work
  
  return 0;
}

