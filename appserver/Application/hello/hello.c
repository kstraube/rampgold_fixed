#include <stdlib.h>
#include <stdio.h>
#include <hart.h>
#include <assert.h>

#define P (hart_max_harts())
static hart_barrier_t bar;

void hart_entry()
{
  int N = 8192;
  int i;
  volatile int* array = alloca(N*sizeof(int));
  for(i = 0; i < N; i++)
    array[i]++;

  printf("Hello from thread %d!\n",hart_self());
  hart_barrier_wait(&bar,hart_self());
}

int main()
{
  hart_barrier_init(&bar,P);
  assert(hart_request(P-1) == 0);

  hart_barrier_wait(&bar,0);
  return 0;
}
