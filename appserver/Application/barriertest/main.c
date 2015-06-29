#include <hart.h>
#include <util.h>
#include <assert.h>
#include <barrier.h>

struct barrier_t b0,b1;
int nbarriers = 0;
int done = 0;
double t0,t1;

void do_work_son()
{
  int id = hart_self();
  if(id == 0)
    t0 = microtime();

  int i;
  for(i = 0; !done; i++)
  {
    if(id == 0)
    {
      if(i % 1000 == 0 && (t1 = microtime())-t0 > 1)
        done = 1;
    }

    barrier_wait(&b0,id);
  }

  if(id == 0)
    nbarriers = i;
}

void hart_entry()
{
  do_work_son();
  hart_yield();
}

int main(int argc, char** argv)
{
  assert(argc == 2);

  int n = atoi(argv[1]);
  barrier_init(&b0,n);
  barrier_init(&b1,n);

  assert(hart_request(n-1) == 0);
  do_work_son();

  printf("%p %p\n",b0.allnodes,b0.allnodes+1);
  printf("%d barriers/sec\n",(int)(nbarriers/(t1-t0)));

  return 0;
}
