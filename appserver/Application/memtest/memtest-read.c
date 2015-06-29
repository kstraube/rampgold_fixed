#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <host.h>
#include <hart.h>
#include <barrier.h>
#include <assert.h>

#define MIN_CHUNK_SIZE 8192
#define MAX_CHUNK_SIZE 8192 // * sizeof(long)
#define CHUNK_ALIGN 32
#define STRIDE 1
#define SEQUENTIAL 1
#define TEST_SIZE 16*1024*1024 // 1.5GB

#define debug_printf

typedef struct
{
  unsigned int lfsr_state;
  long* my_start;
  long* my_end;
  long i;
}
thread_state_t;

unsigned int lfsr(unsigned int* lfsr_state)
{
  return *lfsr_state = (*lfsr_state >> 1) ^ (-(*lfsr_state & 1u) & 0xd0000001u);
}

int num_errors = 0;

void flag_error(long* addr)
{
  static int my_num_errors[MAX_PROCS] = {0};
  static hart_lock_t error_lock = HART_LOCK_INIT;

  hart_lock_lock(&error_lock);
  num_errors++;
  my_num_errors[hart_self()]++;

  printf("Core %d, local error #%d, global error #%d: ",hart_self(),my_num_errors[hart_self()],num_errors);
  if(addr == 0)
    printf("icache test failed!\n");
  else
    printf("addr %08x\n",addr);

  hart_lock_unlock(&error_lock);
}

void init_mem(long* mem0, int size)
{
  volatile long* mem = mem0;
  assert(size % (sizeof(long)*8) == 0);

  int i;
  for(i = 0; i < size/sizeof(long); i+=8)
  {
    mem[i+0] = (long)&mem[i+0];
    mem[i+1] = (long)&mem[i+1];
    mem[i+2] = (long)&mem[i+2];
    mem[i+3] = (long)&mem[i+3];
    mem[i+4] = (long)&mem[i+4];
    mem[i+5] = (long)&mem[i+5];
    mem[i+6] = (long)&mem[i+6];
    mem[i+7] = (long)&mem[i+7];

    long x = mem[i+16384/sizeof(long)];

    assert(mem[i+0] == (long)&mem[i+0]);
    assert(mem[i+1] == (long)&mem[i+1]);
    assert(mem[i+2] == (long)&mem[i+2]);
    assert(mem[i+3] == (long)&mem[i+3]);
    assert(mem[i+4] == (long)&mem[i+4]);
    assert(mem[i+5] == (long)&mem[i+5]);
    assert(mem[i+6] == (long)&mem[i+6]);
    assert(mem[i+7] == (long)&mem[i+7]);
  }
}

void random_test(thread_state_t* state)
{
  int chunk_size = MIN_CHUNK_SIZE == MAX_CHUNK_SIZE ? MIN_CHUNK_SIZE : 
                   MIN_CHUNK_SIZE + (lfsr(&state->lfsr_state) % ((MAX_CHUNK_SIZE-MIN_CHUNK_SIZE)/CHUNK_ALIGN))*CHUNK_ALIGN;

  int pos = SEQUENTIAL ? state->i : lfsr(&state->lfsr_state);

  volatile long* chunk_start = state->my_start + (pos%((state->my_end-state->my_start)/CHUNK_ALIGN))*CHUNK_ALIGN;

  if(chunk_start + chunk_size > state->my_end)
    chunk_size = state->my_end - chunk_start;

  debug_printf("core %d: start %08x, size %d\n",hart_self(),chunk_start,chunk_size);

  // verify result
  int i;
  for(i = 0; i < chunk_size; i+=STRIDE)
    if(chunk_start[i] != (long)&chunk_start[i])
      flag_error((long*)&chunk_start[i]);
}

long* start = 0;
long* end = 0;
struct barrier_t barrier;

void icache_test()
{
  int i = 0;

  __asm__ __volatile__ ("nop;nop;nop;nop;nop;nop;nop; inc %0" : "=r"(i) : "0"(i));
  __asm__ __volatile__ ("nop;nop;nop;nop;nop;nop;nop; inc %0" : "=r"(i) : "0"(i));
  __asm__ __volatile__ ("nop;nop;nop;nop;nop;nop;nop; inc %0" : "=r"(i) : "0"(i));
  __asm__ __volatile__ ("nop;nop;nop;nop;nop;nop;nop; inc %0" : "=r"(i) : "0"(i));
  __asm__ __volatile__ ("nop;nop;nop;nop;nop;nop;nop; inc %0" : "=r"(i) : "0"(i));
  __asm__ __volatile__ ("nop;nop;nop;nop;nop;nop;nop; inc %0" : "=r"(i) : "0"(i));
  __asm__ __volatile__ ("nop;nop;nop;nop;nop;nop;nop; inc %0" : "=r"(i) : "0"(i));
  __asm__ __volatile__ ("nop;nop;nop;nop;nop;nop;nop; inc %0" : "=r"(i) : "0"(i));
  __asm__ __volatile__ ("nop;nop;nop;nop;nop;nop;nop; inc %0" : "=r"(i) : "0"(i));
  __asm__ __volatile__ ("nop;nop;nop;nop;nop;nop;nop; inc %0" : "=r"(i) : "0"(i));
  __asm__ __volatile__ ("nop;nop;nop;nop;nop;nop;nop; inc %0" : "=r"(i) : "0"(i));
  __asm__ __volatile__ ("nop;nop;nop;nop;nop;nop;nop; inc %0" : "=r"(i) : "0"(i));
  __asm__ __volatile__ ("nop;nop;nop;nop;nop;nop;nop; inc %0" : "=r"(i) : "0"(i));
  __asm__ __volatile__ ("nop;nop;nop;nop;nop;nop;nop; inc %0" : "=r"(i) : "0"(i));
  __asm__ __volatile__ ("nop;nop;nop;nop;nop;nop;nop; inc %0" : "=r"(i) : "0"(i));
  __asm__ __volatile__ ("nop;nop;nop;nop;nop;nop;nop; inc %0" : "=r"(i) : "0"(i));
  __asm__ __volatile__ ("nop;nop;nop;nop;nop;nop;nop; inc %0" : "=r"(i) : "0"(i));
  __asm__ __volatile__ ("nop;nop;nop;nop;nop;nop;nop; inc %0" : "=r"(i) : "0"(i));
  __asm__ __volatile__ ("nop;nop;nop;nop;nop;nop;nop; inc %0" : "=r"(i) : "0"(i));
  __asm__ __volatile__ ("nop;nop;nop;nop;nop;nop;nop; inc %0" : "=r"(i) : "0"(i));
  __asm__ __volatile__ ("nop;nop;nop;nop;nop;nop;nop; inc %0" : "=r"(i) : "0"(i));
  __asm__ __volatile__ ("nop;nop;nop;nop;nop;nop;nop; inc %0" : "=r"(i) : "0"(i));
  __asm__ __volatile__ ("nop;nop;nop;nop;nop;nop;nop; inc %0" : "=r"(i) : "0"(i));
  __asm__ __volatile__ ("nop;nop;nop;nop;nop;nop;nop; inc %0" : "=r"(i) : "0"(i));
  __asm__ __volatile__ ("nop;nop;nop;nop;nop;nop;nop; inc %0" : "=r"(i) : "0"(i));
  __asm__ __volatile__ ("nop;nop;nop;nop;nop;nop;nop; inc %0" : "=r"(i) : "0"(i));
  __asm__ __volatile__ ("nop;nop;nop;nop;nop;nop;nop; inc %0" : "=r"(i) : "0"(i));
  __asm__ __volatile__ ("nop;nop;nop;nop;nop;nop;nop; inc %0" : "=r"(i) : "0"(i));
  __asm__ __volatile__ ("nop;nop;nop;nop;nop;nop;nop; inc %0" : "=r"(i) : "0"(i));
  __asm__ __volatile__ ("nop;nop;nop;nop;nop;nop;nop; inc %0" : "=r"(i) : "0"(i));
  __asm__ __volatile__ ("nop;nop;nop;nop;nop;nop;nop; inc %0" : "=r"(i) : "0"(i));
  __asm__ __volatile__ ("nop;nop;nop;nop;nop;nop;nop; inc %0" : "=r"(i) : "0"(i));

  if(i != 32)
    flag_error(0);
}

void go()
{
  extern char _end;
  thread_state_t state;
  int id = hart_self(), P = hart_max_harts();

  assert(MIN_CHUNK_SIZE % CHUNK_ALIGN == 0);
  assert(MAX_CHUNK_SIZE % CHUNK_ALIGN == 0);
  assert((end-start) % CHUNK_ALIGN == 0);
  assert((start-(long*)0) % CHUNK_ALIGN == 0);
  assert((end-start) % P == 0);

  state.my_start = start+(end-start)/P*id;
  state.my_end = start+(end-start)/P*(id+1);
  state.i = 0;
  state.lfsr_state = id+1;

  assert((state.my_start-(long*)0) % CHUNK_ALIGN == 0);

  init_mem(state.my_start,(state.my_end-state.my_start)*sizeof(long));
  barrier_wait(&barrier,id);

  for(state.i = 0; ; state.i++)
  {
    if(id == 0 && state.i % (4096/P) == 0)
      printf("Heartbeat.  Iteration %d, %d errors\n",state.i,num_errors);

    icache_test();
    random_test(&state);

    barrier_wait(&barrier,id);
  }
}

void hart_entry()
{
  go();
  hart_yield();
}

int main()
{
  start = (long*)malloc(TEST_SIZE+CHUNK_ALIGN);

  if(start == 0)
  {
    printf("Couldn't allocate %d bytes!\n",TEST_SIZE);
    return 0;
  }
  start += CHUNK_ALIGN - (start - (long*)0) % CHUNK_ALIGN;
  end = start + TEST_SIZE/sizeof(long);

  barrier_init(&barrier,hart_max_harts());

  hart_request(hart_max_harts()-1);
  go();
  return 0;
}
