#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <host.h>
#include <hart.h>
#include <barrier.h>
#include <assert.h>

#define MIN_CHUNK_SIZE 128
#define MAX_CHUNK_SIZE 128 // * sizeof(long)
#define CHUNK_ALIGN 8
#define STRIDE 1
#define SEQUENTIAL 1
#define START_ADDR ((char*)0x30000000)
#define END_ADDR ((char*)0x50000000)
#define TEST_SIZE (END_ADDR-START_ADDR)  // 1GB

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

void error_mode()
{
  #if defined(__i386__) || defined(__x86_64__)
    abort();
  #else
    asm volatile("ta 0x7f");
  #endif
}

void flag_error(long* addr, long expected, long actual)
{
#ifdef MEMTEST_ALL
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
#else
    volatile int* magic_mem = (volatile int*)0x70000000;

    magic_mem[7] = 0;
    magic_mem[1] = 97;
    magic_mem[2] = (long)addr;
    magic_mem[3] = expected;
    magic_mem[4] = actual;
    magic_mem[0] = 0x80;
#endif
}

inline void random_test(thread_state_t* state)
{
  int chunk_size = MIN_CHUNK_SIZE == MAX_CHUNK_SIZE ? MIN_CHUNK_SIZE : 
                   MIN_CHUNK_SIZE + (lfsr(&state->lfsr_state) % ((MAX_CHUNK_SIZE-MIN_CHUNK_SIZE)/CHUNK_ALIGN))*CHUNK_ALIGN;

  int pos = SEQUENTIAL ? state->i : lfsr(&state->lfsr_state);

  long* chunk_start = state->my_start + (pos%((state->my_end-state->my_start)/CHUNK_ALIGN))*CHUNK_ALIGN;

  if(chunk_start + chunk_size > state->my_end)
    chunk_size = state->my_end - chunk_start;

  //debug_printf("core %d: start %08x, size %d\n",hart_self(),chunk_start,chunk_size);

  int i,stride=STRIDE;
  #ifdef UNROLL
    stride *= 4
  #endif
  for(i = 0; i < chunk_size; i+=stride)
  {
    chunk_start[i+0*STRIDE] = (long)&chunk_start[i+0*STRIDE] - state->lfsr_state;
    #ifdef UNROLL
      chunk_start[i+1*STRIDE] = (long)&chunk_start[i+1*STRIDE] - state->lfsr_state;
      chunk_start[i+2*STRIDE] = (long)&chunk_start[i+2*STRIDE] - state->lfsr_state;
      chunk_start[i+3*STRIDE] = (long)&chunk_start[i+3*STRIDE] - state->lfsr_state;
    #endif
  }

  // kick stuff out of cache
  int x;
  for(i = 0; i < 32; i+=stride)
  {
    x = ((volatile long*)state->my_start)[i+0*STRIDE];
    #ifdef UNROLL
      x = ((volatile long*)state->my_start)[i+1*STRIDE];
      x = ((volatile long*)state->my_start)[i+2*STRIDE];
      x = ((volatile long*)state->my_start)[i+3*STRIDE];
    #endif
  }

  // verify result
  for(i = 0; i < chunk_size; i+=STRIDE)
    if(chunk_start[i] != (long)&chunk_start[i] - state->lfsr_state)
      flag_error(&chunk_start[i],chunk_start[i],(long)&chunk_start[i]-state->lfsr_state);
}

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
    flag_error(0,0,0);
}

long* start = 0;
long* end = 0;
struct barrier_t barrier;

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

  for(state.i = 0; ; state.i++)
  {
    #ifdef MEMTEST_ALL
      barrier_wait(&barrier,id);

      if(id == 0 && state.i % (32768/P) == 0)
        printf("Heartbeat.  Iteration %d, %d errors\n",state.i,num_errors);

      icache_test();
    #endif

    //random_test(&state);
  }
}

void hart_entry()
{
  go();
  hart_yield();
}

int main()
{
  start = (long*)START_ADDR;
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
