#include <stdio.h>
#include "kernel.h"
#include <reent.h>

#define MIN_CHUNK_SIZE 8
#define MAX_CHUNK_SIZE 8 // * sizeof(int)
#define CHUNK_ALIGN 8
#define STRIDE 1

#define debug_printf fake_printf

typedef struct
{
  int pre_pad[32];
  unsigned int lfsr_state;
  int my_start;
  int my_end;
  int i;
  volatile int buffer[MAX_CHUNK_SIZE];
  int post_pad[32];
}
thread_state_t;

typedef struct
{
  int* addra;
  int vala;
  int valb;
  int thread;
}
error_t;
volatile error_t error;
long long errors_pad[64];
long long* errors = &errors_pad[32];

unsigned int lfsr(unsigned int* lfsr_state)
{
  return *lfsr_state = (*lfsr_state >> 1) ^ (-(*lfsr_state & 1u) & 0xd0000001u);
}

void check_error()
{
  return;

  /*volatile int* foo = (int*)&error - 16384;
  int a = foo[0]; a = foo[1]; a = foo[2]; a = foo[3]; a == foo[4];

  if(error.addra)
  {
    (*errors)++;
    printf("Detected an error: ([%x]==%x) != %x\n",error.addra,error.vala,error.valb);
    __asm__ __volatile__ ("ta 0x7d");
    error.addra = 0;
    flush(&error); flush(&error+1);
  }*/
}

void flush(void* ptr)
{
  /*__asm__ __volatile__ ("flush %0" : : "r"(ptr));
  int x = *(volatile int*)((char*)ptr-16384);*/
}

void flag_error(int* addr)
{
  //__asm__ __volatile__ ("ta 0x7d");
  /*error.thread = core_id();
  error.vala = *addr;
  error.valb = (int)addr;
  error.addra = addr;
  flush(&error+1);
  flush(&error);*/
}

inline void random_test(thread_state_t* state)
{
  int chunk_size;
  if(MIN_CHUNK_SIZE == MAX_CHUNK_SIZE)
    chunk_size = MIN_CHUNK_SIZE;
  else
    chunk_size = MIN_CHUNK_SIZE/CHUNK_ALIGN*CHUNK_ALIGN + (lfsr(&state->lfsr_state) % ((MAX_CHUNK_SIZE-MIN_CHUNK_SIZE)/CHUNK_ALIGN))*CHUNK_ALIGN;

  //int* chunk_start = state->my_start + (lfsr(&state->lfsr_state)%((state->my_end-state->my_start)/CHUNK_ALIGN))*CHUNK_ALIGN;
  int* chunk_start = state->my_start + state->i*MAX_CHUNK_SIZE;
  if(chunk_start > state->my_end)
  {
    chunk_start = state->my_start;
    state->i = 0;
  }

  debug_printf("start 0x%x, size %d\n",chunk_start,chunk_size);

  int i;
  /*for(i = 0; i < chunk_size; i+=STRIDE*4)
  {
    chunk_start[i+0*STRIDE] = (int)&chunk_start[i+0*STRIDE];
    chunk_start[i+1*STRIDE] = (int)&chunk_start[i+1*STRIDE];
    chunk_start[i+2*STRIDE] = (int)&chunk_start[i+2*STRIDE];
    chunk_start[i+3*STRIDE] = (int)&chunk_start[i+3*STRIDE];
  }*/

  // kick stuff out of cache
  int x;
  for(i = 0; i < 32; i+=STRIDE*4)
  {
    x = ((volatile int*)state->my_start)[i+0*STRIDE];
    x = ((volatile int*)state->my_start)[i+1*STRIDE];
    x = ((volatile int*)state->my_start)[i+2*STRIDE];
    x = ((volatile int*)state->my_start)[i+3*STRIDE];
  }

  /*// verify result
  for(i = 0; i < chunk_size; i+=STRIDE)
    if(chunk_start[i] != (int)&chunk_start[i])
      flag_error(&chunk_start[i]);*/
}

void kernel_main()
{
  /*thread_state_t state;
  state.lfsr_state = core_id()+1;

  if(core_id() == 0)
    memset(&error,0,sizeof(error));

  int id = core_id(), P = num_cores();
  int* start = (int*)(0x10000);
  int* end = (int*)(KERNEL_VIRTUAL_START);
  int* my_start = start+(end-start)/P*id;
  int* my_end = start+(end-start)/P*(id+1);
  if(my_end > end) my_end = end;

  //state.my_start = my_start+64;
  //state.my_end = my_end-64-MAX_CHUNK_SIZE;

  state.my_start = start;
  state.my_end = start+32;

  extern spinlock_t kernel_lock;
  state.my_start = &kernel_lock - 256*1024*1024 + core_id()*4096;
  state.my_end = state.my_end + 4096;*/

  long long i;
  for(i = 0; ; i++)
  {
    __asm__ __volatile__ ("nop;nop;nop;nop;nop;nop;nop;nop");
    __asm__ __volatile__ ("nop;nop;nop;nop;nop;nop;nop;nop");
    __asm__ __volatile__ ("nop;nop;nop;nop;nop;nop;nop;nop");
    __asm__ __volatile__ ("nop;nop;nop;nop;nop;nop;nop;nop");
    __asm__ __volatile__ ("nop;nop;nop;nop;nop;nop;nop;nop");
    __asm__ __volatile__ ("nop;nop;nop;nop;nop;nop;nop;nop");
    __asm__ __volatile__ ("nop;nop;nop;nop;nop;nop;nop;nop");
    __asm__ __volatile__ ("nop;nop;nop;nop;nop;nop;nop;nop");
    __asm__ __volatile__ ("nop;nop;nop;nop;nop;nop;nop;nop");
    __asm__ __volatile__ ("nop;nop;nop;nop;nop;nop;nop;nop");
    __asm__ __volatile__ ("nop;nop;nop;nop;nop;nop;nop;nop");
    __asm__ __volatile__ ("nop;nop;nop;nop;nop;nop;nop;nop");
    __asm__ __volatile__ ("nop;nop;nop;nop;nop;nop;nop;nop");
    __asm__ __volatile__ ("nop;nop;nop;nop;nop;nop;nop;nop");
    __asm__ __volatile__ ("nop;nop;nop;nop;nop;nop;nop;nop");
    __asm__ __volatile__ ("nop;nop;nop;nop;nop;nop;nop;nop");
    __asm__ __volatile__ ("nop;nop;nop;nop;nop;nop;nop;nop");
    __asm__ __volatile__ ("nop;nop;nop;nop;nop;nop;nop;nop");
    __asm__ __volatile__ ("nop;nop;nop;nop;nop;nop;nop;nop");
    __asm__ __volatile__ ("nop;nop;nop;nop;nop;nop;nop;nop");
    __asm__ __volatile__ ("nop;nop;nop;nop;nop;nop;nop;nop");
    __asm__ __volatile__ ("nop;nop;nop;nop;nop;nop;nop;nop");
    __asm__ __volatile__ ("nop;nop;nop;nop;nop;nop;nop;nop");
    __asm__ __volatile__ ("nop;nop;nop;nop;nop;nop;nop;nop");
    __asm__ __volatile__ ("nop;nop;nop;nop;nop;nop;nop;nop");
    __asm__ __volatile__ ("nop;nop;nop;nop;nop;nop;nop;nop");
    __asm__ __volatile__ ("nop;nop;nop;nop;nop;nop;nop;nop");
    __asm__ __volatile__ ("nop;nop;nop;nop;nop;nop;nop;nop");
    __asm__ __volatile__ ("nop;nop;nop;nop;nop;nop;nop;nop");
    __asm__ __volatile__ ("nop;nop;nop;nop;nop;nop;nop;nop");
    __asm__ __volatile__ ("nop;nop;nop;nop;nop;nop;nop;nop");
    __asm__ __volatile__ ("nop;nop;nop;nop;nop;nop;nop;nop");
    /*check_error();
    state.i = i;
    random_test(&state);*/
  }
}

void* kernel_entryp = &kernel_main;

void lock();
void unlock();


void fake_printf(char* str, ...)
{
  //__asm__ __volatile__ ("save %sp,-64,%sp; restore");
  //__write(1,str,strlen(str));

  lock();
  unlock();

  //extern spinlock_t kernel_lock;
  //spinlock_lock(&kernel_lock);
  //spinlock_unlock(&kernel_lock);
}

/*asm (
  ".global lock\n"
  "lock:\n\t"
  "sethi %hi(kernel_lock),%g1\n\t"
  "clr %g2\n\t"
  "or %g1,%lo(kernel_lock),%g3\n\t"
  "mov %g2,%g1\n\t"
//  "blah: st %g1,[%g3]\n\t"
  "blah: ld [%g3],%g1\n\t"
  "cmp %g1,0\n\t"
  "bne blah\n\t"
  "mov %g2,%g1\n\t"
  "retl\n\t"
  "nop\n\t"
);

asm (
  ".global unlock\n"
  "unlock:\n\t"
  "sethi %hi(kernel_lock),%g1\n\t"
  //"clr [%g1+%lo(kernel_lock)]\n\t"
  "ld [%g1+%lo(kernel_lock)],%g1\n\t"
  "retl\n\t"
  "nop\n\t"
);*/

asm (
  ".global lock\n"
  "lock:\n\t"
  "sethi %hi(kernel_lock),%g1\n\t"
  "clr %g2\n\t"
  "or %g1,%lo(kernel_lock),%g3\n\t"
  "mov %g2,%g1\n\t"
//  "blah: st %g1,[%g3]\n\t"
  "blah: nop\n\t"
  "cmp %g1,0\n\t"
  "bne blah\n\t"
  "mov %g2,%g1\n\t"
  "retl\n\t"
  "nop\n\t"
);

asm (
  ".global unlock\n"
  "unlock:\n\t"
  "nop\n\t"
  "nop\n\t"
  "retl\n\t"
  "nop\n\t"
);
