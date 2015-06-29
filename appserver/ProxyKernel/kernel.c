#include "kernel.h"
#include <string.h>
#include "syscall.h"
#include <stdarg.h>
#include <sys/time.h>
#include <ros/procinfo.h>
#include <itoa.h>

long long __args[(ARGS_SIZE+8)/sizeof(long long)];

#ifndef SMALL_MEM
  #include <Functional/trapnames.c>
#endif

spinlock_t kernel_lock = SPINLOCK_INIT;
volatile int kernel_lock_depth = 0;
volatile int kernel_lock_owner = -1;

void lock_kernel()
{
  if(kernel_lock_owner != core_id())
  {
    spinlock_lock(&kernel_lock);
    kernel_lock_owner = core_id();
  }

  kernel_lock_depth++;
}

void unlock_kernel()
{
  if(kernel_lock_owner != core_id())
  {
    panic("attempted to unlock kernel without owning lock!");
    return; // avoids a 'save' in the common case
  }

  if(--kernel_lock_depth == 0)
  {
    kernel_lock_owner = -1;
    spinlock_unlock(&kernel_lock);
  }
}

void* kmalloc(int size, int align)
{
  // kernel knows best -- kmalloc never fails!

  static spinlock_t mlock = SPINLOCK_INIT;
  spinlock_lock(&mlock);

  static char* brk = 0;
  if(brk == 0)
  {
    extern char _end;
    brk = &_end;
  }

  char* oldbrk = brk;
  if((long)oldbrk & (align-1))
    oldbrk += align - ((long)oldbrk & (align-1));
  brk = oldbrk + size;

  spinlock_unlock(&mlock);

  return oldbrk;
}

void* kcalloc(int size, int align)
{
  void* ptr = kmalloc(size,align);
  return memset(ptr,0,size);
}

void kernel_boot()
{
  __procinfo.pid = 1;
  __procinfo.ppid = 0;
  __procinfo.max_harts = num_cores();
  __procinfo.tsc_freq = TSC_HZ;

  int* args = (int*)&__args[1];
  int argc = args[0];

  for(int i = 0; i < argc; i++)
    __procinfo.argp[i] = args[i+1]+__procinfo.argbuf;
  int size = sizeof(__procinfo.argbuf);
  if(ARGS_SIZE < size)
    size = ARGS_SIZE;
  memcpy(__procinfo.argbuf,args,size);

  __procinfo.argp[argc] = 0;
  __procinfo.argp[argc+1] = 0;
  __procinfo.argp[argc+2] = 0;
}

void vprintk(const char* str, va_list vl)
{
  // this is unsafe but sufficient
  char buf[1024];
  kvsprintf(buf,str,vl);
  __write(2,buf,strlen(buf));
}

void printk(const char* str, ...)
{
  va_list vl;
  va_start(vl,str);
  vprintk(str,vl);
}

char* ksprintf(char* buf, const char* str, ...)
{
  va_list vl;
  va_start(vl,str);
  return kvsprintf(buf,str,vl);
}

char* kvsprintf(char* buf, const char* str, va_list vl)
{
  int ipos, opos = 0, ilen, temp, ch;
  for(ipos = 0; ch = str[ipos]; ipos++)
  {
    if(ch == '%')
    {
      for(temp = ipos+1; str[temp] < 'a' || str[temp] > 'z'; temp++);
      ipos = temp;
      switch(str[temp])
      {
        case 'l':
          itoa(va_arg(vl,long long),buf+opos,10);
          opos = strlen(buf);
          break;
        case 'd':
          itoa((long long)va_arg(vl,int),buf+opos,10);
          opos = strlen(buf);
          break;
        case 'p':
          buf[opos++] = '0';
          buf[opos++] = 'x';
        case 'x':
          itoa((unsigned long long)va_arg(vl,unsigned int),buf+opos,16);
          opos = strlen(buf);
          break;
        case '%':
          buf[opos++] = '%';
          break;
        case 'c':
          buf[opos++] = va_arg(vl,int);
          break;
        case 's':
          strcpy(buf+opos,va_arg(vl,const char*));
          opos = strlen(buf);
          break;
      }
    }
    else
      buf[opos++] = ch;
  }
  buf[opos] = 0;
  return buf;
}

void dump_state(const trap_state_t* state)
{
  char buf[1024];
  const char regname[] = "goli";
  int num_special = 8;
  const char regname2[][4] = {"psr","pc ","npc","wim","tbr","fsr","far","fpu"};

  strcpy(buf,"state dump for thread ");
  int i,j,pos = 0;
  while(buf[pos++]);
  itoa16(core_id(),buf+pos); pos += 8;
  buf[pos++] = '\n';

  for(i = 0; i < 4; i++)
  {
    buf[pos++] = regname[i];
    buf[pos++] = ' ';
    buf[pos++] = ' ';
    for(j = 0; j < 8; j++)
    {
      buf[pos++] = ' ';
      itoa16(state->gpr[i*8+j],buf+pos); pos += 8;
    }
    buf[pos++] = '\n';
  }

  if(state->psr & 0x1000)
  {
    for(i = 0; i < 4; i++)
    {
      buf[pos++] = 'f';
      buf[pos++] = '0'+i*8/10;
      buf[pos++] = '0'+i*8%10;
      for(j = 0; j < 8; j++)
      {
        buf[pos++] = ' ';
        itoa16(state->gpr[i*8+j],buf+pos); pos += 8;
      }
      buf[pos++] = '\n';
    }
  }

  for(i = 0; i < num_special; i++)
  {
    buf[pos++] = regname2[i][0];
    buf[pos++] = regname2[i][1];
    buf[pos++] = regname2[i][2];
    buf[pos++] = ' ';
    itoa16(state->gpr[32+i],buf+pos); pos += 8;

    if(i % 2 || i == num_special-1)
      buf[pos++] = '\n';
    else
    {
      buf[pos++] = ' ';
      buf[pos++] = ' ';
      buf[pos++] = ' ';
      buf[pos++] = ' ';
      buf[pos++] = ' ';
      buf[pos++] = ' ';
    }
  }

  __write(2,buf,pos);
}

char* itoa16(unsigned int value, char* buffer)
{
  int i;
  buffer[8] = 0;

  #define char_val(value) (((value) & 0xF) < 10 ? '0'+((value) & 0xF) : 'a'-10+((value) & 0xF))

  buffer[7] = char_val(value>>0);
  buffer[6] = char_val(value>>4);
  buffer[5] = char_val(value>>8);
  buffer[4] = char_val(value>>12);
  buffer[3] = char_val(value>>16);
  buffer[2] = char_val(value>>20);
  buffer[1] = char_val(value>>24);
  buffer[0] = char_val(value>>28);

  return buffer;
}

void unhandled_trap(trap_state_t* state)
{
  int trap = (state->tbr >> 4) & 0xFF;
  char msg[64];

  lock_kernel();
  dump_state(state);
  backtrace(state);

  #ifdef SMALL_MEM
    panic("unhandled trap: 0x%x",trap);
  #else
    panic("unhandled trap: %s",get_trap_name(trap));
  #endif
}

void access_exception(trap_state_t* state)
{
#ifdef SMALL_MEM
  if(state->mmu_fsr & 0x2)
  {
    uint32_t probe_addr = (state->mmu_far & ~0xFFF) | 0x400, probe_result;
    load_alternate(probe_addr,ASI_PROBE,probe_result);
    char buf[64];
    printk("Thread %d access exception, addr = 0x%08x (probe=0x%08x)\n",core_id(),state->mmu_far,probe_result);
  }
#endif
  unhandled_trap(state);
}

void panic(const char* msg, ...)
{
  lock_kernel();

  char msg0[256];
  const char kp[] = "kernel panic! ";
  memcpy(msg0,kp,sizeof(kp)-1);
  strcpy(msg0+sizeof(kp)-1,msg);
  strcat(msg0,"\n");

  va_list vl;
  va_start(vl,msg);
  vprintk(msg0,vl);

  sys_exit(-1);
}

void flushw_helper(int level)
{
  if(level > 0)
  {
    flushw_helper(level-1);
    __asm__ __volatile__("");
  }
}

void flush_windows()
{
  extern int nwindows;
  flushw_helper(nwindows-1);
}

void handle_flushw(trap_state_t* state)
{
  flush_windows();
  state->pc = state->npc;
  state->npc++;
}

void backtrace(trap_state_t* state)
{
  flush_windows();

  char str[64] = "Backtrace:\n";
  __write(2,str,strlen(str));

  void* sp = (void*)state->gpr[14];
  void* func = (void*)state->pc;

  do
  {
    printk(str,"func = %08x, sp = %08x\n",func,sp);

    func = *((void**)sp+15);
    sp = *((void**)sp+14);
  }
  while(sp);
}

void become_supervisor(trap_state_t* state)
{
  state->psr |= 0x40;
  state->pc = state->npc;
  state->npc++;
}

volatile long long timer_ticks = 0;
void timer_interrupt()
{
  if(core_id() == 0)
    timer_ticks++;
}

