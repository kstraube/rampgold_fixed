#include "syscall.h"
#include "kernel.h"

extern volatile int magic_mem[10];

int sys_nbputch(int ch)
{
  static spinlock_t putch_lock = SPINLOCK_INIT;
  spinlock_lock(&putch_lock);

  int ret = -1;
  if(magic_mem[8] == 0)
  {
    magic_mem[8] = (unsigned int)(unsigned char)ch;
    ret = 0;
  }

  spinlock_unlock(&putch_lock);
  return ret;
}

int sys_nbgetch()
{
  static spinlock_t getch_lock = SPINLOCK_INIT;
  spinlock_lock(&getch_lock);

  int result = -1;
  if(magic_mem[9])
  {
    result = magic_mem[9];
    magic_mem[9] = 0;
  }

  spinlock_unlock(&getch_lock);
  return result;
}

int sys_frontend(int a0, int a1, int a2, int a3, int syscall_num, int* err)
{
  int fail, ret;

  static spinlock_t frontend_lock = SPINLOCK_INIT;
  spinlock_lock(&frontend_lock);

  magic_mem[7] = 0;
  magic_mem[1] = syscall_num;
  magic_mem[2] = a0;
  magic_mem[3] = a1;
  magic_mem[4] = a2;
  magic_mem[5] = a3;
  magic_mem[6] = 0;
  magic_mem[0] = 0x80;

  while (magic_mem[7] == 0) ;

  ret = magic_mem[1];
  if(err)
    *err = magic_mem[2];

  spinlock_unlock(&frontend_lock);

  return ret;
}

#pragma weak print_stats
void print_stats(int tare)
{
}

void sys_exit(int status)
{
  print_stats(0);
  sys_frontend(status,0,0,0,RAMP_SYSCALL_exit,0);
  while(1);
}

