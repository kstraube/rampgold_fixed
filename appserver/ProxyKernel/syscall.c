#include "syscall.h"
#include "kernel.h"
#include <string.h>
#include <sys/time.h>
#include <sys/times.h>
#include <sys/resource.h>
#include <stdio.h>
#include <ros/syscall.h>
#include <ros/mman.h>
#include <ros/arch/mmu.h>

active_message_mailbox_t active_message_mailbox[MAX_PROCS];

extern volatile int magic_mem[10];

int sys_unimp(int a, int b, int c, int d, int syscall_num)
{
  char msg[64] = "unimplemented syscall number 0x";
  itoa16(syscall_num,msg+strlen(msg));
  panic(msg);
  return 0;
}

int sys_brk(void* addr)
{
  static spinlock_t brk_lock = SPINLOCK_INIT;
  spinlock_lock(&brk_lock);

  static void* heap_bottom = (void*)0x400000;
  static void* heap_top = (void*)0x400000;

  if(addr < heap_bottom || addr >= (void*)(0+UMMAP_START))
    goto out;

  if(addr > heap_top)
    memset(heap_top,0,addr-heap_top);

  heap_top = addr;

out:
  spinlock_unlock(&brk_lock);
  return (int)heap_top;
}

void gettimesinceboot(struct timeval* tp)
{
  long long dt = read_perfctr(0,0);
  tp->tv_sec = dt/TSC_HZ;
  tp->tv_usec = (dt % TSC_HZ)*1000000/TSC_HZ;
}

int sys_gettimeofday(struct timeval* tp, void* tzp)
{
  static int t0 = 0;
  if(t0 == 0)
    t0 = sys_frontend(0,0,0,0,RAMP_SYSCALL_time,0);

  gettimesinceboot(tp);
  tp->tv_sec += t0;
}

int sys_getcpuid()
{
  return core_id();
}

int sys_getvcoreid()
{
  return core_id();
}

int sys_getpid()
{
  return 1;
}

int sys_proc_destroy(int which)
{
  if(which == sys_getpid())
    sys_exit(0);
  return -1;
}

#define FORWARD_SYSCALL(name) \
  int sys_##name(int a0, int a1, int a2, int a3, int num, int* err) { \
    return sys_frontend(a0, a1, a2, a3, RAMP_SYSCALL_##name, err); \
  }

#define UNIMPLEMENTED_SYSCALL(name) \
  int sys_##name(int a0, int a1, int a2, int a3, int num, int* err) { \
    panic("implement " XSTR(name) ", foo!"); \
  }

FORWARD_SYSCALL(write)
FORWARD_SYSCALL(read)
FORWARD_SYSCALL(open)
FORWARD_SYSCALL(close)
FORWARD_SYSCALL(access)
FORWARD_SYSCALL(tcgetattr)
FORWARD_SYSCALL(tcsetattr)
FORWARD_SYSCALL(getcwd)
FORWARD_SYSCALL(chdir)
FORWARD_SYSCALL(chmod)
FORWARD_SYSCALL(link)
FORWARD_SYSCALL(unlink)
FORWARD_SYSCALL(fcntl)
FORWARD_SYSCALL(lseek)
FORWARD_SYSCALL(fstat)
FORWARD_SYSCALL(lstat)
FORWARD_SYSCALL(stat)
FORWARD_SYSCALL(umask)

UNIMPLEMENTED_SYSCALL(fork)
UNIMPLEMENTED_SYSCALL(exec)
UNIMPLEMENTED_SYSCALL(run_binary)
UNIMPLEMENTED_SYSCALL(proc_run)
UNIMPLEMENTED_SYSCALL(proc_create)
UNIMPLEMENTED_SYSCALL(shared_page_alloc)
UNIMPLEMENTED_SYSCALL(shared_page_free)
UNIMPLEMENTED_SYSCALL(trywait)

static spinlock_t mmap_lock = SPINLOCK_INIT;
static char* used_pages;
#define is_page_used(ppn) (used_pages[(ppn)/8] & (1<<((ppn)%8)))
#define set_page_used(ppn,used) do { \
    if(!(used)) \
      used_pages[(ppn)/8] &= ~(1<<((ppn)%8)); \
    else \
      used_pages[(ppn)/8] |= (1<<((ppn)%8)); \
  } while(0)

static void mmap_init()
{
  static spinlock_t mmap_init = SPINLOCK_INIT;
  if(spinlock_trylock(&mmap_init) == 0)
    used_pages = kcalloc(KERNEL_VIRTUAL_START/8/PGSIZE,4);
}

int mmap(uint32_t addr, uint32_t len, int prot, int flags, int fd, int pgoff, int* err)
{
  mmap_init();

  spinlock_lock(&mmap_lock);

  int num_pages = (len+PGSIZE-1)/PGSIZE;
  if(!(flags & MAP_FIXED)) 
  {
    if(addr == 0)
      addr = UMMAP_START;
    addr = addr/PGSIZE*PGSIZE;

    for( ; addr < KERNEL_VIRTUAL_START-num_pages*PGSIZE; addr += PGSIZE)
    {
      int j = 0;
      for( ; j < num_pages; j++)
        if(is_page_used(addr/PGSIZE+j))
          break;
      if(j == num_pages)
        break;
      addr += j*PGSIZE;
    }
    if(addr == KERNEL_VIRTUAL_START-num_pages*PGSIZE)
      goto fail;
  }
  else if(addr % PGSIZE)
    goto fail;
  else if(addr >= KERNEL_VIRTUAL_START || addr+len >= KERNEL_VIRTUAL_START)
    goto fail;
  else
    num_pages = len/PGSIZE;

  if(fd >= 0 && (flags & (MAP_SHARED|MAP_ANON)))
    goto fail;

  for(int i = 0; i < num_pages; i++)
    set_page_used(addr/PGSIZE+i,1);

  memset((void*)addr,0,num_pages*PGSIZE);
  if(fd >= 0)
  {
    int ret = sys_frontend(fd,addr,len,pgoff*PGSIZE,RAMP_SYSCALL_pread,err);
    if(ret == -1)
      goto fail;
  }

  spinlock_unlock(&mmap_lock);

  return addr;


fail:
  spinlock_unlock(&mmap_lock);
  return -1;
}

int sys_mmap(int a0, int a1, int a2, int* extra_args, int foo, int* err)
{
  return mmap(a0,a1,a2,extra_args[0],extra_args[1],extra_args[2],err);
}

int sys_munmap(uint32_t addr, uint32_t len)
{
  mmap_init();

  if(addr % PGSIZE)
    return -1;
  int num_pages = (len+PGSIZE-1)/PGSIZE;

  spinlock_lock(&mmap_lock);

  for(int i = 0; i < num_pages; i++)
    set_page_used(addr/PGSIZE+i,0);
  memset((void*)addr,0,num_pages*PGSIZE);

  spinlock_unlock(&mmap_lock);

  return 0;
}

int sys_mprotect(uint32_t addr, uint32_t len, int prot)
{
  return 0;
}

int sys_resource_req(int resource, int num, int num_min, int flags)
{
  if(resource != 0)
    return -1;

  static spinlock_t resource_lock = SPINLOCK_INIT;
  spinlock_lock(&resource_lock);

  static int cores_granted = 1;
  if(num > num_cores() || num < cores_granted)
  {
    spinlock_unlock(&resource_lock);
    return -1;
  }

  for(int i = 0; i < num-cores_granted; i++)
  {
    int found = 0;
    for(int j = 1; j < num_cores() && !found; j++)
    {
      if(active_message_mailbox[j].lock == SPINLOCK_INIT)
      {
        spinlock_lock(&active_message_mailbox[j].lock);
        if(active_message_mailbox[j].send)
          panic("wtf");
        extern uint32_t user_entryp;
        active_message_mailbox[j].PC = user_entryp;
        active_message_mailbox[j].send = 1;
        found = 1;
      }
    }
    if(!found)
      panic("couldn't find a core");
  }

  cores_granted = num;
  spinlock_unlock(&resource_lock);

  return 0;
}

int sys_proc_yield()
{
  if(core_id() == 0)
    sys_exit(0);
  else
  {
    if(!active_message_mailbox[core_id()].lock)
      panic("wtf");
    if(active_message_mailbox[core_id()].send)
      panic("wtf");
    active_message_mailbox[core_id()].lock = SPINLOCK_INIT;

    asm volatile("ta 1");
  }
}

int handle_syscall(trap_state_t* state, int syscall_num, int a0, int a1, int a2, int a3)
{
  const static void* syscall_table[] = {
    [SYS_getcpuid] = (syscall_t)sys_getcpuid,
    [SYS_getvcoreid] = (syscall_t)sys_getvcoreid,
    [SYS_getpid] = (syscall_t)sys_getpid,
    [SYS_proc_create] = (syscall_t)sys_proc_create,
    [SYS_proc_run] = (syscall_t)sys_proc_run,
    [SYS_proc_destroy] = (syscall_t)sys_proc_destroy,
    [SYS_yield] = (syscall_t)sys_proc_yield,
    [SYS_run_binary] = (syscall_t)sys_run_binary,
    [SYS_fork] = (syscall_t)sys_fork,
    [SYS_exec] = (syscall_t)sys_exec,
    [SYS_trywait] = (syscall_t)sys_trywait,
    [SYS_mmap] = (syscall_t)sys_mmap,
    [SYS_munmap] = (syscall_t)sys_munmap,
    [SYS_mprotect] = (syscall_t)sys_mprotect,
    [SYS_brk] = (syscall_t)sys_brk,
    [SYS_shared_page_alloc] = (syscall_t)sys_shared_page_alloc,
    [SYS_shared_page_free] = (syscall_t)sys_shared_page_free,
    [SYS_resource_req] = (syscall_t)sys_resource_req,
    [SYS_read] = (syscall_t)sys_read,
    [SYS_write] = (syscall_t)sys_write,
    [SYS_open] = (syscall_t)sys_open,
    [SYS_close] = (syscall_t)sys_close,
    [SYS_fstat] = (syscall_t)sys_fstat,
    [SYS_stat] = (syscall_t)sys_stat,
    [SYS_lstat] = (syscall_t)sys_lstat,
    [SYS_fcntl] = (syscall_t)sys_fcntl,
    [SYS_access] = (syscall_t)sys_access,
    [SYS_umask] = (syscall_t)sys_umask,
    [SYS_chmod] = (syscall_t)sys_chmod,
    [SYS_lseek] = (syscall_t)sys_lseek,
    [SYS_link] = (syscall_t)sys_link,
    [SYS_unlink] = (syscall_t)sys_unlink,
    [SYS_chdir] = (syscall_t)sys_chdir,
    [SYS_getcwd] = (syscall_t)sys_getcwd,
    [SYS_gettimeofday] = (syscall_t)sys_gettimeofday,
    [SYS_tcgetattr] = (syscall_t)sys_tcgetattr,
    [SYS_tcsetattr] = (syscall_t)sys_tcsetattr
  };

  syscall_t p = (syscall_t)syscall_table[syscall_num];
  if(syscall_num*sizeof(void*) >= sizeof(syscall_table))
    p = (syscall_t)sys_unimp;

  if(p == (syscall_t)sys_unimp) dump_state(state);

  int result = p(a0,a1,a2,a3,syscall_num,&state->gpr[9]);

  // don't reexecute the trap instruction
  state->pc = state->npc;
  state->npc++;

  // return error code to user
  state->gpr[8] = result;

  return 0;
}
