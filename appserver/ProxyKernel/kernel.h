#ifndef _KERNEL_H
#define _KERNEL_H

#define KERNEL_USE_TIMER
//#define KERNEL_USE_MMU
//#define DISABLE_FPU

#define ASI_BYPASS 0x1E
#define ASI_IO 0x02
#define ASI_MMU_REGS 0x04
#define ASI_FLUSH 0x03
#define ASI_PROBE 0x03
#define MMU_CONTROL_REG 0x000
#define MMU_CONTEXT_TABLE_REG 0x100
#define MMU_CONTEXT_REG 0x200
#define MMU_FAULT_STATUS_REG 0x300
#define MMU_FAULT_ADDRESS_REG 0x400

#define USER_VIRTUAL_START       0x00000000
#define USER_SIZE                KERNEL_VIRTUAL_START //0x70000000
#define USER_STACK_SIZE_THREAD   0x00010000
#define UMMAP_START              0x10000000
// FIXME
#define KERNEL_VIRTUAL_START     0x70000000
#define KERNEL_SIZE              0x01000000
#define KSTKSHIFT                12
#define KERNEL_STACK_SIZE_THREAD (1 << KSTKSHIFT)

#define bootstacktop KERNEL_VIRTUAL_START+KERNEL_SIZE

#define ARGS_SIZE                0x00001000

#define TIMER_HZ 100

#include <Common/host.h>

#ifndef __ASSEMBLER__

#include <TestAppServer/perfctr.h>
#include <stdarg.h>

#define _QUOTEME(x) #x
#define QUOTEME(x) _QUOTEME(x)

void panic(const char* msg, ...);
char* ksprintf(char* buf, const char* str, ...);
char* kvsprintf(char* buf, const char* str, va_list vl);
void lock_kernel();
void unlock_kernel();
char* itoa16(unsigned int value, char* buffer);
void backtrace();
void printk(const char* str, ...);
void* kcalloc(int size, int align);
void* kmalloc(int size, int align);

static inline long long read_perfctr(int core, int which)
{
  int* addr = (int*)((core*PERFCTR_CORE_ADDR_OFFSET) | (which<<3));
  register long long value asm("o0");
  asm volatile("lda [%0] " QUOTEME(ASI_IO) ",%%o0; inc 4,%0; lda [%0]2,%%o1" : "=r"(addr),"=r"(value) : "0"(addr));
  return value;
}

void print_stats(int tare);

typedef struct
{
  uint32_t gpr[32];
  uint32_t psr;
  uint32_t* pc;
  uint32_t* npc;
  uint32_t wim;
  uint32_t tbr;
  uint32_t mmu_fsr;
  uint32_t mmu_far;
  uint32_t fpu_fsr;
} trap_state_t;

void dump_state(const trap_state_t* state);

typedef struct
{
  spinlock_t lock;
  int srcid;
  int PC;
  int arg0;
  int arg1;
  int arg2;
  int arg3;
  int send;
} active_message_mailbox_t;

#endif

#endif

