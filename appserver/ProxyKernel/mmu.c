#include "kernel.h"
#include "hart.h"
#include <string.h>

void set_up_mmu()
{
  static volatile unsigned int* mmu_context_table;
  static volatile unsigned int* l1_page_table;
  static volatile unsigned int* l2_page_tables;
  static volatile unsigned int* l3_page_tables;
  const int mycontext = 3;

  static volatile int done = 0;
  if(core_id() != 0)
    goto turn_on_mmu;

  unsigned int* mmuctxtbl = kcalloc(4*256,4*256);
  unsigned int* l1pt = kcalloc(4*256,4*256);
  unsigned int* l2pt = kcalloc(4*(KERNEL_VIRTUAL_START >> 18),256);
  unsigned int* l3pt = kcalloc(4*(KERNEL_VIRTUAL_START >> 12),256);
  mmuctxtbl[mycontext] = ((unsigned long)l1pt >> 4) | 1;

  l1pt[KERNEL_VIRTUAL_START >> 24] = (KERNEL_VIRTUAL_START>>4)|0x1E;

  int i;
  for(i = 0; i < (KERNEL_VIRTUAL_START >> 24); i++)
    l1pt[i] = (((long)(l2pt) >> 4) | 1) + 16*i;

  for(i = 0; i < (KERNEL_VIRTUAL_START >> 18); i+=8)
  {
    l2pt[i+0] = ((unsigned long)(l3pt) >> 4 | 1) + 16*(i+0);
    l2pt[i+1] = ((unsigned long)(l3pt) >> 4 | 1) + 16*(i+1);
    l2pt[i+2] = ((unsigned long)(l3pt) >> 4 | 1) + 16*(i+2);
    l2pt[i+3] = ((unsigned long)(l3pt) >> 4 | 1) + 16*(i+3);
    l2pt[i+4] = ((unsigned long)(l3pt) >> 4 | 1) + 16*(i+4);
    l2pt[i+5] = ((unsigned long)(l3pt) >> 4 | 1) + 16*(i+5);
    l2pt[i+6] = ((unsigned long)(l3pt) >> 4 | 1) + 16*(i+6);
    l2pt[i+7] = ((unsigned long)(l3pt) >> 4 | 1) + 16*(i+7);
  }

  for(i = 0; i < (KERNEL_VIRTUAL_START >> 12); i+=8)
  {
    l3pt[i+0] = 256*(i+0) | 0x0E;
    l3pt[i+1] = 256*(i+1) | 0x0E;
    l3pt[i+2] = 256*(i+2) | 0x0E;
    l3pt[i+3] = 256*(i+3) | 0x0E;
    l3pt[i+4] = 256*(i+4) | 0x0E;
    l3pt[i+5] = 256*(i+5) | 0x0E;
    l3pt[i+6] = 256*(i+6) | 0x0E;
    l3pt[i+7] = 256*(i+7) | 0x0E;
  }
  l3pt[0] = 0x1A;

  mmu_context_table = mmuctxtbl;
  l1_page_table = l1pt;
  l2_page_tables = l2pt;
  l3_page_tables = l3pt;

  done = 1;
turn_on_mmu:
  while(!done);

  store_alternate(0x400,ASI_FLUSH,0);
  store_alternate(MMU_CONTEXT_TABLE_REG,ASI_MMU_REGS,(int)mmu_context_table>>4);
  store_alternate(MMU_CONTEXT_REG,ASI_MMU_REGS,mycontext);
  store_alternate(MMU_CONTROL_REG,ASI_MMU_REGS,1);
}
