#include <iostream>
#include <ProxyKernel/kernel.h>
using namespace std;

int main()
{
  int ctxaddr = KERNEL_VIRTUAL_START;
  int l1ptaddr = ctxaddr+0x1000;
  int l2ptaddr = l1ptaddr+256*4;
  int l3ptaddr = l2ptaddr+256*64*4;

  cerr << "ctxaddr  == 0x" << hex << ctxaddr << endl;
  cerr << "1lptaddr == 0x" << hex << l1ptaddr << endl;

  cout << hex;
  cout << ".global mmu_context_table" << endl;
  cout << "mmu_context_table:" << endl;
  cout << ".skip 4096" << endl;

  cout << ".global l1_page_table" << endl;
  cout << "l1_page_table:" << endl;
  for(int i = 0; i < 256; i++)
    cout << "  .word 0x" << (((l2ptaddr+64*i*4)>>4)|1) << endl;

  cout << ".global l2_page_tables" << endl;
  cout << "l2_page_tables:" << endl;
  for(int i = 0; i < 256*64; i++)
    cout << "  .word 0x" << (((l3ptaddr+64*i*4)>>4)|1) << endl;

  cout << ".global l3_page_tables" << endl;
  cout << "l3_page_tables:" << endl;
  for(int i = 0; i < 16; i++)
    cout << "  .word 0x" << ((i<<8)|0x1A) << endl;
  for(int i = 16; i < KERNEL_VIRTUAL_START/4096; i++)
    cout << "  .word 0x" << ((i<<8)|0x0E) << endl;
  for(int i = KERNEL_VIRTUAL_START/4096; i < 128*64*64; i++)
    cout << "  .word 0x" << ((i<<8)|0x1E) << endl;
  for(int i = 128*64*64; i < 256*64*64; i++)
    cout << "  .word 0" << endl;

  return 0;
}
