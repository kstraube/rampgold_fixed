#include "openprom.h"
#include <host.h>
#include "bootloader.h"
#include "syscall.h"

char* arg0 = 0;
char* arg1 = "-p";
char* arg2 = "console=tty";
char* arg3 = 0;

struct property
{
  char name[32];
  char value[32];
  int value_len;
};

struct node
{
  const struct property* properties;
  int next_sibling;
  int first_child;
};

#define MAX_NODES 70
struct node nodes[MAX_NODES];
int num_nodes = 0;

struct linux_romvec romvec;
struct linux_nodeops nodeops;
struct linux_mlist_v0 available[32];
struct linux_mlist_v0* available_ptr;
struct linux_mlist_v0* totphys_ptr;
struct linux_mlist_v0 totphys[32];
struct linux_mlist_v0* prommap_ptr;
struct linux_mlist_v0 prommap[32];
struct linux_arguments_v0* arguments;
struct linux_arguments_v0 arguments0;
void (*romvec_synchook)() = 0;
char stdout_type;
char stdin_type;

const int last_noncpu_node = 3;

void romvec_strcpy(char* dest, const char* src)
{
  int i = 0;
  do
  {
    dest[i] = src[i];
  }
  while(src[i++]);
}

void romvec_memcpy(char* dest, const char* src, int len)
{
  int i;
  for(i = 0; i < len; i++)
    dest[i] = src[i];
}

int romvec_str_eq(const char* s0, const char* s1)
{
  const unsigned char* a = (const unsigned char*)s0; // improves gcc codegen
  const unsigned char* b = (const unsigned char*)s1;
  int i;
  for(i = 0; a[i] && a[i] == b[i]; i++);
  return a[i] == b[i];
}

int romvec_strlen(const char* s)
{
  const unsigned char* s0 = (const unsigned char*)s;
  int i;
  for(i = 0; s[i]; i++);
  return i;
}

int romvec_no_nextnode(int node)
{
  if(node < 0 || node >= num_nodes)
    return -1;
  return nodes[node].next_sibling;
}

int romvec_no_child(int node)
{
  if(node < 0 || node >= num_nodes)
    return -1;
  return nodes[node].first_child;
}

const struct property root_properties[] = {
  {"name","ramp_root",10},
  {"device_type","root",5},
  {"compatible","leon2",6},
  /* see arch/sparc/include/asm/idprom.h for explanation of below */
  {"idprom",{1,0x31,0xfe,0xed,0xbe,0xef,0xf0,0x0d,0,0,0,0,0,0,0,0x8f},16},
  {"","",0}
};

const struct property display_properties[] = {
  {"name","ramp_display",13},
  {"device_type","display",8},
  {"","",0}
};

const struct property auxio_properties[] = {
  {"name","auxiliary-io",13},
  {"","",0}
};

const struct property cpu_properties[] = {
  {"name","ramp_cpu",9},
  {"device_type","cpu",4},
  {"","",0}
};

char* romvec_no_nextprop(int node, char* which)
{
  const struct property* properties = node < num_nodes ? nodes[node].properties : 0;

  if(properties)
  {
    int i;
    for(i = 0; properties[i].name[0]; i++)
      if(romvec_str_eq(properties[i].name,which))
        return (char*)properties[i+1].name;
  }

  return "";
}

int romvec_no_proplen(int node, const char* which)
{
  const struct property* properties = node < num_nodes ? nodes[node].properties : 0;

  if(properties)
  {
    int i;
    for(i = 0; properties[i].name[0]; i++)
      if(romvec_str_eq(properties[i].name,which))
        return properties[i].value_len;
  }

  return -1;
}

int romvec_no_getprop(int node, const char* which, char* dest)
{
  const struct property* properties = node < num_nodes ? nodes[node].properties : 0;

  if(properties)
  {
    int i;
    for(i = 0; properties[i].name[0]; i++)
    {
      if(romvec_str_eq(properties[i].name,which))
      {
        romvec_memcpy(dest,properties[i].value,properties[i].value_len);
        return 0;
      }
    }
  }

  return -1;
}

int romvec_nbgetchar()
{
  return sys_nbgetch();
}

int romvec_getchar()
{
  int ch;
  while((ch = romvec_nbgetchar()) == -1);
  return ch;
}

int romvec_nbputchar(int ch)
{
  return sys_nbputch(ch);
}

void romvec_putchar(int ch)
{
  while(romvec_nbputchar(ch) == -1);
}

void romvec_putstr(char* str, int len)
{
  int i;
  for(i = 0; i < len; i++)
    romvec_putchar(str[i]);
}

void romvec_halt()
{
  char msg[] = "PROM halt!\n";
  romvec_putstr(msg,sizeof(msg)-1);
  sys_exit(-1);
}

void romvec_abort()
{
  char msg[] = "PROM abort!\n";
  romvec_putstr(msg,sizeof(msg)-1);
  sys_exit(-1);
}

void romvec_reboot(char* bootstr)
{
  char msg[] = "PROM reboot!\n";
  romvec_putstr(msg,sizeof(msg)-1);
  sys_exit(-1);
}

void set_up_mmu()
{
  int my_context = 0, i;
  extern unsigned int __mmu_context_table[CTX_TABLE_ENTRIES];
  extern unsigned int __l1_page_table[L1_PAGE_TABLE_ENTRIES];

  // we aren't mapped in yet, so subtract our offset
  unsigned int offset;
  __asm__ __volatile__ ("1: call 2f; nop; 2: set 1b,%0; sub %%o7,%0,%0" : "=r"(offset) : : "o7");
  unsigned int* mmu_context_table = __mmu_context_table+offset/sizeof(unsigned int);
  unsigned int* l1_page_table = __l1_page_table+offset/sizeof(unsigned int);

  // invalidate all contexts but current one
  for(i = 0; i < CTX_TABLE_ENTRIES; i++)
    mmu_context_table[i] = 0;
  mmu_context_table[my_context] = ((int)l1_page_table >> 4) | 1;

  // invalidate the whole page table
  for(i = 0; i < L1_PAGE_TABLE_ENTRIES; i++)
    l1_page_table[i] = 0;

  // map this bootloader (0V -> 0P, 16MB)
  l1_page_table[0] = 0x1E;

  // map the kernel (0xf0000000 -> 0x00000000, 256MB)
  unsigned int virtual;
  for(virtual = 0xf0000000; virtual != 0; virtual += L1_PAGE_SIZE)
    l1_page_table[virtual/L1_PAGE_SIZE] = ((virtual+0x10000000) >> 4) | 0x1E;

  // flush tlb
  store_alternate(0x000,3,0x400);
  // write context table register
  store_alternate(0x100,4,(int)mmu_context_table>>4);
  // write context number
  store_alternate(0x200,4,my_context);
  // write control register to turn on MMU
  store_alternate(0x000,4,1);  
}

void romvec_init()
{
  #define make_node(node,prop,sib,child) do { int temp = node; if(temp >= MAX_NODES) romvec_halt(); nodes[temp].properties = prop; nodes[temp].next_sibling = sib; nodes[temp].first_child = child; } while(0)
  make_node(0,0,1,-1);
  make_node(1,root_properties,-1,2);
  num_nodes = 2;
  int i;
  for(i = 0; i < num_cores(); i++)
  {
    make_node(num_nodes,cpu_properties,num_nodes+1,-1); num_nodes++;
  }
  make_node(num_nodes,display_properties,num_nodes+1,-1); num_nodes++;
  make_node(num_nodes,auxio_properties,-1,-1); num_nodes++;
  
  nodeops.no_nextnode = &romvec_no_nextnode;
  nodeops.no_getprop = &romvec_no_getprop;
  nodeops.no_proplen = &romvec_no_proplen;
  nodeops.no_child = &romvec_no_child;
  nodeops.no_nextprop = &romvec_no_nextprop;
  romvec.pv_nodeops = &nodeops;

  romvec.pv_getchar = &romvec_getchar;
  romvec.pv_nbgetchar = &romvec_nbgetchar;
  romvec.pv_putchar = &romvec_putchar;
  romvec.pv_nbputchar = &romvec_nbputchar;
  romvec.pv_putstr = &romvec_putstr;
  romvec.pv_halt = &romvec_halt;
  romvec.pv_abort = &romvec_abort;
  romvec.pv_reboot = &romvec_reboot;
  romvec.pv_synchook = &romvec_synchook;

  unsigned int mb0 = memsize_MB();
  if(mb0 > 4096 || mb0 < 256)
    romvec_halt();

  unsigned int start = 0, mb = mb0;
  for(i = 0; mb > 0; i++)
  {
    unsigned int this_mb = mb >= 256 ? 256 : mb;
    totphys[i].start_adr = start;
    start += totphys[i].num_bytes = this_mb<<20;
    mb -= this_mb;
    totphys[i].theres_more = &totphys[i+1];
  }
  totphys[i-1].theres_more = 0;
  totphys_ptr = totphys;
  romvec.pv_v0mem.v0_totphys = &totphys_ptr;

  // we leave the first 256MB "unavailable"
  //start = 256*1024*1024; mb = mb0-256;
  start = 0; mb = mb0;
  for(i = 0; mb > 0; i++)
  {
    unsigned int this_mb = mb >= 256 ? 256 : mb;
    available[i].start_adr = start;
    start += available[i].num_bytes = this_mb<<20;
    mb -= this_mb;
    available[i].theres_more = &available[i+1];
  }
  available[i-1].theres_more = 0;
  available_ptr = available;
  romvec.pv_v0mem.v0_available = &available_ptr;

  prommap[0].start_adr = 0;
  prommap[0].num_bytes = 256*1024*1024;
  prommap[0].theres_more = 0;
  prommap_ptr = prommap;
  romvec.pv_v0mem.v0_prommap = &prommap_ptr;

  arguments0.argv[0] = arg0;
  arguments0.argv[1] = arg1;
  arguments0.argv[2] = arg2;
  arguments0.argv[3] = arg3;
  arguments = &arguments0;
  romvec.pv_v0bootargs = &arguments;

  stdout_type = PROMDEV_TTYA;
  romvec.pv_stdout = &stdout_type;
  stdin_type = PROMDEV_TTYA;
  romvec.pv_stdin = &stdin_type;

  char str[] = "Jumping into Linux...\n";
  romvec_putstr(str,sizeof(str)-1);
}
