#include <TestAppServer/perfctr.h>
#include "syscall.h"
#include "kernel.h"
#include <string.h>

void print_stats(int tare)
{
  int i,i0,p,ncores=num_cores();
  #define num_global_ctrs (sizeof(target_global_counters)/sizeof(char*))
  #define num_per_proc_ctrs (sizeof(per_proc_counters)/sizeof(char*))
  static long long global_ctrs[num_global_ctrs];
  static long long per_proc_ctrs[MAX_PROCS][num_per_proc_ctrs];

  for(i = 0; i < num_global_ctrs; i++)
    global_ctrs[i] = read_perfctr(0,i) - (tare ? 0 : global_ctrs[i]);

  for(p = 0; p < ncores; p++)
    for(i = 0; i < num_per_proc_ctrs; i++)
      per_proc_ctrs[p][i] = read_perfctr(p,i+num_global_ctrs) - (tare ? 0 : per_proc_ctrs[p][i]);

  if(tare)
    return;

  char buf[64];
  char pad0[32];
  for(i = 0; i < 31; i++)
    pad0[i] = ' ';
  pad0[31] = 0;

  for(p = 0; p < ncores; p++)
  {
    ksprintf(buf,"\ncore %d:\n",p);
    __write(2,buf,strlen(buf));
    for(i = 0; i < num_per_proc_ctrs; i++)
    {
      char* pad = pad0+2+strlen(per_proc_counters[i]);
      ksprintf(buf,"  %s%s %l\n",per_proc_counters[i],pad,per_proc_ctrs[p][i]);
      __write(2,buf,strlen(buf));
    }
  }

  for(i = 0; i < num_global_ctrs; i++)
  {
    char* pad = pad0+strlen(target_global_counters[i]);
    ksprintf(buf,"%s%s %l\n",target_global_counters[i],pad,global_ctrs[i]);
    __write(2,buf,strlen(buf));
  }
}
