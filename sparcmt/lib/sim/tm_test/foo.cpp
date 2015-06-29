#include <stdio.h>
#include <Functional/sim.h>
#include <Functional/processor.h>
#include <Functional/iobus.h>
#include <TestAppServer/appserver.h>
#include <TestAppServer/tohost.h>
#include "tm_test.h"
#include <assert.h>
#include <queue>
#include <utility>

appserver_t* app = NULL;
sim_t* sim = NULL;
class iobus_dpi_t;
iobus_dpi_t* iobus = NULL;

const tm2cpu_token_type* current_tm2cpu = NULL;
tm_cpu_ctrl_token_type* current_cpu2tm = NULL;
const io_bus_out_type* current_io_in = NULL;
io_bus_in_type* current_io_out = NULL;
io_bus_in_type next_io_out;

unsigned int get_bitfield(const svBitVecVal* b, int width)
{
  assert(width <= 32);
  return width == 32 ? b[0] : b[0] & ~(-1 << width);
}

void set_bitfield(svBitVecVal* b, int width, unsigned int val)
{
  assert(width <= 32);
  b[0] = width == 32 ? val : val & ~(-1 << width);
}

class iobus_dpi_t : public iobus_t
{
public:
  std::queue<std::pair<uint32,uint32> > deferred_store_queue;
  int* load_retry;
  int* load_data;
  int prev_load_attempted,prev_prev_load_attempted;
  
  iobus_dpi_t(sim_t* s)
   : iobus_t(s)
  {
    load_retry = (int*)calloc(sim->nprocs,sizeof(int));
    load_data = (int*)calloc(sim->nprocs,sizeof(int));
    prev_load_attempted = prev_prev_load_attempted = -1;
  }
  
  ~iobus_dpi_t()
  {
    free(load_retry);
    free(load_data);
  }

  uint32 load_word(uint32 addr, processor_t* proc)
  {
    if(current_tm2cpu == NULL)
      return 0;
    
    int tid = get_bitfield(current_tm2cpu->tid,6);
    if(load_retry[tid] == 2)
    {
      load_retry[tid] = 0;
      return load_data[tid];
    }

    set_bitfield(current_io_out->addr,13,addr);
    
    next_io_out.rw = 0;
    next_io_out.en = 1;
    next_io_out.replay = load_retry[tid];
    
    prev_load_attempted = tid;
    load_retry[tid] = 1;
    throw trap_replay;
  }
  
  void store_word(uint32 addr, uint32 val, processor_t* proc)
  {
    if(current_tm2cpu == NULL)
    {
      deferred_store_queue.push(std::pair<uint32,uint32>(addr,val));
      return;
    }
      
    set_bitfield(current_io_out->addr,13,addr);

    set_bitfield(next_io_out.wdata,32,val);
    next_io_out.rw = 1;
    next_io_out.en = 1;
    next_io_out.replay = 0;
    set_bitfield(next_io_out.we,4,-1);
  }
  
  void tick()
  {
    memcpy(current_io_out,&next_io_out,sizeof(next_io_out));
    set_bitfield(current_io_out->tid,6,get_bitfield(current_tm2cpu->tid,6));
    memset(&next_io_out,0,sizeof(next_io_out));
    
    if(prev_prev_load_attempted != -1)
    {
      if(current_io_in->retry)
        load_retry[prev_prev_load_attempted] = 1;
      else
      {
        load_retry[prev_prev_load_attempted] = 2;
        load_data[prev_prev_load_attempted] = get_bitfield(current_io_in->rdata,32);
      }
    }
    prev_prev_load_attempted = prev_load_attempted;
    prev_load_attempted = -1;
  }
  
  void execute_deferred_store()
  {
    printf("Executing deferred store [%x] <= %x\n",deferred_store_queue.front().first,deferred_store_queue.front().second);
    store_word(deferred_store_queue.front().first,deferred_store_queue.front().second,NULL);
    deferred_store_queue.pop();
  }
};

extern "C" void init(const char* cmdline, int silent)
{
  memset(&next_io_out,0,sizeof(next_io_out));
  
  printf("Making sim\n");
  
  sim = new sim_t;
  sim->interactive = 0;
  sim->silent = silent;

  printf("Making IO bus\n");
  sim->iobus = iobus = new iobus_dpi_t(sim);
  
  printf("Making appserver\n");
  app = new appserver_t;
  app->set_htif(sim);
  
  char* env = 0;
  char** envp = &env;
  int argc = 1 + (cmdline[0] != 0);
  for(int i = 0; cmdline[i]; i++)
    argc += (cmdline[i] == ' ');
  char** argv = (char**)malloc(argc*sizeof(char*));
  argv[0] = strdup("sparcfs_app");
  const char* start = cmdline;
  for(int i = 1; i < argc-1; i++)
  {
    const char* end = strchr(start,' ');
    argv[i] = (char*)malloc((end-start+1)*sizeof(char));
    memcpy(argv[i],start,end-start);
    argv[i][end-start] = 0;
    start = end+1;
  }
  if(start[0])
    argv[argc-1] = strdup(start);
    
  printf("Invoking ");
  for(int i = 0; i < argc; i++)
    printf("%s ",argv[i]);
  printf("\n");

  app->load_program(argc,argv,envp);
  
  for(int i = 0; i < argc; i++)
    free(argv[i]);
  free(argv);
  
  printf("Running %s...\n",sim->silent ? "silently" : "noisily");
}

extern "C" void insn_retired_callback(int tid, uint32 insn, uint32 pc, uint32 npc, uint32 eff_addr)
{
  assert(current_tm2cpu && current_cpu2tm);
  assert((int)get_bitfield(current_tm2cpu->tid,6) == tid);
  
  set_bitfield(current_cpu2tm->inst,32,insn);
  set_bitfield(current_cpu2tm->paddr,32,eff_addr);
  set_bitfield(current_cpu2tm->npc,32,npc);
}

extern "C" void tick(const tm2cpu_token_type* tm2cpu, tm_cpu_ctrl_token_type* cpu2tm, const io_bus_out_type* io_in, io_bus_in_type* io_out)
{
  int tid = get_bitfield(tm2cpu->tid,6);
  current_tm2cpu = tm2cpu;
  current_cpu2tm = cpu2tm;
  current_io_in = io_in;
  current_io_out = io_out;
  
  if(sim == NULL || app->do_exit)
    return;
  
  set_bitfield(cpu2tm->tid,6,tid);
  current_cpu2tm->valid = tm2cpu->valid;
  current_cpu2tm->run = tm2cpu->run;
  current_cpu2tm->replay = 0;
  current_cpu2tm->retired = tm2cpu->run;
  
  iobus->tick();
  if(!iobus->deferred_store_queue.empty())
  {
    iobus->execute_deferred_store();
    current_cpu2tm->replay = tm2cpu->valid;
    current_cpu2tm->retired = 0;
  }
  else if(tm2cpu->run)
  {
    assert(tid < sim->nprocs);
    sim->procs[tid].execute();
  }
  
  static int orig_tohost = 0;
  orig_tohost = app->poll_once(orig_tohost);
}
