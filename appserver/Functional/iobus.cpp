#include "iobus.h"
#include "sim.h"
#include "processor.h"
#include "targetconfig.h"
#include "cache.h"
#include <sys/times.h>
#include <Common/util.h>

iobus_functional_t::iobus_functional_t(sim_t* s)
  : iobus_t(s)
{
}

uint32_t iobus_functional_t::load_word(uint32_t addr, processor_t* proc)
{
  uint64_t ctr;
  static uint32_t latch = 0;
  struct tms t;
  
  int which_counter = (addr >> 3) & 0x1F;
  unsigned int which_cpu = (addr >> 10) & 0x3F;
  if(which_cpu >= sim->nprocs)
    return 0;

  switch(which_counter)
  {
    case  0: ctr = sim->cycle; break;
    case  1: times(&t); ctr = uint64_t(double(t.tms_utime)/sysconf(_SC_CLK_TCK)*1e8); break;
    case  2: ctr = 0; break;
    case  3: ctr = 0; break;
    case  4: ctr = 0; break;
    case  5: ctr = 0; break;
    case  6: ctr = 0; break;
    case  7: ctr = 0; break;
    case  8: ctr = 0; break;
    case  9: ctr = 0; break;
    case 10: ctr = 0; break;
    case 11: ctr = 0; break;
    case 12: ctr = 0; break;
    case 13: ctr = 0; break;
    case 14: ctr = 0; break;
    case 15: ctr = 0; break;
    case 16: ctr = 0; break;
    case 17: ctr = sim->procs[which_cpu].nretired; break;
    case 18: ctr = sim->procs[which_cpu].ncti; break;
    case 19: ctr = sim->procs[which_cpu].nfpop; break;
    case 20: ctr = 0; break;
    case 21: ctr = sim->procs[which_cpu].nldhit; break;
    case 22: ctr = sim->procs[which_cpu].nld-sim->procs[which_cpu].nldhit; break;
    case 23: ctr = sim->procs[which_cpu].nsthit; break;
    case 24: ctr = sim->procs[which_cpu].nst-sim->procs[which_cpu].nsthit; break;
    case 25: ctr = sim->procs[which_cpu].nretired-sim->procs[which_cpu].nicmiss; break;
    case 26: ctr = sim->procs[which_cpu].nicmiss; break;
    case 27: ctr = sim->procs[which_cpu].ntrap; break;
    default: ctr = 0; break;
  }

  if(addr % 8 == 4)
    return latch;
  else
  {
    debug_assert(addr % 8 == 0);
    latch = (uint32_t)ctr;
    return (uint32_t)(ctr >> 32);
  }

  return ctr;
}

void iobus_functional_t::store_word(uint32_t addr, uint32_t value, processor_t* proc)
{
  static int cache_config[32] = {0};

  uint32_t mask = (addr >> 16) & 0xF;
  unsigned int which_cpu = (addr >> 10) & 0x3F;
  addr = addr & 0x1FF;

  switch(mask)
  {
    case 0: // timing model
      if(addr < sizeof(cache_config))
        cache_config[addr/4] = value;
      if(addr == 124)
      {
        if(cache_config[6] && cache_config[14] && cache_config[22])
        {
          #ifdef CACHE_SIM
            memory_t* l2_cache = new simple_cache_t(sim->nprocs,cache_config[16],cache_config[17],cache_config[18],cache_config[19],cache_config[20],cache_config[21],cache_config[22],cache_config[23], new deterministic_memory_t(cache_config[24]));

            memory_t* l1d_cache = new simple_cache_t(sim->nprocs,cache_config[0],cache_config[1],cache_config[2],cache_config[3],cache_config[4],cache_config[5],cache_config[6],cache_config[7],l2_cache);
            for(int i = 0; i < sim->nprocs; i++)
              sim->procs[i].dcache = l1d_cache;

            memory_t* l1i_cache = new simple_cache_t(sim->nprocs,cache_config[8],cache_config[9],cache_config[10],cache_config[11],cache_config[12],cache_config[13],cache_config[14],cache_config[15],l2_cache);
            for(int i = 0; i < sim->nprocs; i++)
              sim->procs[i].icache = l1i_cache;
          #endif
        }
      }
      break;

    case 1: // timer interrupt
    {
      int timer_enable = (value >> TIMER_PERIOD_BITS) & 1;
      int timer_period = value & ((1 << TIMER_PERIOD_BITS)-1);
      proc->timer_period = timer_enable ? 1+timer_period : 0;
      break;
    }
    case 2: // ipi
      if(which_cpu >= sim->nprocs)
        break;
      sim->procs[which_cpu].ipi_pending = true;
      break;
  }
}

