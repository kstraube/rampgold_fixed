#ifndef _PERFCTR_H
#define _PERFCTR_H

#define PERFCTR_CORE_ADDR_OFFSET 1024

static const char* target_global_counters[] = 
{
  "cycles",
  "host cycles",
  "l2 hits",
  "l2 misses",
  "l2 writebacks",
  "host i$ misses",
  "host d$ load misses",
  "host d$ store misses",
  "host itlb misses",
  "host dtlb misses", 
  "host d$ block counts",
  "host d$ raw hazards",
  "host total replays",
  "host mul replays",
  "host fpu replays",
  "host microcode modes",
  "host idle cycles"
};

static const char* per_proc_counters[] =
{
  "instructions retired",
  "control transfer instructions",
  "flops",
  "l1 writebacks",
  "l1 load hits",
  "l1 load misses",
  "l1 store hits",
  "l1 store misses",
  "l1 icache hits",
  "l1 icache misses",
  "traps"
};

static const char* host_global_counters[] =
{
  "host cycles",
  "I$ misses",
  "LD misses",
  "ST missies",
  "Instruction retired", 
  "Loads and stores",
  "block count",
  "raw count",
  "replay",
  "microcode",
  "idle"
}; 

#endif
