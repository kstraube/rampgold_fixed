#include "tm_test.h"
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <time.h>
#include <assert.h>

DPI_LINK_DECL DPI_DLLESPEC
int
init_simulator(
    const char* cmdline,
    int ncores,
    int silent)
{
  extern void init(const char*,int);
  char buf[256];
  assert(strlen(cmdline) < 224);
  sprintf(buf,"-p%d %s",ncores,cmdline);
  init(buf,silent);
  
  return 0;
}

DPI_LINK_DECL DPI_DLLESPEC
int
tick_simulator(
    const tm2cpu_token_type* tm2cpu,
    tm_cpu_ctrl_token_type* cpu2tm,
    const io_bus_out_type* io_tm2cpu,
    io_bus_in_type* io_cpu2tm)
{
  extern void tick(const tm2cpu_token_type* tm2cpu, tm_cpu_ctrl_token_type* cpu2tm, const io_bus_out_type* io_in, io_bus_in_type* io_out);
  tick(tm2cpu,cpu2tm,io_tm2cpu,io_cpu2tm);
  
  return 0;
}

