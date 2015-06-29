/* Author: Yunsup Lee, Andrew S. Waterman
 *         Parallel Computing Laboratory
 *         Electrical Engineering and Computer Sciences
 *         University of California, Berkeley
 *
 * Copyright (c) 2008, The Regents of the University of California.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *     * Redistributions of source code must retain the above copyright
 *       notice, this list of conditions and the following disclaimer.
 *     * Redistributions in binary form must reproduce the above copyright
 *       notice, this list of conditions and the following disclaimer in the
 *       documentation and/or other materials provided with the distribution.
 *     * Neither the name of the University of California, Berkeley nor the
 *       names of its contributors may be used to endorse or promote products
 *       derived from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE REGENTS ''AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
 * IN NO EVENT SHALL THE REGENTS BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
 * THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include <Functional/cache.h>
#include "appserver.h"
#include "tohost.h"
#include "perfctr.h"
#include <errno.h>
#include <string.h>
#include <assert.h>
#include <signal.h>
#include <Common/htif.h>
#include <Common/memif.h>
#include <Common/util.h>
#include <Common/elf.h>
#include <termios.h>
#include <stdarg.h>
#include <sys/stat.h>

#include "htif_sparc_dma.h"
#include "htif_x86_dma.h"
#include <Functional/sim.h>

void sigint_handler(int sig)
{
  // die gracefully, calling destructors
  exit(0);
}

appserver_t::appserver_t()
{
  seteuid(getuid());

  htif = NULL;
  print_stats = false;
  do_exit = false;
  exit_code = 0;
  noecho = 0;
  nsyscalls = 0;
  no_poll = 1;
  make_trace = 0;
  trace_start = 0;
  max_cycles = 0;
}

appserver_t::~appserver_t()
{
  if(noecho)
  {
    tcsetattr(1,0,&old_termios);
    noecho = 0;
  }

  if(print_stats)
    stats();
}

void appserver_t::noecho_init()
{
  noecho = 1;

  tcgetattr(1,&old_termios);
  struct termios termios = old_termios;
  termios.c_lflag &= ~ECHO;
  termios.c_lflag &= ~ICANON;
  tcsetattr(1,0,&termios);
}

std::string appserver_t::get_filename(const char* fn, const char* path)
{
  if(strchr(fn,'/') != NULL || path == NULL)
    return fn;

  int len = strlen(fn);
  const char* end;

  do
  {
    end = strchr(path,':');
    if(end == NULL) end = path+strlen(path);

    char* new_fn = (char*)alloca(end-path+len+2);
    memcpy(new_fn,path,end-path);
    new_fn[end-path] = '/';
    memcpy(new_fn+(end-path)+1,fn,len+1);

    struct stat buf;
    if(stat(new_fn,&buf) == 0)
      return new_fn;
  }
  while((path = strchr(path,':')) && ++path);

  return fn;
}

void appserver_t::configure_cache(const std::string& name, uint32_t* buf, int max_tags, int max_assoc, int min_offset_bits, int max_offset_bits, int max_banks, int cacheprivate)
{
  int cachesize = properties.get_int((name+".size").c_str());
  int linesize = properties.get_int((name+".linesize").c_str());
  int assoc = properties.get_int((name+".assoc").c_str());
  int access_time = properties.get_int((name+".access_time").c_str());
  int banks = properties.get_int((name+".banks").c_str());

  // cachesize is really the size of each cache bank.
  assert(ispow2(cachesize) && ispow2(linesize) && ispow2(assoc));
  assert(banks <= max_banks && ispow2(banks));
  cachesize /= banks;

  // num_caches is the number of private caches that this cache represents
  int num_caches = cacheprivate ? nprocs : 1;

  int num_sets = cachesize/linesize;
  int num_ways = num_sets/assoc;
  int max_sets = max_tags/assoc;
  max_tags /= max_banks;

  assert(num_ways*num_caches <= max_tags);
  assert(assoc <= max_assoc && assoc <= num_sets);
  assert(min_offset_bits <= log2i(linesize) && log2i(linesize) <= max_offset_bits);

  int target_index_mask = num_ways-1;

  int offset_bits = log2i(linesize);
  int tag_mask = ~(linesize-1);
  int tag_ram_index_mask = (max_tags/max_assoc/num_caches-1) & target_index_mask;
  int bank_mux = bit_reverse(assoc-1,log2i(max_assoc));
  int bank_shift = log2i(max_tags/max_assoc/num_caches);

  #if DEBUG_LEVEL > 0

  printf("  CACHE %s\n",name.c_str());
  printf("------------------------\n");
  printf("SIZE          %10d\n",cachesize);
  printf("ASSOCIATIVITY %10d\n",assoc);
  printf("LINE SIZE     %10d\n",linesize);
  printf("ACCESS TIME   %10d\n",access_time);
  printf("OFFSET BITS   %10d\n",offset_bits);
  printf("TAG MASK      %10x\n",tag_mask);
  printf("TAG RAM MASK  %10x\n",tag_ram_index_mask);
  printf("INDEX MASK    %10x\n",target_index_mask);
  printf("BANK MUX      %10x\n",bank_mux);
  printf("BANK SHIFT    %10x\n",bank_shift);
  printf("\n");

  #endif

  buf[0] = log2i(banks);
  buf[1] = offset_bits-min_offset_bits;
  buf[2] = tag_mask;
  buf[3] = target_index_mask;
  buf[4] = tag_ram_index_mask;
  buf[5] = bank_mux;
  buf[6] = bank_shift;
  buf[7] = access_time;
}

void appserver_t::configure_timing_model()
{
  nprocs = roundup_pow2(nprocs);

  uint32_t buf[128];
  memset(buf,0,sizeof(buf));

  configure_cache("l1d",&buf[0],simple_cache_t::L1D_MAX_TAGS,simple_cache_t::L1D_MAX_ASSOC,simple_cache_t::L1D_MIN_OFFSET_BITS,simple_cache_t::L1D_MAX_OFFSET_BITS,1,1);
  configure_cache("l1i",&buf[8],simple_cache_t::L1I_MAX_TAGS,simple_cache_t::L1I_MAX_ASSOC,simple_cache_t::L1I_MIN_OFFSET_BITS,simple_cache_t::L1I_MAX_OFFSET_BITS,1,1);
  configure_cache("l2",&buf[16],simple_cache_t::L2_MAX_TAGS,simple_cache_t::L2_MAX_ASSOC,simple_cache_t::L2_MIN_OFFSET_BITS,simple_cache_t::L2_MAX_OFFSET_BITS,simple_cache_t::L2_MAX_NUM_BANKS,0);

  buf[24] = properties.get_int("dram.access_time");
  buf[25] = properties.get_int("dram.cycle_time");
  buf[26] = properties.get_int("gsf.cycles_per_frame");

  // initial GSF credits
  for(int i = 0; i < simple_cache_t::MAX_PARTITIONS; i++)
    buf[32+i] = buf[26];

  // initial partition IDs
  for(int i = 0; i < simple_cache_t::MAX_CORES; i++)
    buf[64+i] = 0;

  for(int i = 0; i < sizeof(buf)/sizeof(uint32_t); i++)
    buf[i] = htobe32(buf[i]);

  htif->lmem().write(0,sizeof(buf),(uint8_t*)buf,2);
}

void appserver_t::set_htif(htif_t* foo)
{
  htif = foo;
}

void appserver_t::make_htif(const char* s)
{
  if(!strcmp(s,"hw"))
    set_htif(new htif_sparchw_dma_t(properties));
  else if(!strcmp(s,"vs"))
    set_htif(new htif_sparcvs_dma_t(properties));
  else if(!strcmp(s,"fs"))
  {
    sim_t* sim = new sim_t;
    sim->trace = make_trace;
    sim->trace_start = trace_start;
    set_htif(sim);
  }
  else if(!strcmp(s,"x86"))
    set_htif(new htif_x86_dma_t(properties));
  else
    throw std::runtime_error("Unknown HTIF! Use [hw,vs,fs]");
}

void usage()
{
  printf("Usage: appserver [-f<conf>] [-p<nprocs>] [-s] <htif> <kernel> [binary] [args]\n");
}

int appserver_t::load_program(int argc, char* argv[], char* envp[])
{
    const char* path = NULL;
    for(char** p = envp; *p; p++)
    {
        if(strncmp(*p,"PATH=",5) == 0)
        {
            path = *p+5;
            break;
        }
    }

    nprocs = 1;
    const char* configfile = "appserver.conf";
    const char* eth_if = NULL;
    int nargs = parse_args(argc,argv,"pdfstdudsbiscl",&nprocs,&configfile,&make_trace,&trace_start,&print_stats,&eth_if,&max_cycles);
    argc -= nargs; argv += nargs;

    if(properties.read_file(get_filename(configfile,path).c_str()) < 0)
      throw std::runtime_error(std::string("Could not open properties file ")+configfile+"!");
    properties.read_file(get_filename("appserver.conf.local",path).c_str());

    if(eth_if != NULL)
      properties.set_string("htif_sparchw_dma.eth_if",eth_if);

    if(argc < 4)
    {
      usage();
      return -1;
    }
    if(htif == NULL)
      make_htif(argv[1]);
   
    htif->set_memsize(properties.get_int("dram.size"));
    htif->set_num_cores(nprocs);
  
    htif->set_reset(1);
    htif->set_reset(0);

    if(properties.get_int("appserver.noecho"))
        noecho_init();

    configure_timing_model();

    if(strcmp(argv[2],"memtest") == 0)
    {
      memtest();
      return 0;
    }

    if(strcmp(argv[2],"none") != 0)
    {
      memimage_t kernel_memimage(properties.get_int("ipl.kernel_offset"));
      memimage_t user_memimage(properties.get_int("ipl.user_offset"));
      std::map<std::string,vaddr> kernel_symtab;
      int ksize,usize;
      uint8_t* kbytes,*ubytes;
      vaddr uentry;

      if(readfile(get_filename(argv[2],path).c_str(),(char**)&kbytes,&ksize))
      {
        warn("Couldn't open kernel image %s!\n",argv[2]);
        return -1;
      }
      load_elf(kbytes,ksize,htif->big_endian(),&kernel_memimage,properties.get_int("ipl.zero_kernel_bss"),NULL,&kernel_symtab);
      free(kbytes); kbytes = 0;

      if(strcmp(argv[3],"none") != 0)
      {
        if(readfile(get_filename(argv[3],path).c_str(),(char**)&ubytes,&usize))
        {
          warn("Couldn't open user image %s!\n",argv[3]);
          return -1;
        }
        load_elf(ubytes,usize,htif->big_endian(),&user_memimage,true,&uentry);
        uentry += properties.get_int("ipl.user_offset");
        free(ubytes); ubytes = 0;

        if(kernel_symtab.count("user_entryp") == 0)
          warn("I don't know where to write the user-code entry point!");
        else
        {
          uint32_t foo = htif->htotl(uentry);
          kernel_memimage.write(kernel_symtab["user_entryp"],4,(uint8_t*)&foo);
        }
      }

      if(kernel_symtab.count("__args"))
      {
        uint8_t args[ARGS_SIZE+8];
        int args_size = pack_argc_argv(args+8,0,argc-3,argv+3);
        *(uint32_t*)args = htif->htotl(args_size);
        kernel_memimage.write(kernel_symtab["__args"],args_size+8,args);
      }

      if(kernel_symtab.count("magic_mem") == 0)
      {
        warn("I don't know the magic memory address!");
        htif->set_magicmemaddr(0);
      }
      else
      {
        no_poll = 0;
        htif->set_magicmemaddr(kernel_symtab["magic_mem"]+properties.get_int("ipl.kernel_offset"));
      }

      kernel_memimage.copy_to_memif(htif->lmem());
      user_memimage.copy_to_memif(htif->lmem());

      if(properties.get_int("ipl.verify"))
      {
        kernel_memimage.check_memif(htif->lmem());
        user_memimage.check_memif(htif->lmem());
      }
    }

    syscall_init();

    if(print_stats)
      stats();

    signal(SIGINT,sigint_handler);
    signal(SIGABRT,sigint_handler);

    return 0;
}

void appserver_t::stats()
{
  int use_host_counters = properties.get_int("appserver.host_counters");
  int global_stats_only = properties.get_int("appserver.global_stats_only");

  const char** global_counters = use_host_counters ? host_global_counters : target_global_counters;
  int num_global_counters = (use_host_counters ? sizeof(host_global_counters) : sizeof(target_global_counters))/sizeof(char*);
  int num_per_proc_counters = sizeof(per_proc_counters)/sizeof(char*);

  struct timeval t;
  gettimeofday(&t,0);
  double wall_time = (t.tv_sec-t0.tv_sec)+(t.tv_usec-t0.tv_usec)/1e6;

  static bool silent = true;
  if(!silent)
    printf("wall time: %.2f s\n",wall_time);

  int counters_per_proc = PERFCTR_CORE_ADDR_OFFSET/sizeof(uint64_t);
  static uint64_t* counters = 0, *counters2 = 0;
  if(counters == 0)
  {
    counters = new uint64_t[nprocs*counters_per_proc];
    counters2 = new uint64_t[nprocs*counters_per_proc];
    memset(counters2,0,nprocs*PERFCTR_CORE_ADDR_OFFSET);
  }

  memcpy(counters,counters2,nprocs*PERFCTR_CORE_ADDR_OFFSET);
  htif->lmem().read(0,nprocs*PERFCTR_CORE_ADDR_OFFSET,(uint8_t*)counters2,2);

  if(silent)
  {
    silent = false;
    return;
  }
  #define READ_COUNTER(i) (be64toh(counters2[(i)])-be64toh(counters[(i)]))

  long long total_insn = 0;
  if(!use_host_counters) for(int p = 0; p < nprocs; p++) 
  {
    if(!global_stats_only)
      printf("\ncore %d\n",p);
    for(int i = 0; i < num_per_proc_counters; i++)
    {
      if(!global_stats_only)
        printf("  %s: %lld\n",per_proc_counters[i],READ_COUNTER(i+num_global_counters+p*counters_per_proc));
      if(!strcmp(per_proc_counters[i],"instructions retired"))
        total_insn += READ_COUNTER(i+num_global_counters+p*counters_per_proc);
    }
  }

  for(int i = 0; i < num_global_counters; i++)
    if(use_host_counters || strncmp(global_counters[i],"host ",5) != 0)
      printf("%s: %lld\n",global_counters[i],READ_COUNTER(i));

  if(use_host_counters)
  {
    printf("Aggregate simulator MIPS: %.3f\n",READ_COUNTER(4)/(wall_time*1e6));
    return;
  }

  printf("Number of system calls: %d\n",nsyscalls);
  printf("Aggregate simulator MIPS: %.3f\n",total_insn/(wall_time*1e6));

  fflush(stdout);
}

int appserver_t::poll_once(int tohost)
{
  uint8_t magicmem[40];

  for(int i = 0, tries = 10; ; i++)
  {
    try
    {
      htif->lmem().read(htif->get_magicmemaddr(),sizeof(magicmem),magicmem);
      break;
    }
    catch(illegal_packet_exception& e)
    {
      if(i == tries-1)
        throw e;
    }
  }

  if(noecho)
  {
    if(magicmem[35] != 0)
    {
      if(write(1,magicmem+35,1) == 1)
      {
        magicmem[35] = 0;
        htif->lmem().write(htif->get_magicmemaddr()+32,4,magicmem+32);
      }
    }
    if(magicmem[39] == 0 && kbhit())
    {
      magicmem[39] = getchar();
      if(magicmem[39] == 0x7F)
        magicmem[39] = 0x08;
      htif->lmem().write(htif->get_magicmemaddr()+36,4,magicmem+36);
    }
  }

  int new_tohost = htif->htotl(*(uint32_t*)magicmem);
  if(new_tohost == tohost)
    return tohost;
  tohost = new_tohost;

  switch (tohost)
  {
    case TOHOST_SYSREQ:
      syscall((uint8_t*)magicmem);
      // after syscall, fromhost == 1 and tohost == 0
      tohost = 0;
      break;

    case TOHOST_FAIL:
      exit_code = tohost;
      printf("fail (code %d)",tohost);
      do_exit = 1;
      break;

    case TOHOST_OK:
      exit_code = 0;
      do_exit = 1;
      break;

    default:
      printf("Unknown tohost value %d!\n",tohost);
      exit_code = -1;
      do_exit = 1;
      break;
  }

  return tohost;
}

int appserver_t::run()
{
  int tohost = 0;
  htif->set_run(1);

  while(!do_exit)
  {
    htif->run_for_a_while();
    if(!no_poll)
      tohost = poll_once(tohost);

    if(max_cycles && htif->get_cycle() > max_cycles)
    {
      do_exit = true;
      exit_code = 0;
    }
  }

  return exit_code;
}
