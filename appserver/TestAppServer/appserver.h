/* Author: Yunsup Lee
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

#ifndef __APPSERVER_H
#define __APPSERVER_H

#include <Common/htif.h>
#include <Common/host.h>
#include <Common/properties.h>
#include <map>
#include <string>
#include <sys/time.h>
#include <termios.h>
#include <ProxyKernel/syscall.h>
#include <dirent.h>

int kbhit();

class syscall_process_t
{
public:
  syscall_process_t();
  ~syscall_process_t();
  syscall_process_t& operator = (const syscall_process_t&);

  void become();
  void update();

  void mapfd(int,int);
  int next_fd(int start = 0);
  int next_dir();

  int mask;
  std::map<int,int> fdmap;
  std::map<int,DIR*> dirmap;
  char pwd[RAMP_MAXPATH];
};

class appserver_t
{
public:
    appserver_t();
    ~appserver_t();
    void syscall_init();
    void make_htif(const char* s);
    void set_htif(htif_t*);

    void memtest();
    void configure_cache(const std::string& name, uint32_t* buf, int max_tags, int max_assoc, int min_offset_bits, int max_offset_bits, int max_banks, int cacheprivate);
    void configure_timing_model();
    int load_program(int argc, char* argv[], char* envp[]);
    int run();
    int poll_once(int tohost);
    int write_syscall(int fd, void* buf, int len);
    int read_syscall(int fd, void* buf, int len);
    void syscall(uint8_t* magicmem);
    void stats();
    void noecho_init();

public:
    static std::string get_filename(const char* fn, const char* path);

    properties_t properties;
    bool noecho;
    long long max_cycles;
    int make_trace;
    int trace_start;
    //WINDOW* window;
    struct termios old_termios;
    htif_t* htif;
    int exit_code;
    std::map<int,syscall_process_t> processes;
    char pwd[RAMP_MAXPATH];
    struct timeval t0;
    int nprocs;
    bool do_exit;
    int print_stats;
    int nsyscalls;
    bool no_poll;
    
    friend void sigint_handler(int sig);
};

const int ARGS_SIZE = 4096;
int pack_argc_argv(uint8_t args[ARGS_SIZE], uint32_t args_start, int argc, char** argv);

#endif // __APPSERVER_H
