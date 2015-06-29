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

#include "appserver.h"
#include <ProxyKernel/syscall.h>
#include "sysargs.h"
#include "tohost.h"
#include <errno.h>
#include <string.h>
#include <Common/htif.h>
#include <Common/memif.h>
#include <Common/util.h>
#include <assert.h>
#include <stdarg.h>
#include <utime.h>

int kbhit() // is there a keypress pending?
{  
  struct timeval tv;  
  fd_set fds;  
  tv.tv_sec = 0;  
  tv.tv_usec = 0;  
  FD_ZERO(&fds);  
  FD_SET(STDIN_FILENO, &fds); //STDIN_FILENO is 0  
  select(STDIN_FILENO+1, &fds, NULL, NULL, &tv);  
  return FD_ISSET(STDIN_FILENO, &fds);  
}  

void __strace(const properties_t& properties, const char* str, ...)
{
  va_list vl;
  va_start(vl,str);
  if(properties.get_int("appserver.strace"))
    vprintf(str,vl);
  va_end(vl);
}
#define strace(...) __strace(properties,__VA_ARGS__)

int null(const char*, ...) {}

syscall_process_t::syscall_process_t()
{
}

syscall_process_t::~syscall_process_t()
{
  for(std::map<int,int>::iterator i = fdmap.begin(); i != fdmap.end(); ++i)
    close(i->second);
}

void syscall_process_t::mapfd(int fake, int real)
{
  assert(fdmap.count(fake) == 0);
  assert((fdmap[fake] = dup(real)) != -1);
}

syscall_process_t& syscall_process_t::operator = (const syscall_process_t& p)
{
  strcpy(pwd,p.pwd);
  mask = p.mask;

  for(std::map<int,int>::const_iterator i = p.fdmap.begin();
                                        i != p.fdmap.end(); ++i)
    mapfd(i->first,i->second);

  return *this;
}

int syscall_process_t::next_fd(int start)
{
  int prev_fd = MAX(start,0)-1;
  for(std::map<int,int>::iterator i = fdmap.begin(); i != fdmap.end(); ++i)
    if(i->first >= start && ++prev_fd != i->first)
      return prev_fd;
  return fdmap.size();
}

void syscall_process_t::become()
{
  int foo = chdir(pwd); // warn_unused_result
  umask(mask);
}

void syscall_process_t::update()
{
  mask = umask(0);
  assert(getcwd(pwd,RAMP_MAXPATH) == pwd);
}

void appserver_t::syscall_init()
{
  if(properties.has_key("appserver.chroot"))
  {
    seteuid(0);
    assert(chroot(properties.get_string("appserver.chroot").c_str()) == 0);
    seteuid(getuid());
  }
  
  assert(getcwd(pwd,RAMP_MAXPATH) == pwd);
  gettimeofday(&t0,0);

  strcpy(processes[0].pwd,properties.has_key("appserver.chroot") ? "/" : pwd);
  processes[0].mask = 0022;

  processes[0].mapfd(0,0);
  processes[0].mapfd(1,1);
  processes[0].mapfd(2,2);
}

void appserver_t::syscall(uint8_t* magicmem)
{
  uint32_t which, pid;
  int32_t arg0, arg1, arg2, arg3;
  int32_t ret = 0;

  int freq = 100000000;
  int clk_tck = 100;

  uint32_t* buf = (uint32_t*)magicmem;
  which = htif->htotl(buf[1]);
  arg0 = htif->htotl(buf[2]);
  arg1 = htif->htotl(buf[3]);
  arg2 = htif->htotl(buf[4]);
  arg3 = htif->htotl(buf[5]);
  pid = htif->htotl(buf[6]);

  strace("syscall# = %d\n", which);

  if(!processes.count(pid))
  {
    fprintf(stderr,"Syscall from unknown process %d!\n",pid);
    abort();
  }
  processes[pid].become();

  errno = 0;

  switch (which)
  {
  case RAMP_SYSCALL_proc_init:
    strace("SYSCALL_proc_init called!\n");
    {
      assert(processes.count(arg0) == 0);
      processes[arg0] = processes[pid];
      ret = 0;
    }
    break;
  case RAMP_SYSCALL_proc_free:
    strace("SYSCALL_proc_free called!\n");
    {
      assert(processes.count(arg0) == 1);
      processes.erase(arg0);
      ret = 0;
    }
    break;
  case RAMP_SYSCALL_exit:
    strace("SYSCALL_exit called!\n");
    {
      int status = arg0;
      exit_code = arg0;
      do_exit = true;
    }
    break;
  case RAMP_SYSCALL_dup2:
    {
      if(arg1 < 0 || processes[pid].fdmap.count(arg0) == 0)
      {
        errno = EBADF;
        ret = -1;
      }
      else if(arg0 == arg1)
        ret = arg0;
      else
      {
        if((ret = dup(processes[pid].fdmap[arg0])) < 0)
          break;

        if(processes[pid].fdmap.count(arg1))
          close(processes[pid].fdmap[arg1]);

        processes[pid].fdmap[arg1] = ret;
        ret = arg1;
      }
      strace("SYSCALL_dup2(%d,%d) == %d called!\n",arg0,arg1,ret);
    }
    break;
  case RAMP_SYSCALL_utime:
    {
      sysargs_t sysargs_f(*htif, arg0, RAMP_MAXPATH);
      char* file = (char*)sysargs_f.get_buffer();

      struct utimbuf ut;
      ut.actime = arg1;
      ut.modtime = arg2;

      ret = utime(file,&ut);

      strace("SYSCALL_utime(\"%s\",%d,%d) == %d called!\n",file,arg1,arg2,ret);
    }
    break;
  case RAMP_SYSCALL_umask:
    {
      ret = umask(arg0);
    }
    break;
  case RAMP_SYSCALL_read:
    {
      int fd = -1;
      if(processes[pid].fdmap.count(arg0) == 0)
      {
        ret = (uint32_t)-1;
        errno = EBADF;
      }
      else
      {
        fd = processes[pid].fdmap[arg0];
        sysargs_t sysargs(*htif, arg1, arg2);

        if(processes[pid].dirmap.count(arg0))
        {
          struct ramp_dirent
          {
            uint64_t d_ino;
            uint64_t d_off;
            uint16_t d_reclen;
            uint8_t  d_type;
            char     d_name[256];
          } *rde = (struct ramp_dirent*)sysargs.buffer();
          
          if(arg2 < sizeof(struct ramp_dirent))
          {
            ret = -1;
            errno = EINVAL;
          }
          else
          {
            struct dirent* de = readdir(processes[pid].dirmap[arg0]);
            if(de == NULL)
              ret = 0;
            else
            {
              ret = 8+8+2+1+strnlen(de->d_name,256);
              rde->d_ino = htif->htotll(de->d_ino);
              rde->d_off = htif->htotll(de->d_off);
              rde->d_reclen = htif->htots(ret);
              rde->d_type = de->d_type;
              strncpy(rde->d_name,de->d_name,256);
            }
          }
        }
        else
          ret = read(fd, sysargs.buffer(), arg2);

        sysargs.put_buffer();
      }
      strace("SYSCALL_read(%d(%d),0x%x,%d) == %d called!\n",arg0,fd,arg1,arg2,ret);
    }
    break;
  case RAMP_SYSCALL_pread:
    {
      int fd = -1;
      if(processes[pid].fdmap.count(arg0) == 0)
      {
        ret = (uint32_t)-1;
        errno = EBADF;
      }
      else
      {
        fd = processes[pid].fdmap[arg0];
        sysargs_t sysargs(*htif, arg1, arg2);
        ret = pread(fd, sysargs.buffer(), arg2, arg3);

        sysargs.put_buffer();
      }
      strace("SYSCALL_pread(%d(%d),0x%x,%d,%d) == %d called!\n",arg0,fd,arg1,arg2,arg3,ret);
    }
    break;
  case RAMP_SYSCALL_write:
    {
      int fd = -1;
      if(processes[pid].fdmap.count(arg0) == 0)
      {
        ret = (uint32_t)-1;
        errno = EBADF;
      }
      else
      {
        fd = processes[pid].fdmap[arg0];
        sysargs_t sysargs(*htif, arg1, arg2);
        ret = write(fd,sysargs.get_buffer(),arg2);
      }
      strace("SYSCALL_write(%d(%d),0x%x,%d) == %d called!\n",arg0,fd,arg1,arg2,ret);
    }
    break;
  case RAMP_SYSCALL_pwrite:
    {
      int fd = -1;
      if(processes[pid].fdmap.count(arg0) == 0)
      {
        ret = (uint32_t)-1;
        errno = EBADF;
      }
      else
      {
        fd = processes[pid].fdmap[arg0];
        sysargs_t sysargs(*htif, arg1, arg2);
        ret = pwrite(fd,sysargs.get_buffer(),arg2,arg3);
      }
      strace("SYSCALL_pwrite(%d(%d),0x%x,%d,%d) == %d called!\n",arg0,fd,arg1,arg2,arg3,ret);
    }
    break;
  case RAMP_SYSCALL_chmod:
    {
      sysargs_t sysargs_f(*htif, arg0, RAMP_MAXPATH);
      char* file = (char*)sysargs_f.get_buffer();
      ret = chmod(file,arg1);

      strace("SYSCALL_chmod(\"%s\",%d) == %d called!\n",file,arg1,ret);
    }
    break;
  case RAMP_SYSCALL_access:
    {
      sysargs_t sysargs_f(*htif, arg0, RAMP_MAXPATH);
      char* file = (char*)sysargs_f.get_buffer();
      ret = access(file,arg1);

      strace("SYSCALL_access(\"%s\",%d) == %d called!\n",file,arg1,ret);
    }
    break;
  case RAMP_SYSCALL_kdup: // duplicate an fd into the kernel
    {
      if(processes[pid].fdmap.count(arg0) == 0)
      {
        ret = (uint32_t)-1;
        errno = EBADF;
      }
      else
      {
        int fd = processes[pid].fdmap[arg0];
        int newfd = dup(fd);

        if (newfd != -1)
          processes[0].fdmap[ret = processes[0].next_fd()] = newfd;
        else
          ret = (uint32_t)-1;
      }
      strace("SYSCALL_kdup(%d) == %d called!\n",arg0,ret);
    }
    break;
  case RAMP_SYSCALL_dup:
    {
      if(processes[pid].fdmap.count(arg0) == 0)
      {
        ret = (uint32_t)-1;
        errno = EBADF;
      }
      else
      {
        int fd = processes[pid].fdmap[arg0];
        int newfd = dup(fd);

        if (newfd != -1)
          processes[pid].fdmap[ret = processes[pid].next_fd()] = newfd;
        else
          ret = (uint32_t)-1;
      }
      strace("SYSCALL_dup(%d) == %d called!\n",arg0,ret);
    }
    break;
  case RAMP_SYSCALL_open:
    {
      sysargs_t sysargs_f(*htif, arg0, RAMP_MAXPATH);
      char* file = (char*)sysargs_f.get_buffer();
      int flag = arg1; //sysargs_t::convert_flag(arg1,false);
      int mode = arg2;

      DIR* d = NULL;
      int fd = -1;
      struct stat st;
      if(!(flag & O_WRONLY) && !(flag & O_RDWR) && stat(file,&st) != -1 && (st.st_mode & S_IFDIR))
      {
        if(d = opendir(file))
          fd = dirfd(d);
      }
      else
        fd = open(file, flag, mode);

      if (fd != -1)
      {
        processes[pid].fdmap[ret = processes[pid].next_fd()] = fd;
        if(d)
          processes[pid].dirmap[ret] = d;
      }
      else
        ret = (uint32_t)-1;

      strace("SYSCALL_open(\"%s\",0x%x(0x%x),0x%x) == %d(%d) called!\n",file,arg1,flag,mode,ret,fd);
    }
    break;
  case RAMP_SYSCALL_fcntl:
    {
      if(processes[pid].fdmap.count(arg0) == 0)
      {
        ret = (uint32_t)-1;
        errno = EBADF;
      }
      else
      {
        ret = fcntl(processes[pid].fdmap[arg0],arg1,arg2);

        if(ret != -1)
        {
          if(arg1 == F_DUPFD)
          {
            int oldfd = ret;
            processes[pid].fdmap[ret = processes[pid].next_fd(arg2)] = oldfd;
          }
        }
      }
      strace("SYSCALL_fcntl(%d,%d,0x%x) == %d called!\n",arg0,arg1,arg2,ret);
    }
    break;
  case RAMP_SYSCALL_close:
    {
      if(processes[pid].fdmap.count(arg0) == 0)
      {
        errno = EBADF;
        ret = (uint32_t)-1;
      }
      else
      {
        ret = close(processes[pid].fdmap[arg0]);
        if(ret == 0)
        {
          processes[pid].fdmap.erase(arg0);
          processes[pid].dirmap.erase(arg0);
        }
      }
      strace("SYSCALL_close(%d) == %d called!\n",arg0,ret);
    }
    break;
  case RAMP_SYSCALL_lseek:
    strace("SYSCALL_lseek called!\n");
    {
      if(processes[pid].fdmap.count(arg0) == 0)
      {
        ret = (uint32_t)-1;
        errno = EBADF;
      }
      else
      {
        int fd = processes[pid].fdmap[arg0];
        ret = lseek(fd, (off_t)arg1, arg2);
      }
    }
    break;
  case RAMP_SYSCALL_link:
    strace("SYSCALL_link called!\n");
    {
      sysargs_t sysargs_f0(*htif, arg0, RAMP_MAXPATH);
      char* file0 = (char*)sysargs_f0.get_buffer();

      sysargs_t sysargs_f1(*htif, arg1, RAMP_MAXPATH);
      char* file1 = (char*)sysargs_f1.get_buffer();

      ret = link(file0,file1);
    }
    break;
  case RAMP_SYSCALL_unlink:
    strace("SYSCALL_unlink called!\n");
    {
      sysargs_t sysargs_f(*htif, arg0, RAMP_MAXPATH);
      char* file = (char*)sysargs_f.get_buffer();

      ret = unlink(file);
    }
    break;
  case RAMP_SYSCALL_chdir:
    strace("SYSCALL_chdir called!\n");
    {
      sysargs_t sysargs_f(*htif, arg0, RAMP_MAXPATH);
      char* file = (char*)sysargs_f.get_buffer();

      ret = chdir(file);
    }
    break;
  case RAMP_SYSCALL_getcwd:
    strace("SYSCALL_getcwd called!\n");
    {
      sysargs_t sysargs(*htif, arg0, arg1);
      char* ret2 = getcwd((char*)sysargs.buffer(),arg1);
      ret = ret2 ? arg0 : 0;
      sysargs.put_buffer();
    }
    break;
  case RAMP_SYSCALL_stat:
    strace("SYSCALL_stat called!\n");
    {
      sysargs_t sysargs_f(*htif, arg0, RAMP_MAXPATH);
      char* file = (char*)sysargs_f.get_buffer();
      sysargs_t sysargs(*htif, arg1, sizeof(newlib_stat));
      struct stat linux_stat;

      ret = stat(file, &linux_stat);
      sysargs.convert_stat(&linux_stat);

      if (ret == 0)
      {
        sysargs.put_buffer();
      }
    }
    break;
  case RAMP_SYSCALL_fstat:
    strace("SYSCALL_fstat called!\n");
    {
      if(processes[pid].fdmap.count(arg0) == 0)
        ret = (uint32_t)-1;
      else
      {
        int fd = processes[pid].fdmap[arg0];
        sysargs_t sysargs(*htif, arg1, sizeof(newlib_stat));
        struct stat linux_stat;

        ret = fstat(fd, &linux_stat);
        sysargs.convert_stat(&linux_stat);

        if (ret == 0)
          sysargs.put_buffer();
      }
    }
    break;

  case RAMP_SYSCALL_lstat:
    strace("SYSCALL_lstat called!\n");
    {
      sysargs_t sysargs_f(*htif, arg0, RAMP_MAXPATH);
      char* file = (char*)sysargs_f.get_buffer();
      sysargs_t sysargs(*htif, arg1, sizeof(newlib_stat));
      struct stat linux_stat;

      ret = lstat(file, &linux_stat);
      sysargs.convert_stat(&linux_stat);

      if (ret == 0)
      {
        sysargs.put_buffer();
      }
    }
    break;

  case RAMP_SYSCALL_tcsetattr:
    strace("SYSCALL_tcsetattr called!\n");
    if(processes[pid].fdmap.count(arg0) == 0)
    {
      ret = (uint32_t)-1;
      errno = EBADF;
    }
    else
    {
      int fd = processes[pid].fdmap[arg0];
      sysargs_t sysargs(*htif, arg2, sizeof(struct termios));
      struct termios* tios = (struct termios*)sysargs.get_buffer();

      tios->c_iflag = htif->htotl(tios->c_iflag);
      tios->c_oflag = htif->htotl(tios->c_oflag);
      tios->c_cflag = htif->htotl(tios->c_cflag);
      tios->c_lflag = htif->htotl(tios->c_lflag);
      tios->c_line = htif->htotl(tios->c_line);
      tios->c_ispeed = htif->htotl(tios->c_ispeed);
      tios->c_ospeed = htif->htotl(tios->c_ospeed);
      ret = tcsetattr(fd,arg1,tios);
    }
    break;

  case RAMP_SYSCALL_tcgetattr:
    strace("SYSCALL_tcgetattr called!\n");
    if(processes[pid].fdmap.count(arg0) == 0)
    {
      ret = (uint32_t)-1;
      errno = EBADF;
    }
    else
    {
      int fd = processes[pid].fdmap[arg0];
      sysargs_t sysargs(*htif, arg1, sizeof(struct termios));
      struct termios* tios = (struct termios*)sysargs.buffer();
      ret = tcgetattr(fd,tios);

      if (ret == 0)
      {
        tios->c_iflag = htif->htotl(tios->c_iflag);
        tios->c_oflag = htif->htotl(tios->c_oflag);
        tios->c_cflag = htif->htotl(tios->c_cflag);
        tios->c_lflag = htif->htotl(tios->c_lflag);
        tios->c_line = htif->htotl(tios->c_line);
        tios->c_ispeed = htif->htotl(tios->c_ispeed);
        tios->c_ospeed = htif->htotl(tios->c_ospeed);
        sysargs.put_buffer();
      }
    }
    break;

  case RAMP_SYSCALL_time:
    strace("SYSCALL_time called!\n");
    {
      static int t0 = 0;
      if(t0 == 0)
        t0 = time(NULL);
      ret = t0;
    }
    break;

  default:
    printf("not serving system call #%d. panic!\n", which);
    exit(-1);
    break;
  }

  processes[pid].update();

  strace("Syscall result %d\n",ret);

  buf[7] = htif->htotl(1); // set_fromhost(1)
  buf[0] = htif->htotl(0); // clear tohost
  buf[1] = htif->htotl(ret);
  buf[2] = htif->htotl(errno);
  htif->lmem().write(htif->get_magicmemaddr(),32,(uint8_t*)buf);

  nsyscalls++;
}

int pack_argc_argv(uint8_t args[ARGS_SIZE], uint32_t args_start, int argc, char** argv)
{
  uint32_t* buf = (uint32_t*)args;
  // make room for argc, pointers to args, args themselves
  int args_size = (argc+3)*sizeof(uint32_t);
  for(int i = 0; i < argc; i++)
  {
    int len = strlen(argv[i])+1;
    if(args_size+len > ARGS_SIZE)
      argc = i;
    else
      args_size += strlen(argv[i])+1;
  }
  
  // first word on stack is argc  
  buf[0] = htobe32(argc);
  // next argc words are pointers to args.
  // these are relative to args_start, so the proxykernel
  // might have to add in something like this to compensate:
  // USER_VIRTUAL_START+USER_SIZE-ARGS_SIZE
  buf[1] = htobe32(args_start + (argc+3)*sizeof(uint32_t));
  for(int i = 1; i < argc; i++)
    buf[i+1] = buf[i] + htobe32(strlen(argv[i-1])+1);
  // and the two words after that are null pointers
  buf[argc+1] = 0; // argv[argc] == NULL
  buf[argc+2] = 0; // envp == NULL

  uint8_t* ptr = (uint8_t*)&buf[argc+3];
  // now come the args themselves
  for(int i = 0; i < argc; i++)
  {
    int len = strlen(argv[i])+1;
    memcpy(ptr,argv[i],len);
    ptr += len;
  }

  return ptr-args;
}

