/* Author: Andrew S. Waterman
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


#include "util.h"
#include <unistd.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <alloca.h>
#include <stdarg.h>
#include <string.h>
#include <sys/time.h>

double microtime()
{
  struct timeval tv;
  gettimeofday(&tv,0);
  return tv.tv_sec+tv.tv_usec/1e6;
}

int parse_args(int argc, char** argv, const char* opts, ...)
{
  va_list argp;
  int i,j,nopts;
  void** optvals;

  va_start(argp,opts);

  nopts = strlen(opts)/2;

  optvals = (void**)alloca(nopts*sizeof(void*));
  for(i = 0; i < nopts; i++)
    optvals[i] = va_arg(argp,void*);

  for(i = 1; i < argc && argv[i][0] == '-'; i++)
  {
    int found = 0;
    for(j = 0; !found && j < nopts; j++)
    {
      if(argv[i][1] == opts[j*2])
      {
        int base = 10;
        found = 1;
        switch(opts[j*2+1])
        {
          case 'b':
            *(int*)optvals[j] = 1;
            break;
          case 'x':
            base = 16;
          case 'd':
            *(int*)optvals[j] = argv[i][2] == '-' ? strtol(argv[i]+2,NULL,base) : strtoul(argv[i]+2,NULL,base);
            break;
          case 'l':
            *(long long*)optvals[j] = strtoll(argv[i]+2,NULL,base);
            break;
          case 's':
            *(char**)optvals[j] = argv[i]+2;
            break;
          default:
            error("Unrecognized option type %c",opts[j*2+1]);
        }
      }
    }

    if(!found)
      error("Unrecognized flag -%c",(argv[i][1] ? argv[i][1] : ' '));
  }

  va_end(argp);
  return i-1;
}

void writefile_posix(int fd, char* buf, int size)
{
  int pos = 0;
  int thissize = 0;
  do
  {
    thissize = write(fd,buf+pos,size);
    size -= thissize;
    pos += thissize;
  } while(thissize > 0 && size > 0);
}

char* readfile_posix(int fd, int* size)
{
  int bufsize = 4096;
  char* elf = NULL;
  *size = 0;
  int thissize = 0;
  do
  {
    elf = (char*)realloc(elf,*size+bufsize);
    thissize = read(fd,elf+*size,bufsize);
    *size += thissize;

    if(thissize == bufsize && bufsize*2 > 0)
      bufsize *= 2;
  } while(thissize > 0);

  return elf;
}

int readfile(const char* fn, char** bytes, int* size)
{
  int fd = open(fn,O_RDONLY);
  if(fd < 0)
    return fd;

  *bytes = readfile_posix(fd,size);
  return 0;
}
