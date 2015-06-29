/* Author: Yunsup Lee and Andrew Waterman
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

#ifndef __SYSARGS_H
#define __SYSARGS_H

#ifdef __APPLE_CC__
  #define O_DSYNC 0
  #define O_RSYNC 0
  #define O_LARGEFILE 0
#endif

#include <sys/stat.h>
#include <fcntl.h>
#include <Common/htif.h>
#include <Common/properties.h>

// ROS ABI

struct newlib_dirent {
   int32_t        d_off;
  uint32_t        d_fileno;
  uint16_t        d_reclen;
  uint16_t        d_namlen;
  uint8_t         d_name[256];
};

struct newlib_stat
{
   int16_t st_dev;
  uint32_t st_ino;
  uint16_t st_mode;
  uint16_t st_nlink;
  uint16_t st_uid;
  uint16_t st_gid;
   int16_t st_rdev;
   int32_t st_size;
   int32_t _st_atime;
   int32_t st_spare1;
   int32_t _st_mtime;
   int32_t st_spare2;
   int32_t _st_ctime;
   int32_t st_spare3;
   int32_t st_blksize;
   int32_t st_blocks;
   int32_t st_spare4[2];
};

#define RAMP_O_RDONLY 0x0000
#define RAMP_O_WRONLY 0x0001
#define RAMP_O_RDWR   0x0002
#define RAMP_O_NONBLOCK 0x04
#define RAMP_O_APPEND 0x0008
#define RAMP_O_NOCTTY 0x0100
#define RAMP_O_CREAT  0x0200
#define RAMP_O_TRUNC  0x0400
#define RAMP_O_EXCL   0x0800
#define RAMP_O_NDELAY RAMP_O_NONBLOCK

class sysargs_t
{
public:
    sysargs_t(htif_t& _htif, uint32_t _addr, uint32_t _len);
    ~sysargs_t();
    void* buffer();
    void* get_buffer();
    void put_buffer();
    void convert_stat(struct stat* linux_stat);
    static int convert_flag(int solaris_flag, bool backwards);

private:
    htif_t& htif;
    uint32_t addr;
    uint32_t len;
    uint8_t* buf;
};

#endif // __SYSARGS_H
