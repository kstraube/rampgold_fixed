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

#include "sysargs.h"
#include <Common/host.h>

sysargs_t::sysargs_t(htif_t& _htif, uint32_t _addr, uint32_t _len)
  : htif(_htif),
    addr(_addr),
    len(_len)
{
    buf = new uint8_t[len];
}

sysargs_t::~sysargs_t()
{
    delete [] buf;
}

void* sysargs_t::buffer()
{
    return buf;
}

void* sysargs_t::get_buffer()
{
    htif.lmem().read(addr, len, (uint8_t*)buf);
    return buf;
}

void sysargs_t::put_buffer()
{
    htif.lmem().write(addr, len, (const uint8_t*)buf);
}

void sysargs_t::convert_stat(struct stat* linux_stat)
{
    struct newlib_stat* s_stat = (struct newlib_stat*)buf;

    s_stat->st_dev = htif.htots(linux_stat->st_dev);
    s_stat->st_ino = htif.htotl(linux_stat->st_ino);
    s_stat->st_mode = htif.htots(linux_stat->st_mode);
    s_stat->st_nlink = htif.htots(linux_stat->st_nlink);
    s_stat->st_uid = htif.htots(linux_stat->st_uid);
    s_stat->st_gid = htif.htots(linux_stat->st_gid);
    s_stat->st_rdev = htif.htots(linux_stat->st_rdev);
    s_stat->st_size = htif.htotl(linux_stat->st_size);
    s_stat->_st_atime = htif.htotl(linux_stat->st_atime);
    s_stat->_st_mtime = htif.htotl(linux_stat->st_mtime);
    s_stat->_st_ctime = htif.htotl(linux_stat->st_ctime);
    s_stat->st_blksize = htif.htotl(linux_stat->st_blksize);
    s_stat->st_blocks = htif.htotl(linux_stat->st_blocks);
}

int sysargs_t::convert_flag(int solaris_flag, bool backwards)
{
    int linux_flag = 0;
    #if 0
    int solaris_convert_table[][2] =
    {
        {SOLARIS_O_RDONLY, O_RDONLY},
        {SOLARIS_O_WRONLY, O_WRONLY},
        {SOLARIS_O_RDWR, O_RDWR},
        {SOLARIS_O_APPEND, O_APPEND},
        {SOLARIS_O_CREAT, O_CREAT},
        {SOLARIS_O_DSYNC, O_DSYNC},
        {SOLARIS_O_EXCL, O_EXCL},
        {SOLARIS_O_LARGEFILE, O_LARGEFILE},
        {SOLARIS_O_NOCTTY, O_NOCTTY},
        {SOLARIS_O_NOFOLLOW, O_NOFOLLOW},
        {SOLARIS_O_NOLINKS, 0},
        {SOLARIS_O_NONBLOCK, O_NONBLOCK},
        {SOLARIS_O_NDELAY, O_NDELAY},
        {SOLARIS_O_RSYNC, O_RSYNC},
        {SOLARIS_O_SYNC, O_SYNC},
        {SOLARIS_O_TRUNC, O_TRUNC},
        {SOLARIS_O_XATTR, 0},
        {-1, -1},
    };
    #endif
    int convert_table[][2] =
    {
        {RAMP_O_RDONLY, O_RDONLY},
        {RAMP_O_WRONLY, O_WRONLY},
        {RAMP_O_RDWR, O_RDWR},
        {RAMP_O_APPEND, O_APPEND},
        {RAMP_O_CREAT, O_CREAT},
        {RAMP_O_EXCL, O_EXCL},
        {RAMP_O_NOCTTY, O_NOCTTY},
        {RAMP_O_NONBLOCK, O_NONBLOCK},
        {RAMP_O_NDELAY, O_NDELAY},
        {RAMP_O_TRUNC, O_TRUNC},
        {-1, -1},
    };

    for (int i=0; convert_table[i][0] != -1; i++)
        if (solaris_flag & convert_table[i][!!backwards])
            linux_flag |= convert_table[i][!backwards];

    return linux_flag;
}
