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

#include <map>
#include <Common/host.h>
#include <Common/util.h>
#include <Common/elf.h>
#include <Common/htif.h>
#include <Common/memif.h>
#include "testserver.h"
#include "tohost.h"

testserver_t::testserver_t(htif_t& _htif)
  : htif(_htif), poll_tohost(true)
{
}

int testserver_t::load_program(int argc, char* argv[], char* envp[])
{
    nprocs = 1;
    int nargs = parse_args(argc,argv,"pd",&nprocs);
    argc -= nargs;
    argv += nargs;

    if (argc < 2)
    {
        printf("Usage: testserver <binary>\n");
        return -1;
    }

    htif.set_memsize(0x80000000);
    htif.set_num_cores(nprocs);

    std::map<std::string,vaddr> symtab;
    memimage_t memimage;
    uint8_t* bytes;
    int size;

    for(int i = 1; i < argc; i++)
    {
      if(readfile(argv[i],(char**)&bytes,&size) < 0)
        error("Couldn't open image %s!\n",argv[1]);
      load_elf(bytes,size,&memimage,NULL,&symtab);
    }

    memimage.copy_to_memif(htif.lmem());
    memimage.check_memif(htif.lmem());

    if(symtab.count("magic_mem") == 0)
    {
      warn("I don't know the magic memory address!");
      poll_tohost = false;
    }
    else htif.set_magicmemaddr(symtab["magic_mem"]);

    htif.set_num_cores(nprocs);

    htif.set_reset(1);
    htif.set_reset(0);

    return 0;
}

int testserver_t::run()
{
    int loop = 1;
    int tohost = htif.get_tohost();

    htif.set_run(1);

    while (loop)
    {
        tohost = htif.run_to_tohost(tohost);

        if(poll_tohost) switch (tohost)
        {
        case TOHOST_NULL:
            break;
        case TOHOST_OK:
            loop = 0;
            break;
        default:
            printf("fail (code %d)",tohost);
            loop = 0;
            break;
        }
    }

    return tohost;
}
