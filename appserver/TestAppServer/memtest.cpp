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
#include <Common/htif.h>
#include <Common/memif.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <stdio.h>

unsigned int lfsr()
{
  static unsigned int val = 1;
  val = (val >> 1) ^ (-(val & 1u) & 0xd0000001u);
  return val;
}

void appserver_t::memtest()
{
    long long errors = 0;
    
    typedef uint32_t datatype;
    uint32_t maxsize = 1048576;
    const int NUM_READS = 8;

    datatype* data_readback[NUM_READS];
    for(int i = 0; i < NUM_READS; i++)
      data_readback[i] = (datatype*)malloc(maxsize);

    datatype* data = (datatype*)malloc(maxsize);
    datatype* zero = (datatype*)calloc(maxsize,1);
    datatype* junk = (datatype*)malloc(maxsize);

    for(long long i = 0; ; i++)
    {
        uint32_t align = 32;
        uint32_t size = 512; //lfsr() % maxsize + 1;
        uint32_t start = 0;
        uint32_t end = 2047*1024*1024;

        uint32_t blockstart = (lfsr() % ((end-start)/align))*align + start;
        if(blockstart+size > end)
          size = end-blockstart;
        uint32_t blockend = blockstart+size;

        uint32_t lut [8] = {0xAAAAAAAA,0x11223344,0xAAAAAAAA,0x11223344,0xAAAAAAAA,0x11223344,0xAAAAAAAA,0x11223344};
        uint32_t lut2[8] = {0x55555555,0xAAAAAAAA,0x55555555,0xAAAAAAAA,0x55555555,0xAAAAAAAA,0x55555555,0xAAAAAAAA};

        for(int k = 0; k < size/sizeof(datatype); k++)
//          data[k] = k*sizeof(datatype)+blockstart;
          data[k] = lfsr();

        htif->lmem().write(blockstart,size,(uint8_t*)zero);
        htif->lmem().write(blockstart+16384,size,(uint8_t*)zero);

        htif->lmem().write(blockstart,size,(uint8_t*)data);

        for(int j = 0; j < NUM_READS; j++)
        {
          htif->lmem().read(blockstart+16384,size,(uint8_t*)junk);
          htif->lmem().read(blockstart,size,(uint8_t*)data_readback[j]);
        }

        for(int k = 0; k < size/sizeof(datatype); k++)
        {
          bool correct = true;
          for(int j = 0; j < NUM_READS; j++)
            if(data[k] != data_readback[j][k])
              correct = false;

          if(!correct)
          {
            //if(data[k] != data_readback[0][k] && data[k] != data_readback[1][k] && data[k] != data_readback[2][k])
            //  printf("WRITE FAILURE!!! :(\n");
            
            //uint32_t temp;
            //htif->lmem().read_uint32(blockstart+k*sizeof(datatype),&temp);
            //if(temp != data[k])
            //  printf("WRITE FAILURE!!!!! expected %08x, got %08x\n",data[k],temp);
            
            errors++;
            printf("Memory error.  start=%08X end=%08X badaddr=%08X size=%d\n",blockstart,blockend,blockstart+k*sizeof(datatype),size);

            int* cl1 = (int*)&data[k/8*8];
            printf("Expected cache line: ");
            for(int j = 0; j < 8; j++)
              printf("%08X ",cl1[j]);
            printf("\n");
            for(int j = 0; j < NUM_READS; j++)
            {
              int* cl2 = (int*)&data_readback[j][k/8*8];
              printf("Got cache line:      ");
              for(int j = 0; j < 8; j++)
                printf("%08X ",cl2[j]);
              printf("\n");
            }

            k = (k+32/sizeof(datatype))/(32/sizeof(datatype))*(32/sizeof(datatype));
          }
        }

        //if(i % (32768/maxsize) == 0)
          printf("Heartbeat.  %lld tests of size %d.  %lld errors.\n",i,size,errors);
    }
}
