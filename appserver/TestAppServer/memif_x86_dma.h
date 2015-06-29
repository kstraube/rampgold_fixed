/* Author: Andrew Waterman, Yunsup Lee
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

#ifndef __MEMIF_X86_DMA_H
#define __MEMIF_X86_DMA_H

#include "memif_sparc_dma.h"
#include <Common/memif.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <string.h>
#ifdef __linux__
  #include <netpacket/packet.h>
#else
  #include <sys/types.h>
  #include <net/if.h>
  #include <net/if_dl.h>
  #include <net/if_types.h>
  #include <net/ndrv.h>
#endif

class htif_x86_dma_t;

#define X86_CMD_LOAD  0
#define X86_CMD_STORE 1
#define X86_CMD_ACK   2

#define X86_MAX_PAYLOAD_SIZE 1024
#define X86_MAX_PACKET_SIZE (X86_MAX_PAYLOAD_SIZE+sizeof(x86_packet_header))
struct x86_packet_header
{
  char dst_mac[6];
  char src_mac[6];
  short ethertype;
  char cmd;
  char seqno;
  int payload_size;
  int addr;
};

struct x86_packet
{
  x86_packet_header header;
  char payload[X86_MAX_PAYLOAD_SIZE];
  int packet_size;

  int size()
  {
    return packet_size;
  }

  x86_packet() {}
  x86_packet(const char* dst_mac, const char* src_mac, char cmd, char seqno,
             int payload_size, int addr, const uint8_t* bytes)
  {
    header.ethertype = RAMP_ETHERTYPE;
    memcpy(header.dst_mac,dst_mac,6);
    memcpy(header.src_mac,src_mac,6);
    header.cmd = cmd;
    header.seqno = seqno;
    header.payload_size = ntohl(payload_size);
    header.addr = ntohl(addr);
    if(bytes)
      memcpy(payload,bytes,payload_size);
    packet_size = sizeof(header)+payload_size;
  }
};

class memif_x86_dma_t : public memif_t
{
public:
  
  memif_x86_dma_t(htif_x86_dma_t* htif, const char *_hw_addr, const char *_eth_device);

  uint32_t read_chunk_align() { return 4; }
  uint32_t read_chunk_min_size() { return 4; }
  uint32_t read_chunk_max_size() { return 1024; }
  memif_t::error read_chunk(uint32_t addr, uint32_t len, uint8_t* bytes, uint8_t asi);
  uint32_t write_chunk_align() { return read_chunk_align(); }
  uint32_t write_chunk_min_size() { return read_chunk_min_size(); }
  uint32_t write_chunk_max_size() { return read_chunk_max_size(); }
  memif_t::error write_chunk(uint32_t addr, uint32_t len, const uint8_t* bytes, uint8_t asi);
    
  memif_t::error read_uint32(uint32_t addr, uint32_t* word, uint8_t asi)
  {
    memif_t::error e = read_chunk(addr,4,(uint8_t*)word, asi);
    *word = le32toh(*word);
    return e;
  }

  memif_t::error write_uint32(uint32_t addr, uint32_t word, uint8_t asi)
  {
    word = htole32(word);
    return write_chunk(addr,4,(uint8_t*)word,asi);
  }
  
  memif_t::error set_num_cores(int val) { return memif_t::OK; }

  memif_t::error start(void) { return memif_t::OK; }
  void stop(void) { }

protected:

  htif_x86_dma_t* htif;

  sockaddr_ll myaddr;
  int sock;
  char ros_mac[6];
  char appsvr_mac[6];
  char eth_device[64];

  memif_t::error flush_cache(uint8_t nthreads) { return memif_t::OK; }
  void send_packet(x86_packet* packet);

  char seqno;
  char next_seqno() { return seqno++; }

  friend class htif_x86_dma_t;
};

#endif // memif_sparchw_dma_H
