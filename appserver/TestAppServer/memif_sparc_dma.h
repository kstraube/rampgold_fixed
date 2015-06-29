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

#ifndef __MEMIF_SPARC_DMA_H
#define __MEMIF_SPARC_DMA_H

#include <Common/memif.h>
#include <sys/socket.h>
#ifdef __linux__
  #include <netpacket/packet.h>
#else
  #include <sys/types.h>
  #include <net/if.h>
  #include <net/if_dl.h>
  #include <net/if_types.h>
  #include <net/ndrv.h>
#endif

#define RAMP_ETHERTYPE 	  0x8888

#define RAMP_TYPE_DATA      0
#define RAMP_TYPE_COMMAND   1
#define RAMP_TYPE_TIMING    2
#define RAMP_TYPE_RESET     3
#define RAMP_TYPE_ACK     254
#define RAMP_TYPE_NACK    255

#define RAMP_PIPE_BCAST   255
#define RAMP_PIPE_MAC     254
#define RAMP_PIPE_RESET   253
#define RAMP_NUM_PIPES    256

struct ramp_packet;
static const char broadcast_mac[6] = {0xFF,0xFF,0xFF,0xFF,0xFF,0xFF};

class memif_sparc_dma_t : public memif_t
{
public:
  
  memif_sparc_dma_t();

  uint32_t read_chunk_align();
  uint32_t read_chunk_min_size();
  uint32_t read_chunk_max_size();
  memif_t::error read_chunk(uint32_t addr, uint32_t len, uint8_t* bytes, uint8_t asi);
  uint32_t write_chunk_align();
  uint32_t write_chunk_min_size();
  uint32_t write_chunk_max_size();
  memif_t::error write_chunk(uint32_t addr, uint32_t len, const uint8_t* bytes, uint8_t asi);
    
  memif_t::error read_uint32(uint32_t addr, uint32_t* word, uint8_t asi);
  memif_t::error write_uint32(uint32_t addr, uint32_t word, uint8_t asi);
  
  memif_t::error set_num_cores(int val);

  memif_t::error start(void);
  void stop(void);

protected:
  int talk_to_dma(uint8_t nthreads, uint32_t interleaving, uint32_t addr, uint32_t len, const uint8_t* bytes, uint8_t* result, uint16_t read_len);
  int execute_insn(uint8_t count, uint32_t opcode, uint32_t data);
  memif_t::error flush_cache(uint8_t count);
  memif_t::error set_run(int run, int threads_active);

  void send_packet(ramp_packet* p);
  short next_seqno(uint8_t pipeline);
  int wait_for_ack(char *buf, int len);

  virtual int do_send(const char* packet, int size) = 0;
  virtual bool broadcast_first() = 0;

  short seqno[RAMP_NUM_PIPES];
  int sock;
  char ramp_mac[6];
  char appsvr_mac[6];

  bool mac_configured;
  bool mt_init;  
  int reset_status;
  int num_cores;
  uint64_t memsize;

  friend class htif_sparc_dma_t;
};

class memif_sparchw_dma_t : public memif_sparc_dma_t
{
public:
  memif_sparchw_dma_t(const char *_hw_addr, const char *_eth_device);
  ~memif_sparchw_dma_t();

protected:

  void init(void);
  void fini(void);
  
  int do_send(const char* packet, int size);
  bool broadcast_first() { return 0; };
  
  char eth_device[64];
  #ifdef __linux__
    struct sockaddr_ll myaddr;
  #else
    struct sockaddr myaddr;
  #endif
};

class memif_sparcvs_dma_t : public memif_sparc_dma_t
{
public:
  memif_sparcvs_dma_t(const char* _host, int _port, const char* hwaddr);
  ~memif_sparcvs_dma_t();

protected:

  void init(void);
  void fini(void);

  int do_send(const char* packet, int size);
  bool broadcast_first() { return 1; };

  char host[1024];
  int port;
};

class illegal_packet_exception : public std::runtime_error
{
public:
  illegal_packet_exception(const std::string& s) : std::runtime_error(s) {}
};

#endif // memif_sparchw_dma_H
